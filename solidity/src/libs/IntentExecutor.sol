// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { Ownable } from "solady/src/auth/Ownable.sol";
import { LibBit } from "solady/src/utils/LibBit.sol";
import { ReentrancyGuardTransient } from "solady/src/utils/ReentrancyGuardTransient.sol";
import { SafeTransferLib } from "solady/src/utils/SafeTransferLib.sol";

/// @title IntentExecutor
/// @author LI.FI / Intent Factory
/// @notice Multicall-like execution contract for Intent Factory bundle execution.
/// @dev Replaces Multicall3 as the execution target for IF solver.
///      Three-phase execution:
///      1. Safe approvals — safeApproveWithRetry(type(uint256).max) for each input token,
///         handling USDT-style tokens that revert on non-zero-to-non-zero approve.
///         Allowance is checked first; if already type(uint256).max the approve is skipped
///         entirely (~1,800+ gas saved per repeat, avoiding the Approval event emission).
///      2. Call execution — arbitrary batched calls (swap, fee transfer, etc.)
///      3. Balance sweep — reads balanceOf(this) for each output token and transfers
///         the full remaining balance to the specified recipient.
///
///      Access control: executeAndSweep() and executeAndSweepNative() only run a call
///      that a solver authorized earlier in the same transaction. The solver is the
///      account that calls the CAT validator's `entry`. The validator then reaches this
///      contract through its CALL_PROXY, a permissionless forwarder, so `msg.sender`
///      cannot identify the solver. The solver therefore calls
///      authorizeCall(keccak256(execPayload)) first, and each execution consumes one
///      authorization of keccak256(msg.data). The authorization lives in transient
///      storage, so it ends with the transaction and rolls back with a reverted frame.
///
///      The solver MUST call authorizeCall() in the same atomic batch as the validator
///      `entry` it authorizes (ERC-7821 revert flag 0x00, which bubbles any failed call,
///      and no multichain replay), directly before that `entry`. If `entry` fails inside
///      a batch that skips failures (flag 0x01, or 0x02 for logical failures), the
///      authorization stays live until the transaction ends, and any code that runs
///      later in that transaction can execute the authorized payload. That payload
///      delivers the fill's proceeds to the validator, where any account can take them
///      with a self-signed constraint, so a skipping batch leaks the fill. The failure
///      need not be accidental: anyone can relay the signed batch with too little gas
///      for `entry`, or replay a multichain batch on a chain where `entry` fails.
///
///      An authorization admits the exact calldata only, so its approvals, calls and
///      sweep recipients are those the solver chose. One exception: native value sent
///      with executeAndSweepNative() is not part of the authorization.
///
///      A solver must be an account only its key controls. Adding a forwarder (such as
///      a validator's CALL_PROXY) as a solver lets anyone authorize any call.
///
///      The owner manages the solver set and transfers ownership only through solady's
///      two-step handover. The gate cannot be disabled.
///
///      The authorizations and the reentrancy guard live in transient storage, so the
///      contract requires a Cancun-compatible VM (TSTORE/TLOAD).
///
///      Tokens or ETH left in this contract after a call stay until a later authorized
///      call moves them, or until a spender that an earlier call max-approved pulls
///      them. Do not leave tokens behind.
///
///      function selection:
///      - If the swap/call outputs ERC20 tokens only, use executeAndSweep().
///      - If the swap/call outputs native ETH (e.g. unwrap WETH → ETH, or a
///        DEX that settles in ETH), you MUST use executeAndSweepNative().
///        executeAndSweep() has no native sweep step; any ETH received during
///        execution will remain in the contract until the next authorized call.
///
/// @custom:version 3.0.0
contract IntentExecutor is Ownable, ReentrancyGuardTransient {
    /// @dev Multicall3-compatible call struct (no value)
    struct Call3 {
        address target;
        bool allowFailure;
        bytes callData;
    }

    /// @dev Multicall3-compatible call struct with value (for native transfers)
    struct Call3Value {
        address target;
        bool allowFailure;
        uint256 value;
        bytes callData;
    }

    /// @dev Result struct matching Multicall3
    struct Result {
        bool success;
        bytes returnData;
    }

    /// @dev Token + spender pair for safe max approvals
    struct Approval {
        address token;
        address spender;
    }

    /// @dev Token + destination pair for post-execution sweep
    struct SweepTarget {
        address token;
        address recipient;
    }

    /// Errors ///

    error ZeroRecipient();
    /// @dev No authorization from a solver covers this calldata in the current transaction.
    error CallNotAuthorized();
    /// @dev The caller of authorizeCall() is not in the solver set.
    error NotSolver();
    /// @dev The zero address cannot be a solver.
    error ZeroSolver();
    /// @dev Ownership moves only through the two-step handover and cannot be renounced.
    error OwnershipTransferDisabled();

    /// Events ///

    event Swept(address indexed token, address indexed recipient, uint256 amount);
    event SweptNative(address indexed recipient, uint256 amount);
    event SolverSet(address indexed solver, bool allowed);

    /// Storage ///

    /// @dev Seed of the transient authorization slots: keccak256("IntentExecutor.authorization").
    uint256 private constant _AUTHORIZATION_SEED = 0x019bc4d42441a5967a54f65a55b6922eab59e08350d9747659b3c06bbbe4f3fa;

    /// @notice Accounts allowed to authorize calls.
    mapping(address solver => bool allowed) public isSolver;

    /// @param owner_ Manages the solver set. Must not be zero.
    /// @param solvers Initial solver set.
    constructor(
        address owner_,
        address[] memory solvers
    ) {
        if (owner_ == address(0)) revert NewOwnerIsZeroAddress();
        _initializeOwner(owner_);
        for (uint256 i = 0; i < solvers.length; ++i) {
            _setSolver(solvers[i], true);
        }
    }

    /// Admin Methods ///

    /// @notice Add or remove a solver.
    function setSolver(
        address solver,
        bool allowed
    ) external onlyOwner {
        _setSolver(solver, allowed);
    }

    /// @dev Reverts ZeroSolver when adding the zero address: it can never call, so it
    /// only signals a mistyped solver list.
    function _setSolver(
        address solver,
        bool allowed
    ) private {
        if (allowed && solver == address(0)) revert ZeroSolver();
        isSolver[solver] = allowed;
        emit SolverSet(solver, allowed);
    }

    /// @dev Disabled: use requestOwnershipHandover() and completeOwnershipHandover().
    function transferOwnership(
        address
    ) public payable override onlyOwner {
        revert OwnershipTransferDisabled();
    }

    /// @dev Disabled: the solver set must stay manageable.
    function renounceOwnership() public payable override onlyOwner {
        revert OwnershipTransferDisabled();
    }

    /// @dev The contract already requires TSTORE for its authorizations, so the guard uses
    /// transient storage on every chain, not only on Ethereum mainnet.
    function _useTransientReentrancyGuardOnlyOnMainnet() internal pure override returns (bool) {
        return false;
    }

    /// Solver Methods ///

    /// @notice Authorize one execution of the call whose complete calldata hashes to
    /// `callHash`, for the rest of the current transaction.
    /// @dev `callHash` is keccak256 of the calldata this contract will receive, which is
    /// the validator's `execPayload` and the V2 binding's `payloadHash`. Authorizing the
    /// same hash twice admits two executions.
    function authorizeCall(
        bytes32 callHash
    ) external {
        if (!isSolver[msg.sender]) revert NotSolver();
        bytes32 slot = _authorizationSlot(callHash);
        assembly ("memory-safe") {
            tstore(slot, add(tload(slot), 1))
        }
    }

    /// @notice Number of executions of `callHash` still authorized in this transaction.
    function authorizations(
        bytes32 callHash
    ) external view returns (uint256 count) {
        bytes32 slot = _authorizationSlot(callHash);
        assembly ("memory-safe") {
            count := tload(slot)
        }
    }

    /// External Methods ///

    /// @notice Execute with safe approvals, batched calls, and ERC20 balance sweep.
    /// @dev Three-phase execution:
    ///      1. For each approval: safeApproveWithRetry(token, spender, type(uint256).max)
    ///      2. Execute all calls in order
    ///      3. For each sweep target: transfer full balanceOf(this) to recipient
    ///
    ///      ERC20 outputs only. This function does NOT sweep native ETH.
    ///      If any executed call sends ETH to this contract (e.g. WETH unwrap,
    ///      native-output DEX), that ETH will be left in the contract until the
    ///      next authorized call. Use executeAndSweepNative() instead whenever
    ///      the output may include native ETH.
    ///
    ///      Reverts CallNotAuthorized unless a solver authorized keccak256(msg.data)
    ///      earlier in this transaction. Consumes that authorization before any call.
    /// @param approvals Token+spender pairs to max-approve before execution
    /// @param calls Array of calls to execute (swap, fee transfer, etc.)
    /// @param sweepTargets Token+recipient pairs to sweep after execution
    /// @return results Array of call results
    function executeAndSweep(
        Approval[] calldata approvals,
        Call3[] calldata calls,
        SweepTarget[] calldata sweepTargets
    ) external nonReentrant returns (Result[] memory results) {
        _consumeAuthorization();
        _safeApproveAll(approvals);
        results = _executeCalls(calls);
        _sweepAll(sweepTargets);
    }

    /// @notice Execute with safe approvals, batched calls with value, and native + ERC20 balance sweep.
    /// @dev Used for swaps that output native tokens (ETH/MATIC/etc). Extends executeAndSweep()
    ///      with two additional capabilities: calls may forward ETH via the value field, and any
    ///      native balance remaining after execution is swept to nativeSweepRecipient.
    ///
    ///      Use this function (instead of executeAndSweep()) whenever the output may include
    ///      native ETH — e.g. WETH unwrap, a DEX that settles in ETH, or any call chain where
    ///      ETH could land in this contract. If you use executeAndSweep() in that scenario the
    ///      ETH will be left in the contract until the next authorized call.
    ///
    ///      Reverts CallNotAuthorized unless a solver authorized keccak256(msg.data)
    ///      earlier in this transaction. Consumes that authorization before any call.
    ///      msg.value is not part of the authorization.
    /// @param approvals Token+spender pairs to max-approve before execution
    /// @param calls Array of calls with value to execute
    /// @param sweepTargets ERC20 token+recipient pairs to sweep after execution
    /// @param nativeSweepRecipient Address to receive remaining native balance. Reverts ZeroRecipient
    ///     when zero, like an ERC20 sweep target.
    /// @return results Array of call results
    function executeAndSweepNative(
        Approval[] calldata approvals,
        Call3Value[] calldata calls,
        SweepTarget[] calldata sweepTargets,
        address payable nativeSweepRecipient
    ) external payable nonReentrant returns (Result[] memory results) {
        if (nativeSweepRecipient == address(0)) revert ZeroRecipient();
        _consumeAuthorization();
        _safeApproveAll(approvals);
        results = _executeCallsWithValue(calls);
        _sweepAll(sweepTargets);

        uint256 nativeBalance = address(this).balance;
        if (nativeBalance > 0) {
            SafeTransferLib.safeTransferETH(nativeSweepRecipient, nativeBalance);
            emit SweptNative(nativeSweepRecipient, nativeBalance);
        }
    }

    /// @notice Receive native ETH (required for swaps that output native tokens)
    receive() external payable { }

    /// Internal Methods ///

    /// @dev Consumes one authorization of keccak256(msg.data), or reverts
    ///      CallNotAuthorized when none is left.
    function _consumeAuthorization() private {
        bytes32 callHash;
        assembly ("memory-safe") {
            let m := mload(0x40)
            calldatacopy(m, 0, calldatasize())
            callHash := keccak256(m, calldatasize())
        }
        bytes32 slot = _authorizationSlot(callHash);
        bool authorized;
        assembly ("memory-safe") {
            let count := tload(slot)
            authorized := iszero(iszero(count))
            if authorized { tstore(slot, sub(count, 1)) }
        }
        if (!authorized) revert CallNotAuthorized();
    }

    /// @dev Transient slot of the authorization counter for `callHash`. Hashing with a
    ///      seed keeps solver-chosen hashes away from any other transient slot.
    function _authorizationSlot(
        bytes32 callHash
    ) private pure returns (bytes32 slot) {
        assembly ("memory-safe") {
            mstore(0x00, callHash)
            mstore(0x20, _AUTHORIZATION_SEED)
            slot := keccak256(0x00, 0x40)
        }
    }

    /// @dev Safe max-approve each token to its spender.
    ///      Uses SafeTransferLib.safeApproveWithRetry which handles USDT-style tokens
    ///      by resetting to 0 first if needed.
    ///      Skips the approve entirely when allowance is already type(uint256).max,
    ///      avoiding an unnecessary SSTORE + Approval event (~1,800+ gas per pair).
    function _safeApproveAll(
        Approval[] calldata approvals
    ) private {
        uint256 len = approvals.length;
        for (uint256 i = 0; i < len; ++i) {
            address token = approvals[i].token;
            address spender = approvals[i].spender;
            if (_allowance(token, address(this), spender) < type(uint256).max) {
                SafeTransferLib.safeApproveWithRetry(token, spender, type(uint256).max);
            }
        }
    }

    /// @dev Returns the ERC20 allowance of `owner` for `spender`. Returns 0 on failure.
    /// This contract returns 0 if no contract has been deployed.
    function _allowance(
        address token,
        address owner,
        address spender
    ) private view returns (uint256 amount) {
        assembly ("memory-safe") {
            // Save free memory pointer. We will overwrite it.
            let m := mload(0x40)
            mstore(0x34, spender) // Spender zero-pad: 0x34-0x3f, address: 0x40-0x53 (corrupts free ptr temporarily).
            mstore(0x14, owner) // Owner zero-pad: 0x14-0x1f, address: 0x20-0x33.
            mstore(0x00, 0xdd62ed3e000000000000000000000000) // `allowance(address,address)` selector at 0x10.
            amount := mul( // The arguments of `mul` are evaluated from right to left.
                mload(0x00),
                and( // The arguments of `and` are evaluated from right to left.
                    gt(returndatasize(), 0x1f), // At least 32 bytes returned.
                    staticcall(gas(), token, 0x10, 0x44, 0x00, 0x20)
                )
            )
            mstore(0x40, m) // Restore the free memory pointer.
        }
    }

    /// @dev Transfer full remaining balance of each token to its recipient.
    function _sweepAll(
        SweepTarget[] calldata sweepTargets
    ) private {
        uint256 len = sweepTargets.length;
        for (uint256 i = 0; i < len; ++i) {
            SweepTarget calldata target = sweepTargets[i];
            if (target.recipient == address(0)) revert ZeroRecipient();
            uint256 balance = SafeTransferLib.balanceOf(target.token, address(this));
            if (balance > 0) {
                _transfer(target.token, target.recipient, balance);
                emit Swept(target.token, target.recipient, balance);
            }
        }
    }

    function _transfer(
        address token,
        address to,
        uint256 amount
    ) internal virtual {
        SafeTransferLib.safeTransfer(token, to, amount);
    }

    /// @dev Executes an array of calls without value
    function _executeCalls(
        Call3[] calldata calls
    ) private returns (Result[] memory results) {
        uint256 len = calls.length;
        results = new Result[](len);
        for (uint256 i = 0; i < len; ++i) {
            Call3 calldata call3 = calls[i];
            (bool success, bytes memory ret) = call3.target.call(call3.callData);
            // Branchless: revert if both allowFailure=false and success=false
            if (LibBit.and(!call3.allowFailure, !success)) {
                assembly {
                    revert(add(ret, 0x20), mload(ret))
                }
            }
            results[i] = Result(success, ret);
        }
    }

    /// @dev Executes an array of calls with value
    function _executeCallsWithValue(
        Call3Value[] calldata calls
    ) private returns (Result[] memory results) {
        uint256 len = calls.length;
        results = new Result[](len);
        for (uint256 i = 0; i < len; ++i) {
            Call3Value calldata call3 = calls[i];
            (bool success, bytes memory ret) = call3.target.call{ value: call3.value }(call3.callData);
            // Branchless: revert if both allowFailure=false and success=false
            if (LibBit.and(!call3.allowFailure, !success)) {
                assembly {
                    revert(add(ret, 0x20), mload(ret))
                }
            }
            results[i] = Result(success, ret);
        }
    }
}
