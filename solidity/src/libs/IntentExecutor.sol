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
///      Four-phase execution:
///      1. Approvals — safeApproveWithRetry(type(uint256).max) for each token+spender pair,
///         handling USDT-style tokens that revert on non-zero-to-non-zero approve.
///      2. Call execution — arbitrary batched calls (swap, fee transfer, etc.)
///      3. Revocation — each pair's allowance is set back to zero, so a spender can pull
///         this contract's tokens only during the call that approved it. A token that
///         reverts on approve(0) cannot be approved.
///      4. Balance sweep — reads balanceOf(this) for each output token and transfers
///         the full remaining balance to the specified recipient.
///
///      Access control: executeAndSweep() and executeAndSweepNative() only run a call
///      that a solver authorized earlier in the same transaction. The solver is the
///      account that calls the CAT validator's `entry`. The validator then reaches this
///      contract through its CALL_PROXY, a permissionless forwarder, so `msg.sender`
///      cannot identify the solver. The solver therefore calls
///      authorizeCall(keccak256(execPayload), validator) first, and each execution
///      consumes one authorization of keccak256(msg.data). The authorization lives in
///      transient storage, so it ends with the transaction and rolls back with a
///      reverted frame.
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
///      A call to an address without code succeeds, so an `entry` sent to a validator
///      that is not deployed on the chain would return without consuming the
///      authorization, even in an atomic batch. authorizeCall() therefore takes the
///      validator whose `entry` follows and reverts ValidatorHasNoCode when that address
///      holds no code. The solver MUST pass the address its `entry` calls.
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
///      contract requires a Cancun-compatible VM (TSTORE/TLOAD). The constructor probes
///      transient storage, so deployment fails on any other VM.
///
///      Tokens or ETH left in this contract after a call stay until a later authorized
///      call moves them. Do not leave tokens behind.
///
///      Allowances from the `approvals` list end with the call, but `calls` can grant
///      others (token.approve(), Permit2) that outlive it. Such an allowance lets its
///      spender pull whatever this contract holds during any later call, including the
///      inputs of an honest fill. revokeApprovals() lets the owner clear them, for
///      example after removing a compromised solver. Revoking a token's allowance to
///      Permit2 disables every Permit2 allowance of that token.
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
    /// @dev The VM does not support transient storage (TSTORE/TLOAD).
    error TransientStorageUnsupported();
    /// @dev The validator passed to authorizeCall() holds no code on this chain.
    error ValidatorHasNoCode();

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
    /// @dev Deployment fails on a VM without transient storage. TSTORE is an undefined
    /// opcode there, so the probe aborts the creation. A VM that accepts TSTORE but does
    /// not read the value back reverts TransientStorageUnsupported.
    constructor(
        address owner_,
        address[] memory solvers
    ) {
        bool transientStorage;
        assembly ("memory-safe") {
            tstore(0, 1)
            transientStorage := tload(0)
            tstore(0, 0)
        }
        if (!transientStorage) revert TransientStorageUnsupported();
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

    /// @notice Set each token+spender allowance of this contract to zero.
    /// @dev Clears allowances that outlived the call that granted them, such as ones a
    /// compromised solver granted through `calls`.
    function revokeApprovals(
        Approval[] calldata approvals
    ) external onlyOwner {
        _safeRevokeAll(approvals);
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
    /// @param validator The validator whose `entry` consumes the authorization. Must hold
    /// code: an `entry` sent to an empty address succeeds without consuming it.
    function authorizeCall(
        bytes32 callHash,
        address validator
    ) external {
        if (!isSolver[msg.sender]) revert NotSolver();
        if (validator.code.length == 0) revert ValidatorHasNoCode();
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

    /// @notice Execute with call-scoped approvals, batched calls, and ERC20 balance sweep.
    /// @dev Four-phase execution:
    ///      1. For each approval: safeApproveWithRetry(token, spender, type(uint256).max)
    ///      2. Execute all calls in order
    ///      3. For each approval: set the allowance back to zero
    ///      4. For each sweep target: transfer full balanceOf(this) to recipient
    ///
    ///      ERC20 outputs only. This function does NOT sweep native ETH.
    ///      If any executed call sends ETH to this contract (e.g. WETH unwrap,
    ///      native-output DEX), that ETH will be left in the contract until the
    ///      next authorized call. Use executeAndSweepNative() instead whenever
    ///      the output may include native ETH.
    ///
    ///      Reverts CallNotAuthorized unless a solver authorized keccak256(msg.data)
    ///      earlier in this transaction. Consumes that authorization before any call.
    /// @param approvals Token+spender pairs to max-approve for the duration of the calls
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
        _safeRevokeAll(approvals);
        _sweepAll(sweepTargets);
    }

    /// @notice Execute with call-scoped approvals, batched calls with value, and native + ERC20 balance sweep.
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
    /// @param approvals Token+spender pairs to max-approve for the duration of the calls
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
        _safeRevokeAll(approvals);
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

    /// @dev Max-approve each token to its spender.
    ///      Uses SafeTransferLib.safeApproveWithRetry, which resets USDT-style tokens to 0
    ///      first when an allowance from before this version is still non-zero.
    function _safeApproveAll(
        Approval[] calldata approvals
    ) private {
        uint256 len = approvals.length;
        for (uint256 i = 0; i < len; ++i) {
            SafeTransferLib.safeApproveWithRetry(approvals[i].token, approvals[i].spender, type(uint256).max);
        }
    }

    /// @dev Set each token+spender allowance to zero. Reverts on a token whose approve(0)
    ///      fails, so no allowance from the call survives it.
    function _safeRevokeAll(
        Approval[] calldata approvals
    ) private {
        uint256 len = approvals.length;
        for (uint256 i = 0; i < len; ++i) {
            SafeTransferLib.safeApprove(approvals[i].token, approvals[i].spender, 0);
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
