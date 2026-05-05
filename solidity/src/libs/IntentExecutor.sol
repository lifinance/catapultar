// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import { LibBit } from "solady/src/utils/LibBit.sol";
import { ReentrancyGuard } from "solady/src/utils/ReentrancyGuard.sol";
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
///      This contract is stateless and designed for permissionless deployment
///      via the Catapultar stack's CREATE2 deployment scheme.
///
///      This contract intentionally has no access control. executeAndSweep(),
///      executeAndSweepNative(), and receive() are all open to any caller.
///      The security model relies entirely on the caller supplying correct sweep
///      recipients: tokens and ETH are swept out within the same transaction,
///      so the contract should hold no balance between calls under normal
///      operation. Any residual balance (e.g. from a direct ETH send or a
///      failed sweep) can be extracted by any subsequent caller — this is
///      accepted and expected. Do not leave tokens behind.
///
///      function selection:
///      - If the swap/call outputs ERC20 tokens only, use executeAndSweep().
///      - If the swap/call outputs native ETH (e.g. unwrap WETH → ETH, or a
///        DEX that settles in ETH), you MUST use executeAndSweepNative().
///        executeAndSweep() has no native sweep step; any ETH received during
///        execution will remain in the contract and be claimable by anyone.
///
/// @custom:version 2.0.0
contract IntentExecutor is ReentrancyGuard {
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

    /// Events ///

    event Swept(address indexed token, address indexed recipient, uint256 amount);
    event SweptNative(address indexed recipient, uint256 amount);

    /// External Methods ///

    /// @notice Execute with safe approvals, batched calls, and ERC20 balance sweep.
    /// @dev Three-phase execution:
    ///      1. For each approval: safeApproveWithRetry(token, spender, type(uint256).max)
    ///      2. Execute all calls in order
    ///      3. For each sweep target: transfer full balanceOf(this) to recipient
    ///
    ///      ERC20 outputs only. This function does NOT sweep native ETH.
    ///      If any executed call sends ETH to this contract (e.g. WETH unwrap,
    ///      native-output DEX), that ETH will be left in the contract and can
    ///      be swept by any subsequent caller. Use executeAndSweepNative()
    ///      instead whenever the output may include native ETH.
    /// @param approvals Token+spender pairs to max-approve before execution
    /// @param calls Array of calls to execute (swap, fee transfer, etc.)
    /// @param sweepTargets Token+recipient pairs to sweep after execution
    /// @return results Array of call results
    function executeAndSweep(
        Approval[] calldata approvals,
        Call3[] calldata calls,
        SweepTarget[] calldata sweepTargets
    ) external nonReentrant returns (Result[] memory results) {
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
    ///      ETH will be left in the contract and claimable by anyone.
    /// @param approvals Token+spender pairs to max-approve before execution
    /// @param calls Array of calls with value to execute
    /// @param sweepTargets ERC20 token+recipient pairs to sweep after execution
    /// @param nativeSweepRecipient Address to receive remaining native balance (zero address falls back to
    ///     msg.sender)
    /// @return results Array of call results
    function executeAndSweepNative(
        Approval[] calldata approvals,
        Call3Value[] calldata calls,
        SweepTarget[] calldata sweepTargets,
        address payable nativeSweepRecipient
    ) external payable nonReentrant returns (Result[] memory results) {
        _safeApproveAll(approvals);
        results = _executeCallsWithValue(calls);
        _sweepAll(sweepTargets);

        uint256 nativeBalance = address(this).balance;
        if (nativeBalance > 0) {
            address sweepRecipient = nativeSweepRecipient == address(0) ? msg.sender : nativeSweepRecipient;
            SafeTransferLib.safeTransferETH(sweepRecipient, nativeBalance);
            emit SweptNative(sweepRecipient, nativeBalance);
        }
    }

    /// @notice Receive native ETH (required for swaps that output native tokens)
    receive() external payable { }

    /// Internal Methods ///

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
