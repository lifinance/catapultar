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
///         Max approval means subsequent executions with the same token+spender
///         skip the storage write (~3-4k gas saved per repeat).
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

    /// @notice Execute with safe approvals, batched calls with value, and native balance sweep.
    /// @dev Used for swaps that output native tokens (ETH/MATIC/etc).
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
    ///      Max approval is a one-time storage write — subsequent calls with
    ///      the same token+spender pair are a no-op read (~3-4k gas saved).
    function _safeApproveAll(
        Approval[] calldata approvals
    ) private {
        uint256 len = approvals.length;
        for (uint256 i = 0; i < len; ++i) {
            SafeTransferLib.safeApproveWithRetry(approvals[i].token, approvals[i].spender, type(uint256).max);
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
                SafeTransferLib.safeTransfer(target.token, target.recipient, balance);
                emit Swept(target.token, target.recipient, balance);
            }
        }
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
