// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { AllowanceSpend, Outcome } from "../libs/LibExecutionConstraint.sol";

/// @notice The functions `CATValidatorV1_1` adds to `CATValidator`.
/// @dev `CATValidatorV1_1.entry` is overloaded by the base's `entry`, so the contract's own name cannot select it in
/// `abi.encodeCall` or `.selector`.
interface ICATValidatorV1_1 {
    /// @notice Execute a transaction for `account` given a signed constraint that also commits `executionTarget` and
    /// `payloadHash`. Forwards no native value to the call.
    /// @param execTarget Target the call proxy calls with `execPayload`; receives the pulled allowances.
    /// @param execPayload Calldata for `execTarget`. Empty skips the call.
    /// @param account Signer of the constraint and source of the allowances.
    /// @param nonce Constraint nonce. A non-zero nonce is spent once; nonce 0 is reusable.
    /// @param allowances Signed token allowances and the spends to pull now.
    /// @param outcomes Minimum balances the validator must hold after the call, each forwarded to its destination.
    /// @param executionTarget Committed `execTarget`; zero means unconstrained, and reverts on nonce 0.
    /// @param payloadHash Committed `keccak256(execPayload)`; zero means unconstrained.
    /// @param signature Signature of `account` over the v1.1 digest: ECDSA, or ERC-1271 data for a contract signer.
    function entry(
        address execTarget,
        bytes calldata execPayload,
        address account,
        uint256 nonce,
        AllowanceSpend[] calldata allowances,
        Outcome[] calldata outcomes,
        address executionTarget,
        bytes32 payloadHash,
        bytes calldata signature
    ) external;

    /// @notice Amount of `token` the running 9-argument `entry` moved out of its signer. Zero outside it and during
    /// the allowance transfers.
    function pulled(
        address token
    ) external view returns (uint256);

    /// @notice Id of the running 9-argument `entry`: 1, 2, 3, ... within a transaction. Zero outside it.
    function entryId() external view returns (uint256);
}
