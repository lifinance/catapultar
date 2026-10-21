// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { AllowanceSpend, Outcome } from "../libs/LibExecutionConstraint.sol";

/// @notice The v1.1 surface that `CATValidatorV1_1` adds to the hold-and-forward v1.
/// @dev `CATValidatorV1_1.entry` is overloaded by v1's `entry`, so the contract's own name cannot select it in
/// `abi.encodeCall` or `.selector`.
interface ICATValidatorV1_1 {
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

    function pulled(
        address token
    ) external view returns (uint256);

    function entryId() external view returns (uint256);
}
