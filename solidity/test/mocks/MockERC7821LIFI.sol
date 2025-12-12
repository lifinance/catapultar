// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import { Brutalizer } from "solady/test/utils/Brutalizer.sol";

import { ERC7821LIFI } from "../../src/libs/ERC7821LIFI.sol";

/// @dev WARNING! This mock is strictly intended for testing purposes only.
/// Do NOT copy anything here into production code unless you really know what you are doing.
contract MockERC7821LIFI is ERC7821LIFI, Brutalizer {
    bytes validOpData;

    error Unauthorized();

    function executionModeRevert(
        bytes32 mode
    ) external view returns (bytes32) {
        return _executionModeRevert(mode);
    }

    function executionModeId(
        bytes32 mode
    ) external view returns (uint256) {
        return _executionModeId(mode);
    }

    function _validateOpData(
        bytes32,
        ERC7821LIFI.Call[] calldata,
        bytes calldata opData
    ) internal view override returns (bool) {
        return keccak256(validOpData) == keccak256(opData);
    }

    function executeDirect(
        Call[] calldata calls
    ) public payable virtual {
        _misalignFreeMemoryPointer();
        _brutalizeMemory();
        _execute(calls, bytes32(0));
        _checkMemory();
    }

    function setValidCalldata(
        bytes calldata val
    ) public {
        validOpData = val;
    }
}
