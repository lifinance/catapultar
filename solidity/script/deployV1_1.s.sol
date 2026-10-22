// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { multichain } from "./multichain.s.sol";

import { CATValidatorV1_1 } from "../src/CATValidatorV1_1.sol";

/// @notice Deploys CATValidatorV1_1 to its deterministic address (CREATE2, salt 0). The constructor reverts on a chain
/// without transient storage (EIP-1153).
contract deployV1_1 is multichain {
    error NotExpectedAddress(address expected, address deployedTo);

    function run(
        string[] calldata chains
    ) public iterChains(chains) broadcast returns (CATValidatorV1_1 validator) {
        address payable expectedAddress =
            payable(getExpectedCreate2Address(bytes32(0), type(CATValidatorV1_1).creationCode, hex""));
        if (expectedAddress.code.length == 0) {
            validator = new CATValidatorV1_1{ salt: bytes32(0) }();
            if (expectedAddress != address(validator)) revert NotExpectedAddress(expectedAddress, address(validator));
        }
        return CATValidatorV1_1(expectedAddress);
    }
}
