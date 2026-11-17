// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { multichain } from "./multichain.s.sol";

import { CATValidatorV1_1 } from "../src/CATValidatorV1_1.sol";

/// @notice Deploys CATValidatorV1_1 to its deterministic address (CREATE2, salt 0). Reverts unless the creation code
/// hashes to the pin in `snapshots/v1-1-bytecode.json`. The constructor reverts on a chain without transient storage
/// (EIP-1153).
contract deployV1_1 is multichain {
    error NotExpectedAddress(address expected, address deployedTo);
    error CreationCodeNotPinned(bytes32 pinned, bytes32 built);

    function run(
        string[] calldata chains
    ) public iterChains(chains) broadcast returns (CATValidatorV1_1 validator) {
        bytes memory creationCode = type(CATValidatorV1_1).creationCode;
        bytes32 pinned = vm.parseJsonBytes32(vm.readFile("snapshots/v1-1-bytecode.json"), ".CATValidatorV1_1");
        if (keccak256(creationCode) != pinned) revert CreationCodeNotPinned(pinned, keccak256(creationCode));

        address payable expectedAddress = payable(getExpectedCreate2Address(bytes32(0), creationCode, hex""));
        if (expectedAddress.code.length == 0) {
            validator = new CATValidatorV1_1{ salt: bytes32(0) }();
            if (expectedAddress != address(validator)) revert NotExpectedAddress(expectedAddress, address(validator));
        }
        return CATValidatorV1_1(expectedAddress);
    }
}
