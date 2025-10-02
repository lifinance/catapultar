// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.22;

import { multichain } from "./multichain.s.sol";

import { CatapultarFactory } from "../src/CatapultarFactory.sol";

interface KeylessCreate2Factory {
    function safeCreate2(
        bytes32 salt,
        bytes calldata initializationCode
    ) external payable returns (address deploymentAddress);
}

contract deploy is multichain {
    error NotExpectedAddress(address expected, address deployedTo);

    function run(
        string[] calldata chains
    ) public iterChains(chains) broadcast returns (CatapultarFactory factory) {
        address expectedFactoryAddress = getExpectedCreate2Address(
            bytes32(0), // salt
            type(CatapultarFactory).creationCode,
            hex""
        );
        if (expectedFactoryAddress.code.length == 0) {
            factory = new CatapultarFactory{ salt: bytes32(0) }();
            if (expectedFactoryAddress != address(factory)) {
                revert NotExpectedAddress(expectedFactoryAddress, address(factory));
            }
        }
    }
}
