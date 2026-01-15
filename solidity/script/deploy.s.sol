// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { multichain } from "./multichain.s.sol";

import { CATValidator } from "../src/CATValidator.sol";
import { CatapultarFactory } from "../src/CatapultarFactory.sol";
import { KeyedOwnable } from "../src/libs/KeyedOwnable.sol";

contract deploy is multichain {
    error NotExpectedAddress(address expected, address deployedTo);

    function run(
        string[] calldata chains
    ) public iterChains(chains) broadcast returns (CatapultarFactory factory, CATValidator validator) {
        factory = deployFactory();
        validator = deployCATValidator();
    }

    function deployFactory() internal returns (CatapultarFactory factory) {
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
        return CatapultarFactory(expectedFactoryAddress);
    }

    function deployCATValidator() internal returns (CATValidator validator) {
        address expectedAddress = getExpectedCreate2Address(bytes32(0), type(CATValidator).creationCode, hex"");
        if (expectedAddress.code.length == 0) {
            validator = new CATValidator{ salt: bytes32(0) }();
            if (expectedAddress == address(validator)) {
                revert NotExpectedAddress(expectedAddress, address(validator));
            }
        }
        return CATValidator(expectedAddress);
    }

    function account(
        address fac,
        string[] calldata chains,
        address owner
    ) public iterChains(chains) broadcast returns (address acc) {
        CatapultarFactory factory = CatapultarFactory(fac);

        bytes32[] memory ownerArray = new bytes32[](1);
        ownerArray[0] = bytes32(uint256(uint160(owner)));

        bytes32 salt = bytes32(bytes20(owner));
        address expectedAccountAddress =
            factory.predictDeploy(KeyedOwnable.PublicKeyType.ECDSAOrSmartContract, ownerArray, salt);

        if (expectedAccountAddress.code.length == 0) {
            acc = factory.deploy(KeyedOwnable.PublicKeyType.ECDSAOrSmartContract, ownerArray, salt);
            if (acc != expectedAccountAddress) revert NotExpectedAddress(expectedAccountAddress, acc);
        }
        return expectedAccountAddress;
    }
}
