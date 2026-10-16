// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { multichain } from "./multichain.s.sol";

import { CATValidator } from "../src/CATValidator.sol";
import { CATValidatorV2 } from "../src/CATValidatorV2.sol";
import { CatapultarFactory } from "../src/CatapultarFactory.sol";
import { IntentExecutor } from "../src/libs/IntentExecutor.sol";
import { KeyedOwnable } from "../src/libs/KeyedOwnable.sol";

contract deploy is multichain {
    error NotExpectedAddress(address expected, address deployedTo);
    error CanonicalVmMissing(address virtualMachine);

    /// @dev The v1.2 LI.FI VirtualMachine, at one CREATE2 address on every chain it
    /// supports. CATValidatorV2 staticcalls it to run committed validation programs,
    /// so it must exist on the target chain. The address is the only constructor
    /// argument and folds into the CREATE2 init code: changing it moves the validator.
    address internal constant CANONICAL_VM = 0xA9f22b951d5A9CBBD0eC8d2741EA44BFDD2D11fd;

    function run(
        string[] calldata chains
    )
        public
        iterChains(chains)
        broadcast
        returns (
            CatapultarFactory factory,
            CATValidator validator,
            CATValidatorV2 validatorV2,
            IntentExecutor intentExecutor
        )
    {
        factory = deployFactory();
        validator = deployCATValidator();
        validatorV2 = deployCATValidatorV2();
        intentExecutor = deployIntentExecutor();
    }

    /// @notice Deploy only CATValidatorV2. Consumers that keep an existing factory and
    /// v1 validator use this to adopt V2 without moving their escrow addresses.
    function runValidatorV2(
        string[] calldata chains
    ) public iterChains(chains) broadcast returns (CATValidatorV2) {
        return deployCATValidatorV2();
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
        address payable expectedAddress =
            payable(getExpectedCreate2Address(bytes32(0), type(CATValidator).creationCode, hex""));
        if (expectedAddress.code.length == 0) {
            validator = new CATValidator{ salt: bytes32(0) }();
            if (expectedAddress != address(validator)) revert NotExpectedAddress(expectedAddress, address(validator));
        }
        return CATValidator(expectedAddress);
    }

    function deployCATValidatorV2() internal returns (CATValidatorV2 validatorV2) {
        if (CANONICAL_VM.code.length == 0) revert CanonicalVmMissing(CANONICAL_VM);

        address payable expectedAddress = payable(getExpectedCreate2Address(
                bytes32(0), type(CATValidatorV2).creationCode, abi.encode(CANONICAL_VM)
            ));
        if (expectedAddress.code.length == 0) {
            validatorV2 = new CATValidatorV2{ salt: bytes32(0) }(CANONICAL_VM);
            if (expectedAddress != address(validatorV2)) {
                revert NotExpectedAddress(expectedAddress, address(validatorV2));
            }
        }
        return CATValidatorV2(expectedAddress);
    }

    function deployIntentExecutor() internal returns (IntentExecutor intentExecutor) {
        address payable expectedAddress =
            payable(getExpectedCreate2Address(bytes32(0), type(IntentExecutor).creationCode, hex""));
        if (expectedAddress.code.length == 0) {
            intentExecutor = new IntentExecutor{ salt: bytes32(0) }();
            if (expectedAddress != address(intentExecutor)) {
                revert NotExpectedAddress(expectedAddress, address(intentExecutor));
            }
        }
        return IntentExecutor(expectedAddress);
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
