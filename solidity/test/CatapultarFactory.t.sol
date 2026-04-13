// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

// forge-lint: disable-start(unsafe-typecast)

import { Test } from "forge-std/src/Test.sol";

import { LibClone } from "solady/src/utils/LibClone.sol";

import { CatapultarFactory } from "../src/CatapultarFactory.sol";
import { KeyedOwnable } from "../src/libs/KeyedOwnable.sol";

contract CatapultarFactoryTest is Test {
    CatapultarFactory factory;

    function setUp() external {
        factory = new CatapultarFactory();
    }

    /// forge-config: default.isolate = true
    function test_deploy() external {
        address owner = makeAddr("owner");
        bytes32 salt = bytes32(bytes20(uint160(owner)));

        bytes32[] memory keys = new bytes32[](1);
        keys[0] = bytes32(uint256(uint160(owner)));

        address deployedTo = factory.deploy(KeyedOwnable.PublicKeyType.ECDSAOrSmartContract, keys, salt);
        vm.snapshotGasLastCall("deploy");

        // Check that the deployed proxy has code.
        assertNotEq(deployedTo.code.length, 0);

        // Try deploying again.
        vm.expectRevert(abi.encodeWithSignature("DeploymentFailed()"));

        factory.deploy(KeyedOwnable.PublicKeyType.ECDSAOrSmartContract, keys, salt);
    }

    function test_version() external view {
        assertEq(factory.VERSION(), "0.1.0");
    }

    /// forge-config: default.isolate = true
    function test_deployWithDigest() external {
        address owner = makeAddr("owner");
        bytes32 salt = bytes32(bytes20(uint160(owner)));

        bytes32[] memory keys = new bytes32[](1);
        keys[0] = bytes32(uint256(uint160(owner)));

        address deployedTo =
            factory.deployWithDigest(KeyedOwnable.PublicKeyType.ECDSAOrSmartContract, keys, salt, bytes32(0), false);
        vm.snapshotGasLastCall("deployWithDigest");

        // Check that the deployed proxy has code.
        assertNotEq(deployedTo.code.length, 0);

        // Try deploying again.
        vm.expectRevert(abi.encodeWithSignature("DeploymentFailed()"));
        factory.deployWithDigest(KeyedOwnable.PublicKeyType.ECDSAOrSmartContract, keys, salt, bytes32(0), false);
    }

    /// forge-config: default.isolate = true
    function test_deployUpgradeable() external {
        address owner = makeAddr("owner");
        bytes32 salt = bytes32(bytes20(uint160(owner)));

        bytes32[] memory keys = new bytes32[](1);
        keys[0] = bytes32(uint256(uint160(owner)));

        address deployedTo = factory.deployUpgradeable(KeyedOwnable.PublicKeyType.ECDSAOrSmartContract, keys, salt);
        vm.snapshotGasLastCall("deployUpgradeable");

        // Check that the deployed proxy has code.
        assertNotEq(deployedTo.code.length, 0);

        // Try deploying again.
        vm.expectRevert(abi.encodeWithSignature("DeploymentFailed()"));
        factory.deployUpgradeable(KeyedOwnable.PublicKeyType.ECDSAOrSmartContract, keys, salt);
    }

    function test_predictDeploy() external {
        address owner = makeAddr("owner");
        bytes32 salt = bytes32(bytes20(uint160(owner)));

        bytes32[] memory keys = new bytes32[](1);
        keys[0] = bytes32(uint256(uint160(owner)));

        address predictedDeployedTo = factory.predictDeploy(KeyedOwnable.PublicKeyType.ECDSAOrSmartContract, keys, salt);

        address deployedTo = factory.deploy(KeyedOwnable.PublicKeyType.ECDSAOrSmartContract, keys, salt);
        assertEq(predictedDeployedTo, deployedTo);
    }

    function test_predictDeployWithDigest() external {
        address owner = makeAddr("owner");
        bytes32 salt = bytes32(bytes20(uint160(owner)));

        bytes32 embeddedCall = keccak256(bytes("randomCall"));

        bytes32[] memory keys = new bytes32[](1);
        keys[0] = bytes32(uint256(uint160(owner)));

        address predictedDeployedTo = factory.predictDeployWithDigest(
            KeyedOwnable.PublicKeyType.ECDSAOrSmartContract, keys, salt, embeddedCall, false
        );

        address deployedTo = factory.deployWithDigest(
            KeyedOwnable.PublicKeyType.ECDSAOrSmartContract, keys, salt, embeddedCall, false
        );
        assertEq(predictedDeployedTo, deployedTo);
    }

    function test_predictDeployUpgradeable() external {
        address owner = makeAddr("owner");
        bytes32 salt = bytes32(bytes20(uint160(owner)));

        bytes32[] memory keys = new bytes32[](1);
        keys[0] = bytes32(uint256(uint160(owner)));

        address predictedDeployedTo =
            factory.predictDeployUpgradeable(KeyedOwnable.PublicKeyType.ECDSAOrSmartContract, keys, salt);

        address deployedTo = factory.deployUpgradeable(KeyedOwnable.PublicKeyType.ECDSAOrSmartContract, keys, salt);
        assertEq(predictedDeployedTo, deployedTo);
    }

    // Verifies that _salt encodes preSalt || ktp || numOwners || owners as documented.
    function test_saltEncoding() external view {
        bytes32 preSalt = bytes32(uint256(0xdead));
        KeyedOwnable.PublicKeyType ktp = KeyedOwnable.PublicKeyType.P256;

        bytes32[] memory keys = new bytes32[](2);
        keys[0] = bytes32(uint256(1));
        keys[1] = bytes32(uint256(2));

        bytes32 expectedSalt = keccak256(abi.encodePacked(preSalt, uint8(ktp), uint8(keys.length), keys[0], keys[1]));
        address expected = LibClone.predictDeterministicAddress_PUSH0(factory.EXECUTOR(), expectedSalt, address(factory));

        assertEq(factory.predictDeploy(ktp, keys, preSalt), expected);
    }

}
