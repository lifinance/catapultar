// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { Test } from "forge-std/Test.sol";

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

        address deployedTo = factory.deploy(owner, salt);
        vm.snapshotGasLastCall("deploy");

        // Check that the deployed proxy has code.
        assertNotEq(deployedTo.code.length, 0);

        // Try deploying again.
        vm.expectRevert(abi.encodeWithSignature("DeploymentFailed()"));

        factory.deploy(KeyedOwnable.KeyType.ECDSAThenSmartContract, keys, salt);
    }

    /// forge-config: default.isolate = true
    function test_deployWithEmbedCall() external {
        address owner = makeAddr("owner");
        bytes32 salt = bytes32(bytes20(uint160(owner)));

        bytes32[] memory keys = new bytes32[](1);
        keys[0] = bytes32(uint256(uint160(owner)));

        address deployedTo =
            factory.deployWithEmbedCall(KeyedOwnable.KeyType.ECDSAThenSmartContract, keys, salt, bytes32(0));
        vm.snapshotGasLastCall("deployWithEmbedCall");

        // Check that the deployed proxy has code.
        assertNotEq(deployedTo.code.length, 0);

        // Try deploying again.
        vm.expectRevert(abi.encodeWithSignature("DeploymentFailed()"));
        factory.deployWithEmbedCall(KeyedOwnable.KeyType.ECDSAThenSmartContract, keys, salt, bytes32(0));
    }

    /// forge-config: default.isolate = true
    function test_deployUpgradeable() external {
        address owner = makeAddr("owner");
        bytes32 salt = bytes32(bytes20(uint160(owner)));

        bytes32[] memory keys = new bytes32[](1);
        keys[0] = bytes32(uint256(uint160(owner)));

        address deployedTo = factory.deployUpgradeable(KeyedOwnable.KeyType.ECDSAThenSmartContract, keys, salt);
        vm.snapshotGasLastCall("deployUpgradeable");

        // Check that the deployed proxy has code.
        assertNotEq(deployedTo.code.length, 0);

        // Try deploying again.
        vm.expectRevert(abi.encodeWithSignature("DeploymentFailed()"));
        factory.deployUpgradeable(KeyedOwnable.KeyType.ECDSAThenSmartContract, keys, salt);
    }

    function test_predictDeploy() external {
        address owner = makeAddr("owner");
        bytes32 salt = bytes32(bytes20(uint160(owner)));

        bytes32[] memory keys = new bytes32[](1);
        keys[0] = bytes32(uint256(uint160(owner)));

        address predictedDeployedTo = factory.predictDeploy(KeyedOwnable.KeyType.ECDSAThenSmartContract, keys, salt);

        address deployedTo = factory.deploy(KeyedOwnable.KeyType.ECDSAThenSmartContract, keys, salt);
        assertEq(predictedDeployedTo, deployedTo);
    }

    function test_predictDeployWithEmbedCall() external {
        address owner = makeAddr("owner");
        bytes32 salt = bytes32(bytes20(uint160(owner)));

        bytes32 embeddedCall = keccak256(bytes("randomCall"));

        bytes32[] memory keys = new bytes32[](1);
        keys[0] = bytes32(uint256(uint160(owner)));

        address predictedDeployedTo =
            factory.predictDeployWithEmbedCall(KeyedOwnable.KeyType.ECDSAThenSmartContract, keys, salt, embeddedCall);

        address deployedTo =
            factory.deployWithEmbedCall(KeyedOwnable.KeyType.ECDSAThenSmartContract, keys, salt, embeddedCall);
        assertEq(predictedDeployedTo, deployedTo);
    }

    function test_predictDeployUpgradeable() external {
        address owner = makeAddr("owner");
        bytes32 salt = bytes32(bytes20(uint160(owner)));

        bytes32[] memory keys = new bytes32[](1);
        keys[0] = bytes32(uint256(uint160(owner)));

        address predictedDeployedTo =
            factory.predictDeployUpgradeable(KeyedOwnable.KeyType.ECDSAThenSmartContract, keys, salt);

        address deployedTo = factory.deployUpgradeable(KeyedOwnable.KeyType.ECDSAThenSmartContract, keys, salt);
        assertEq(predictedDeployedTo, deployedTo);
    }

    // --- Check salt contains owner --- //

    function testRevert_deploy_salt_does_not_contain_owner(address owner, bytes32 salt) external {
        vm.assume(owner != address(0));
        if (bytes20(salt) != bytes20(0) && address(uint160(bytes20(salt))) != owner) {
            vm.expectRevert(abi.encodeWithSignature("SaltDoesNotStartWith()"));
        }
        bytes32[] memory keys = new bytes32[](1);
        keys[0] = bytes32(uint256(uint160(owner)));

        factory.deploy(KeyedOwnable.KeyType.ECDSAThenSmartContract, keys, salt);
    }

    function testRevert_deployWithEmbedCall_salt_does_not_contain_owner(address owner, bytes32 salt) external {
        vm.assume(owner != address(0));
        if (bytes20(salt) != bytes20(0) && address(uint160(bytes20(salt))) != owner) {
            vm.expectRevert(abi.encodeWithSignature("SaltDoesNotStartWith()"));
        }
        bytes32[] memory keys = new bytes32[](1);
        keys[0] = bytes32(uint256(uint160(owner)));

        factory.deployWithEmbedCall(KeyedOwnable.KeyType.ECDSAThenSmartContract, keys, salt, bytes32(0));
    }

    function testRevert_deployUpgradeable_salt_does_not_contain_owner(address owner, bytes32 salt) external {
        vm.assume(owner != address(0));
        if (bytes20(salt) != bytes20(0) && address(uint160(bytes20(salt))) != owner) {
            vm.expectRevert(abi.encodeWithSignature("SaltDoesNotStartWith()"));
        }
        bytes32[] memory keys = new bytes32[](1);
        keys[0] = bytes32(uint256(uint160(owner)));

        factory.deployUpgradeable(KeyedOwnable.KeyType.ECDSAThenSmartContract, keys, salt);
    }

    function testRevert_predictDeploy_salt_does_not_contain_owner(address owner, bytes32 salt) external {
        vm.assume(owner != address(0));
        if (bytes20(salt) != bytes20(0) && address(uint160(bytes20(salt))) != owner) {
            vm.expectRevert(abi.encodeWithSignature("SaltDoesNotStartWith()"));
        }
        bytes32[] memory keys = new bytes32[](1);
        keys[0] = bytes32(uint256(uint160(owner)));

        factory.predictDeploy(KeyedOwnable.KeyType.ECDSAThenSmartContract, keys, salt);
    }

    function testRevert_predictDeployWithEmbedCall_salt_does_not_contain_owner(address owner, bytes32 salt) external {
        vm.assume(owner != address(0));
        if (bytes20(salt) != bytes20(0) && address(uint160(bytes20(salt))) != owner) {
            vm.expectRevert(abi.encodeWithSignature("SaltDoesNotStartWith()"));
        }
        bytes32[] memory keys = new bytes32[](1);
        keys[0] = bytes32(uint256(uint160(owner)));

        factory.predictDeployWithEmbedCall(KeyedOwnable.KeyType.ECDSAThenSmartContract, keys, salt, bytes32(0));
    }

    function testRevert_predictDeployUpgradeable_salt_does_not_contain_owner(address owner, bytes32 salt) external {
        vm.assume(owner != address(0));
        if (bytes20(salt) != bytes20(0) && address(uint160(bytes20(salt))) != owner) {
            vm.expectRevert(abi.encodeWithSignature("SaltDoesNotStartWith()"));
        }
        bytes32[] memory keys = new bytes32[](1);
        keys[0] = bytes32(uint256(uint160(owner)));

        factory.predictDeployUpgradeable(KeyedOwnable.KeyType.ECDSAThenSmartContract, keys, salt);
    }
}
