// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

// forge-lint: disable-start(unsafe-typecast)
// forge-lint: disable-start(erc20-unchecked-transfer)

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

        address deployedTo = factory.deploy(KeyedOwnable.KeyType.ECDSAOrSmartContract, keys, salt);
        vm.snapshotGasLastCall("deploy");

        // Check that the deployed proxy has code.
        assertNotEq(deployedTo.code.length, 0);

        // Try deploying again.
        vm.expectRevert(abi.encodeWithSignature("DeploymentFailed()"));

        factory.deploy(KeyedOwnable.KeyType.ECDSAOrSmartContract, keys, salt);
    }

    /// forge-config: default.isolate = true
    function test_deployWithDigest() external {
        address owner = makeAddr("owner");
        bytes32 salt = bytes32(bytes20(uint160(owner)));

        bytes32[] memory keys = new bytes32[](1);
        keys[0] = bytes32(uint256(uint160(owner)));

        address deployedTo =
            factory.deployWithDigest(KeyedOwnable.KeyType.ECDSAOrSmartContract, keys, salt, bytes32(0), false);
        vm.snapshotGasLastCall("deployWithDigest");

        // Check that the deployed proxy has code.
        assertNotEq(deployedTo.code.length, 0);

        // Try deploying again.
        vm.expectRevert(abi.encodeWithSignature("DeploymentFailed()"));
        factory.deployWithDigest(KeyedOwnable.KeyType.ECDSAOrSmartContract, keys, salt, bytes32(0), false);
    }

    /// forge-config: default.isolate = true
    function test_deployUpgradeable() external {
        address owner = makeAddr("owner");
        bytes32 salt = bytes32(bytes20(uint160(owner)));

        bytes32[] memory keys = new bytes32[](1);
        keys[0] = bytes32(uint256(uint160(owner)));

        address deployedTo = factory.deployUpgradeable(KeyedOwnable.KeyType.ECDSAOrSmartContract, keys, salt);
        vm.snapshotGasLastCall("deployUpgradeable");

        // Check that the deployed proxy has code.
        assertNotEq(deployedTo.code.length, 0);

        // Try deploying again.
        vm.expectRevert(abi.encodeWithSignature("DeploymentFailed()"));
        factory.deployUpgradeable(KeyedOwnable.KeyType.ECDSAOrSmartContract, keys, salt);
    }

    function test_predictDeploy() external {
        address owner = makeAddr("owner");
        bytes32 salt = bytes32(bytes20(uint160(owner)));

        bytes32[] memory keys = new bytes32[](1);
        keys[0] = bytes32(uint256(uint160(owner)));

        address predictedDeployedTo = factory.predictDeploy(KeyedOwnable.KeyType.ECDSAOrSmartContract, keys, salt);

        address deployedTo = factory.deploy(KeyedOwnable.KeyType.ECDSAOrSmartContract, keys, salt);
        assertEq(predictedDeployedTo, deployedTo);
    }

    function test_predictDeployWithDigest() external {
        address owner = makeAddr("owner");
        bytes32 salt = bytes32(bytes20(uint160(owner)));

        bytes32 embeddedCall = keccak256(bytes("randomCall"));

        bytes32[] memory keys = new bytes32[](1);
        keys[0] = bytes32(uint256(uint160(owner)));

        address predictedDeployedTo =
            factory.predictDeployWithDigest(KeyedOwnable.KeyType.ECDSAOrSmartContract, keys, salt, embeddedCall, false);

        address deployedTo =
            factory.deployWithDigest(KeyedOwnable.KeyType.ECDSAOrSmartContract, keys, salt, embeddedCall, false);
        assertEq(predictedDeployedTo, deployedTo);
    }

    function test_predictDeployUpgradeable() external {
        address owner = makeAddr("owner");
        bytes32 salt = bytes32(bytes20(uint160(owner)));

        bytes32[] memory keys = new bytes32[](1);
        keys[0] = bytes32(uint256(uint160(owner)));

        address predictedDeployedTo =
            factory.predictDeployUpgradeable(KeyedOwnable.KeyType.ECDSAOrSmartContract, keys, salt);

        address deployedTo = factory.deployUpgradeable(KeyedOwnable.KeyType.ECDSAOrSmartContract, keys, salt);
        assertEq(predictedDeployedTo, deployedTo);
    }

    // --- Check salt contains owner --- //

    function testRevert_deploy_salt_does_not_contain_owner(
        address owner,
        bytes32 salt
    ) external {
        vm.assume(owner != address(0));
        if (bytes20(salt) != bytes20(0) && address(uint160(bytes20(salt))) != owner) {
            vm.expectRevert(abi.encodeWithSignature("SaltDoesNotStartWith()"));
        }
        bytes32[] memory keys = new bytes32[](1);
        keys[0] = bytes32(uint256(uint160(owner)));

        factory.deploy(KeyedOwnable.KeyType.ECDSAOrSmartContract, keys, salt);
    }

    function testRevert_deployWithDigest_salt_does_not_contain_owner(
        address owner,
        bytes32 salt
    ) external {
        vm.assume(owner != address(0));
        if (bytes20(salt) != bytes20(0) && address(uint160(bytes20(salt))) != owner) {
            vm.expectRevert(abi.encodeWithSignature("SaltDoesNotStartWith()"));
        }
        bytes32[] memory keys = new bytes32[](1);
        keys[0] = bytes32(uint256(uint160(owner)));

        factory.deployWithDigest(KeyedOwnable.KeyType.ECDSAOrSmartContract, keys, salt, bytes32(0), false);
    }

    function testRevert_deployUpgradeable_salt_does_not_contain_owner(
        address owner,
        bytes32 salt
    ) external {
        vm.assume(owner != address(0));
        if (bytes20(salt) != bytes20(0) && address(uint160(bytes20(salt))) != owner) {
            vm.expectRevert(abi.encodeWithSignature("SaltDoesNotStartWith()"));
        }
        bytes32[] memory keys = new bytes32[](1);
        keys[0] = bytes32(uint256(uint160(owner)));

        factory.deployUpgradeable(KeyedOwnable.KeyType.ECDSAOrSmartContract, keys, salt);
    }

    function testRevert_predictDeploy_salt_does_not_contain_owner(
        address owner,
        bytes32 salt
    ) external {
        vm.assume(owner != address(0));
        if (bytes20(salt) != bytes20(0) && address(uint160(bytes20(salt))) != owner) {
            vm.expectRevert(abi.encodeWithSignature("SaltDoesNotStartWith()"));
        }
        bytes32[] memory keys = new bytes32[](1);
        keys[0] = bytes32(uint256(uint160(owner)));

        factory.predictDeploy(KeyedOwnable.KeyType.ECDSAOrSmartContract, keys, salt);
    }

    function testRevert_predictDeployWithDigest_salt_does_not_contain_owner(
        address owner,
        bytes32 salt
    ) external {
        vm.assume(owner != address(0));
        if (bytes20(salt) != bytes20(0) && address(uint160(bytes20(salt))) != owner) {
            vm.expectRevert(abi.encodeWithSignature("SaltDoesNotStartWith()"));
        }
        bytes32[] memory keys = new bytes32[](1);
        keys[0] = bytes32(uint256(uint160(owner)));

        factory.predictDeployWithDigest(KeyedOwnable.KeyType.ECDSAOrSmartContract, keys, salt, bytes32(0), false);
    }

    function testRevert_predictDeployUpgradeable_salt_does_not_contain_owner(
        address owner,
        bytes32 salt
    ) external {
        vm.assume(owner != address(0));
        if (bytes20(salt) != bytes20(0) && address(uint160(bytes20(salt))) != owner) {
            vm.expectRevert(abi.encodeWithSignature("SaltDoesNotStartWith()"));
        }
        bytes32[] memory keys = new bytes32[](1);
        keys[0] = bytes32(uint256(uint160(owner)));

        factory.predictDeployUpgradeable(KeyedOwnable.KeyType.ECDSAOrSmartContract, keys, salt);
    }
}
