// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { Test } from "forge-std/Test.sol";

import { CatapultarFactory } from "../src/CatapultarFactory.sol";

contract CatapultarFactoryTest is Test {
    CatapultarFactory factory;

    function setUp() external {
        factory = new CatapultarFactory();
    }

    /// forge-config: default.isolate = true
    function test_deploy() external {
        address owner = makeAddr("owner");
        bytes32 salt = bytes32(bytes20(uint160(owner)));

        address deployedTo = factory.deploy(owner, salt);
        vm.snapshotGasLastCall("deploy");

        // Check that the deployed proxy has code.
        assertNotEq(deployedTo.code.length, 0);

        // Try deploying again.
        vm.expectRevert(abi.encodeWithSignature("DeploymentFailed()"));
        factory.deploy(owner, salt);
    }

    /// forge-config: default.isolate = true
    function test_deployWithEmbedCall() external {
        address owner = makeAddr("owner");
        bytes32 salt = bytes32(bytes20(uint160(owner)));

        address deployedTo = factory.deployWithEmbedCall(owner, salt, bytes32(0));
        vm.snapshotGasLastCall("deployWithEmbedCall");

        // Check that the deployed proxy has code.
        assertNotEq(deployedTo.code.length, 0);

        // Try deploying again.
        vm.expectRevert(abi.encodeWithSignature("DeploymentFailed()"));
        factory.deployWithEmbedCall(owner, salt, bytes32(0));
    }

    /// forge-config: default.isolate = true
    function test_deployUpgradeable() external {
        address owner = makeAddr("owner");
        bytes32 salt = bytes32(bytes20(uint160(owner)));

        address deployedTo = factory.deployUpgradeable(owner, salt);
        vm.snapshotGasLastCall("deployUpgradeable");

        // Check that the deployed proxy has code.
        assertNotEq(deployedTo.code.length, 0);

        // Try deploying again.
        vm.expectRevert(abi.encodeWithSignature("DeploymentFailed()"));
        factory.deployUpgradeable(owner, salt);
    }

    function test_predictDeploy() external {
        address owner = makeAddr("owner");
        bytes32 salt = bytes32(bytes20(uint160(owner)));

        address predictedDeployedTo = factory.predictDeploy(owner, salt);
        address deployedTo = factory.deploy(owner, salt);
        assertEq(predictedDeployedTo, deployedTo);
    }

    function test_predictDeployWithEmbedCall() external {
        address owner = makeAddr("owner");
        bytes32 salt = bytes32(bytes20(uint160(owner)));

        bytes32 embeddedCall = keccak256(bytes("randomCall"));

        address predictedDeployedTo = factory.predictDeployWithEmbedCall(owner, salt, embeddedCall);
        address deployedTo = factory.deployWithEmbedCall(owner, salt, embeddedCall);
        assertEq(predictedDeployedTo, deployedTo);
    }

    function test_predictDeployUpgradeable() external {
        address owner = makeAddr("owner");
        bytes32 salt = bytes32(bytes20(uint160(owner)));

        address predictedDeployedTo = factory.predictDeployUpgradeable(owner, salt);
        address deployedTo = factory.deployUpgradeable(owner, salt);
        assertEq(predictedDeployedTo, deployedTo);
    }

    // --- Check salt contains owner --- //

    function testRevert_deploy_salt_does_not_contain_owner(address owner, bytes32 salt) external {
        if (bytes20(salt) != bytes20(0) && address(uint160(bytes20(salt))) != owner) {
            vm.expectRevert(abi.encodeWithSignature("SaltDoesNotStartWith()"));
        }
        factory.deploy(owner, salt);
    }

    function testRevert_deployWithEmbedCall_salt_does_not_contain_owner(address owner, bytes32 salt) external {
        if (bytes20(salt) != bytes20(0) && address(uint160(bytes20(salt))) != owner) {
            vm.expectRevert(abi.encodeWithSignature("SaltDoesNotStartWith()"));
        }
        factory.deployWithEmbedCall(owner, salt, bytes32(0));
    }

    function testRevert_deployUpgradeable_salt_does_not_contain_owner(address owner, bytes32 salt) external {
        if (bytes20(salt) != bytes20(0) && address(uint160(bytes20(salt))) != owner) {
            vm.expectRevert(abi.encodeWithSignature("SaltDoesNotStartWith()"));
        }
        factory.deployUpgradeable(owner, salt);
    }
}
