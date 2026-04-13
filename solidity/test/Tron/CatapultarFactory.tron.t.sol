// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

// forge-lint: disable-start(unsafe-typecast)

import { Test } from "forge-std/src/Test.sol";

import { LibCloneTron } from "../../src/libs/LibClone.tron.sol";

import { CatapultarFactoryTron } from "../../src/CatapultarFactory.tron.sol";
import { KeyedOwnable } from "../../src/libs/KeyedOwnable.sol";

contract CatapultarFactoryTronTest is Test {
    CatapultarFactoryTron factory;

    function setUp() external {
        factory = new CatapultarFactoryTron();
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

    // Note: predictDeploy uses the Tron CREATE2 prefix (0x41) rather than the EVM prefix (0xff).
    // In Foundry (EVM environment) the actual deployed address will differ from the prediction.
    // These tests validate that predictions are deterministic and that different salts produce
    // different predicted addresses — the correct Tron behaviour when running on-chain.

    function test_predictDeploy_deterministic() external {
        address owner = makeAddr("owner");
        bytes32 salt = bytes32(bytes20(uint160(owner)));

        bytes32[] memory keys = new bytes32[](1);
        keys[0] = bytes32(uint256(uint160(owner)));

        address firstCall = factory.predictDeploy(KeyedOwnable.PublicKeyType.ECDSAOrSmartContract, keys, salt);
        address secondCall = factory.predictDeploy(KeyedOwnable.PublicKeyType.ECDSAOrSmartContract, keys, salt);
        assertEq(firstCall, secondCall);
    }

    function test_predictDeploy_different_salts(bytes12 extra) external {
        address owner = makeAddr("owner");
        bytes32 saltA = bytes32(bytes20(uint160(owner)));
        bytes32 saltB = bytes32(abi.encodePacked(bytes20(uint160(owner)), extra));
        vm.assume(saltA != saltB);

        bytes32[] memory keys = new bytes32[](1);
        keys[0] = bytes32(uint256(uint160(owner)));

        address addrA = factory.predictDeploy(KeyedOwnable.PublicKeyType.ECDSAOrSmartContract, keys, saltA);
        address addrB = factory.predictDeploy(KeyedOwnable.PublicKeyType.ECDSAOrSmartContract, keys, saltB);
        assertNotEq(addrA, addrB);
    }

    function test_predictDeployWithDigest_deterministic() external {
        address owner = makeAddr("owner");
        bytes32 salt = bytes32(bytes20(uint160(owner)));
        bytes32 embeddedCall = keccak256(bytes("randomCall"));

        bytes32[] memory keys = new bytes32[](1);
        keys[0] = bytes32(uint256(uint160(owner)));

        address firstCall = factory.predictDeployWithDigest(
            KeyedOwnable.PublicKeyType.ECDSAOrSmartContract, keys, salt, embeddedCall, false
        );
        address secondCall = factory.predictDeployWithDigest(
            KeyedOwnable.PublicKeyType.ECDSAOrSmartContract, keys, salt, embeddedCall, false
        );
        assertEq(firstCall, secondCall);
    }

    function test_predictDeployWithDigest_digest_affects_address() external {
        address owner = makeAddr("owner");
        bytes32 salt = bytes32(bytes20(uint160(owner)));

        bytes32[] memory keys = new bytes32[](1);
        keys[0] = bytes32(uint256(uint160(owner)));

        address withDigest = factory.predictDeployWithDigest(
            KeyedOwnable.PublicKeyType.ECDSAOrSmartContract, keys, salt, keccak256(bytes("digest")), false
        );
        address withoutDigest = factory.predictDeployWithDigest(
            KeyedOwnable.PublicKeyType.ECDSAOrSmartContract, keys, salt, bytes32(0), false
        );
        assertNotEq(withDigest, withoutDigest);
    }

    function test_predictDeployUpgradeable_deterministic() external {
        address owner = makeAddr("owner");
        bytes32 salt = bytes32(bytes20(uint160(owner)));

        bytes32[] memory keys = new bytes32[](1);
        keys[0] = bytes32(uint256(uint160(owner)));

        address firstCall =
            factory.predictDeployUpgradeable(KeyedOwnable.PublicKeyType.ECDSAOrSmartContract, keys, salt);
        address secondCall =
            factory.predictDeployUpgradeable(KeyedOwnable.PublicKeyType.ECDSAOrSmartContract, keys, salt);
        assertEq(firstCall, secondCall);
    }

    function test_predictDeployUpgradeable_differs_from_minimal() external {
        address owner = makeAddr("owner");
        bytes32 salt = bytes32(bytes20(uint160(owner)));

        bytes32[] memory keys = new bytes32[](1);
        keys[0] = bytes32(uint256(uint160(owner)));

        address minimal = factory.predictDeploy(KeyedOwnable.PublicKeyType.ECDSAOrSmartContract, keys, salt);
        address upgradeable = factory.predictDeployUpgradeable(KeyedOwnable.PublicKeyType.ECDSAOrSmartContract, keys, salt);
        assertNotEq(minimal, upgradeable);
    }

    // Verifies that _salt encodes preSalt || ktp || numOwners || owners as documented.
    function test_saltEncoding() external view {
        bytes32 preSalt = bytes32(uint256(0xdead));
        KeyedOwnable.PublicKeyType ktp = KeyedOwnable.PublicKeyType.P256;

        bytes32[] memory keys = new bytes32[](2);
        keys[0] = bytes32(uint256(1));
        keys[1] = bytes32(uint256(2));

        bytes32 expectedSalt = keccak256(abi.encodePacked(preSalt, uint8(ktp), uint8(keys.length), keys[0], keys[1]));
        address expected =
            LibCloneTron.predictDeterministicAddress_PUSH0(factory.EXECUTOR(), expectedSalt, address(factory));

        assertEq(factory.predictDeploy(ktp, keys, preSalt), expected);
    }

}
