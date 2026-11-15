// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { Test } from "forge-std/src/Test.sol";

import { deploy } from "../script/deploy.s.sol";

contract DeployHarness is deploy {
    function cancunProbe() external pure returns (bytes memory) {
        return CANCUN_PROBE;
    }

    function exposed_requireCancun() external {
        requireCancun();
    }
}

/**
 * @notice The deploy script refuses to deploy CATValidatorV2 on a chain without Cancun
 * opcodes. These tests pin the probe code on the local VM, both as init code (the
 * `eth_call` creation) and as runtime code (the state-override call), and the eth_call
 * paths on live forks. The mainnet fork test skips when `VC_MAINNET_RPC_URL` is unset;
 * the Pharos fork test skips when `PHAROS_RPC_URL` is unset.
 */
contract DeployCancunProbeTest is Test {
    DeployHarness harness;

    function setUp() public {
        harness = new DeployHarness();
    }

    function deployInitCode(
        bytes memory initCode
    ) internal returns (address deployed) {
        assembly ("memory-safe") {
            deployed := create(0, add(initCode, 0x20), mload(initCode))
        }
    }

    function test_cancunProbe_returnsOneOnCancun() public {
        address probe = deployInitCode(harness.cancunProbe());
        assertNotEq(probe, address(0));
        assertEq(probe.code, abi.encode(uint256(1)));
    }

    function test_cancunProbe_failsOnShanghai() public {
        bytes memory initCode = harness.cancunProbe();
        vm.setEvmVersion("shanghai");
        assertEq(deployInitCode(initCode), address(0));
    }

    function test_cancunProbe_runtimeReturnsOneOnCancun() public {
        address probe = makeAddr("probe");
        vm.etch(probe, harness.cancunProbe());
        (bool success, bytes memory output) = probe.call("");
        assertTrue(success);
        assertEq(output, abi.encode(uint256(1)));
    }

    function test_cancunProbe_runtimeFailsOnShanghai() public {
        address probe = makeAddr("probe");
        vm.etch(probe, harness.cancunProbe());
        vm.setEvmVersion("shanghai");
        (bool success,) = probe.call("");
        assertFalse(success);
    }

    /// @dev Without a fork, `vm.rpc` has no node to call; the probe fails closed.
    function test_requireCancun_revertsWithoutNode() public {
        vm.expectRevert(deploy.ChainLacksCancun.selector);
        harness.exposed_requireCancun();
    }

    function test_requireCancun_passesOnMainnetFork() public {
        string memory rpcUrl = vm.envOr("VC_MAINNET_RPC_URL", string(""));
        if (bytes(rpcUrl).length == 0) {
            vm.skip(true, "VC_MAINNET_RPC_URL unset");
            return;
        }
        vm.createSelectFork(rpcUrl);
        new DeployHarness().exposed_requireCancun();
    }

    /// @dev The Pharos node returns empty output for every `eth_call` creation, so the
    /// creation probe fails there and only the state-override probe can pass.
    function test_requireCancun_passesOnPharosFork() public {
        string memory rpcUrl = vm.envOr("PHAROS_RPC_URL", string(""));
        if (bytes(rpcUrl).length == 0) {
            vm.skip(true, "PHAROS_RPC_URL unset");
            return;
        }
        vm.createSelectFork(rpcUrl);
        new DeployHarness().exposed_requireCancun();
    }
}
