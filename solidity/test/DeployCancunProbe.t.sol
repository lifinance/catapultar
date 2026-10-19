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
 * opcodes. These tests pin the probe init code on the local VM and the eth_call path on
 * a mainnet fork; the fork test skips when `VC_MAINNET_RPC_URL` is unset.
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
}
