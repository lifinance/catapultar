// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { Test } from "forge-std/src/Test.sol";

import { deploy } from "../script/deploy.s.sol";
import { CATValidator } from "../src/CATValidator.sol";
import { CATValidatorV2 } from "../src/CATValidatorV2.sol";

contract DeployIntentExecutorHarness is deploy {
    function exposed_callProxyOf(
        address validator
    ) external pure returns (address) {
        return callProxyOf(validator);
    }

    function exposed_requireNoForwarderSolver(
        address[] memory solvers,
        address[] memory forwarders
    ) external pure {
        requireNoForwarderSolver(solvers, forwarders);
    }

    function exposed_expectedCATValidatorAddress() external pure returns (address) {
        return expectedCATValidatorAddress();
    }

    function exposed_expectedCATValidatorV2Address() external pure returns (address) {
        return expectedCATValidatorV2Address();
    }
}

/**
 * @notice The deploy script refuses an IntentExecutor solver list that contains a
 * permissionless forwarder, which would let anyone call fill() with any payload.
 */
contract DeployIntentExecutorTest is Test {
    DeployIntentExecutorHarness harness;

    function setUp() public {
        harness = new DeployIntentExecutorHarness();
    }

    /// @dev Pins the CREATE nonce the script assumes: a constructor change that creates
    /// another contract before the call proxy would move CALL_PROXY.
    function test_callProxyOf_matchesDeployedValidators() public {
        CATValidator validator = new CATValidator();
        assertEq(harness.exposed_callProxyOf(address(validator)), validator.CALL_PROXY());

        CATValidatorV2 validatorV2 = new CATValidatorV2(makeAddr("vm"));
        assertEq(harness.exposed_callProxyOf(address(validatorV2)), validatorV2.CALL_PROXY());
    }

    /// @dev Each known forwarder is refused wherever it sits in the solver list; an
    /// ordinary solver passes.
    function test_requireNoForwarderSolver_rejectsForwarders() public {
        address listedForwarder = makeAddr("listedForwarder");
        address[] memory forwarders = new address[](1);
        forwarders[0] = listedForwarder;

        address[] memory rejected = new address[](5);
        rejected[0] = harness.exposed_callProxyOf(harness.exposed_expectedCATValidatorAddress());
        rejected[1] = harness.exposed_callProxyOf(harness.exposed_expectedCATValidatorV2Address());
        rejected[2] = 0xcA11bde05977b3631167028862bE2a173976CA11; // Multicall3
        rejected[3] = 0x72aB1B98b60a9251Cc00ab1C3bBe9F48CdFdCA40; // legacy IntentExecutor
        rejected[4] = listedForwarder;

        address[] memory solvers = new address[](2);
        solvers[0] = makeAddr("solver");
        for (uint256 i = 0; i < rejected.length; ++i) {
            solvers[1] = rejected[i];
            vm.expectRevert(abi.encodeWithSelector(deploy.SolverIsForwarder.selector, rejected[i]));
            harness.exposed_requireNoForwarderSolver(solvers, forwarders);
        }

        solvers[1] = makeAddr("otherSolver");
        harness.exposed_requireNoForwarderSolver(solvers, forwarders);
        harness.exposed_requireNoForwarderSolver(solvers, new address[](0));
    }
}
