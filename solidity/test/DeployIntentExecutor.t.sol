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

    function exposed_requireNoCallProxySolver(
        address[] memory solvers
    ) external pure {
        requireNoCallProxySolver(solvers);
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
 * validator's CALL_PROXY, a permissionless forwarder that would let anyone authorize
 * any payload.
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

    function test_requireNoCallProxySolver_rejectsValidatorCallProxies() public {
        address callProxy = harness.exposed_callProxyOf(harness.exposed_expectedCATValidatorAddress());
        address callProxyV2 = harness.exposed_callProxyOf(harness.exposed_expectedCATValidatorV2Address());

        address[] memory solvers = new address[](2);
        solvers[0] = makeAddr("solver");

        solvers[1] = callProxy;
        vm.expectRevert(abi.encodeWithSelector(deploy.SolverIsCallProxy.selector, callProxy));
        harness.exposed_requireNoCallProxySolver(solvers);

        solvers[1] = callProxyV2;
        vm.expectRevert(abi.encodeWithSelector(deploy.SolverIsCallProxy.selector, callProxyV2));
        harness.exposed_requireNoCallProxySolver(solvers);

        solvers[1] = makeAddr("otherSolver");
        harness.exposed_requireNoCallProxySolver(solvers);
    }
}
