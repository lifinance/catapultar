// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { IERC20 } from "forge-std/src/interfaces/IERC20.sol";

import { CATValidatorV2 } from "../../src/CATValidatorV2.sol";
import { DerivedProgramHarness } from "./DerivedProgramHarness.sol";

interface IFeed {
    function latestAnswer() external view returns (int256);
}

/// The PRD §2 Stop Loss fixture settled in wallet mode through the deployed CATValidatorV2 on Base.
/// Inputs: the placeholder 8-command program until C2 swaps in WS-A's committed program.
contract DerivedProgramEntryTest is DerivedProgramHarness {
    function setUp() external {
        setUpHarness();
    }

    function test_derived_pass_feedAt1990() external onlyBaseFork {
        (bytes memory program, bytes32[] memory params) = placeholderProgram();
        mockAnswer(1990e8);
        (uint256 entryGas, uint256 vmGas) = settleThroughEntry(program, params, 0xC1A55, "");
        emit log_named_uint("pass entry gas", entryGas);
        emit log_named_uint("pass runVM gas", vmGas);
    }

    function test_derived_fail_feedAt2251() external onlyBaseFork {
        (bytes memory program, bytes32[] memory params) = placeholderProgram();
        mockAnswer(2251e8);
        (uint256 entryGas, uint256 vmGas) =
            settleThroughEntry(program, params, 0xC1A56, abi.encodeWithSelector(LTE_FAILED, 2251e8, STRIKE));
        emit log_named_uint("fail(2251) entry gas", entryGas);
        emit log_named_uint("fail(2251) runVM gas", vmGas);
    }

    function test_derived_fail_pastExpiry() external onlyBaseFork {
        (bytes memory program, bytes32[] memory params) = placeholderProgram();
        mockAnswer(1990e8);
        vm.warp(EXPIRES_AT + 1);
        (uint256 entryGas, uint256 vmGas) =
            settleThroughEntry(program, params, 0xC1A57, abi.encodeWithSelector(LTE_FAILED, EXPIRES_AT + 1, EXPIRES_AT));
        emit log_named_uint("fail(expiry) entry gas", entryGas);
        emit log_named_uint("fail(expiry) runVM gas", vmGas);
    }

    /// Demo step 7: the executor forces settlement while the live feed sits above the strike.
    /// Must revert ValidationFailed(AssertLteFailed(answer, strike)) and leave the nonce unspent.
    function test_step7_forcedSettlement_reverts() external onlyBaseFork {
        uint256 answer = uint256(IFeed(BASE_FEED_ETH_USD).latestAnswer());
        require(answer > STRIKE, "live ETH/USD is below the strike; step 7 needs it above");
        (bytes memory program, bytes32[] memory params) = placeholderProgram();
        uint256 nonce = uint256(keccak256("triggers-step7"));

        fundFixture();
        EntryCall memory c = buildEntry(program, params, nonce);
        emit log_named_bytes32("step7 digest", c.digest);
        emit log_named_bytes("step7 entry calldata", c.calldata_);

        vm.prank(executor);
        vm.expectRevert(
            abi.encodeWithSelector(
                CATValidatorV2.ValidationFailed.selector, abi.encodeWithSelector(LTE_FAILED, answer, STRIKE)
            )
        );
        (bool ok,) = address(validator).call(c.calldata_);
        assertTrue(ok, "expectRevert consumes the revert");
        assertFalse(validator.spentNonces(user, nonce), "nonce must stay unspent");
        assertEq(IERC20(BASE_WETH).balanceOf(user), ALLOCATED_WETH, "WETH must stay with the user");
    }
}
