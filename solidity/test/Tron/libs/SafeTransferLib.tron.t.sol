// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import { Test } from "forge-std/src/Test.sol";

import { SafeTransferLib } from "solady/src/utils/SafeTransferLib.sol";
import { MockERC20 } from "solady/test/utils/mocks/MockERC20.sol";

import { SafeTransferLibTron } from "../../../src/libs/SafeTransferLib.tron.sol";

import { MockTronUSDT } from "../../mocks/MockTronUSDT.sol";

/// @dev Harness to expose library functions for testing.
contract SafeTransferLibHarness {
    function safeTransfer(
        address token,
        address to,
        uint256 amount
    ) external {
        SafeTransferLibTron.safeTransfer(token, to, amount);
    }

    function safeTransferFrom(
        address token,
        address from,
        address to,
        uint256 amount
    ) external {
        SafeTransferLib.safeTransferFrom(token, from, to, amount);
    }

    function safeApproveWithRetry(
        address token,
        address to,
        uint256 amount
    ) external {
        SafeTransferLib.safeApproveWithRetry(token, to, amount);
    }

    function safeTransferETH(
        address to,
        uint256 amount
    ) external {
        SafeTransferLib.safeTransferETH(to, amount);
    }

    function balanceOf(
        address token,
        address account
    ) external view returns (uint256) {
        return SafeTransferLib.balanceOf(token, account);
    }

    receive() external payable { }
}

contract SafeTransferLibTronTest is Test {
    SafeTransferLibHarness harness;
    MockTronUSDT tronUsdt;
    MockERC20 standardToken;
    address recipient;

    function setUp() external {
        harness = new SafeTransferLibHarness();
        tronUsdt = new MockTronUSDT();
        standardToken = new MockERC20("Standard", "STD", 18);
        recipient = makeAddr("recipient");
    }

    // -- safeTransfer with MockTronUSDT (broken transfer) --

    function test_safeTransfer_tronUsdt_succeeds() external {
        uint256 amount = 1000e6;
        tronUsdt.mint(address(harness), amount);

        harness.safeTransfer(address(tronUsdt), recipient, amount);

        assertEq(tronUsdt.balanceOf(recipient), amount);
        assertEq(tronUsdt.balanceOf(address(harness)), 0);
    }

    function test_safeTransfer_tronUsdt_multipleTransfers() external {
        uint256 total = 3000e6;
        tronUsdt.mint(address(harness), total);

        harness.safeTransfer(address(tronUsdt), recipient, 1000e6);
        harness.safeTransfer(address(tronUsdt), recipient, 1000e6);
        harness.safeTransfer(address(tronUsdt), recipient, 1000e6);

        assertEq(tronUsdt.balanceOf(recipient), total);
        assertEq(tronUsdt.balanceOf(address(harness)), 0);
    }

    function test_fuzz_safeTransfer_tronUsdt(
        uint256 amount
    ) external {
        vm.assume(amount > 0);
        tronUsdt.mint(address(harness), amount);

        harness.safeTransfer(address(tronUsdt), recipient, amount);

        assertEq(tronUsdt.balanceOf(recipient), amount);
        assertEq(tronUsdt.balanceOf(address(harness)), 0);
    }

    // -- safeTransfer with standard ERC20 --

    function test_safeTransfer_standardToken_succeeds() external {
        uint256 amount = 1 ether;
        standardToken.mint(address(harness), amount);

        harness.safeTransfer(address(standardToken), recipient, amount);

        assertEq(standardToken.balanceOf(recipient), amount);
        assertEq(standardToken.balanceOf(address(harness)), 0);
    }

    // -- safeTransfer reverts --

    function test_safeTransfer_revertsOnInsufficientBalance() external {
        tronUsdt.mint(address(harness), 100e6);

        vm.expectRevert();
        harness.safeTransfer(address(tronUsdt), recipient, 200e6);
    }

    function test_safeTransfer_revertsOnNoCode() external {
        address noCode = makeAddr("noCode");

        vm.expectRevert();
        harness.safeTransfer(noCode, recipient, 1 ether);
    }

    // -- safeTransferFrom (Solady original, should work normally) --

    function test_safeTransferFrom_tronUsdt_succeeds() external {
        address sender = makeAddr("sender");
        uint256 amount = 1000e6;
        tronUsdt.mint(sender, amount);

        vm.prank(sender);
        tronUsdt.approve(address(harness), amount);

        harness.safeTransferFrom(address(tronUsdt), sender, recipient, amount);

        assertEq(tronUsdt.balanceOf(recipient), amount);
        assertEq(tronUsdt.balanceOf(sender), 0);
    }

    // -- safeApproveWithRetry (Solady original, should work normally) --

    function test_safeApproveWithRetry_tronUsdt_succeeds() external {
        harness.safeApproveWithRetry(address(tronUsdt), recipient, type(uint256).max);

        assertEq(tronUsdt.allowance(address(harness), recipient), type(uint256).max);
    }

    // -- safeTransferETH (Solady original) --

    function test_safeTransferETH_succeeds() external {
        vm.deal(address(harness), 1 ether);

        harness.safeTransferETH(recipient, 1 ether);

        assertEq(recipient.balance, 1 ether);
        assertEq(address(harness).balance, 0);
    }

    // -- balanceOf (Solady original) --

    function test_balanceOf_returnsCorrectBalance() external {
        uint256 amount = 500e6;
        tronUsdt.mint(address(harness), amount);

        assertEq(harness.balanceOf(address(tronUsdt), address(harness)), amount);
    }
}
