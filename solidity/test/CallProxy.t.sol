// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { Test } from "forge-std/src/Test.sol";
import { MockERC20 } from "solady/test/utils/mocks/MockERC20.sol";

import { CallProxy } from "../src/CallProxy.sol";

contract MockMocker {
    error CustomError(bytes);

    function reverting(
        bytes calldata revertData
    ) external pure {
        revert CustomError(revertData);
    }

    function returning(
        bytes calldata returnData
    ) external pure returns (bytes memory) {
        return returnData;
    }
}

contract MockValueSink {
    uint256 public received;

    receive() external payable {
        received += msg.value;
    }
}

contract CallProxyTest is Test {
    address c;

    function setUp() external {
        c = address(new CallProxy());
    }

    function test_forwardCall(
        address target,
        bytes calldata cdata
    ) external {
        vm.assume(target.code.length == 0);
        bytes memory payload = abi.encodePacked(bytes32(uint256(uint160(target))), cdata);

        vm.expectCall(target, cdata);
        c.call(payload);
    }

    function test_forwardCall_reverts(
        bytes calldata revertData
    ) external {
        address target = address(new MockMocker());
        bytes memory cdata = abi.encodeCall(MockMocker.reverting, (revertData));
        bytes memory payload = abi.encodePacked(bytes32(uint256(uint160(target))), cdata);

        vm.expectCall(target, cdata);
        vm.expectRevert(abi.encodeWithSelector(MockMocker.CustomError.selector, (revertData)), c);
        (bool success,) = c.call(payload);
        assertEq(success, false);
    }

    function test_forwardCall_returns(
        bytes calldata returnData
    ) external {
        address target = address(new MockMocker());
        bytes memory cdata = abi.encodeCall(MockMocker.returning, (returnData));
        bytes memory payload = abi.encodePacked(bytes32(uint256(uint160(target))), cdata);

        vm.expectCall(target, cdata);
        (bool success, bytes memory rt) = c.call(payload);
        assertEq(rt, abi.encode(returnData));
        assertEq(success, true);
    }

    function test_emptyEtherTransfer_fails() external {
        vm.deal(address(this), 1 ether);
        // Empty calldata causes sub(calldatasize(), 32) to underflow to 2^256-32,
        // triggering an impossibly large memory expansion that exhausts all gas.
        (bool success,) = address(c).call{ value: 1 ether }("");
        assertFalse(success);
    }

    // -----------------------------------------------------------------------
    // Adversarial: the proxy holds no privileges a direct caller can abuse.
    // -----------------------------------------------------------------------

    /// The proxy is the msg.sender of forwarded calls. An approval granted to
    /// another contract (e.g. CATValidator) cannot be spent through the proxy.
    function test_directCall_cannot_spend_foreign_approval(
        uint128 amount
    ) external {
        vm.assume(amount > 0);
        address account = makeAddr("account");
        address spender = makeAddr("spender");
        address attacker = makeAddr("attacker");

        MockERC20 token = new MockERC20("Token", "TKN", 18);
        token.mint(account, amount);
        vm.prank(account);
        token.approve(spender, amount);

        bytes memory cdata = abi.encodeCall(MockERC20.transferFrom, (account, attacker, uint256(amount)));
        bytes memory payload = abi.encodePacked(bytes32(uint256(uint160(address(token)))), cdata);

        // The allowance is keyed to `spender`, not the proxy, so the forwarded
        // transferFrom reverts and the revert bubbles up through the proxy.
        vm.prank(attacker);
        (bool success,) = c.call(payload);
        assertFalse(success);

        assertEq(token.balanceOf(account), amount);
        assertEq(token.balanceOf(attacker), 0);
        assertEq(token.allowance(account, spender), amount);
    }

    /// Ether parked on the proxy is not extractable: the fallback forwards
    /// callvalue() only, never the proxy's own balance.
    function test_directCall_cannot_drain_residual_ether() external {
        MockValueSink sink = new MockValueSink();
        vm.deal(c, 1 ether);

        bytes memory payload = abi.encodePacked(bytes32(uint256(uint160(address(sink)))));
        (bool success,) = c.call(payload);
        assertTrue(success);

        assertEq(sink.received(), 0);
        assertEq(c.balance, 1 ether);
    }

    /// Value attached to a proxy call is forwarded to the target in full.
    function test_forwardCall_forwards_value(
        uint96 value
    ) external {
        MockValueSink sink = new MockValueSink();
        vm.deal(address(this), value);

        bytes memory payload = abi.encodePacked(bytes32(uint256(uint160(address(sink)))));
        (bool success,) = c.call{ value: value }(payload);
        assertTrue(success);

        assertEq(sink.received(), value);
        assertEq(address(sink).balance, value);
        assertEq(c.balance, 0);
    }
}
