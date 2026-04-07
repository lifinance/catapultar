// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { Test } from "forge-std/src/Test.sol";

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
}
