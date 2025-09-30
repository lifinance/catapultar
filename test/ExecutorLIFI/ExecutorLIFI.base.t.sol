// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { Test } from "forge-std/Test.sol";

import { ERC7821 } from "solady/src/accounts/ERC7821.sol";
import { LibClone } from "solady/src/utils/LibClone.sol";

import { BitmapNonce } from "../../src/BitmapNonce.sol";
import { ExecutorLIFI } from "../../src/ExecutorLIFI.sol";
import { LibCalls } from "../../src/LibCalls.sol";
import { MockExecutorLIFI } from "../mocks/MockExecutorLIFI.sol";

abstract contract ExecutorLIFITest is Test {
    function enableCalls() internal view virtual returns (bool);

    function typehash(uint256 nonce, bytes32 mode, ERC7821.Call[] calldata calls) external returns (bytes32) {
        return LibCalls.typehash(nonce, mode, calls);
    }

    address executorTemplate;
    MockExecutorLIFI executor;

    function setUp() external {
        executorTemplate = address(new MockExecutorLIFI(enableCalls()));

        // Make a clone of the executor so we can access it in the expected manner.
        executor = MockExecutorLIFI(payable(LibClone.deployERC1967(executorTemplate)));
    }

    function init() internal returns (address owner) {
        owner = makeAddr("owner");
        executor.init(owner);
    }

    function test_template_init_disabled() external {
        vm.expectRevert(abi.encodeWithSignature("InvalidInitialization()"));
        MockExecutorLIFI(payable(executorTemplate)).init(makeAddr("owner"));
    }

    function test_init() external {
        assertEq(executor.owner(), address(0));

        address owner = makeAddr("owner");
        executor.init(owner);

        assertEq(executor.owner(), owner);

        // Ensure we can't init again.
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSignature("InvalidInitialization()"));
        executor.init(owner);
    }

    // function test_upgrade() external {
    //     address owner = init();

    //     address newImplementation = address(new MockExecutorLIFI(enableCalls()));

    //     vm.prank(makeAddr("notOwner"));
    //     vm.expectRevert(abi.encodeWithSignature("Unauthorized()"));
    //     executor.upgradeToAndCall(newImplementation, hex"");

    //     vm.prank(owner);
    //     executor.upgradeToAndCall(newImplementation, hex"");
    // }

    function test_use_nonce() external {
        executor.useUnorderedNonce(0);
        executor.useUnorderedNonce(1);

        vm.expectRevert(abi.encodeWithSelector(BitmapNonce.InvalidNonce.selector));
        executor.useUnorderedNonce(0);
    }

    function test_use_nonce_no_collision(uint256 nonceA, uint256 nonceB) external {
        vm.assume(nonceA != nonceB);
        executor.useUnorderedNonce(nonceA);
        executor.useUnorderedNonce(nonceB);
    }

    function test_validate_op_data() external {
        ERC7821.Call[] memory calls = new ERC7821.Call[](0);
        bytes32 mode = bytes32(0);
        bytes memory opData = abi.encode(0);
        bool result;

        vm.prank(address(executor));
        result = executor.validateOpData(mode, calls, opData);
        assertEq(result, true);

        vm.prank(address(executor));
        vm.expectRevert(abi.encodeWithSelector(BitmapNonce.InvalidNonce.selector));
        result = executor.validateOpData(mode, calls, opData);
        assertEq(result, false);

        opData = abi.encode(1);
        vm.prank(address(executor));
        result = executor.validateOpData(mode, calls, opData);
        assertEq(result, true);
    }

    // function test_validate_op_data_calldata() external {
    //     vm.skip(!enableCalls());
    //     bool result;

    //     ERC7821.Call[] memory calls = new ERC7821.Call[](0);
    //     uint256 nonce = 0;
    //     bytes32 mode = bytes32(0);
    //     bytes32 typeHash = this.typehash(nonce, mode, calls);

    //     init(typeHash);

    //     bytes memory opData = abi.encode(nonce);
    //     vm.prank(makeAddr("random"));
    //     result = executor.validateOpData(mode, calls, opData);
    //     assertEq(result, true);
    // }
}
