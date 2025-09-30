// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { Test } from "forge-std/Test.sol";

import { ERC7821 } from "solady/src/accounts/ERC7821.sol";
import { LibClone } from "solady/src/utils/LibClone.sol";

import { BitmapNonce } from "../../src/BitmapNonce.sol";

import { ExecutorLIFI } from "../../src/ExecutorLIFI.sol";
import { LibCalls } from "../../src/LibCalls.sol";
import { MockExecutorLIFI } from "../mocks/MockExecutorLIFI.sol";

interface EIP712 {
    function DOMAIN_SEPARATOR() external view returns (bytes32);
}

abstract contract ExecutorLIFITest is Test {
    function deploy() internal virtual returns (address template, address proxied);

    function upgradable() internal pure virtual returns (bool);

    function embeddedCalls() internal pure virtual returns (bool);

    function typehash(uint256 nonce, bytes32 mode, ERC7821.Call[] calldata calls) external pure returns (bytes32) {
        return LibCalls.typehash(nonce, mode, calls);
    }

    address executorTemplate;
    MockExecutorLIFI executor;

    function setUp() external {
        address executorProxied;
        (executorTemplate, executorProxied) = deploy();
        executor = MockExecutorLIFI(payable(executorProxied));
    }

    function init() internal returns (address owner, uint256 key) {
        (owner, key) = makeAddrAndKey("owner");
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

    function test_upgradable() external {
        assertEq(executor.upgradable(), upgradable());
    }

    function test_upgrade() external {
        (address owner,) = init();

        address newImplementation = address(new MockExecutorLIFI(false));

        vm.prank(makeAddr("notOwner"));
        vm.expectRevert(abi.encodeWithSignature("Unauthorized()"));
        executor.upgradeToAndCall(newImplementation, hex"");

        if (!upgradable()) vm.expectRevert(abi.encodeWithSelector(ExecutorLIFI.NotUpgradeable.selector));
        vm.prank(owner);
        executor.upgradeToAndCall(newImplementation, hex"");
    }

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

    function test_check_embedded_calls() external {
        bytes32 embed = executor.embeddedCall();
        assertEq(embed, bytes32(0));
    }

    function test_embed_arbitrary(
        bytes32 embed
    ) external {
        vm.skip(!embeddedCalls());

        executor = MockExecutorLIFI(payable(LibClone.cloneDeterministic(executorTemplate, abi.encodePacked(embed), 0)));

        bytes32 read = executor.embeddedCall();
        assertEq(read, embed);
    }

    function test_embed_new_address() external {
        vm.skip(!embeddedCalls());

        bytes32 embedA = bytes32(uint256(1));
        bytes32 embedB = bytes32(uint256(2));

        address cloneA = LibClone.cloneDeterministic(executorTemplate, abi.encodePacked(embedA), 0);
        address cloneB = LibClone.cloneDeterministic(executorTemplate, abi.encodePacked(embedB), 0);

        assertNotEq(cloneA, cloneB);
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

    function test_validate_op_data_embedded_calls() external {
        vm.skip(!embeddedCalls());

        ERC7821.Call[] memory calls = new ERC7821.Call[](1);
        uint256 nonce = 0;
        bytes32 mode = bytes32(0);
        bytes32 typeHash = this.typehash(nonce, mode, calls);

        // Check that our default account (that has 0 embedded) return false
        bytes memory opData = abi.encode(nonce);
        vm.prank(makeAddr("random"));
        bool result = executor.validateOpData(mode, calls, opData);
        assertEq(result, false);

        // We need to deploy a proxy specifically with the embedded typehash.
        executor =
            MockExecutorLIFI(payable(LibClone.cloneDeterministic(executorTemplate, abi.encodePacked(typeHash), 0)));

        bytes32 embed = executor.embeddedCall();
        assertEq(embed, typeHash);

        vm.prank(makeAddr("random"));
        result = executor.validateOpData(mode, calls, opData);
        assertEq(result, true);
    }

    function test_validate_op_data_signatures() external {
        (address owner, uint256 privateKey) = init();

        uint256 nonce = 1;
        ERC7821.Call[] memory calls = new ERC7821.Call[](0);
        bytes32 mode = bytes32(0);
        bool result;

        bytes32 domainSeparator = EIP712(address(executor)).DOMAIN_SEPARATOR();
        bytes32 msgHash = keccak256(abi.encodePacked("\x19\x01", domainSeparator, this.typehash(nonce, mode, calls)));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, msgHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        uint256 snapshot = vm.snapshot();

        result = executor.validateOpData(mode, calls, abi.encodePacked(nonce, signature));
        assertEq(result, true);

        vm.expectRevert(abi.encodeWithSignature("InvalidNonce()"));
        executor.validateOpData(mode, calls, abi.encodePacked(nonce, signature));

        vm.revertTo(snapshot);

        result = executor.validateOpData(mode, calls, abi.encodePacked(nonce + 1, signature));
        assertEq(result, false);
    }
}
