// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

// forge-lint: disable-start(unsafe-typecast)
// forge-lint: disable-start(erc20-unchecked-transfer)
// forge-lint: disable-start(unchecked-call)

import { Test } from "forge-std/src/Test.sol";

import { ERC7821 } from "solady/src/accounts/ERC7821.sol";
import { LibClone } from "solady/src/utils/LibClone.sol";

import { Catapultar } from "../../src/Catapultar.sol";

import { BitmapNonce } from "../../src/libs/BitmapNonce.sol";

import { KeyedOwnable } from "../../src/libs/KeyedOwnable.sol";
import { LibCalls } from "../../src/libs/LibCalls.sol";

import { MockCatapultar } from "../mocks/MockCatapultar.sol";
import { MockERC20 } from "../mocks/MockERC20.sol";

interface EIP712 {
    function DOMAIN_SEPARATOR() external view returns (bytes32);
}

/// @notice This test contract is meant to be implemented by sub-test contracts that proxy the actual implementation to
/// mimic how the contract is intended to be used in practise.
abstract contract CatapultarTest is Test {
    function deploy() internal virtual returns (address template, address proxied);

    function upgradeable() internal pure virtual returns (bool);

    function typehash(
        uint256 nonce,
        bytes32 mode,
        ERC7821.Call[] calldata calls
    ) external pure returns (bytes32) {
        return LibCalls.typehash(nonce, mode, calls);
    }

    address executorTemplate;
    MockCatapultar executor;

    MockERC20 token;

    function setUp() external {
        address executorProxied;
        (executorTemplate, executorProxied) = deploy();
        executor = MockCatapultar(payable(executorProxied));

        token = new MockERC20("Mock", "MCK", 18);

        uint256 amount = 10 ** 18;
        (address own,) = makeAddrAndKey("owner");
        token.mint(own, amount);
        token.mint(address(executor), amount);
    }

    function init() internal returns (address owner, uint256 key) {
        (owner, key) = makeAddrAndKey("owner");
        bytes32[] memory keys = new bytes32[](1);
        keys[0] = bytes32(uint256(uint160(owner)));

        executor.init(KeyedOwnable.KeyType.ECDSAOrSmartContract, keys);
    }

    function test_template_init_disabled() external {
        bytes32[] memory keys = new bytes32[](1);
        keys[0] = bytes32(uint256(uint160(makeAddr("owner"))));
        vm.expectRevert(abi.encodeWithSignature("InvalidInitialization()"));
        MockCatapultar(payable(executorTemplate)).init(KeyedOwnable.KeyType.ECDSAOrSmartContract, keys);
    }

    function test_init() external {
        assertEq(executor.owner(), address(0));

        address owner = makeAddr("owner");

        bytes32[] memory keys = new bytes32[](1);
        keys[0] = bytes32(uint256(uint160(owner)));

        executor.init(KeyedOwnable.KeyType.ECDSAOrSmartContract, keys);

        assertEq(executor.owner(), owner);

        // Ensure we can't init again.
        vm.prank(owner);
        vm.expectRevert(abi.encodeWithSignature("InvalidInitialization()"));
        executor.init(KeyedOwnable.KeyType.ECDSAOrSmartContract, keys);
    }

    /// forge-config: default.isolate = true
    function test_overhead_baseline() external {
        (address owner,) = init();
        uint256 amount = 10 ** 18;

        vm.prank(owner);
        token.transfer(makeAddr("to"), amount);
        vm.snapshotGasLastCall("erc20TransferBaseline");
    }

    /// forge-config: default.isolate = true
    function test_overhead_baseline_twice() external {
        (address owner,) = init();
        uint256 amount = 10 ** 18;

        vm.prank(owner);
        token.transfer(makeAddr("to"), amount / 2);
        vm.prank(owner);
        token.transfer(makeAddr("next"), amount / 2);
        vm.snapshotGasLastCall("erc20TransferBaselineSecond");
    }

    /// forge-config: default.isolate = true
    function test_overhead_sca() external {
        (, uint256 privateKey) = init();
        uint256 amount = 10 ** 18;
        bytes32 executionMode = bytes10(0x01000000000078210001);
        uint256 nonce = 1;

        ERC7821.Call[] memory calls = new ERC7821.Call[](1);
        calls[0] = ERC7821.Call({
            to: address(token), data: abi.encodeCall(MockERC20.transfer, (makeAddr("to"), amount)), value: 0
        });

        bytes32 domainSeparator = EIP712(address(executor)).DOMAIN_SEPARATOR();
        bytes32 msgHash =
            keccak256(abi.encodePacked("\x19\x01", domainSeparator, this.typehash(nonce, executionMode, calls)));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, msgHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        executor.execute(executionMode, abi.encode(calls, abi.encodePacked(nonce, signature)));
        vm.snapshotGasLastCall("erc20TransferSCA");
    }

    /// forge-config: default.isolate = true
    function test_hot_overhead_sca() external {
        (address owner, uint256 privateKey) = init();
        uint256 amount = 10 ** 18;
        bytes32 executionMode = bytes10(0x01000000000078210001);
        uint256 nonce = 1;

        vm.prank(owner);
        executor.invalidateUnorderedNonces(0, 1 << 255);

        ERC7821.Call[] memory calls = new ERC7821.Call[](1);
        calls[0] = ERC7821.Call({
            to: address(token), data: abi.encodeCall(MockERC20.transfer, (makeAddr("to"), amount)), value: 0
        });

        bytes32 domainSeparator = EIP712(address(executor)).DOMAIN_SEPARATOR();
        bytes32 msgHash =
            keccak256(abi.encodePacked("\x19\x01", domainSeparator, this.typehash(nonce, executionMode, calls)));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, msgHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        executor.execute(executionMode, abi.encode(calls, abi.encodePacked(nonce, signature)));
        vm.snapshotGasLastCall("erc20TransferSCAHotNonce");
    }

    /// forge-config: default.isolate = true
    function test_overhead_sca_twice() external {
        (, uint256 privateKey) = init();
        uint256 amount = 10 ** 18;
        bytes32 executionMode = bytes10(0x01000000000078210001);
        uint256 nonce = 1;

        ERC7821.Call[] memory calls = new ERC7821.Call[](2);
        calls[0] = ERC7821.Call({
            to: address(token), data: abi.encodeCall(MockERC20.transfer, (makeAddr("to"), amount / 2)), value: 0
        });
        calls[1] = ERC7821.Call({
            to: address(token), data: abi.encodeCall(MockERC20.transfer, (makeAddr("next"), amount / 2)), value: 0
        });

        bytes32 domainSeparator = EIP712(address(executor)).DOMAIN_SEPARATOR();
        bytes32 msgHash =
            keccak256(abi.encodePacked("\x19\x01", domainSeparator, this.typehash(nonce, executionMode, calls)));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, msgHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        executor.execute(executionMode, abi.encode(calls, abi.encodePacked(nonce, signature)));
        vm.snapshotGasLastCall("erc20TransferTwiceSCA");
    }

    /// forge-config: default.isolate = true
    function test_overhead_sca_twice_hot() external {
        (address owner, uint256 privateKey) = init();
        uint256 amount = 10 ** 18;
        bytes32 executionMode = bytes10(0x01000000000078210001);
        uint256 nonce = 1;

        vm.prank(owner);
        executor.invalidateUnorderedNonces(0, 1 << 255);

        ERC7821.Call[] memory calls = new ERC7821.Call[](2);
        calls[0] = ERC7821.Call({
            to: address(token), data: abi.encodeCall(MockERC20.transfer, (makeAddr("to"), amount / 2)), value: 0
        });
        calls[1] = ERC7821.Call({
            to: address(token), data: abi.encodeCall(MockERC20.transfer, (makeAddr("next"), amount / 2)), value: 0
        });

        bytes32 domainSeparator = EIP712(address(executor)).DOMAIN_SEPARATOR();
        bytes32 msgHash =
            keccak256(abi.encodePacked("\x19\x01", domainSeparator, this.typehash(nonce, executionMode, calls)));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, msgHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        executor.execute(executionMode, abi.encode(calls, abi.encodePacked(nonce, signature)));
        vm.snapshotGasLastCall("erc20TransferTwiceSCAHotNonce");
    }

    function test_upgradeable() external view {
        assertEq(executor.upgradeable(), upgradeable());
    }

    function test_upgrade() external {
        (address owner,) = init();

        address newImplementation = address(new MockCatapultar());

        vm.prank(makeAddr("notOwner"));
        vm.expectRevert(abi.encodeWithSignature("Unauthorized()"));
        executor.upgradeToAndCall(newImplementation, hex"");

        if (!upgradeable()) vm.expectRevert(abi.encodeWithSelector(Catapultar.NotUpgradeable.selector));
        vm.prank(owner);
        executor.upgradeToAndCall(newImplementation, hex"");
    }

    function test_useUnorderedNonce() external {
        vm.expectRevert(abi.encodeWithSelector(BitmapNonce.InvalidNonce.selector));
        executor.useUnorderedNonce(0);

        executor.useUnorderedNonce(1);
        executor.useUnorderedNonce(2);

        vm.expectRevert(abi.encodeWithSelector(BitmapNonce.InvalidNonce.selector));
        executor.useUnorderedNonce(1);
    }

    function test_useUnorderedNonce_no_collision(
        uint256 nonceA,
        uint256 nonceB
    ) external {
        vm.assume(nonceA != 0);
        vm.assume(nonceB != 0);
        vm.assume(nonceA != nonceB);
        executor.useUnorderedNonce(nonceA);
        executor.useUnorderedNonce(nonceB);
    }

    function test_embed_new_address() external {
        bytes32 embedA = bytes32(uint256(1));
        bytes32 embedB = bytes32(uint256(2));

        address cloneA = LibClone.cloneDeterministic(executorTemplate, abi.encodePacked(embedA), 0);
        address cloneB = LibClone.cloneDeterministic(executorTemplate, abi.encodePacked(embedB), 0);

        assertNotEq(cloneA, cloneB);
    }

    function test_validateOpData() external {
        ERC7821.Call[] memory calls = new ERC7821.Call[](0);
        bytes32 mode = bytes32(0);
        bytes memory opData = abi.encode(1);
        bool result;

        vm.prank(address(executor));
        result = executor.validateOpData(mode, calls, opData);
        assertEq(result, true);

        vm.prank(address(executor));
        vm.expectRevert(abi.encodeWithSelector(BitmapNonce.InvalidNonce.selector));
        result = executor.validateOpData(mode, calls, opData);
        assertEq(result, false);

        opData = abi.encode(2);
        vm.prank(address(executor));
        result = executor.validateOpData(mode, calls, opData);
        assertEq(result, true);
    }

    function test_invalidateUnorderedNonces() external {
        (address owner,) = init();

        ERC7821.Call[] memory calls = new ERC7821.Call[](0);
        bytes32 mode = bytes32(0);
        bool result;

        uint256 snapshot = vm.snapshot();

        vm.prank(address(executor));
        result = executor.validateOpData(mode, calls, abi.encode(1));
        assertEq(result, true);

        vm.revertTo(snapshot);

        vm.expectEmit();
        emit BitmapNonce.UnorderedNonceInvalidation(0, 7);

        vm.prank(owner);
        executor.invalidateUnorderedNonces(0, 7);

        vm.startPrank(address(executor));

        vm.expectRevert(abi.encodeWithSelector(BitmapNonce.InvalidNonce.selector));
        executor.validateOpData(mode, calls, abi.encode(1));

        vm.expectRevert(abi.encodeWithSelector(BitmapNonce.InvalidNonce.selector));
        executor.validateOpData(mode, calls, abi.encode(2));

        result = executor.validateOpData(mode, calls, abi.encode(12));
        assertEq(result, true);

        vm.stopPrank();
    }

    function testRevert_invalidateUnorderedNonces_onlyOwnerOrSelf() external {
        (address owner,) = init();

        vm.expectRevert(abi.encodeWithSignature("Unauthorized()"));
        executor.invalidateUnorderedNonces(0, 3);

        vm.prank(owner);
        executor.invalidateUnorderedNonces(0, 3);

        vm.prank(address(executor));
        executor.invalidateUnorderedNonces(0, 3);
    }

    function testRevert_invalidateUnorderedNonces_asBatch() external {
        ERC7821.Call[] memory calls = new ERC7821.Call[](1);
        calls[0] = ERC7821.Call({
            to: address(0), data: abi.encodeCall(executor.invalidateUnorderedNonces, (0, 2)), value: 0
        });

        vm.prank(address(executor));
        executor.execute(bytes10(0x01000000000078210001), abi.encode(calls, abi.encode(1)));
    }

    function test_validateOpData_digest() external {
        ERC7821.Call[] memory calls = new ERC7821.Call[](1);
        uint256 nonce = 1;
        bytes32 mode = bytes32(0);
        bytes32 typeHash = this.typehash(nonce, mode, calls);

        // Check that our default account (that has 0 embedded) return false
        bytes memory opData = abi.encode(nonce);
        vm.prank(makeAddr("random"));
        bool result = executor.validateOpData(mode, calls, opData);
        assertEq(result, false);

        // We need to deploy a proxy specifically with the embedded typehash.
        executor = MockCatapultar(payable(LibClone.cloneDeterministic(executorTemplate, 0)));
        executor.setSignature(typeHash, Catapultar.DigestApproval.Call);

        uint8 embeddedAt = uint8(executor.approvedDigest(typeHash));
        assertEq(embeddedAt, uint8(Catapultar.DigestApproval.Call));

        vm.prank(makeAddr("random"));
        result = executor.validateOpData(mode, calls, opData);
        assertEq(result, true);
    }

    function test_validateOpData_signatures() external {
        (, uint256 privateKey) = init();

        uint256 nonce = 1;
        ERC7821.Call[] memory calls = new ERC7821.Call[](0);
        bytes32 mode = bytes32(0);

        bytes32 domainSeparator = EIP712(address(executor)).DOMAIN_SEPARATOR();
        bytes32 msgHash = keccak256(abi.encodePacked("\x19\x01", domainSeparator, this.typehash(nonce, mode, calls)));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, msgHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        uint256 snapshot = vm.snapshot();

        assertTrue(executor.validateOpData(mode, calls, abi.encodePacked(nonce, signature)));

        vm.expectRevert(abi.encodeWithSignature("InvalidNonce()"));
        executor.validateOpData(mode, calls, abi.encodePacked(nonce, signature));

        vm.revertTo(snapshot);

        assertFalse(executor.validateOpData(mode, calls, abi.encodePacked(nonce + 1, signature)));
    }

    function test_validateOpData_signatures_multichain() external {
        vm.chainId(100);
        (, uint256 privateKey) = init();
        ERC7821.Call[] memory calls = new ERC7821.Call[](0);
        uint256 snapshot = vm.snapshot();
        {
            bytes32 mode = 0x0100000000007821000100000000000000000000000000000000000000000000;
            uint256 nonce = 1;

            bytes32 domainSeparator = EIP712(address(executor)).DOMAIN_SEPARATOR();
            bytes32 msgHash =
                keccak256(abi.encodePacked("\x19\x01", domainSeparator, this.typehash(nonce, mode, calls)));

            (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, msgHash);
            bytes memory signature = abi.encodePacked(r, s, v);

            assertTrue(executor.validateOpData(mode, calls, abi.encodePacked(nonce, signature)));

            vm.revertTo(snapshot);

            vm.chainId(101);
            assertFalse(executor.validateOpData(mode, calls, abi.encodePacked(nonce, signature)));
        }
        vm.chainId(100);
        {
            // Multichain flow
            bytes32 multichainMode = 0x0100010000007821000100000000000000000000000000000000000000000000;
            uint256 nonce = 2;
            (, string memory name, string memory version,,,,) = executor.eip712Domain();
            bytes32 domainSeparator = keccak256(
                abi.encode(
                    keccak256(bytes("EIP712Domain(string name,string version,address verifyingContract)")),
                    keccak256(bytes(name)),
                    keccak256(bytes(version)),
                    address(executor)
                )
            );
            bytes32 msgHash = keccak256(
                abi.encodePacked("\x19\x01", domainSeparator, this.typehash(nonce, multichainMode, calls))
            );
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, msgHash);
            bytes memory signature = abi.encodePacked(r, s, v);

            assertTrue(executor.validateOpData(multichainMode, calls, abi.encodePacked(nonce, signature)));

            // The nonce would technically not be spent but we are on the same storage.
            vm.revertTo(snapshot);
            vm.chainId(101);
            assertTrue(executor.validateOpData(multichainMode, calls, abi.encodePacked(nonce, signature)));
        }
    }

    bytes4 constant SUCCESS_IS_VALID_SIGNATURE = bytes4(keccak256("isValidSignature(bytes32,bytes)"));
    bytes4 constant IS_NOT_VALID_SIGNATURE = bytes4(uint32(0xFFFFFFFF));

    function test_isValidSignature() external {
        (, uint256 privateKey) = init();

        bytes32 msgHash = keccak256(bytes("RandomPayload"));
        // Check that a random signature is not valid.
        bytes4 result = executor.isValidSignature(msgHash, abi.encodePacked(keccak256(""), keccak256("")));
        assertEq(bytes32(result), bytes32(IS_NOT_VALID_SIGNATURE));

        bytes32 toSign = keccak256(
            abi.encode(keccak256(bytes("Replay(address account,bytes32 payload)")), address(executor), msgHash)
        );
        // Sign the payload directionly.
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, toSign);

        bytes memory signature = abi.encodePacked(r, s, v);

        result = executor.isValidSignature(msgHash, signature);

        assertEq(bytes32(result), bytes32(SUCCESS_IS_VALID_SIGNATURE));

        // Deploy another proxy version to check whether we can replay the signature. Do note that this technically also
        // uses a different underlying template.
        (, address newExecutorProxied) = deploy();

        result = MockCatapultar(payable(newExecutorProxied)).isValidSignature(msgHash, signature);

        assertEq(bytes32(result), bytes32(IS_NOT_VALID_SIGNATURE));
    }

    function test_isValidSignature_setSignature() external {
        init();

        bytes32 msgHash = keccak256(bytes("RandomPayload"));
        bytes4 result = executor.isValidSignature(msgHash, hex"");
        assertEq(bytes32(result), bytes32(IS_NOT_VALID_SIGNATURE));

        bytes32 toSign = keccak256(
            abi.encode(keccak256(bytes("Replay(address account,bytes32 payload)")), address(executor), msgHash)
        );
        // Set the signature (as call).
        vm.prank(address(executor));
        executor.setSignature(toSign, Catapultar.DigestApproval.Call);

        result = executor.isValidSignature(msgHash, hex"");
        assertEq(bytes32(result), bytes32(IS_NOT_VALID_SIGNATURE));

        // Set the signature (as signature).
        vm.prank(address(executor));
        executor.setSignature(toSign, Catapultar.DigestApproval.Signature);

        result = executor.isValidSignature(msgHash, hex"");
        assertEq(bytes32(result), bytes32(SUCCESS_IS_VALID_SIGNATURE));
    }

    function testRevert_isValidSignature_no_rehash() external {
        (, uint256 privateKey) = init();

        bytes32 msgHash = keccak256(bytes("RandomPayload"));
        // Sign the payload directionly.
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, msgHash);

        bytes4 result = executor.isValidSignature(msgHash, abi.encodePacked(r, s, v));

        assertNotEq(bytes32(result), bytes32(SUCCESS_IS_VALID_SIGNATURE));
        assertEq(bytes32(result), bytes32(bytes4(0xffffffff)));
    }

    // Considering this account is a SCA, we need to be able to handle the callbacks for token transfers.
    function test_token_transfer_fallback() external {
        // 0x150b7a02: `onERC721Received(address,address,uint256,bytes)`.
        // 0xf23a6e61: `onERC1155Received(address,address,uint256,uint256,bytes)`.
        // 0xbc197c81: `onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)`.

        (bool success,) = address(executor)
            .call(
                abi.encodeWithSignature(
                    "onERC721Received(address,address,uint256,bytes)", address(0), address(0), uint256(0), new bytes(0)
                )
            );
        assertEq(success, true);
        (success,) = address(executor)
            .call(
                abi.encodeWithSignature(
                    "onERC1155Received(address,address,uint256,uint256,bytes)",
                    address(0),
                    address(0),
                    uint256(0),
                    uint256(0),
                    new bytes(0)
                )
            );
        assertEq(success, true);

        (success,) = address(executor)
            .call(
                abi.encodeWithSignature(
                    "onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)",
                    address(0),
                    address(0),
                    new uint256[](0),
                    new uint256[](0),
                    new bytes(0)
                )
            );
        assertEq(success, true);
    }
}
