// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { Test } from "forge-std/Test.sol";

import { ERC7821 } from "solady/src/accounts/ERC7821.sol";

import { ERC7821LIFI } from "../../src/libs/ERC7821LIFI.sol";

import { MockERC7821LIFI } from "../mocks/MockERC7821LIFI.sol";

contract ERC7821LIFITest is Test {
    error SmallError();
    error CustomError(bytes);

    event CallReverted(bytes32 extraData, bytes revertData);

    MockERC7821LIFI mbe;

    bytes32 internal constant _SUPPORTED_MODE = bytes10(0x01000000000078210001);

    bytes[] internal _bytes;

    function setUp() public {
        mbe = new MockERC7821LIFI();
    }

    function revertsWithSmallError() external payable {
        revert SmallError();
    }

    function revertsWithCustomError(
        bytes calldata m
    ) external payable {
        revert CustomError(m);
    }

    function returnsBytes(
        bytes memory b
    ) external payable returns (bytes memory) {
        return b;
    }

    function returnsHash(
        bytes memory b
    ) external payable returns (bytes32) {
        return keccak256(b);
    }

    function testERC7821LIFI_executionModeRevert(
        bytes32 mode
    ) external view {
        bytes32 result = mbe.executionModeRevert(mode);
        bytes32 toSelect = mode & bytes32(0x00ff000000000000000000000000000000000000000000000000000000000000);
        if (uint256(toSelect) > 0) vm.assertEq(toSelect << 8, result);
        else vm.assertEq(result, bytes32(0x0000000000000000000000000000000000000000000000000000000000000000));
    }

    struct RandomBytes {
        bytes payload;
        bool fail;
    }

    function testERC7821LIFI_nonces(
        uint256 nonce,
        RandomBytes[] calldata randomBytes
    ) external {
        ERC7821.Call[] memory calls = new ERC7821.Call[](randomBytes.length);
        for (uint256 i; i < randomBytes.length; ++i) {
            calls[i] = ERC7821.Call({
                to: address(this),
                data: abi.encodeWithSignature(
                    randomBytes[i].fail ? "revertsWithCustomError(bytes)" : "returnsBytes(bytes)",
                    randomBytes[i].payload
                ),
                value: 0
            });
        }

        mbe.setValidCalldata(abi.encode(nonce));

        uint256 extraDataU = uint256(bytes32(bytes1(0x01))) + uint256((nonce << (9 * 8)) >> 8);
        for (uint256 i; i < randomBytes.length; ++i) {
            if (randomBytes[i].fail) {
                vm.expectEmit(true, true, true, true);
                emit CallReverted(
                    bytes32(extraDataU + i), abi.encodeWithSelector(CustomError.selector, (randomBytes[i].payload))
                );
            }
        }

        bytes memory executionData = abi.encode(calls, abi.encode(nonce));

        vm.prank(address(mbe));
        mbe.execute(bytes10(0x01010000000078210001), executionData);
    }

    function testERC7821LIFI_small_error(
        uint256 nonce
    ) external {
        ERC7821.Call[] memory calls = new ERC7821.Call[](1);
        calls[0] =
            ERC7821.Call({ to: address(this), data: abi.encodeWithSignature("revertsWithSmallError()"), value: 0 });

        mbe.setValidCalldata(abi.encode(nonce));
        uint256 extraDataU = uint256(bytes32(bytes1(0x01))) + uint256((nonce << (9 * 8)) >> 8);
        vm.expectEmit(true, true, true, true);
        emit CallReverted(bytes32(extraDataU + 0), abi.encodeWithSelector(SmallError.selector));

        bytes memory executionData = abi.encode(calls, abi.encode(nonce));

        vm.prank(address(mbe));
        mbe.execute(bytes10(0x01010000000078210001), executionData);
    }

    /// The following test does not work, because for it to work it has to allocate memory for type(uint64).max) + 1
    /// many items.
    /// That is not possible.
    // function testRevert_TooManyCalls() external {
    //     ERC7821.Call[] memory calls = new ERC7821.Call[](uint256(type(uint64).max) + 1);

    // bytes memory executionData = abi.encode(calls, abi.encode(0));
    // mbe.setValidCalldata(abi.encode(0));

    // vm.prank(address(mbe));
    // vm.expectRevert(abi.encodeWithSelector(ERC7821LIFI.TooManyCalls.selector));
    // mbe.execute(bytes10(0x01010000000078210001), executionData);
    //}

    function testRevert_noOpData() external {
        ERC7821.Call[] memory calls = new ERC7821.Call[](1);

        bytes memory opData = new bytes(31);
        bytes memory executionData = abi.encode(calls, opData);
        mbe.setValidCalldata(opData);

        vm.prank(address(mbe));
        vm.expectRevert(abi.encodeWithSelector(ERC7821LIFI.OpDataTooSmall.selector));
        mbe.execute(bytes10(0x01010000000078210001), executionData);
    }

    function testRevert_invalidOpData() external {
        ERC7821.Call[] memory calls = new ERC7821.Call[](1);

        bytes memory opData = abi.encode(1);
        bytes memory executionData = abi.encode(calls, opData);

        vm.prank(address(mbe));
        vm.expectRevert(abi.encodeWithSelector(ERC7821LIFI.InvalidOpData.selector));
        mbe.execute(bytes10(0x01010000000078210001), executionData);

        mbe.setValidCalldata(opData);

        vm.prank(address(mbe));
        mbe.execute(bytes10(0x01010000000078210001), executionData);
    }

    // --- Test Helpers --- //

    function _totalValue(
        ERC7821.Call[] memory calls
    ) internal pure returns (uint256 result) {
        unchecked {
            for (uint256 i; i < calls.length; ++i) {
                result += calls[i].value;
            }
        }
    }
}
