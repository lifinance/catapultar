// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { Test } from "forge-std/src/Test.sol";

import { ERC7821 } from "solady/src/accounts/ERC7821.sol";

import { ERC7821LIFI } from "../../src/libs/ERC7821LIFI.sol";

import { MockERC7821LIFI } from "../mocks/MockERC7821LIFI.sol";

contract ERC7821LIFITest is Test {
    error SmallError();
    error CustomError(bytes);

    event CallReverted(bytes32 extraData, bytes revertData);

    MockERC7821LIFI mbe;

    bytes32 internal constant _SUPPORTED_MODE = bytes10(0x01000000000078210001);
    bytes32 internal constant _ESTIMATE_GAS_MODE = bytes10(0x01020000000078210001);
    bytes32 internal constant _ESTIMATE_GAS_MULTICHAIN_MODE =
        0x0102010000007821000100000000000000000000000000000000000000000000;

    bytes[] internal _bytes;
    uint256 internal healthyCalls;

    function setUp() public {
        mbe = new MockERC7821LIFI();
    }

    function revertsWithSmallError() external payable {
        revert SmallError();
    }

    function revertsWithNoData() external payable {
        assembly ("memory-safe") {
            revert(0x00, 0x00)
        }
    }

    function revertsWithCustomError(
        bytes calldata m
    ) external payable {
        revert CustomError(m);
    }

    function healthy() external payable {
        ++healthyCalls;
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

    function testERC7821LIFI_estimateGasModeSupported() external view {
        assertEq(mbe.executionModeId(_ESTIMATE_GAS_MODE), 2);
        assertEq(mbe.executionModeId(_ESTIMATE_GAS_MULTICHAIN_MODE), 2);
        assertTrue(mbe.supportsExecutionMode(_ESTIMATE_GAS_MODE));
        assertTrue(mbe.supportsExecutionMode(_ESTIMATE_GAS_MULTICHAIN_MODE));
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

    function testERC7821LIFI_estimateGas_nonEmptyRevertDataContinues(
        uint256 nonce,
        bytes calldata payload
    ) external {
        ERC7821.Call[] memory calls = new ERC7821.Call[](2);
        calls[0] = ERC7821.Call({
            to: address(this), data: abi.encodeWithSignature("revertsWithCustomError(bytes)", payload), value: 0
        });
        calls[1] = ERC7821.Call({ to: address(this), data: abi.encodeWithSignature("healthy()"), value: 0 });

        mbe.setValidCalldata(abi.encode(nonce));
        uint256 extraDataU = uint256(bytes32(bytes1(0x02))) + uint256((nonce << (9 * 8)) >> 8);
        vm.expectEmit(true, true, true, true);
        emit CallReverted(bytes32(extraDataU + 0), abi.encodeWithSelector(CustomError.selector, payload));

        bytes memory executionData = abi.encode(calls, abi.encode(nonce));

        vm.prank(address(mbe));
        mbe.execute(_ESTIMATE_GAS_MODE, executionData);

        assertEq(healthyCalls, 1);
    }

    function testRevert_ERC7821LIFI_estimateGas_emptyRevertData(
        uint256 nonce
    ) external {
        ERC7821.Call[] memory calls = new ERC7821.Call[](2);
        calls[0] = ERC7821.Call({ to: address(this), data: abi.encodeWithSignature("revertsWithNoData()"), value: 0 });
        calls[1] = ERC7821.Call({ to: address(this), data: abi.encodeWithSignature("healthy()"), value: 0 });

        mbe.setValidCalldata(abi.encode(nonce));
        bytes memory executionData = abi.encode(calls, abi.encode(nonce));

        vm.prank(address(mbe));
        // The EstimateGas frame reverts with EMPTY returndata (the EstimateGasEmptyRevertData
        // event marker is discarded by the revert) so parent EstimateGas frames compose.
        vm.expectRevert(bytes(""));
        mbe.execute(_ESTIMATE_GAS_MODE, executionData);

        assertEq(healthyCalls, 0);
    }

    /// An empty-data failure inside a NESTED EstimateGas frame must propagate through the
    /// parent EstimateGas frame as another empty revert, all the way to the top.
    function testRevert_ERC7821LIFI_estimateGas_emptyRevertDataComposes(
        uint256 nonce
    ) external {
        ERC7821.Call[] memory innerCalls = new ERC7821.Call[](1);
        innerCalls[0] =
            ERC7821.Call({ to: address(this), data: abi.encodeWithSignature("revertsWithNoData()"), value: 0 });
        bytes memory innerExecutionData = abi.encode(innerCalls, abi.encode(nonce));

        ERC7821.Call[] memory calls = new ERC7821.Call[](2);
        calls[0] = ERC7821.Call({
            to: address(mbe),
            data: abi.encodeWithSignature("execute(bytes32,bytes)", _ESTIMATE_GAS_MODE, innerExecutionData),
            value: 0
        });
        calls[1] = ERC7821.Call({ to: address(this), data: abi.encodeWithSignature("healthy()"), value: 0 });

        mbe.setValidCalldata(abi.encode(nonce));
        bytes memory executionData = abi.encode(calls, abi.encode(nonce));

        vm.prank(address(mbe));
        vm.expectRevert(bytes(""));
        mbe.execute(_ESTIMATE_GAS_MODE, executionData);

        assertEq(healthyCalls, 0);
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
