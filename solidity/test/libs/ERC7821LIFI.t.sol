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
    bytes32 internal constant _RAISE_REVERT_ESTIMATE_MODE = bytes10(0x01030000000078210001);
    bytes32 internal constant _RAISE_REVERT_ESTIMATE_MULTICHAIN_MODE =
        0x0103010000007821000100000000000000000000000000000000000000000000;

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

    function revertsWithEstimateGasStarved(
        uint256 gasLeft
    ) external payable {
        revert ERC7821LIFI.EstimateGasStarved(gasLeft);
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
        assertEq(mbe.executionModeId(_RAISE_REVERT_ESTIMATE_MODE), 2);
        assertEq(mbe.executionModeId(_RAISE_REVERT_ESTIMATE_MULTICHAIN_MODE), 2);
        assertTrue(mbe.supportsExecutionMode(_RAISE_REVERT_ESTIMATE_MODE));
        assertTrue(mbe.supportsExecutionMode(_RAISE_REVERT_ESTIMATE_MULTICHAIN_MODE));
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

    /// Starvation is classified by gas accounting, not returndata: an empty-data failure
    /// with ample gas remaining is a genuine (bare) logical revert and is skipped.
    function testERC7821LIFI_estimateGas_emptyRevertDataAmpleGasContinues(
        uint256 nonce
    ) external {
        ERC7821.Call[] memory calls = new ERC7821.Call[](2);
        calls[0] = ERC7821.Call({ to: address(this), data: abi.encodeWithSignature("revertsWithNoData()"), value: 0 });
        calls[1] = ERC7821.Call({ to: address(this), data: abi.encodeWithSignature("healthy()"), value: 0 });

        mbe.setValidCalldata(abi.encode(nonce));
        uint256 extraDataU = uint256(bytes32(bytes1(0x02))) + uint256((nonce << (9 * 8)) >> 8);
        vm.expectEmit(true, true, true, true);
        emit CallReverted(bytes32(extraDataU + 0), bytes(""));

        bytes memory executionData = abi.encode(calls, abi.encode(nonce));

        vm.prank(address(mbe));
        mbe.execute(_ESTIMATE_GAS_MODE, executionData);

        assertEq(healthyCalls, 1);
    }

    /// A failure that leaves the frame below the starvation threshold reverts the estimation
    /// with `EstimateGasStarved` even when the failure carries typed revert data — a callee
    /// that wraps an inner OOG as a typed error cannot fake its gas consumption.
    function testRevert_ERC7821LIFI_estimateGas_starvedTypedRevertReverts(
        uint256 nonce,
        bytes calldata payload
    ) external {
        ERC7821.Call[] memory calls = new ERC7821.Call[](2);
        calls[0] = ERC7821.Call({
            to: address(this), data: abi.encodeWithSignature("revertsWithCustomError(bytes)", payload), value: 0
        });
        calls[1] = ERC7821.Call({ to: address(this), data: abi.encodeWithSignature("healthy()"), value: 0 });

        mbe.setValidCalldata(abi.encode(nonce));
        bytes memory executionData = abi.encode(calls, abi.encode(nonce));

        vm.prank(address(mbe));
        vm.expectPartialRevert(ERC7821LIFI.EstimateGasStarved.selector);
        // The whole frame runs below the starvation threshold, so any failure classifies
        // as starvation and forces the estimator up.
        mbe.execute{ gas: 250_000 }(_ESTIMATE_GAS_MODE, executionData);

        assertEq(healthyCalls, 0);
    }

    /// A failed call reverting `EstimateGasStarved` (a child EstimateGas frame's starvation
    /// verdict) is bubbled unchanged by selector, even when THIS frame has ample gas — so
    /// nesting EstimateGas frames does not weaken the check.
    function testRevert_ERC7821LIFI_estimateGas_starvedSelectorBubblesWithAmpleGas(
        uint256 nonce,
        uint256 gasLeft
    ) external {
        ERC7821.Call[] memory calls = new ERC7821.Call[](2);
        calls[0] = ERC7821.Call({
            to: address(this),
            data: abi.encodeWithSignature("revertsWithEstimateGasStarved(uint256)", gasLeft),
            value: 0
        });
        calls[1] = ERC7821.Call({ to: address(this), data: abi.encodeWithSignature("healthy()"), value: 0 });

        mbe.setValidCalldata(abi.encode(nonce));
        bytes memory executionData = abi.encode(calls, abi.encode(nonce));

        vm.prank(address(mbe));
        // The child's exact error (including its gasLeft) is bubbled, not re-wrapped.
        vm.expectRevert(abi.encodeWithSelector(ERC7821LIFI.EstimateGasStarved.selector, gasLeft));
        mbe.execute(_ESTIMATE_GAS_MODE, executionData);

        assertEq(healthyCalls, 0);
    }

    /// A starved NESTED EstimateGas frame re-raises `EstimateGasStarved`, which the parent
    /// bubbles by selector to the top.
    function testRevert_ERC7821LIFI_estimateGas_starvationComposes(
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
        vm.expectPartialRevert(ERC7821LIFI.EstimateGasStarved.selector);
        mbe.execute{ gas: 250_000 }(_ESTIMATE_GAS_MODE, executionData);

        assertEq(healthyCalls, 0);
    }

    /// A RaiseRevert frame nested inside an EstimateGas frame (the shape the SDK's
    /// estimation twin produces for atomic sub-batches): a data-carrying failure in
    /// the inner frame bubbles its exact revert data, which the outer EstimateGas
    /// frame skips + logs — with the inner frame's earlier state changes ROLLED BACK,
    /// matching the on-chain SkipRevert-outer behavior.
    function testERC7821LIFI_estimateGas_nestedRaiseRevert_dataRevertSkipsAndRollsBack(
        uint256 nonce,
        bytes calldata payload
    ) external {
        ERC7821.Call[] memory innerCalls = new ERC7821.Call[](2);
        innerCalls[0] = ERC7821.Call({ to: address(this), data: abi.encodeWithSignature("healthy()"), value: 0 });
        innerCalls[1] = ERC7821.Call({
            to: address(this), data: abi.encodeWithSignature("revertsWithCustomError(bytes)", payload), value: 0
        });
        bytes memory innerExecutionData = abi.encode(innerCalls, abi.encode(nonce));

        ERC7821.Call[] memory calls = new ERC7821.Call[](2);
        calls[0] = ERC7821.Call({
            to: address(mbe),
            data: abi.encodeWithSignature("execute(bytes32,bytes)", _SUPPORTED_MODE, innerExecutionData),
            value: 0
        });
        calls[1] = ERC7821.Call({ to: address(this), data: abi.encodeWithSignature("healthy()"), value: 0 });

        mbe.setValidCalldata(abi.encode(nonce));
        uint256 extraDataU = uint256(bytes32(bytes1(0x02))) + uint256((nonce << (9 * 8)) >> 8);
        vm.expectEmit(true, true, true, true);
        emit CallReverted(bytes32(extraDataU + 0), abi.encodeWithSelector(CustomError.selector, payload));

        bytes memory executionData = abi.encode(calls, abi.encode(nonce));

        vm.prank(address(mbe));
        mbe.execute(_ESTIMATE_GAS_MODE, executionData);

        // The inner frame's healthy() was rolled back with the inner revert;
        // only the outer frame's second call landed.
        assertEq(healthyCalls, 1);
    }

    /// A failure inside a nested RaiseRevert frame that leaves the outer EstimateGas frame
    /// starved forces the estimator up — a starved call inside an atomic sub-batch cannot
    /// hide behind the sub-batch's bubbled revert data.
    function testRevert_ERC7821LIFI_estimateGas_nestedRaiseRevert_starvedBubbles(
        uint256 nonce
    ) external {
        ERC7821.Call[] memory innerCalls = new ERC7821.Call[](1);
        innerCalls[0] =
            ERC7821.Call({ to: address(this), data: abi.encodeWithSignature("revertsWithNoData()"), value: 0 });
        bytes memory innerExecutionData = abi.encode(innerCalls, abi.encode(nonce));

        ERC7821.Call[] memory calls = new ERC7821.Call[](2);
        calls[0] = ERC7821.Call({
            to: address(mbe),
            data: abi.encodeWithSignature("execute(bytes32,bytes)", _SUPPORTED_MODE, innerExecutionData),
            value: 0
        });
        calls[1] = ERC7821.Call({ to: address(this), data: abi.encodeWithSignature("healthy()"), value: 0 });

        mbe.setValidCalldata(abi.encode(nonce));
        bytes memory executionData = abi.encode(calls, abi.encode(nonce));

        vm.prank(address(mbe));
        vm.expectPartialRevert(ERC7821LIFI.EstimateGasStarved.selector);
        mbe.execute{ gas: 250_000 }(_ESTIMATE_GAS_MODE, executionData);

        assertEq(healthyCalls, 0);
    }

    /// A RaiseRevertEstimate frame (the estimation twin of an atomic sub-batch): a
    /// data-carrying logical failure bubbles its exact revert data, which the outer
    /// EstimateGas frame skips + logs — with the inner frame's earlier state changes
    /// ROLLED BACK, exactly like RaiseRevert.
    function testERC7821LIFI_raiseRevertEstimate_dataRevertBubblesExactAndRollsBack(
        uint256 nonce,
        bytes calldata payload
    ) external {
        ERC7821.Call[] memory innerCalls = new ERC7821.Call[](2);
        innerCalls[0] = ERC7821.Call({ to: address(this), data: abi.encodeWithSignature("healthy()"), value: 0 });
        innerCalls[1] = ERC7821.Call({
            to: address(this), data: abi.encodeWithSignature("revertsWithCustomError(bytes)", payload), value: 0
        });
        bytes memory innerExecutionData = abi.encode(innerCalls, abi.encode(nonce));

        ERC7821.Call[] memory calls = new ERC7821.Call[](2);
        calls[0] = ERC7821.Call({
            to: address(mbe),
            data: abi.encodeWithSignature("execute(bytes32,bytes)", _RAISE_REVERT_ESTIMATE_MODE, innerExecutionData),
            value: 0
        });
        calls[1] = ERC7821.Call({ to: address(this), data: abi.encodeWithSignature("healthy()"), value: 0 });

        mbe.setValidCalldata(abi.encode(nonce));
        uint256 extraDataU = uint256(bytes32(bytes1(0x02))) + uint256((nonce << (9 * 8)) >> 8);
        vm.expectEmit(true, true, true, true);
        emit CallReverted(bytes32(extraDataU + 0), abi.encodeWithSelector(CustomError.selector, payload));

        bytes memory executionData = abi.encode(calls, abi.encode(nonce));

        vm.prank(address(mbe));
        mbe.execute(_ESTIMATE_GAS_MODE, executionData);

        // The inner frame's healthy() was rolled back with the inner revert;
        // only the outer frame's second call landed.
        assertEq(healthyCalls, 1);
    }

    /// A starved failure inside a RaiseRevertEstimate frame is classified by the frame
    /// itself and re-raised as `EstimateGasStarved`, which the outer EstimateGas frame
    /// bubbles by selector to the top.
    function testRevert_ERC7821LIFI_raiseRevertEstimate_starvedRaisesTyped(
        uint256 nonce
    ) external {
        ERC7821.Call[] memory innerCalls = new ERC7821.Call[](1);
        innerCalls[0] =
            ERC7821.Call({ to: address(this), data: abi.encodeWithSignature("revertsWithNoData()"), value: 0 });
        bytes memory innerExecutionData = abi.encode(innerCalls, abi.encode(nonce));

        ERC7821.Call[] memory calls = new ERC7821.Call[](2);
        calls[0] = ERC7821.Call({
            to: address(mbe),
            data: abi.encodeWithSignature("execute(bytes32,bytes)", _RAISE_REVERT_ESTIMATE_MODE, innerExecutionData),
            value: 0
        });
        calls[1] = ERC7821.Call({ to: address(this), data: abi.encodeWithSignature("healthy()"), value: 0 });

        mbe.setValidCalldata(abi.encode(nonce));
        bytes memory executionData = abi.encode(calls, abi.encode(nonce));

        vm.prank(address(mbe));
        vm.expectPartialRevert(ERC7821LIFI.EstimateGasStarved.selector);
        mbe.execute{ gas: 250_000 }(_ESTIMATE_GAS_MODE, executionData);

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
