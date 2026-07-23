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

    /// @dev Consumes all forwarded gas via INVALID (0xfe). Observably identical to a true
    /// OOG from the caller's side — failure, empty returndata, all forwarded gas consumed —
    /// though the immediate cause differs. Deterministic and immune to optimizer changes.
    function consumesAllGas() external payable {
        assembly {
            invalid()
        }
    }

    /// @dev Spins until gasleft() <= keep, then reverts with empty returndata, refunding
    /// ~keep gas to the caller frame. Inline assembly keeps the per-iteration cost small and
    /// roughly constant (tens of gas), so the refund lands close to `keep`.
    function revertsLeavingGas(
        uint256 keep
    ) external payable {
        assembly {
            for { } gt(gas(), keep) { } { }
            revert(0x00, 0x00)
        }
    }

    /// @dev Reverts with exactly `raw` — no ABI wrapping — to probe the 0x24 size gate.
    function revertsWithRawBytes(
        bytes calldata raw
    ) external payable {
        assembly {
            calldatacopy(0x00, raw.offset, raw.length)
            revert(0x00, raw.length)
        }
    }

    /// @dev Re-invokes mbe.execute with a bounded gas stipend and bubbles any revert
    /// verbatim (preserving exact returndata, incl. a 0x24 EstimateGasStarved). Relies on
    /// MockERC7821LIFI authorizing on opData only (no msg.sender gate on the opData path).
    function reenterExecuteWithGas(
        uint256 gasLimit,
        bytes32 mode,
        bytes calldata executionData
    ) external payable {
        (bool ok, bytes memory ret) =
            address(mbe).call{ gas: gasLimit }(abi.encodeWithSignature("execute(bytes32,bytes)", mode, executionData));
        if (ok) return;
        assembly {
            revert(add(ret, 0x20), mload(ret))
        }
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

    /// An estimation frame that STARTS below the starvation threshold classifies any failure
    /// as starvation, even one carrying typed revert data. This pins low-gas-start behavior
    /// only; genuine OOG-vs-logical-revert discrimination at ample gas is covered by
    /// realOOGWithAmpleGasStarves / logicalRevertWithSameGasSkips.
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

    /// With a sub-threshold budget, a failure inside a NESTED EstimateGas frame surfaces as
    /// `EstimateGasStarved` at the top. (At this budget both frames are below the threshold,
    /// so this cannot attribute WHERE the classification happened; the selector-bubble
    /// mechanism through an ample-gas parent is pinned by
    /// nestedRealStarvationBubblesBySizeGate.)
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

    /// With a sub-threshold budget, a failure bubbled out of a nested RaiseRevert (atomic)
    /// sub-batch is classified as starvation by the outer EstimateGas frame — the sub-batch's
    /// bubbled revert data does not exempt it from classification.
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

    /// With a sub-threshold budget, a failure inside a nested RaiseRevertEstimate frame
    /// surfaces as `EstimateGasStarved` at the top. (At this budget both frames are below the
    /// threshold, so this cannot attribute WHICH frame classified; own-frame classification
    /// by flag 3 is pinned by nestedRealStarvationClassifiedInInnerFrame.)
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

    /// A genuine all-gas-consuming callee failure, with the estimation frame starting far
    /// above the starvation threshold (~4M), classifies as starvation: the classification is
    /// caused by the callee's gas consumption, not by a low-gas start. Also pins the
    /// starvation payload's shape — a 0x24-byte EstimateGasStarved(uint256) with gasLeft below
    /// the threshold — so a malformed construction (wrong selector, wrong length, or an
    /// above-threshold gasLeft) fails this test.
    function testRevert_ERC7821LIFI_estimateGas_realOOGWithAmpleGasStarves() external {
        uint256 nonce = 1;
        ERC7821.Call[] memory calls = new ERC7821.Call[](2);
        calls[0] = ERC7821.Call({ to: address(this), data: abi.encodeWithSignature("consumesAllGas()"), value: 0 });
        calls[1] = ERC7821.Call({ to: address(this), data: abi.encodeWithSignature("healthy()"), value: 0 });

        mbe.setValidCalldata(abi.encode(nonce));
        bytes memory executionData = abi.encode(calls, abi.encode(nonce));

        vm.prank(address(mbe));
        (bool success, bytes memory ret) = address(mbe).call{ gas: 4_000_000 }(
            abi.encodeWithSignature("execute(bytes32,bytes)", _ESTIMATE_GAS_MODE, executionData)
        );

        assertFalse(success);
        assertEq(ret.length, 0x24);
        bytes4 sel;
        uint256 gasLeft;
        assembly ("memory-safe") {
            sel := mload(add(ret, 0x20))
            gasLeft := mload(add(ret, 0x24))
        }
        assertEq(bytes32(sel), bytes32(ERC7821LIFI.EstimateGasStarved.selector));
        assertLt(gasLeft, 262_144);
        assertEq(healthyCalls, 0);
    }

    /// At the exact same gas budget where a genuine all-gas-consuming failure classifies as
    /// starvation (see realOOGWithAmpleGasStarves), a cheap logical revert refunds its unspent
    /// gas and is skipped — the classifier discriminates by gas accounting, not by whether the
    /// call failed.
    function testERC7821LIFI_estimateGas_logicalRevertWithSameGasSkips() external {
        uint256 nonce = 1;
        ERC7821.Call[] memory calls = new ERC7821.Call[](2);
        calls[0] =
            ERC7821.Call({ to: address(this), data: abi.encodeWithSignature("revertsWithSmallError()"), value: 0 });
        calls[1] = ERC7821.Call({ to: address(this), data: abi.encodeWithSignature("healthy()"), value: 0 });

        mbe.setValidCalldata(abi.encode(nonce));
        uint256 extraDataU = uint256(bytes32(bytes1(0x02))) + uint256((nonce << (9 * 8)) >> 8);
        vm.expectEmit(true, true, true, true);
        emit CallReverted(bytes32(extraDataU + 0), abi.encodeWithSelector(SmallError.selector));

        bytes memory executionData = abi.encode(calls, abi.encode(nonce));

        vm.prank(address(mbe));
        mbe.execute{ gas: 4_000_000 }(_ESTIMATE_GAS_MODE, executionData);

        assertEq(healthyCalls, 1);
    }

    /// Top-level RaiseRevertEstimate (flag 3) shares the starvation classifier: a genuine
    /// all-gas-consuming failure re-raises EstimateGasStarved instead of bubbling the (empty)
    /// revert data through the flag-3 logical-revert branch.
    function testRevert_ERC7821LIFI_raiseRevertEstimate_topLevel_realOOGStarves() external {
        uint256 nonce = 1;
        ERC7821.Call[] memory calls = new ERC7821.Call[](1);
        calls[0] = ERC7821.Call({ to: address(this), data: abi.encodeWithSignature("consumesAllGas()"), value: 0 });

        mbe.setValidCalldata(abi.encode(nonce));
        bytes memory executionData = abi.encode(calls, abi.encode(nonce));

        vm.prank(address(mbe));
        vm.expectPartialRevert(ERC7821LIFI.EstimateGasStarved.selector);
        mbe.execute{ gas: 4_000_000 }(_RAISE_REVERT_ESTIMATE_MODE, executionData);
    }

    /// Synthetic above-cap frame (impossible inside an EIP-7825-capped transaction; runs here
    /// because the harness does not enforce the tx gas cap): with more than 64x the threshold,
    /// even a total all-gas-consuming failure leaves the frame's 1/64 reserve above the
    /// threshold, so it is treated as a logical revert and skipped. Pins the threshold's
    /// calibration to the EIP-7825 cap — doubling the constant fails this test.
    function testERC7821LIFI_estimateGas_aboveCapFrameRealOOGSkips() external {
        uint256 nonce = 1;
        ERC7821.Call[] memory calls = new ERC7821.Call[](2);
        calls[0] = ERC7821.Call({ to: address(this), data: abi.encodeWithSignature("consumesAllGas()"), value: 0 });
        calls[1] = ERC7821.Call({ to: address(this), data: abi.encodeWithSignature("healthy()"), value: 0 });

        mbe.setValidCalldata(abi.encode(nonce));
        bytes memory executionData = abi.encode(calls, abi.encode(nonce));

        vm.prank(address(mbe));
        mbe.execute{ gas: 21_000_000 }(_ESTIMATE_GAS_MODE, executionData);

        assertEq(healthyCalls, 1);
    }

    /// The at-cap worst case for detection: with exactly the EIP-7825 transaction gas cap of
    /// 16_777_216 — the largest budget the executor frame can ever hold in a capped
    /// transaction — a true all-gas-consuming failure retains at most cap/64 = 262_144, and
    /// pre-call overhead plus the CallReverted event cost push the measurement strictly below
    /// the threshold, so starvation is still detected. Together with
    /// aboveCapFrameRealOOGSkips this pins the cap as the exact tipping point of the
    /// classifier. Every real cost moves the measurement further below the threshold, so the
    /// thin margin here is deterministic in the passing direction.
    function testRevert_ERC7821LIFI_estimateGas_atCapFrameRealOOGStarves() external {
        uint256 nonce = 1;
        ERC7821.Call[] memory calls = new ERC7821.Call[](2);
        calls[0] = ERC7821.Call({ to: address(this), data: abi.encodeWithSignature("consumesAllGas()"), value: 0 });
        calls[1] = ERC7821.Call({ to: address(this), data: abi.encodeWithSignature("healthy()"), value: 0 });

        mbe.setValidCalldata(abi.encode(nonce));
        bytes memory executionData = abi.encode(calls, abi.encode(nonce));

        vm.prank(address(mbe));
        vm.expectPartialRevert(ERC7821LIFI.EstimateGasStarved.selector);
        mbe.execute{ gas: 16_777_216 }(_ESTIMATE_GAS_MODE, executionData);

        assertEq(healthyCalls, 0);
    }

    /// Top-level RaiseRevertEstimate: a logical revert bubbles its exact revert data and rolls
    /// the whole batch back — earlier calls included — matching RaiseRevert.
    function testRevert_ERC7821LIFI_raiseRevertEstimate_topLevel_logicalRevertBubblesExact(
        uint256 nonce,
        bytes calldata payload
    ) external {
        ERC7821.Call[] memory calls = new ERC7821.Call[](2);
        calls[0] = ERC7821.Call({ to: address(this), data: abi.encodeWithSignature("healthy()"), value: 0 });
        calls[1] = ERC7821.Call({
            to: address(this), data: abi.encodeWithSignature("revertsWithCustomError(bytes)", payload), value: 0
        });

        mbe.setValidCalldata(abi.encode(nonce));
        bytes memory executionData = abi.encode(calls, abi.encode(nonce));

        vm.prank(address(mbe));
        vm.expectRevert(abi.encodeWithSelector(CustomError.selector, payload));
        mbe.execute(_RAISE_REVERT_ESTIMATE_MODE, executionData);

        assertEq(healthyCalls, 0);
    }

    /// Top-level RaiseRevertEstimate with ample gas: an empty-data failure is a bare logical
    /// revert — bubbled as empty revert data, not misclassified as starvation.
    function testRevert_ERC7821LIFI_raiseRevertEstimate_topLevel_emptyRevertBubblesEmpty(
        uint256 nonce
    ) external {
        ERC7821.Call[] memory calls = new ERC7821.Call[](1);
        calls[0] = ERC7821.Call({ to: address(this), data: abi.encodeWithSignature("revertsWithNoData()"), value: 0 });

        mbe.setValidCalldata(abi.encode(nonce));
        bytes memory executionData = abi.encode(calls, abi.encode(nonce));

        vm.prank(address(mbe));
        vm.expectRevert(bytes(""));
        mbe.execute(_RAISE_REVERT_ESTIMATE_MODE, executionData);
    }

    /// Top-level RaiseRevertEstimate success path: all calls execute.
    function testERC7821LIFI_raiseRevertEstimate_topLevel_successExecutesAll(
        uint256 nonce
    ) external {
        ERC7821.Call[] memory calls = new ERC7821.Call[](2);
        calls[0] = ERC7821.Call({ to: address(this), data: abi.encodeWithSignature("healthy()"), value: 0 });
        calls[1] = ERC7821.Call({ to: address(this), data: abi.encodeWithSignature("healthy()"), value: 0 });

        mbe.setValidCalldata(abi.encode(nonce));
        bytes memory executionData = abi.encode(calls, abi.encode(nonce));

        vm.prank(address(mbe));
        mbe.execute(_RAISE_REVERT_ESTIMATE_MODE, executionData);

        assertEq(healthyCalls, 2);
    }

    /// Size-gate near-miss: the EstimateGasStarved selector with only 0x23 bytes of returndata
    /// is not the child-verdict shape — with ample gas it classifies as a logical revert and
    /// is skipped.
    function testERC7821LIFI_estimateGas_sizeGate_shortStarvedPrefixSkipped(
        uint256 nonce
    ) external {
        bytes memory raw = abi.encodePacked(ERC7821LIFI.EstimateGasStarved.selector, new bytes(0x1f)); // 0x23 bytes
        _assertRawRevertSkippedUnderEstimateGas(nonce, raw);
    }

    /// Size-gate near-miss: the EstimateGasStarved selector with 0x25 bytes of returndata is
    /// not the child-verdict shape — widening the gate to `>= 0x24` fails this test.
    function testERC7821LIFI_estimateGas_sizeGate_longStarvedPrefixSkipped(
        uint256 nonce
    ) external {
        bytes memory raw = abi.encodePacked(ERC7821LIFI.EstimateGasStarved.selector, new bytes(0x21)); // 0x25 bytes
        _assertRawRevertSkippedUnderEstimateGas(nonce, raw);
    }

    /// Size-gate near-miss: exactly 0x24 bytes with an off-by-one selector is not the
    /// child-verdict shape — dropping the selector comparison fails this test.
    function testERC7821LIFI_estimateGas_sizeGate_wrongSelectorExactSizeSkipped(
        uint256 nonce
    ) external {
        bytes memory raw = abi.encodePacked(bytes4(0xaf3228d8), bytes32(uint256(1))); // 0x24 bytes, wrong selector
        _assertRawRevertSkippedUnderEstimateGas(nonce, raw);
    }

    /// A 0x25-byte payload carrying the EstimateGasStarved selector does not take the
    /// child-verdict bubble: under top-level RaiseRevertEstimate with ample gas it exits via
    /// the flag-3 logical-revert branch with its exact length preserved — a gate truncating
    /// to 0x24 bytes fails this test.
    function testRevert_ERC7821LIFI_raiseRevertEstimate_sizeGate_longStarvedPrefixBubblesRaw(
        uint256 nonce
    ) external {
        bytes memory raw = abi.encodePacked(ERC7821LIFI.EstimateGasStarved.selector, new bytes(0x21)); // 0x25 bytes
        ERC7821.Call[] memory calls = new ERC7821.Call[](1);
        calls[0] = ERC7821.Call({
            to: address(this), data: abi.encodeWithSignature("revertsWithRawBytes(bytes)", raw), value: 0
        });

        mbe.setValidCalldata(abi.encode(nonce));
        bytes memory executionData = abi.encode(calls, abi.encode(nonce));

        vm.prank(address(mbe));
        vm.expectRevert(raw);
        mbe.execute(_RAISE_REVERT_ESTIMATE_MODE, executionData);
    }

    /// Ample outer gas, REAL inner starvation: the outer frame at ~30M (synthetic above-cap;
    /// ample within-cap outer budgets behave the same since the wrapper refunds its unspent
    /// gas — only budgets near the inner stipend would starve the outer frame itself) never
    /// drops near the threshold itself, so its only revert path is the 0x24 size gate. The
    /// inner EstimateGas frame — entered through a wrapper with a bounded 1M stipend —
    /// genuinely starves on an all-gas-consuming callee and re-raises a real
    /// EstimateGasStarved, which bubbles verbatim through the wrapper and the outer frame.
    /// Deleting the size gate makes the outer frame skip instead, failing this test.
    function testRevert_ERC7821LIFI_estimateGas_nestedRealStarvationBubblesBySizeGate() external {
        uint256 nonce = 1;
        ERC7821.Call[] memory innerCalls = new ERC7821.Call[](1);
        innerCalls[0] = ERC7821.Call({ to: address(this), data: abi.encodeWithSignature("consumesAllGas()"), value: 0 });
        bytes memory innerExecutionData = abi.encode(innerCalls, abi.encode(nonce));

        ERC7821.Call[] memory calls = new ERC7821.Call[](2);
        calls[0] = ERC7821.Call({
            to: address(this),
            data: abi.encodeWithSignature(
                "reenterExecuteWithGas(uint256,bytes32,bytes)", 1_000_000, _ESTIMATE_GAS_MODE, innerExecutionData
            ),
            value: 0
        });
        calls[1] = ERC7821.Call({ to: address(this), data: abi.encodeWithSignature("healthy()"), value: 0 });

        mbe.setValidCalldata(abi.encode(nonce));
        bytes memory executionData = abi.encode(calls, abi.encode(nonce));

        vm.prank(address(mbe));
        vm.expectPartialRevert(ERC7821LIFI.EstimateGasStarved.selector);
        mbe.execute{ gas: 30_000_000 }(_ESTIMATE_GAS_MODE, executionData);

        assertEq(healthyCalls, 0);
    }

    /// Same shape with an inner RaiseRevertEstimate frame: the flag-3 frame classifies the
    /// starvation in ITS OWN frame (a single 1/64 reserve) and re-raises EstimateGasStarved
    /// instead of bubbling the raw empty revert data — the outer frame then bubbles it by
    /// selector through the size gate.
    function testRevert_ERC7821LIFI_raiseRevertEstimate_nestedRealStarvationClassifiedInInnerFrame() external {
        uint256 nonce = 1;
        ERC7821.Call[] memory innerCalls = new ERC7821.Call[](1);
        innerCalls[0] = ERC7821.Call({ to: address(this), data: abi.encodeWithSignature("consumesAllGas()"), value: 0 });
        bytes memory innerExecutionData = abi.encode(innerCalls, abi.encode(nonce));

        ERC7821.Call[] memory calls = new ERC7821.Call[](2);
        calls[0] = ERC7821.Call({
            to: address(this),
            data: abi.encodeWithSignature(
                "reenterExecuteWithGas(uint256,bytes32,bytes)",
                1_000_000,
                _RAISE_REVERT_ESTIMATE_MODE,
                innerExecutionData
            ),
            value: 0
        });
        calls[1] = ERC7821.Call({ to: address(this), data: abi.encodeWithSignature("healthy()"), value: 0 });

        mbe.setValidCalldata(abi.encode(nonce));
        bytes memory executionData = abi.encode(calls, abi.encode(nonce));

        vm.prank(address(mbe));
        vm.expectPartialRevert(ERC7821LIFI.EstimateGasStarved.selector);
        mbe.execute{ gas: 30_000_000 }(_ESTIMATE_GAS_MODE, executionData);

        assertEq(healthyCalls, 0);
    }

    /// Two-sided threshold probe, below side. The callee reverts leaving ~keep gas unspent, so
    /// the frame measures ~ keep + 1/64 reserve (~15k) - CallReverted event cost (~2k), i.e.
    /// ~ keep + 13k. keep = 262_144 - 13_000 - 40_000 lands the measurement ~40k below the
    /// threshold -> starvation, from a frame that started at ~1M (far above it). Brackets the
    /// threshold's magnitude; does not pin exact `<` vs `<=`.
    function testRevert_ERC7821LIFI_estimateGas_belowThresholdClassifiesStarvation() external {
        uint256 nonce = 1;
        uint256 keep = 262_144 - 13_000 - 40_000;
        ERC7821.Call[] memory calls = new ERC7821.Call[](2);
        calls[0] = ERC7821.Call({
            to: address(this), data: abi.encodeWithSignature("revertsLeavingGas(uint256)", keep), value: 0
        });
        calls[1] = ERC7821.Call({ to: address(this), data: abi.encodeWithSignature("healthy()"), value: 0 });

        mbe.setValidCalldata(abi.encode(nonce));
        bytes memory executionData = abi.encode(calls, abi.encode(nonce));

        vm.prank(address(mbe));
        vm.expectPartialRevert(ERC7821LIFI.EstimateGasStarved.selector);
        mbe.execute{ gas: 1_000_000 }(_ESTIMATE_GAS_MODE, executionData);

        assertEq(healthyCalls, 0);
    }

    /// Two-sided threshold probe, above side: keep = 262_144 - 13_000 + 40_000 lands the
    /// measurement ~40k above the threshold -> the same failure shape is a logical revert and
    /// is skipped. Together with the below-side probe this brackets the threshold to +-40k.
    function testERC7821LIFI_estimateGas_aboveThresholdSkipsLogicalRevert() external {
        uint256 nonce = 1;
        uint256 keep = 262_144 - 13_000 + 40_000;
        ERC7821.Call[] memory calls = new ERC7821.Call[](2);
        calls[0] = ERC7821.Call({
            to: address(this), data: abi.encodeWithSignature("revertsLeavingGas(uint256)", keep), value: 0
        });
        calls[1] = ERC7821.Call({ to: address(this), data: abi.encodeWithSignature("healthy()"), value: 0 });

        mbe.setValidCalldata(abi.encode(nonce));
        bytes memory executionData = abi.encode(calls, abi.encode(nonce));

        vm.prank(address(mbe));
        mbe.execute{ gas: 1_000_000 }(_ESTIMATE_GAS_MODE, executionData);

        assertEq(healthyCalls, 1);
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

    /// @dev Executes an EstimateGas batch with ample gas whose first call reverts with the
    /// exact bytes `raw`, and asserts the failure was skipped (i.e. the 0x24 child-verdict
    /// gate was NOT taken and the trailing healthy() call ran).
    function _assertRawRevertSkippedUnderEstimateGas(
        uint256 nonce,
        bytes memory raw
    ) internal {
        ERC7821.Call[] memory calls = new ERC7821.Call[](2);
        calls[0] = ERC7821.Call({
            to: address(this), data: abi.encodeWithSignature("revertsWithRawBytes(bytes)", raw), value: 0
        });
        calls[1] = ERC7821.Call({ to: address(this), data: abi.encodeWithSignature("healthy()"), value: 0 });

        mbe.setValidCalldata(abi.encode(nonce));
        bytes memory executionData = abi.encode(calls, abi.encode(nonce));

        vm.prank(address(mbe));
        mbe.execute(_ESTIMATE_GAS_MODE, executionData);

        assertEq(healthyCalls, 1);
    }

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
