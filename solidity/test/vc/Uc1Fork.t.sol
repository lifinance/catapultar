// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { SafeTransferLib } from "solady/src/utils/SafeTransferLib.sol";

import { CATValidatorV2 } from "../../src/CATValidatorV2.sol";
import { AllowanceSpend, Outcome } from "../../src/libs/LibExecutionConstraint.sol";
import { LibValidationVM } from "../../src/libs/LibValidationVM.sol";
import { VcTestBase } from "./VcTestBase.sol";

/// @dev Test fill driven through `entry()`'s execTarget/execPayload path: moves a
/// pre-funded token balance to the delivery address, standing in for a real
/// solver fill that raises the delivery's balance between the pre-balance
/// snapshot and the validation staticcall.
contract Uc1MockFill {
    /// @dev Payable: `entry()`'s CallProxy forwards the validator's balance as
    /// call value, so a non-payable fill would revert on receipt.
    function deliver(
        address token,
        address to,
        uint256 amount
    ) external payable {
        SafeTransferLib.safeTransfer(token, to, amount);
    }
}

/**
 * @title GD-4 M6 — the pinned uc1 vector on the canonical VM (fork)
 * @notice Proves the re-pinned (GD-7) uc1 hash-parity vector executes on the
 * real, unmodified VirtualMachine on an Ethereum mainnet fork, and settles
 * through `CATValidatorV2.entry()` when the delivery is funded. This replaces
 * the M1 defect spike (`ForkSpike.t.sol`, deleted): before the re-pin the
 * verbatim calldata reverted `InvalidRPNStack()` from one-based register
 * references landing one slot short; post-re-pin the very same program runs its
 * whole read → RPN → assert pipeline correctly and fails only on the genuine
 * invariant (the delivery `0x1111…1111` holds far less than 1e18 WETH on
 * mainnet), reaching `AssertGteFailed`.
 *
 * The uc1 program (from `hash-parity/vectors.json` `programVectors[0]`,
 * `uc1-user-a`) asserts, in order:
 *   1. WETH.balanceOf(delivery) >= preBalance + outcomeMin (1e18), and
 *   2. USDC.balanceOf(delivery) >= invariantThreshold (500e6).
 * Its committed params are `[delivery, outcomeMin, invariantThreshold,
 * rpnProgram, rpnOpsCount]` (5 words); `entry()`/`buildRegisters` inject the
 * escrow `account` at register 5 and the WETH pre-balance at register 6.
 *
 * Every test is fork-gated (`vm.skip(true)` when `VC_MAINNET_RPC_URL` is unset).
 */
contract Uc1ForkTest is VcTestBase {
    /// @dev InvariantChecker: error AssertGteFailed(uint256,uint256) — the same
    /// selector VmPrograms.t.sol pins as the erc20-floor fail-row inner selector.
    bytes4 internal constant ASSERT_GTE_FAILED = bytes4(keccak256("AssertGteFailed(uint256,uint256)"));

    uint256 internal constant GAS_CAP = 5_000_000;

    string internal json;

    function setUp() external {
        if (!hasForkRpc()) return;
        forkMainnet();
        json = readFixture(HASH_PARITY_VECTORS);
    }

    /* ─────────────────────────── VM-level execution
    ─────────────────────── */

    /// @notice The verbatim pinned uc1 runVM calldata executes its whole
    /// read → RPN → assert pipeline on the canonical VM and fails only on the
    /// real WETH floor invariant (delivery holds ~0 WETH, needs >= 1e18).
    function test_uc1_verbatimCalldataExecutesToAssertGteFailed() external {
        if (!hasForkRpc()) return vm.skip(true);

        bytes memory pinnedCalldata = vm.parseJsonBytes(json, ".programVectors[0].calldata");

        (bool ok, bytes memory ret) = VM_ADDR.staticcall(pinnedCalldata);

        assertFalse(ok, "verbatim uc1 calldata unexpectedly executed");
        assertEq(bytes4(ret), ASSERT_GTE_FAILED, "expected AssertGteFailed from the WETH floor invariant");
    }

    /// @notice The same program run against a register file rebuilt through the
    /// PRODUCTION path — `LibValidationVM.buildRegisters(params, account,
    /// preBalances)` with the fixture's five param words, an escrow-shaped
    /// account, and a zero pre-balance — reaches the identical invariant. This
    /// proves `entry()`'s own `params ++ [account] ++ preBalances` construction
    /// (not the fixture's pre-baked register file) executes the pinned body, the
    /// exact claim the C1 register-convention defect blocked.
    function test_uc1_conventionRebuiltExecutesToAssertGteFailed() external {
        if (!hasForkRpc()) return vm.skip(true);

        bytes memory body = vm.parseJsonBytes(json, ".programVectors[0].canonicalBody");
        bytes[] memory params = _uc1Params();
        uint256[] memory preBalances = new uint256[](1); // [0]: nothing delivered pre-snapshot

        bytes[] memory registers = this.exposedBuildRegisters(params, makeAddr("vc/uc1/escrow"), preBalances);
        bytes memory runVMCalldata = this.exposedEncodeRunVM(body, registers);

        (bool ok, bytes memory ret) = VM_ADDR.staticcall(runVMCalldata);

        assertFalse(ok, "convention-rebuilt uc1 program unexpectedly executed");
        assertEq(bytes4(ret), ASSERT_GTE_FAILED, "expected AssertGteFailed from the WETH floor invariant");
    }

    /* ─────────────────────────── settlement through entry()
    ─────────────── */

    /// @notice The C3 "VM accepts valid" flip for uc1: the pinned program settles
    /// through `entry()` when the delivery is funded so both asserts pass.
    function test_uc1_settlesThroughEntryWhenDeliveryFunded() external {
        if (!hasForkRpc()) return vm.skip(true);

        (address signer, uint256 signerKey) = makeAddrAndKey("vc/uc1/account");
        address executor = makeAddr("vc/uc1/executor");
        CATValidatorV2 validator = new CATValidatorV2(VM_ADDR, GAS_CAP);

        bytes memory body = vm.parseJsonBytes(json, ".programVectors[0].canonicalBody");
        bytes32 programHash = vm.parseJsonBytes32(json, ".programVectors[0].validationProgramHash");
        bytes32 paramsHash = vm.parseJsonBytes32(json, ".programVectors[0].paramsHash");
        bytes[] memory params = _uc1Params();
        address delivery = vm.parseJsonAddress(json, ".programVectors[0].params[0].value");

        // One committed outcome: the WETH delivery whose pre-balance the program
        // reads. `amount = 0` makes the balance-delta floor trivially satisfied,
        // so the committed program — not the floor — is the binding constraint.
        Outcome[] memory outcomes = new Outcome[](1);
        outcomes[0] = Outcome({ token: WETH, amount: 0, destination: delivery });

        // Funding math. The program asserts
        //   WETH.balanceOf(delivery) >= preBalance + outcomeMin (1e18)
        // where preBalance is entry()'s snapshot of WETH.balanceOf(delivery)
        // taken BEFORE the fill (register 6). Start the delivery at 0 WETH so the
        // snapshot is 0, then have the fill deliver exactly 1e18 — current
        // (1e18) >= 0 + 1e18 clears it. The USDC invariant is absolute
        // (>= 500e6, no snapshot), so fund the delivery with it directly.
        deal(WETH, delivery, 0);
        deal(USDC, delivery, 500e6);

        Uc1MockFill fill = new Uc1MockFill();
        deal(WETH, address(fill), 1 ether);
        bytes memory execPayload = abi.encodeCall(Uc1MockFill.deliver, (WETH, delivery, 1 ether));

        uint256 nonce = 1;
        bytes memory sig = _sign(validator, executor, signerKey, nonce, outcomes, programHash, paramsHash);

        bytes memory callData = abi.encodeCall(
            CATValidatorV2.entry,
            (
                address(fill),
                execPayload,
                signer,
                nonce,
                new AllowanceSpend[](0),
                outcomes,
                programHash,
                paramsHash,
                body,
                params,
                sig
            )
        );
        vm.prank(executor);
        (bool ok, bytes memory ret) = address(validator).call(callData);

        assertTrue(ok, string.concat("uc1 program did not settle through entry(): ", vm.toString(ret)));
        assertTrue(validator.spentNonces(signer, nonce), "nonce not spent after settlement");
    }

    /* ─────────────────────────── helpers
    ────────────────────────────────── */

    /// @dev The uc1-user-a committed param words, verbatim from the fixture.
    function _uc1Params() internal view returns (bytes[] memory params) {
        uint256 count = jsonArrayLength(json, ".programVectors[0].params");
        params = new bytes[](count);
        for (uint256 i; i < count; ++i) {
            params[i] = abi.encodePacked(
                vm.parseJsonBytes32(json, string.concat(".programVectors[0].params[", vm.toString(i), "].word"))
            );
        }
    }

    function _sign(
        CATValidatorV2 target,
        address executor,
        uint256 signerKey,
        uint256 nonce,
        Outcome[] memory outcomes,
        bytes32 programHash,
        bytes32 paramsHash
    ) internal view returns (bytes memory) {
        bytes32 structHash =
            this.exposedTypehash(new AllowanceSpend[](0), outcomes, executor, nonce, programHash, paramsHash);
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", target.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, digest);
        return abi.encodePacked(r, s, v);
    }

    /* ── calldata trampolines for the library's calldata-typed arguments ── */

    function exposedBuildRegisters(
        bytes[] calldata params,
        address account,
        uint256[] memory preBalances
    ) external pure returns (bytes[] memory) {
        return LibValidationVM.buildRegisters(params, account, preBalances);
    }

    function exposedEncodeRunVM(
        bytes calldata body,
        bytes[] memory registers
    ) external pure returns (bytes memory) {
        return LibValidationVM.encodeRunVM(body, registers);
    }
}
