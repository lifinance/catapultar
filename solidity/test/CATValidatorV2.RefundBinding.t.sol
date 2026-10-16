// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { SafeTransferLib } from "solady/src/utils/SafeTransferLib.sol";

import "./CATValidatorV2.t.sol";

/// @dev stETH-style token: a `transferFrom` moves the full `amount` out of the
/// sender but credits the recipient `lossPerTransfer` wei less. The validator
/// must sweep such tokens to a bound refund wallet without reverting.
contract LossyToken is MockERC20 {
    uint256 public immutable lossPerTransfer;

    constructor(
        uint256 loss
    ) MockERC20("Lossy", "LOSS", 18) {
        lossPerTransfer = loss;
    }

    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) public override returns (bool) {
        _spendAllowance(from, msg.sender, amount);
        uint256 loss = amount > lossPerTransfer ? lossPerTransfer : 0;
        _transfer(from, to, amount - loss);
        if (loss != 0) _burn(from, loss);
        return true;
    }
}

/// @dev Records every `transferFrom` destination, so tests assert where pulled
/// funds actually went instead of inferring it from balances.
contract RecordingToken is MockERC20 {
    address[] internal _destinations;

    constructor() MockERC20("Recording", "REC", 18) { }

    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) public override returns (bool) {
        _destinations.push(to);
        return super.transferFrom(from, to, amount);
    }

    function recordedCount() external view returns (uint256) {
        return _destinations.length;
    }

    function recordedDestination(
        uint256 i
    ) external view returns (address) {
        return _destinations[i];
    }
}

/// @dev ERC-777-style hook invoked on the recipient of a `transferFrom`.
interface IRecipientHook {
    function tokensReceived(
        address from,
        uint256 amount
    ) external;
}

/// @dev ERC-777-style token: after moving funds it calls `tokensReceived` on a
/// contract recipient, giving the recipient code that runs mid-settlement.
contract CallbackToken is MockERC20 {
    constructor() MockERC20("Callback", "CB", 18) { }

    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) public override returns (bool) {
        bool ok = super.transferFrom(from, to, amount);
        if (to.code.length != 0) IRecipientHook(to).tokensReceived(from, amount);
        return ok;
    }
}

/// @dev A contract refund wallet whose recipient hook tries a nested `entry`.
/// The nested call is signed for the wallet as executor over a fresh nonce, so
/// only the reentrancy guard can stop it.
contract HookedRefundWallet {
    address public validator;
    bytes public innerCalldata;
    bool public innerSucceeded;
    bytes4 public innerRevertSelector;

    function arm(
        address validator_,
        bytes calldata innerCalldata_
    ) external {
        validator = validator_;
        innerCalldata = innerCalldata_;
    }

    function tokensReceived(
        address,
        uint256
    ) external {
        (bool ok, bytes memory ret) = validator.call(innerCalldata);
        innerSucceeded = ok;
        if (!ok && ret.length >= 4) {
            bytes4 selector;
            assembly ("memory-safe") {
                selector := mload(add(ret, 32))
            }
            innerRevertSelector = selector;
        }
    }
}

/// @dev Security tests for the D10 binding: the V2 constraint commits
/// `executionTarget` and `payloadHash`, so a refund constraint can only move
/// escrow funds to the committed refund wallet. Inherits the helpers and mocks
/// of `CATValidatorV2TestBase` (`sign` with and without a binding, `unbound`,
/// `oneAllowance`, `fundEscrow`, `OutcomeFill`).
contract CATValidatorV2RefundBindingTest is CATValidatorV2TestBase {
    bytes32 constant EMPTY_PAYLOAD_HASH = keccak256("");

    /// @dev The 10-argument V2 `entry` signature, spelled out because
    /// `abi.encodeCall` cannot resolve the overloaded `entry` inside a nested
    /// call expression.
    string constant ENTRY_V2_SIGNATURE =
        "entry(address,bytes,address,uint256,(address,uint256,uint256)[],(address,uint256,address)[],(address,bytes32),(uint8,bytes32)[],bytes32[],bytes)";

    /// @dev The committed refund binding: the refund wallet and an empty payload.
    function refundBinding(
        address refund
    ) internal pure returns (ExecutionBinding memory) {
        return ExecutionBinding({ executionTarget: refund, payloadHash: EMPTY_PAYLOAD_HASH });
    }

    function refundEntry(
        CATValidatorV2 target,
        uint256 nonce,
        address refund,
        AllowanceSpend[] memory allowances,
        Outcome[] memory outcomes
    ) internal {
        ExecutionBinding memory binding = refundBinding(refund);
        bytes memory sig = sign(target, nonce, allowances, outcomes, binding, bytes32(0), bytes32(0));
        vm.prank(executor);
        target.entry(refund, hex"", signer, nonce, allowances, outcomes, binding, noProgram(), noParams(), sig);
    }

    /// @dev The independent EIP-712 encoding of the V2 digest with the executor
    /// as a parameter, over a zero program commitment. A contract wallet that
    /// calls `entry` from inside a hook is its own executor (msg.sender), so
    /// the default `sign` helper cannot produce its signature.
    function signAs(
        CATValidatorV2 target,
        address executor_,
        uint256 nonce,
        AllowanceSpend[] memory allowances,
        Outcome[] memory outcomes,
        ExecutionBinding memory binding
    ) internal view returns (bytes memory signature) {
        bytes32[] memory allowanceHashes = new bytes32[](allowances.length);
        for (uint256 i; i < allowances.length; ++i) {
            allowanceHashes[i] = keccak256(
                abi.encode(
                    keccak256(bytes("Allowance(address token,uint256 amount)")),
                    allowances[i].token,
                    allowances[i].allocated
                )
            );
        }
        bytes32[] memory outcomeHashes = new bytes32[](outcomes.length);
        for (uint256 i; i < outcomes.length; ++i) {
            outcomeHashes[i] = keccak256(
                abi.encode(
                    keccak256(bytes("Outcome(address token,uint256 amount,address destination)")),
                    outcomes[i].token,
                    outcomes[i].amount,
                    outcomes[i].destination
                )
            );
        }
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256(
                    bytes(
                        "ExecutionConstraint(Allowance[] allowances,Outcome[] outcomes,address executor,uint256 nonce,address executionTarget,bytes32 payloadHash,bytes32 validationProgramHash,bytes32 paramsHash)Allowance(address token,uint256 amount)Outcome(address token,uint256 amount,address destination)"
                    )
                ),
                keccak256(abi.encodePacked(allowanceHashes)),
                keccak256(abi.encodePacked(outcomeHashes)),
                executor_,
                nonce,
                binding.executionTarget,
                binding.payloadHash,
                bytes32(0),
                bytes32(0)
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", target.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, digest);
        signature = abi.encodePacked(r, s, v);
    }

    /* ─────────────────────────── (a) the brief's PoC, closed
    ─────────────────────────── */

    /// @dev The brief's drain: a sweep-shaped refund called with
    /// `execTarget = attacker` now reverts before any allowance moves.
    function test_refund_sweepToAttackerRevertsTargetNotCommitted() external {
        fundEscrow(validator, 100 ether);
        address refund = makeAddr("refund");
        address attacker = makeAddr("attacker");
        ExecutionBinding memory binding = refundBinding(refund);
        AllowanceSpend[] memory allowances = oneAllowance(address(inToken), 1 << 255);
        Outcome[] memory outcomes = oneOutcome(address(inToken), 0, refund);
        bytes memory sig = sign(validator, 1, allowances, outcomes, binding, bytes32(0), bytes32(0));

        vm.prank(executor);
        vm.expectRevert(CATValidatorV2.TargetNotCommitted.selector);
        validator.entry(attacker, hex"", signer, 1, allowances, outcomes, binding, noProgram(), noParams(), sig);

        assertEq(inToken.balanceOf(signer), 100 ether, "escrow balance unchanged");
        assertEq(inToken.balanceOf(attacker), 0);
        assertFalse(validator.spentNonces(signer, 1), "nonce not consumed by a rejected call");
    }

    /// @dev The no-outcome refund shape: a committed empty payload rejects any
    /// non-empty payload, so no call can be made from the settlement.
    function test_refund_nonEmptyPayloadRevertsPayloadNotCommitted() external {
        fundEscrow(validator, 100 ether);
        address refund = makeAddr("refund");
        ExecutionBinding memory binding = refundBinding(refund);
        AllowanceSpend[] memory allowances = oneAllowance(address(inToken), 1 << 255);
        Outcome[] memory outcomes = new Outcome[](0);
        bytes memory sig = sign(validator, 1, allowances, outcomes, binding, bytes32(0), bytes32(0));

        vm.prank(executor);
        vm.expectRevert(CATValidatorV2.PayloadNotCommitted.selector);
        validator.entry(refund, hex"deadbeef", signer, 1, allowances, outcomes, binding, noProgram(), noParams(), sig);

        assertEq(inToken.balanceOf(signer), 100 ether, "escrow balance unchanged");
        assertEq(inToken.balanceOf(refund), 0);
        assertFalse(validator.spentNonces(signer, 1), "nonce not consumed by a rejected call");
    }

    /* ─────────────────────────── (b) honest sweep refund shapes
    ─────────────────────────── */

    /// @dev The honest refund: the whole escrow balance moves to the committed
    /// wallet in one hop; the empty payload skips `_call`.
    function test_refund_honestSweepPaysRefundWallet() external {
        fundEscrow(validator, 100 ether);
        address refund = makeAddr("refund");
        AllowanceSpend[] memory allowances = oneAllowance(address(inToken), 1 << 255);
        Outcome[] memory outcomes = oneOutcome(address(inToken), 0, refund);

        refundEntry(validator, 1, refund, allowances, outcomes);

        assertEq(inToken.balanceOf(refund), 100 ether, "the sweep pays the refund wallet");
        assertEq(inToken.balanceOf(signer), 0);
        assertEq(inToken.balanceOf(address(validator)), 0, "funds never touch the validator");
        assertTrue(validator.spentNonces(signer, 1));
    }

    /// @dev The no-outcome shape: `_validatePayment` makes no call, so tokens
    /// that reject zero-value transfers still refund.
    function test_refund_noOutcomeSweepPaysRefundWallet() external {
        fundEscrow(validator, 100 ether);
        address refund = makeAddr("refund");
        AllowanceSpend[] memory allowances = oneAllowance(address(inToken), 1 << 255);

        refundEntry(validator, 1, refund, allowances, new Outcome[](0));

        assertEq(inToken.balanceOf(refund), 100 ether);
        assertEq(inToken.balanceOf(signer), 0);
        assertTrue(validator.spentNonces(signer, 1));
    }

    /// @dev An escrow under-funded relative to the signed allocation: the
    /// literal spend exceeds the balance, the token's transferFrom fails and
    /// SafeTransferLib reverts. The escrow stays intact and the nonce is free.
    function test_refund_underFundedEscrowRevertsTransferFrom() external {
        fundEscrow(validator, 5 ether);
        address refund = makeAddr("refund");
        ExecutionBinding memory binding = refundBinding(refund);
        AllowanceSpend[] memory allowances = oneAllowance(address(inToken), 100 ether);
        bytes memory sig = sign(validator, 1, allowances, new Outcome[](0), binding, bytes32(0), bytes32(0));

        vm.prank(executor);
        vm.expectRevert(SafeTransferLib.TransferFromFailed.selector);
        validator.entry(refund, hex"", signer, 1, allowances, new Outcome[](0), binding, noProgram(), noParams(), sig);

        assertEq(inToken.balanceOf(signer), 5 ether, "escrow balance unchanged");
        assertFalse(validator.spentNonces(signer, 1));
    }

    /// @dev A balance above a finite allocation with the sweep spend: the magic
    /// spend resolves to the full balance, which exceeds `allocated`, and the
    /// call reverts `AllocationTooSmall`. A sweep refund must sign
    /// `allocated >= balance` (the SDK signs `maxUint256`).
    function test_refund_finiteAllocationBelowBalanceRevertsAllocationTooSmall() external {
        fundEscrow(validator, 10 ether);
        address refund = makeAddr("refund");
        ExecutionBinding memory binding = refundBinding(refund);
        AllowanceSpend[] memory allowances = new AllowanceSpend[](1);
        allowances[0] = AllowanceSpend({ token: address(inToken), allocated: 5 ether, spend: 1 << 255 });
        bytes memory sig = sign(validator, 1, allowances, new Outcome[](0), binding, bytes32(0), bytes32(0));

        vm.prank(executor);
        vm.expectRevert(abi.encodeWithSelector(CATValidator.AllocationTooSmall.selector, 5 ether, 10 ether));
        validator.entry(refund, hex"", signer, 1, allowances, new Outcome[](0), binding, noProgram(), noParams(), sig);

        assertEq(inToken.balanceOf(signer), 10 ether, "escrow balance unchanged");
        assertFalse(validator.spentNonces(signer, 1));
    }

    /// @dev stETH-style lossy token: the sweep spend is the escrow balance, the
    /// wallet receives the balance less the per-transfer loss, and nothing
    /// reverts. Fresh token per loss value; nonces 1 and 2 stay distinct.
    function test_refund_lossyTokenSweepPaysRefundWallet() external {
        address refund = makeAddr("refund");
        for (uint256 loss = 1; loss <= 2; ++loss) {
            LossyToken lossy = new LossyToken(loss);
            lossy.mint(signer, 100 ether);
            vm.prank(signer);
            lossy.approve(address(validator), type(uint256).max);

            AllowanceSpend[] memory allowances = oneAllowance(address(lossy), 1 << 255);
            refundEntry(validator, loss, refund, allowances, new Outcome[](0));

            assertEq(lossy.balanceOf(refund), 100 ether - loss, "balance delivered less the transfer loss");
            assertEq(lossy.balanceOf(signer), 0);
            assertTrue(validator.spentNonces(signer, loss));
        }
    }

    /// @dev A zero balance sweeps zero: the magic spend resolves to 0 and the
    /// settlement succeeds, consuming the nonce.
    function test_refund_zeroBalanceSweepSettles() external {
        fundEscrow(validator, 0);
        address refund = makeAddr("refund");
        AllowanceSpend[] memory allowances = oneAllowance(address(inToken), 1 << 255);

        refundEntry(validator, 1, refund, allowances, new Outcome[](0));

        assertEq(inToken.balanceOf(refund), 0);
        assertEq(inToken.balanceOf(signer), 0);
        assertTrue(validator.spentNonces(signer, 1), "the nonce is consumed even for an empty escrow");
    }

    /* ─────────────────── (c) execute constraint signed 0/0
    ─────────────────────────── */

    /// @dev One signature over the 0/0 binding authorizes any target and any
    /// payload; nonce 0 makes the same signature reusable.
    function test_execute_unboundBindingFillsAnyTargetAndPayload() external {
        fundEscrow(validator, 100 ether);
        AllowanceSpend[] memory allowances = oneAllowance(address(inToken), 1 ether);
        Outcome[] memory outcomes = oneOutcome(address(token), 1 ether, destination);
        bytes memory sig = sign(validator, 0, allowances, outcomes, unbound(), bytes32(0), bytes32(0));
        OutcomeFill otherFill = new OutcomeFill();

        vm.prank(executor);
        validator.entry(
            address(fill),
            abi.encodeCall(OutcomeFill.mint, (token, address(validator), 1.5 ether)),
            signer,
            0,
            allowances,
            outcomes,
            unbound(),
            noProgram(),
            noParams(),
            sig
        );
        vm.prank(executor);
        validator.entry(
            address(otherFill),
            abi.encodeCall(OutcomeFill.mint, (token, address(validator), 2 ether)),
            signer,
            0,
            allowances,
            outcomes,
            unbound(),
            noProgram(),
            noParams(),
            sig
        );

        assertEq(inToken.balanceOf(address(fill)), 1 ether, "first target received the allowance");
        assertEq(inToken.balanceOf(address(otherFill)), 1 ether, "second target received the allowance");
        assertEq(token.balanceOf(destination), 3.5 ether, "both fills paid the outcome");
    }

    /* ───────────── (d) the binding is inside the signed digest
    ─────────────────────────── */

    /// @dev A digest signed for target A does not verify when the caller
    /// supplies binding target B: `_checkBinding` passes (B matches the call),
    /// so the revert is provably the signature over the supplied binding.
    function test_binding_signedTargetADoesNotVerifyForTargetB() external {
        ExecutionBinding memory signedBinding = ExecutionBinding(makeAddr("targetA"), EMPTY_PAYLOAD_HASH);
        ExecutionBinding memory suppliedBinding = ExecutionBinding(makeAddr("targetB"), EMPTY_PAYLOAD_HASH);
        AllowanceSpend[] memory allowances = noAllowances();
        Outcome[] memory outcomes = oneOutcome(address(token), 0, destination);
        bytes memory sig = sign(validator, 1, allowances, outcomes, signedBinding, bytes32(0), bytes32(0));

        vm.prank(executor);
        vm.expectRevert(CATValidator.BadSignature.selector);
        validator.entry(
            suppliedBinding.executionTarget,
            hex"",
            signer,
            1,
            allowances,
            outcomes,
            suppliedBinding,
            noProgram(),
            noParams(),
            sig
        );
        assertFalse(validator.spentNonces(signer, 1));
    }

    /// @dev `payloadHash = 0` (unconstrained) and `keccak256("")` (committed
    /// empty payload) are different signed values: neither verifies against a
    /// digest signed with the other, so a committed refund cannot be widened to
    /// any payload and an unbound constraint cannot be narrowed.
    function test_binding_zeroAndEmptyPayloadHashDoNotVerifyForEachOther() external {
        address refund = makeAddr("refund");
        AllowanceSpend[] memory allowances = noAllowances();
        Outcome[] memory outcomes = oneOutcome(address(token), 0, destination);

        bytes memory sigZero =
            sign(validator, 1, allowances, outcomes, ExecutionBinding(refund, bytes32(0)), bytes32(0), bytes32(0));
        vm.prank(executor);
        vm.expectRevert(CATValidator.BadSignature.selector);
        validator.entry(
            refund, hex"", signer, 1, allowances, outcomes, refundBinding(refund), noProgram(), noParams(), sigZero
        );

        bytes memory sigEmpty = sign(validator, 2, allowances, outcomes, refundBinding(refund), bytes32(0), bytes32(0));
        vm.prank(executor);
        vm.expectRevert(CATValidator.BadSignature.selector);
        validator.entry(
            refund,
            hex"",
            signer,
            2,
            allowances,
            outcomes,
            ExecutionBinding(refund, bytes32(0)),
            noProgram(),
            noParams(),
            sigEmpty
        );
    }

    /* ─────────── (e) fuzz: funds only ever reach the committed target
    ─────────────────────────── */

    /// @dev For a refund constraint committed to `refund` + `keccak256("")`,
    /// fuzz the executor-chosen `execTarget`, payload, spend and supplied
    /// binding. Whatever settles, every recorded `transferFrom` destination is
    /// the committed wallet. The `honest` flag forces the one call shape that
    /// can settle, so the success path is covered deterministically.
    function testFuzz_refund_fundsMoveOnlyToCommittedTarget(
        address fuzzTarget,
        bytes32 fuzzPayloadWord,
        uint256 fuzzSpend,
        address fuzzBindingTarget,
        bytes32 fuzzBindingHash,
        bool honest
    ) external {
        RecordingToken rec = new RecordingToken();
        rec.mint(signer, 100 ether);
        vm.prank(signer);
        rec.approve(address(validator), type(uint256).max);

        address refund = makeAddr("refund");
        ExecutionBinding memory committed = refundBinding(refund);
        uint256 spend = bound(fuzzSpend, 0, 100 ether);
        AllowanceSpend[] memory allowances = oneAllowance(address(rec), spend);
        Outcome[] memory outcomes = new Outcome[](0);
        bytes memory sig = sign(validator, 1, allowances, outcomes, committed, bytes32(0), bytes32(0));

        address execTarget = honest ? refund : fuzzTarget;
        bytes memory payload = honest ? bytes("") : abi.encodePacked(fuzzPayloadWord);
        ExecutionBinding memory supplied = honest ? committed : ExecutionBinding(fuzzBindingTarget, fuzzBindingHash);

        bytes memory callData = abi.encodeWithSignature(
            ENTRY_V2_SIGNATURE,
            execTarget,
            payload,
            signer,
            1,
            allowances,
            outcomes,
            supplied,
            noProgram(),
            noParams(),
            sig
        );
        vm.prank(executor);
        (bool ok,) = address(validator).call(callData);

        uint256 n = rec.recordedCount();
        for (uint256 i; i < n; ++i) {
            assertEq(rec.recordedDestination(i), refund, "transferFrom destination is the committed wallet");
        }
        assertEq(rec.balanceOf(refund), ok ? spend : 0);
        assertEq(rec.balanceOf(signer), ok ? 100 ether - spend : 100 ether);
        assertEq(validator.spentNonces(signer, 1), ok);
        if (!honest) assertFalse(ok, "an uncommitted target, payload or binding cannot settle");
    }

    /* ─────────── (f) fuzz: the 0/0 execute path is unchanged
    ─────────────────────────── */

    /// @dev The execute constraint signed 0/0 behaves exactly as the unbound
    /// path did: pulled funds reach the executor-chosen target, and the outcome
    /// floor is the only bound on the fill.
    function testFuzz_execute_unboundPathReachesTargetAndEnforcesFloor(
        uint256 fuzzSpend,
        uint256 fuzzMint,
        bool secondTarget
    ) external {
        fundEscrow(validator, 100 ether);
        uint256 spend = bound(fuzzSpend, 0, 100 ether);
        uint256 mint = bound(fuzzMint, 0, 3 ether);
        address target = secondTarget ? address(new OutcomeFill()) : address(fill);
        AllowanceSpend[] memory allowances = oneAllowance(address(inToken), spend);
        Outcome[] memory outcomes = oneOutcome(address(token), 1 ether, destination);
        bytes memory sig = sign(validator, 1, allowances, outcomes, unbound(), bytes32(0), bytes32(0));
        bytes memory callData = abi.encodeWithSignature(
            ENTRY_V2_SIGNATURE,
            target,
            abi.encodeCall(OutcomeFill.mint, (token, address(validator), mint)),
            signer,
            1,
            allowances,
            outcomes,
            unbound(),
            noProgram(),
            noParams(),
            sig
        );

        vm.prank(executor);
        (bool ok,) = address(validator).call(callData);

        if (mint >= 1 ether) {
            assertTrue(ok, "floor met: the fill settles");
            assertEq(inToken.balanceOf(target), spend, "the allowance reached the chosen target");
            assertEq(token.balanceOf(destination), mint, "the full held balance is forwarded");
            assertTrue(validator.spentNonces(signer, 1));
        } else {
            assertFalse(ok, "floor not met: the fill reverts");
            assertEq(inToken.balanceOf(target), 0);
            assertEq(inToken.balanceOf(signer), 100 ether, "escrow intact after a failed fill");
            assertEq(token.balanceOf(destination), 0);
            assertFalse(validator.spentNonces(signer, 1));
        }
    }

    /* ─────────── (g) executor-chosen spend burns the shared nonce (K7a)
    ─────────────────────────── */

    /// @dev Residual K7(a), griefing not theft: the spend is unsigned, so an
    /// untrusted executor can settle the bound refund with spend 0. The call
    /// consumes the nonce the execute constraint shares, disabling both signed
    /// paths while the deposit stays in the escrow.
    function test_refund_zeroSpendConsumesSharedNonce() external {
        fundEscrow(validator, 100 ether);
        address refund = makeAddr("refund");
        AllowanceSpend[] memory allowances = oneAllowance(address(inToken), 0);

        refundEntry(validator, 1, refund, allowances, new Outcome[](0));

        assertTrue(validator.spentNonces(signer, 1), "the zero-spend refund consumes the shared nonce");
        assertEq(inToken.balanceOf(refund), 0, "nothing moved");
        assertEq(inToken.balanceOf(signer), 100 ether, "the deposit stays locked in the escrow");

        Outcome[] memory execOutcomes = oneOutcome(address(token), 0, destination);
        bytes memory execSig = sign(validator, 1, noAllowances(), execOutcomes, unbound(), bytes32(0), bytes32(0));
        vm.prank(executor);
        vm.expectRevert(CATValidator.NonceAlreadySpent.selector);
        validator.entry(
            address(fill), hex"", signer, 1, noAllowances(), execOutcomes, unbound(), noProgram(), noParams(), execSig
        );
    }

    /// @dev Same residual with a partial spend: only the refund wallet receives
    /// funds, the rest of the deposit is stranded at the spent nonce.
    function test_refund_partialSpendConsumesSharedNonce() external {
        fundEscrow(validator, 100 ether);
        address refund = makeAddr("refund");
        AllowanceSpend[] memory allowances = oneAllowance(address(inToken), 40 ether);

        refundEntry(validator, 1, refund, allowances, new Outcome[](0));

        assertTrue(validator.spentNonces(signer, 1), "the partial-spend refund consumes the shared nonce");
        assertEq(inToken.balanceOf(refund), 40 ether, "funds moved only to the committed wallet");
        assertEq(inToken.balanceOf(signer), 60 ether, "the remainder stays locked in the escrow");

        Outcome[] memory execOutcomes = oneOutcome(address(token), 0, destination);
        bytes memory execSig = sign(validator, 1, noAllowances(), execOutcomes, unbound(), bytes32(0), bytes32(0));
        vm.prank(executor);
        vm.expectRevert(CATValidator.NonceAlreadySpent.selector);
        validator.entry(
            address(fill), hex"", signer, 1, noAllowances(), execOutcomes, unbound(), noProgram(), noParams(), execSig
        );
    }

    /* ─────────── (h) ERC-777-style callback hits the reentrancy guard
    ─────────────────────────── */

    /// @dev Residual K7(d): a callback-capable token runs refund-wallet code
    /// mid-transfer. A nested `entry` from that hook — signed for the wallet as
    /// executor over a fresh nonce, so nothing else would stop it — hits the
    /// reentrancy guard, and the outer refund still settles.
    function test_refund_recipientHookNestedEntryHitsReentrancyGuard() external {
        CallbackToken cb = new CallbackToken();
        cb.mint(signer, 100 ether);
        vm.prank(signer);
        cb.approve(address(validator), type(uint256).max);

        HookedRefundWallet wallet = new HookedRefundWallet();
        ExecutionBinding memory binding = refundBinding(address(wallet));

        AllowanceSpend[] memory innerAllowances = oneAllowance(address(cb), 1 wei);
        bytes memory innerSig = signAs(validator, address(wallet), 2, innerAllowances, new Outcome[](0), binding);
        wallet.arm(
            address(validator),
            abi.encodeWithSignature(
                ENTRY_V2_SIGNATURE,
                address(wallet),
                bytes(""),
                signer,
                2,
                innerAllowances,
                new Outcome[](0),
                binding,
                noProgram(),
                noParams(),
                innerSig
            )
        );

        AllowanceSpend[] memory allowances = oneAllowance(address(cb), 1 << 255);
        refundEntry(validator, 1, address(wallet), allowances, new Outcome[](0));

        assertFalse(wallet.innerSucceeded(), "the nested entry reverted");
        assertEq(wallet.innerRevertSelector(), ReentrancyGuard.Reentrancy.selector, "the guard stopped it");
        assertFalse(validator.spentNonces(signer, 2), "the nested entry settled nothing");
        assertEq(cb.balanceOf(address(wallet)), 100 ether, "the outer refund settled");
        assertEq(cb.balanceOf(signer), 0);
        assertTrue(validator.spentNonces(signer, 1));
    }

    /* ─────────────────────────── (i) sequences
    ─────────────────────────── */

    /// @dev A failing program on the execute constraint reverts the whole
    /// settlement (nonce unspent, escrow intact), and the bound refund on the
    /// same nonce succeeds afterwards.
    function test_sequence_failedExecuteThenBoundRefundSameNonce() external {
        fundEscrow(echoValidator, 5 ether);
        AllowanceSpend[] memory allowances = oneAllowance(address(inToken), 5 ether);
        Outcome[] memory outcomes = oneOutcome(address(token), 1 ether, destination);
        VMCommand[] memory program = dummyProgram();
        bytes memory payload = abi.encodeCall(OutcomeFill.mint, (token, address(echoValidator), 1 ether));
        bytes memory sigExec = sign(echoValidator, 1, allowances, outcomes, unbound(), hashProgram(program), bytes32(0));

        uint256[] memory spent = new uint256[](1);
        spent[0] = 5 ether;
        uint256[] memory paid = new uint256[](1);
        paid[0] = 1 ether;
        // Compute the expected revert before the prank: `expectedRunVM` calls the
        // harness, and a prank applies to the next external call only.
        bytes memory expected = expectedRunVM(program, noParams(), spent, paid);
        vm.prank(executor);
        vm.expectRevert(expected);
        echoValidator.entry(
            address(fill), payload, signer, 1, allowances, outcomes, unbound(), program, noParams(), sigExec
        );

        assertFalse(echoValidator.spentNonces(signer, 1), "a failed execute leaves the nonce fresh");
        assertEq(inToken.balanceOf(signer), 5 ether, "a failed execute leaves the escrow intact");

        address refund = makeAddr("refund");
        AllowanceSpend[] memory sweep = oneAllowance(address(inToken), 1 << 255);
        refundEntry(echoValidator, 1, refund, sweep, new Outcome[](0));

        assertEq(inToken.balanceOf(refund), 5 ether, "the bound refund settles on the same nonce");
        assertEq(inToken.balanceOf(signer), 0);
        assertTrue(echoValidator.spentNonces(signer, 1));
    }

    /// @dev Nonce 0 is never consumed: bound refunds interleave freely with
    /// unbound executes. The binding still confines the refund to its wallet
    /// (K7(b): a perpetual refund replays only to the refund wallet).
    function test_nonce0_boundRefundsInterleaveWithUnboundExecutes() external {
        fundEscrow(validator, 100 ether);
        address refund = makeAddr("refund");

        refundEntry(validator, 0, refund, oneAllowance(address(inToken), 10 ether), new Outcome[](0));

        AllowanceSpend[] memory fillAllowances = oneAllowance(address(inToken), 30 ether);
        Outcome[] memory outcomes = oneOutcome(address(token), 1 ether, destination);
        bytes memory sigExec = sign(validator, 0, fillAllowances, outcomes, unbound(), bytes32(0), bytes32(0));
        vm.prank(executor);
        validator.entry(
            address(fill),
            abi.encodeCall(OutcomeFill.mint, (token, address(validator), 1.5 ether)),
            signer,
            0,
            fillAllowances,
            outcomes,
            unbound(),
            noProgram(),
            noParams(),
            sigExec
        );

        refundEntry(validator, 0, refund, oneAllowance(address(inToken), 25 ether), new Outcome[](0));

        assertEq(inToken.balanceOf(refund), 35 ether, "both refunds paid the committed wallet");
        assertEq(inToken.balanceOf(address(fill)), 30 ether, "the execute paid its target");
        assertEq(token.balanceOf(destination), 1.5 ether, "the execute paid its outcome");
        assertEq(inToken.balanceOf(signer), 35 ether, "the escrow keeps the rest");
    }
}
