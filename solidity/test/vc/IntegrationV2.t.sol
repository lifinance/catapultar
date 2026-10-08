// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { IERC20 } from "forge-std/src/interfaces/IERC20.sol";
import { ERC7821 } from "solady/src/accounts/ERC7821.sol";
import { SafeTransferLib } from "solady/src/utils/SafeTransferLib.sol";

import { CATValidator } from "../../src/CATValidator.sol";
import { CATValidatorV2 } from "../../src/CATValidatorV2.sol";
import { Catapultar } from "../../src/Catapultar.sol";
import { CatapultarFactory } from "../../src/CatapultarFactory.sol";
import { KeyedOwnable } from "../../src/libs/KeyedOwnable.sol";
import { LibCalls } from "../../src/libs/LibCalls.sol";
import { AllowanceSpend, Outcome } from "../../src/libs/LibExecutionConstraint.sol";
import { LibValidationVM } from "../../src/libs/LibValidationVM.sol";
import { ProgramBuilder } from "./ProgramBuilder.sol";
import { VcTestBase } from "./VcTestBase.sol";

/// @dev A solver fill reached through the validator's CallProxy. `entry()` moves
/// the escrow's allowance to this contract first; the fill then pays out of a
/// pre-funded balance.
contract MockSwap {
    function fill(
        address outToken,
        address to,
        uint256 outAmount
    ) external {
        SafeTransferLib.safeTransfer(outToken, to, outAmount);
    }

    /// @dev Also pays `other` directly, standing in for any transfer to the
    /// delivery address that does not pass through the validator.
    function fillAndSend(
        address outToken,
        address to,
        uint256 outAmount,
        address other,
        uint256 otherAmount
    ) external {
        SafeTransferLib.safeTransfer(outToken, to, outAmount);
        SafeTransferLib.safeTransfer(outToken, other, otherAmount);
    }
}

/**
 * @title CATValidatorV2 on the canonical VirtualMachine (Ethereum mainnet fork)
 * @notice Drives the production settlement path against the deployed, unmodified
 * VirtualMachine, ArithmeticProcessor and InvariantChecker. Each settlement uses
 * a factory-deployed `Catapultar` escrow whose CREATE2 salt commits the call
 * batch that approves the validator and pre-approves the V2 constraint digest,
 * so the digest (and through it the program and params hashes) is bound to the
 * escrow address. `entry()` then runs with an empty signature, which the escrow
 * accepts through ERC-1271.
 *
 * The committed program is a rate check written against the current register
 * layout `params ++ [account] ++ spent ++ paid`: the amount the validator
 * forwarded for outcome 0 must be at least `ceil(spent[0] * rateNumerator /
 * rateDenominator)`. The escrow holds 3000 USDC and spends its whole balance;
 * at one WETH per 3000 USDC the program requires 1 WETH, while the v1 floor of
 * the WETH outcome is 0.9 WETH.
 *
 * Every test skips when `VC_MAINNET_RPC_URL` is unset, so CI without the secret
 * stays green.
 */
contract IntegrationV2Test is VcTestBase {
    bytes32 internal constant REVERT_MODE = bytes32(bytes10(0x01010000000078210001));

    /// @dev InvariantChecker `error AssertGteFailed(uint256 a, uint256 b)`.
    bytes4 internal constant ASSERT_GTE_FAILED = bytes4(keccak256("AssertGteFailed(uint256,uint256)"));

    address internal constant DELIVERY = 0x1111111111111111111111111111111111111111;

    /// @dev `CATValidator.SPEND_BALANCE_OF_MAGIC`: spend the escrow's whole balance.
    uint256 internal constant SPEND_ALL = 1 << 255;

    uint256 internal constant ESCROW_USDC = 3000e6;
    uint256 internal constant FLOOR = 0.9 ether;
    uint256 internal constant RATE_NUMERATOR = 1 ether;
    uint256 internal constant RATE_DENOMINATOR = 3000e6;
    /// @dev `ceil(ESCROW_USDC * RATE_NUMERATOR / RATE_DENOMINATOR)`.
    uint256 internal constant REQUIRED = 1 ether;

    /// @dev Register indices of the rate program: four params, then the
    /// validator-injected account, spent[0] and paid[0], then scratch.
    uint8 internal constant R_RATE_NUM = 0;
    uint8 internal constant R_RATE_DEN = 1;
    uint8 internal constant R_RPN_WORD = 2;
    uint8 internal constant R_RPN_LEN = 3;
    uint8 internal constant R_SPENT_0 = 5;
    uint8 internal constant R_PAID_0 = 6;
    uint8 internal constant R_RPN_CALLDATA = 7;
    uint8 internal constant R_MIN_OUT = 8;
    uint8 internal constant R_ASSERT_CALLDATA = 9;
    uint8 internal constant R_VOID = 0x7A;

    CatapultarFactory internal factory;
    CATValidatorV2 internal validator;
    MockSwap internal swap;
    address internal executor;
    string internal json;

    /// @dev A digest-committed escrow and the key that owns it.
    struct Escrow {
        address payable account;
        address owner;
        uint256 ownerKey;
    }

    /// @dev One settlement's signed inputs and the fill the executor runs.
    struct Settlement {
        AllowanceSpend[] allowances;
        Outcome[] outcomes;
        bytes program;
        bytes[] params;
        bytes fillPayload;
        uint256 nonce;
    }

    function setUp() external {
        forkMainnetIfConfigured();
        if (!hasForkRpc()) return;
        factory = new CatapultarFactory();
        validator = new CATValidatorV2(VM_ADDR);
        swap = new MockSwap();
        executor = makeAddr("vc/executor");
        json = readFixture(HASH_PARITY_VECTORS);
        deal(WETH, DELIVERY, 0);
    }

    /* ─────────────────────────── A: the rate program passes
    ─────────────────────────── */

    /// @notice A committed program that the fill satisfies settles: the canonical
    /// VM accepts it, the nonce is spent, the escrow is drained into the fill, and
    /// the outcome reaches its destination.
    function test_rateProgram_passingFillSettles() external onlyFork {
        Settlement memory s = _rateSettlement(REQUIRED, 1);
        Escrow memory e = _deployEscrow(s);

        vm.expectCall(VM_ADDR, bytes(""), 1);
        _entry(s, e);

        assertTrue(validator.spentNonces(e.account, s.nonce), "nonce not spent after settlement");
        assertEq(SafeTransferLib.balanceOf(USDC, e.account), 0, "escrow not drained by the spend-all allowance");
        assertEq(SafeTransferLib.balanceOf(USDC, address(swap)), ESCROW_USDC, "fill did not receive the escrow funds");
        assertEq(SafeTransferLib.balanceOf(WETH, DELIVERY), REQUIRED, "outcome not delivered");
        assertEq(SafeTransferLib.balanceOf(WETH, address(validator)), 0, "validator kept outcome funds");
    }

    /* ─────────────────────────── B: floor passes, program fails
    ─────────────────────────── */

    /// @notice A fill above the v1 floor but below the committed rate reverts
    /// `ValidationFailed` carrying the InvariantChecker's exact revert, and the
    /// whole settlement rolls back: nonce unspent, escrow funds intact.
    function test_rateProgram_fillAboveFloorBelowRateRevertsValidationFailed() external onlyFork {
        uint256 delivered = 0.95 ether;
        assertGe(delivered, FLOOR, "case must clear the v1 floor");
        Settlement memory s = _rateSettlement(delivered, 2);
        Escrow memory e = _deployEscrow(s);

        vm.expectRevert(_validationFailed(delivered, REQUIRED));
        _entry(s, e);

        assertFalse(validator.spentNonces(e.account, s.nonce), "nonce spent despite validation failure");
        assertEq(SafeTransferLib.balanceOf(USDC, e.account), ESCROW_USDC, "escrow funds moved despite failure");
        assertEq(SafeTransferLib.balanceOf(WETH, DELIVERY), 0, "outcome delivered despite failure");
    }

    /* ─────────────────────────── C: the v1 floor runs first
    ─────────────────────────── */

    /// @notice A fill below the floor reverts v1's `InvalidTokenAmount` before the
    /// program runs: no call reaches the VirtualMachine.
    function test_rateProgram_fillBelowFloorRevertsInvalidTokenAmountFirst() external onlyFork {
        uint256 delivered = 0.5 ether;
        Settlement memory s = _rateSettlement(delivered, 3);
        Escrow memory e = _deployEscrow(s);

        vm.expectCall(VM_ADDR, bytes(""), 0);
        vm.expectRevert(abi.encodeWithSelector(CATValidator.InvalidTokenAmount.selector, FLOOR, delivered));
        _entry(s, e);

        assertFalse(validator.spentNonces(e.account, s.nonce), "nonce spent despite floor failure");
        assertEq(SafeTransferLib.balanceOf(USDC, e.account), ESCROW_USDC, "escrow funds moved despite failure");
    }

    /* ─────────────────────────── paid is what the validator
    forwarded
    ─────────────────────────── */

    /// @notice `paid[0]` counts only what passed through the validator. The fill
    /// pays the validator 0.95 WETH and sends 0.05 WETH straight to the delivery
    /// address: the destination ends at the required 1 WETH, yet the program sees
    /// 0.95 and rejects the settlement.
    function test_rateProgram_directTransferToDeliveryDoesNotCount() external onlyFork {
        uint256 throughValidator = 0.95 ether;
        uint256 direct = REQUIRED - throughValidator;
        Settlement memory s = _rateSettlement(throughValidator, 4);
        s.fillPayload =
            abi.encodeCall(MockSwap.fillAndSend, (WETH, address(validator), throughValidator, DELIVERY, direct));
        deal(WETH, address(swap), REQUIRED);
        Escrow memory e = _deployEscrow(s);

        vm.expectRevert(_validationFailed(throughValidator, REQUIRED));
        _entry(s, e);

        assertFalse(validator.spentNonces(e.account, s.nonce), "nonce spent despite validation failure");
    }

    /* ─────────────────────────── R8: refund after a failed
    settlement
    ─────────────────────────── */

    /// @notice After a `ValidationFailed` attempt the escrow is untouched and its
    /// owner can move the funds out with a signed batch: a failed program never
    /// strands the deposit.
    function test_rateProgram_escrowRefundableAfterValidationFailed() external onlyFork {
        Settlement memory s = _rateSettlement(0.95 ether, 5);
        Escrow memory e = _deployEscrow(s);

        vm.expectRevert(_validationFailed(0.95 ether, REQUIRED));
        _entry(s, e);

        ERC7821.Call[] memory calls = new ERC7821.Call[](1);
        calls[0] = ERC7821.Call({ to: USDC, value: 0, data: abi.encodeCall(IERC20.transfer, (e.owner, ESCROW_USDC)) });
        uint256 refundNonce = 2; // nonce 1 executed the embedded deploy batch
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                Catapultar(e.account).DOMAIN_SEPARATOR(),
                this.exposedCallsTypehash(refundNonce, REVERT_MODE, calls)
            )
        );
        (uint8 v, bytes32 r, bytes32 sig) = vm.sign(e.ownerKey, digest);

        Catapultar(e.account).execute(REVERT_MODE, abi.encode(calls, abi.encodePacked(refundNonce, r, sig, v)));

        assertEq(SafeTransferLib.balanceOf(USDC, e.owner), ESCROW_USDC, "refund did not reach the owner");
        assertEq(SafeTransferLib.balanceOf(USDC, e.account), 0, "escrow still holds funds after refund");
        assertFalse(validator.spentNonces(e.account, s.nonce), "constraint nonce consumed by the refund");
    }

    /* ─────────────────────────── the pinned compiler program
    ─────────────────────────── */

    /// @notice The compose compiler's pinned `uc1-user-a` body, re-encoded through
    /// `LibValidationVM.encodeRunVM` with the fixture's own register file (the
    /// earlier `params ++ [account] ++ preBalances` layout), runs its whole
    /// read, RPN and assert pipeline on the canonical VM and fails only on its
    /// business invariants: first the WETH floor, then the USDC threshold.
    function test_uc1Fixture_failsOnlyOnItsInvariants() external onlyFork {
        bytes memory payload = _uc1Payload();

        (bool ok, bytes memory ret) = VM_ADDR.staticcall(payload);
        assertFalse(ok, "uc1 passed with an unfunded delivery");
        assertEq(ret, abi.encodeWithSelector(ASSERT_GTE_FAILED, 0, 1 ether), "WETH floor not the failing invariant");

        deal(WETH, DELIVERY, 1 ether);
        deal(USDC, DELIVERY, 500e6 - 1);
        (ok, ret) = VM_ADDR.staticcall(payload);
        assertFalse(ok, "uc1 passed below the USDC threshold");
        assertEq(
            ret, abi.encodeWithSelector(ASSERT_GTE_FAILED, 500e6 - 1, 500e6), "USDC threshold not the failing invariant"
        );
    }

    /// @notice The same pinned program passes on the canonical VM once the
    /// delivery address satisfies both invariants.
    function test_uc1Fixture_passesWhenDeliveryFunded() external onlyFork {
        bytes memory payload = _uc1Payload();
        deal(WETH, DELIVERY, 1 ether);
        deal(USDC, DELIVERY, 500e6);

        (bool ok, bytes memory ret) = VM_ADDR.staticcall(payload);

        assertTrue(ok, string.concat("uc1 failed with a funded delivery: ", vm.toString(ret)));
    }

    /* ─────────────────────────── program authoring
    ─────────────────────────── */

    /// @notice The rate program: `paid[0] >= ceil(spent[0] * num / den)`.
    /// Registers: [0] num, [1] den, [2] RPN word, [3] RPN length, [4] account,
    /// [5] spent[0], [6] paid[0]; scratch from [7]. The assertion's return is
    /// written to the void register.
    function rateProgram(
        uint256 numerator,
        uint256 denominator
    ) internal pure returns (bytes memory program, bytes[] memory params) {
        // regValues = [spent[0], num, den]; RPN: push 0, push 1, MUL, push 2, DIV_UP.
        bytes memory rpn = abi.encodePacked(
            ProgramBuilder.RPN_PUSH | 0,
            ProgramBuilder.RPN_PUSH | 1,
            ProgramBuilder.RPN_MUL,
            ProgramBuilder.RPN_PUSH | 2,
            ProgramBuilder.RPN_DIV_UP
        );
        params = new bytes[](4);
        params[R_RATE_NUM] = abi.encodePacked(bytes32(numerator));
        params[R_RATE_DEN] = abi.encodePacked(bytes32(denominator));
        params[R_RPN_WORD] = abi.encodePacked(ProgramBuilder.rpnWord(rpn));
        params[R_RPN_LEN] = abi.encodePacked(bytes32(rpn.length));

        bytes memory bpRpn = abi.encodePacked(
            ProgramBuilder.START_ARRAY_DYNAMIC,
            ProgramBuilder.bpStatic(R_SPENT_0),
            ProgramBuilder.bpStatic(R_RATE_NUM),
            ProgramBuilder.bpStatic(R_RATE_DEN),
            ProgramBuilder.END_CONTAINER,
            ProgramBuilder.bpStatic(R_RPN_WORD),
            ProgramBuilder.bpStatic(R_RPN_LEN)
        );
        bytes memory bpAssert = abi.encodePacked(ProgramBuilder.bpStatic(R_PAID_0), ProgramBuilder.bpStatic(R_MIN_OUT));

        program = abi.encodePacked(
            ProgramBuilder.cmd(
                ProgramBuilder.OP_CALLDATA_BUILD,
                ProgramBuilder.packCallDataBuild(ProgramBuilder.SEL_EVALUATE_RPN, R_RPN_CALLDATA, bpRpn)
            ),
            ProgramBuilder.cmd(
                ProgramBuilder.OP_CALL,
                ProgramBuilder.packCall(
                    ARITHMETIC_PROCESSOR, ProgramBuilder.CALLTYPE_STATICCALL, R_MIN_OUT, R_RPN_CALLDATA, 0
                )
            ),
            ProgramBuilder.cmd(
                ProgramBuilder.OP_CALLDATA_BUILD,
                ProgramBuilder.packCallDataBuild(ProgramBuilder.SEL_ASSERT_GTE, R_ASSERT_CALLDATA, bpAssert)
            ),
            ProgramBuilder.cmd(
                ProgramBuilder.OP_CALL,
                ProgramBuilder.packCall(
                    INVARIANT_CHECKER, ProgramBuilder.CALLTYPE_STATICCALL, R_VOID, R_ASSERT_CALLDATA, 0
                )
            )
        );
    }

    /* ─────────────────────────── settlement harness
    ─────────────────────────── */

    /// @dev One USDC allowance spending the escrow's whole balance into the fill,
    /// one WETH outcome with the 0.9 WETH floor, and a fill that pays `delivered`
    /// WETH to the validator.
    function _rateSettlement(
        uint256 delivered,
        uint256 nonce
    ) internal returns (Settlement memory s) {
        (s.program, s.params) = rateProgram(RATE_NUMERATOR, RATE_DENOMINATOR);
        s.allowances = new AllowanceSpend[](1);
        s.allowances[0] = AllowanceSpend({ token: USDC, allocated: ESCROW_USDC, spend: SPEND_ALL });
        s.outcomes = new Outcome[](1);
        s.outcomes[0] = Outcome({ token: WETH, amount: FLOOR, destination: DELIVERY });
        s.fillPayload = abi.encodeCall(MockSwap.fill, (WETH, address(validator), delivered));
        s.nonce = nonce;
        deal(WETH, address(swap), delivered);
    }

    /// @dev Deploys an escrow whose salt commits a batch that approves the
    /// validator and pre-approves the settlement's V2 digest, runs that batch, and
    /// funds the escrow with `ESCROW_USDC`.
    function _deployEscrow(
        Settlement memory s
    ) internal returns (Escrow memory e) {
        (e.owner, e.ownerKey) = makeAddrAndKey(string.concat("vc/owner-", vm.toString(s.nonce)));
        bytes32 digest = constraintDigest(
            validator.DOMAIN_SEPARATOR(),
            s.allowances,
            s.outcomes,
            executor,
            s.nonce,
            keccak256(s.program),
            hashParams(s.params)
        );

        ERC7821.Call[] memory calls = new ERC7821.Call[](2);
        calls[0] = ERC7821.Call({
            to: USDC, value: 0, data: abi.encodeCall(IERC20.approve, (address(validator), ESCROW_USDC))
        });
        calls[1] = ERC7821.Call({
            to: address(0), // self
            value: 0,
            data: abi.encodeCall(Catapultar.setSignature, (digest, Catapultar.DigestApproval.Signature))
        });

        bytes32[] memory keys = new bytes32[](1);
        keys[0] = bytes32(uint256(uint160(e.owner)));
        e.account = factory.deployWithDigest(
            KeyedOwnable.PublicKeyType.ECDSAOrSmartContract,
            keys,
            bytes32(bytes20(e.owner)),
            this.exposedCallsTypehash(1, REVERT_MODE, calls),
            false
        );
        Catapultar(e.account).execute(REVERT_MODE, abi.encode(calls, abi.encodePacked(uint256(1))));
        deal(USDC, e.account, ESCROW_USDC);
    }

    /// @dev Calls the 9-argument `entry` as the executor with an empty signature.
    function _entry(
        Settlement memory s,
        Escrow memory e
    ) internal {
        vm.prank(executor);
        validator.entry(
            address(swap), s.fillPayload, e.account, s.nonce, s.allowances, s.outcomes, s.program, s.params, hex""
        );
    }

    function _validationFailed(
        uint256 paid,
        uint256 required
    ) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(
            CATValidatorV2.ValidationFailed.selector, abi.encodeWithSelector(ASSERT_GTE_FAILED, paid, required)
        );
    }

    /// @dev `runVM` calldata for the fixture's `uc1-user-a` body and register
    /// file, checked against the compiler's pinned calldata.
    function _uc1Payload() internal view returns (bytes memory payload) {
        bytes memory body = vm.parseJsonBytes(json, ".programVectors[0].canonicalBody");
        bytes[] memory registers = vm.parseJsonBytesArray(json, ".programVectors[0].registers");
        payload = this.exposedEncodeRunVM(body, registers);
        assertEq(payload, vm.parseJsonBytes(json, ".programVectors[0].calldata"), "uc1 re-encoding drifted");
    }

    /* ─────────────────────────── calldata trampolines
    ─────────────────────────── */

    function exposedCallsTypehash(
        uint256 nonce,
        bytes32 mode,
        ERC7821.Call[] calldata calls
    ) external pure returns (bytes32) {
        return LibCalls.typehash(nonce, mode, calls);
    }

    function exposedEncodeRunVM(
        bytes calldata body,
        bytes[] memory registers
    ) external pure returns (bytes memory) {
        return LibValidationVM.encodeRunVM(body, registers);
    }
}
