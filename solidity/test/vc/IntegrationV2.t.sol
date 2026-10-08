// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { ERC7821 } from "solady/src/accounts/ERC7821.sol";
import { SafeTransferLib } from "solady/src/utils/SafeTransferLib.sol";

import { CATValidatorV2 } from "../../src/CATValidatorV2.sol";
import { Catapultar } from "../../src/Catapultar.sol";
import { CatapultarFactory } from "../../src/CatapultarFactory.sol";
import { KeyedOwnable } from "../../src/libs/KeyedOwnable.sol";
import { LibCalls } from "../../src/libs/LibCalls.sol";
import { AllowanceSpend, Outcome } from "../../src/libs/LibExecutionConstraint.sol";
import { ProgramBuilder } from "./ProgramBuilder.sol";
import { VcTestBase } from "./VcTestBase.sol";

/// @dev A solver fill: receives the escrow's allowance token (moved to it by
/// `entry()` before the fill) and delivers `outAmount` of `outToken` to the
/// delivery address, producing the committed outcome. Payable: `entry()`'s
/// CallProxy forwards the validator's balance as call value.
contract MockSwap {
    function fill(
        address outToken,
        address to,
        uint256 outAmount
    ) external payable {
        SafeTransferLib.safeTransfer(outToken, to, outAmount);
    }
}

/**
 * @title GD-4 M6 — CATValidatorV2 escrow flow end-to-end (fork)
 * @notice Drives the production settlement path on an Ethereum mainnet fork: a
 * factory-deployed Catapultar escrow whose CREATE2 salt embeds the v2
 * constraint digest (and therefore the committed validation program + params),
 * funded, then settled through `CATValidatorV2.entry()` with an empty signature
 * (the escrow pre-approves the digest via ERC-1271). The four rows prove the
 * core product claims:
 *   A. a passing committed program settles through the real factory/escrow path;
 *   B. a program strictly stronger than the balance-delta floor reverts
 *      `ValidationFailed` (wrapping the inner `AssertGteFailed`) on a fill that
 *      clears the floor but not the program — funds/nonce untouched (refundable);
 *   C. a floor violation reverts `InvalidTokenAmount` before the program runs at
 *      all (the floor is enforced first, independently of the program);
 *   D. the pinned uc1 program is enforced end-to-end through the escrow path.
 *
 * Every test is fork-gated (`vm.skip(true)` when `VC_MAINNET_RPC_URL` is unset).
 * Extends the v1 `Integration.t.sol::test_validator` recipe to v2.
 */
contract IntegrationV2Test is VcTestBase {
    bytes32 internal constant REVERT_MODE = bytes32(bytes10(0x01010000000078210001));
    /// @dev InvariantChecker: error AssertGteFailed(uint256,uint256).
    bytes4 internal constant ASSERT_GTE_FAILED = bytes4(keccak256("AssertGteFailed(uint256,uint256)"));

    uint256 internal constant GAS_CAP = 5_000_000;
    uint256 internal constant FLOOR = 1 ether;

    address internal constant DELIVERY = 0x1111111111111111111111111111111111111111;

    CatapultarFactory internal factory;
    CATValidatorV2 internal validator;
    MockSwap internal swap;

    /// @dev The escrow deploy inputs vary per settlement so repeated escrows in
    /// one run do not collide (owner in the salt's first 20 bytes).
    uint256 internal ownerSeed;

    string internal json; // hash-parity fixture (Row D)

    function setUp() external {
        if (!hasForkRpc()) return;
        forkMainnet();
        factory = new CatapultarFactory();
        validator = new CATValidatorV2(VM_ADDR, GAS_CAP);
        swap = new MockSwap();
        json = readFixture(HASH_PARITY_VECTORS);
    }

    /// @dev The inputs threaded through the escrow-flow harness. Grouped in a
    /// struct to keep `_settle` under the stack limit.
    struct Settlement {
        Outcome[] outcomes;
        AllowanceSpend[] allowances;
        bytes32 programHash;
        bytes32 paramsHash;
        bytes program;
        bytes[] params;
        bytes fillPayload;
        uint256 nonce;
    }

    /* ─────────────────────────── Row A — passing program
    settles ────────── */

    function test_passingProgramSettles() external {
        if (!hasForkRpc()) return vm.skip(true);

        // Floor met exactly and the program (WETH >= preBalance + 0) is
        // trivially satisfied by any non-decreasing balance: the fill delivers
        // the full floor amount.
        deal(WETH, DELIVERY, 0);
        (bytes memory program, bytes[] memory params) = _erc20FloorProgram(WETH, DELIVERY, 0);
        Settlement memory s = _floorCase(program, params, FLOOR, FLOOR, 1);

        (bool ok,, address escrow) = _settle(s);

        assertTrue(ok, "passing program did not settle through the escrow path");
        assertTrue(validator.spentNonces(escrow, s.nonce), "nonce not spent after settlement");
        assertEq(SafeTransferLib.balanceOf(WETH, DELIVERY), FLOOR, "outcome not delivered");
    }

    /* ─────────────────────────── Row B — stronger-than-floor
    fails ──────── */

    function test_strongerThanFloorRevertsValidationFailed() external {
        if (!hasForkRpc()) return vm.skip(true);

        // The committed program demands WETH >= preBalance + 2 ether — strictly
        // stronger than the 1 ether floor. The fill delivers exactly the floor
        // (1 ether): the floor passes, the program does not.
        deal(WETH, DELIVERY, 0);
        (bytes memory program, bytes[] memory params) = _erc20FloorProgram(WETH, DELIVERY, 2 ether);
        Settlement memory s = _floorCase(program, params, FLOOR, FLOOR, 2);

        (bool ok, bytes memory ret, address escrow) = _settle(s);

        assertFalse(ok, "stronger-than-floor program unexpectedly settled");
        assertEq(bytes4(ret), CATValidatorV2.ValidationFailed.selector, "not ValidationFailed");
        bytes memory inner = abi.decode(_stripSelector(ret), (bytes));
        assertEq(bytes4(inner), ASSERT_GTE_FAILED, "inner selector not AssertGteFailed");
        // Refundable: the whole settlement rolled back.
        assertFalse(validator.spentNonces(escrow, s.nonce), "nonce spent despite validation failure");
        assertEq(SafeTransferLib.balanceOf(WETH, escrow), s.allowances[0].allocated, "escrow funds not refunded");
        assertEq(SafeTransferLib.balanceOf(WETH, DELIVERY), 0, "delivery balance not rolled back");
    }

    /* ─────────────────────────── Row C — floor enforced first
    ───────────── */

    function test_floorFirstInvalidTokenAmount() external {
        if (!hasForkRpc()) return vm.skip(true);

        // The committed program (WETH >= preBalance + 0) would pass, but the
        // fill delivers below the floor: the floor runs first and reverts before
        // the program is ever executed.
        deal(WETH, DELIVERY, 0);
        (bytes memory program, bytes[] memory params) = _erc20FloorProgram(WETH, DELIVERY, 0);
        Settlement memory s = _floorCase(program, params, FLOOR, 0.5 ether, 3);

        (bool ok, bytes memory ret, address escrow) = _settle(s);

        assertFalse(ok, "sub-floor fill unexpectedly settled");
        assertEq(bytes4(ret), CATValidatorV2.InvalidTokenAmount.selector, "floor must revert InvalidTokenAmount first");
        assertFalse(validator.spentNonces(escrow, s.nonce), "nonce spent despite floor failure");
    }

    /* ─────────────────────────── Row D — uc1 enforced
    end-to-end ────────── */

    function test_uc1EnforcedEndToEnd() external {
        if (!hasForkRpc()) return vm.skip(true);

        // The pinned uc1 program asserts WETH.balanceOf(delivery) >= preBalance +
        // 1e18 and USDC.balanceOf(delivery) >= 500e6. Snapshot delivery at 0 WETH,
        // fund USDC directly (absolute invariant), and let the fill deliver 1e18
        // WETH so both asserts pass.
        deal(WETH, DELIVERY, 0);
        deal(USDC, DELIVERY, 500e6);

        Settlement memory s;
        s.program = vm.parseJsonBytes(json, ".programVectors[0].canonicalBody");
        s.programHash = vm.parseJsonBytes32(json, ".programVectors[0].validationProgramHash");
        s.paramsHash = vm.parseJsonBytes32(json, ".programVectors[0].paramsHash");
        s.params = _uc1Params();
        s.nonce = 4;

        s.outcomes = new Outcome[](1);
        s.outcomes[0] = Outcome({ token: WETH, amount: 0, destination: DELIVERY });
        s.allowances = _wethAllowance(1 ether);
        s.fillPayload = abi.encodeCall(MockSwap.fill, (WETH, DELIVERY, 1 ether));

        (bool ok,, address escrow) = _settle(s);

        assertTrue(ok, "uc1 program did not settle through the escrow path");
        assertTrue(validator.spentNonces(escrow, s.nonce), "nonce not spent after uc1 settlement");
    }

    /* ─────────────────────────── escrow-flow harness
    ────────────────────── */

    /// @dev Deploy a digest-committed escrow, run its embedded approve +
    /// setSignature calls, fund it, and settle through `entry()` as the executor
    /// with an empty signature (ERC-1271 accepts the pre-approved digest).
    function _settle(
        Settlement memory s
    ) internal returns (bool ok, bytes memory ret, address escrow) {
        address executor = makeAddr("vc/iv2/executor");
        address owner = makeAddr(string.concat("vc/iv2/owner-", vm.toString(++ownerSeed)));

        bytes32 structHash =
            this.exposedTypehash(s.allowances, s.outcomes, executor, s.nonce, s.programHash, s.paramsHash);
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", validator.DOMAIN_SEPARATOR(), structHash));

        ERC7821.Call[] memory calls = new ERC7821.Call[](2);
        calls[0] = ERC7821.Call({
            to: s.allowances[0].token,
            data: abi.encodeWithSignature("approve(address,uint256)", address(validator), s.allowances[0].allocated),
            value: 0
        });
        calls[1] = ERC7821.Call({
            to: address(0), // self
            data: abi.encodeCall(Catapultar.setSignature, (digest, Catapultar.DigestApproval.Signature)),
            value: 0
        });

        {
            bytes32 callsTypeHash = this.exposedCallsTypehash(1, REVERT_MODE, calls);
            bytes32[] memory keys = new bytes32[](1);
            keys[0] = bytes32(uint256(uint160(owner)));
            escrow = factory.deployWithDigest(
                KeyedOwnable.PublicKeyType.ECDSAOrSmartContract,
                keys,
                bytes32(bytes20(uint160(owner))),
                callsTypeHash,
                false
            );
            Catapultar(payable(escrow)).execute(REVERT_MODE, abi.encode(calls, abi.encodePacked(uint256(1))));
            deal(s.allowances[0].token, escrow, s.allowances[0].allocated);
        }

        bytes memory callData = abi.encodeCall(
            CATValidatorV2.entry,
            (
                address(swap),
                s.fillPayload,
                escrow,
                s.nonce,
                s.allowances,
                s.outcomes,
                s.programHash,
                s.paramsHash,
                s.program,
                s.params,
                hex""
            )
        );
        vm.prank(executor);
        (ok, ret) = address(validator).call(callData);
    }

    /// @dev A single-WETH-outcome settlement: floor amount `floorAmount`, the
    /// fill delivering `deliverAmount` WETH sourced from the escrow's allowance.
    function _floorCase(
        bytes memory program,
        bytes[] memory params,
        uint256 floorAmount,
        uint256 deliverAmount,
        uint256 nonce
    ) internal pure returns (Settlement memory s) {
        s.program = program;
        s.params = params;
        s.programHash = keccak256(program);
        s.paramsHash = _paramsHash(params);
        s.nonce = nonce;

        s.outcomes = new Outcome[](1);
        s.outcomes[0] = Outcome({ token: WETH, amount: floorAmount, destination: DELIVERY });
        s.allowances = _wethAllowance(FLOOR);
        s.fillPayload = abi.encodeCall(MockSwap.fill, (WETH, DELIVERY, deliverAmount));
    }

    function _wethAllowance(
        uint256 amount
    ) internal pure returns (AllowanceSpend[] memory allowances) {
        allowances = new AllowanceSpend[](1);
        allowances[0] = AllowanceSpend({ token: WETH, allocated: amount, spend: amount });
    }

    /* ─────────────────────────── program authoring
    ──────────────────────── */

    /// @dev The uc1 `erc20-floor` shape (VmPrograms.t.sol), parameterized by
    /// token and delivery: reads balanceOf(delivery), computes preBalance + min
    /// via evaluateRPN, asserts current >= preBalance + min.
    /// Layout: [0]=delivery [1]=min [2]=rpnWord [3]=rpnLen ; account at 4 ; preBal0 at 5.
    function _erc20FloorProgram(
        address token,
        address dlv,
        uint256 min
    ) internal pure returns (bytes memory program, bytes[] memory params) {
        params = new bytes[](4);
        params[0] = abi.encodePacked(bytes32(uint256(uint160(dlv))));
        params[1] = abi.encodePacked(bytes32(min));
        // RPN: 0x80 push regValues[0]=preBal0, 0x81 push regValues[1]=min, 0x00 ADD.
        params[2] = abi.encodePacked(bytes32(uint256(0x808100) << 232));
        params[3] = abi.encodePacked(bytes32(uint256(3)));

        bytes memory bpBalance = abi.encodePacked(ProgramBuilder.bpStatic(0));
        bytes memory bpRpn = abi.encodePacked(
            ProgramBuilder.START_ARRAY_DYNAMIC,
            ProgramBuilder.bpStatic(5), // preBal0
            ProgramBuilder.bpStatic(1), // min
            ProgramBuilder.END_CONTAINER,
            ProgramBuilder.bpStatic(2), // rpnWord
            ProgramBuilder.bpStatic(3) // rpnLen
        );
        bytes memory bpAssert = abi.encodePacked(ProgramBuilder.bpStatic(7), ProgramBuilder.bpStatic(9));

        program = abi.encodePacked(
            ProgramBuilder.cmd(
                ProgramBuilder.OP_CALLDATA_BUILD,
                ProgramBuilder.packCallDataBuild(ProgramBuilder.SEL_BALANCE_OF, 6, bpBalance)
            ),
            ProgramBuilder.cmd(
                ProgramBuilder.OP_CALL, ProgramBuilder.packCall(token, ProgramBuilder.CALLTYPE_STATICCALL, 7, 6, 0)
            ),
            ProgramBuilder.cmd(
                ProgramBuilder.OP_CALLDATA_BUILD,
                ProgramBuilder.packCallDataBuild(ProgramBuilder.SEL_EVALUATE_RPN, 8, bpRpn)
            ),
            ProgramBuilder.cmd(
                ProgramBuilder.OP_CALL,
                ProgramBuilder.packCall(ARITHMETIC_PROCESSOR, ProgramBuilder.CALLTYPE_STATICCALL, 9, 8, 0)
            ),
            ProgramBuilder.cmd(
                ProgramBuilder.OP_CALLDATA_BUILD,
                ProgramBuilder.packCallDataBuild(ProgramBuilder.SEL_ASSERT_GTE, 10, bpAssert)
            ),
            ProgramBuilder.cmd(
                ProgramBuilder.OP_CALL,
                ProgramBuilder.packCall(INVARIANT_CHECKER, ProgramBuilder.CALLTYPE_STATICCALL, 11, 10, 0)
            )
        );
    }

    function _uc1Params() internal view returns (bytes[] memory params) {
        uint256 count = jsonArrayLength(json, ".programVectors[0].params");
        params = new bytes[](count);
        for (uint256 i; i < count; ++i) {
            params[i] = abi.encodePacked(
                vm.parseJsonBytes32(json, string.concat(".programVectors[0].params[", vm.toString(i), "].word"))
            );
        }
    }

    /* ─────────────────────────── low-level plumbing
    ─────────────────────── */

    function _paramsHash(
        bytes[] memory params
    ) internal pure returns (bytes32) {
        bytes memory buffer;
        for (uint256 i; i < params.length; ++i) {
            require(params[i].length == 32, "param not 32 bytes");
            buffer = abi.encodePacked(buffer, params[i]);
        }
        return params.length == 0 ? bytes32(0) : keccak256(buffer);
    }

    function _stripSelector(
        bytes memory data
    ) internal pure returns (bytes memory out) {
        out = new bytes(data.length - 4);
        for (uint256 i; i < out.length; ++i) {
            out[i] = data[i + 4];
        }
    }

    /* ── calldata trampoline for LibCalls' calldata-typed arguments ── */

    function exposedCallsTypehash(
        uint256 nonce,
        bytes32 mode,
        ERC7821.Call[] calldata calls
    ) external pure returns (bytes32) {
        return LibCalls.typehash(nonce, mode, calls);
    }
}
