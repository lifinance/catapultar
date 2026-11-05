// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { IERC20 } from "forge-std/src/interfaces/IERC20.sol";
import { ERC7821 } from "solady/src/accounts/ERC7821.sol";
import { SafeTransferLib } from "solady/src/utils/SafeTransferLib.sol";

import { CATValidatorV2 } from "../../src/CATValidatorV2.sol";
import { Catapultar } from "../../src/Catapultar.sol";
import { CatapultarFactory } from "../../src/CatapultarFactory.sol";
import { KeyedOwnable } from "../../src/libs/KeyedOwnable.sol";
import { LibCalls } from "../../src/libs/LibCalls.sol";
import { AllowanceSpend, Outcome } from "../../src/libs/LibExecutionConstraint.sol";
import { ExecutionBinding } from "../../src/libs/LibExecutionConstraintV2.sol";
import { LibValidationVM, VMCommand, VMState } from "../../src/libs/LibValidationVM.sol";
import { ProgramBuilder as PB } from "./ProgramBuilder.sol";
import { VcTestBase } from "./VcTestBase.sol";

interface IAggregator {
    function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80);
}

contract MockFill {
    function fill(
        address outToken,
        address to,
        uint256 outAmount
    ) external {
        SafeTransferLib.safeTransfer(outToken, to, outAmount);
    }
}

/// Oracle stop-loss validation program on the deployed v1.2 VM / InvariantChecker /
/// ArithmeticProcessor / Multicall3 and the live canonical Chainlink ETH/USD feed, settled
/// through the deployed CATValidatorV2.entry on a Base fork.
contract OracleStopTest is VcTestBase {
    bytes32 internal constant REVERT_MODE = bytes32(bytes10(0x01010000000078210001));
    address internal constant FEED = BASE_FEED_ETH_USD;
    address internal constant FEED_BTC = BASE_FEED_BTC_USD;
    address internal constant WETH_ = BASE_WETH;
    address internal constant USDC_ = BASE_USDC;
    address internal constant DELIVERY = 0x1111111111111111111111111111111111111111;
    uint256 internal constant SPEND_ALL = 1 << 255;
    uint256 internal constant ESCROW_USDC = 3000e6;

    bytes4 internal constant SEL_LATEST_ROUND = 0xfeaf968c;
    bytes4 internal constant SEL_NOW = 0x0f28c97d; // Multicall3.getCurrentBlockTimestamp()
    bytes4 internal constant SEL_RANGE = 0xd01207a8; // assertInRange(uint256,uint256,uint256)
    bytes4 internal constant SEL_LTE = 0x99a9e3bb; // assertLessThanEqual(uint256,uint256)
    bytes4 internal constant RANGE_FAILED = 0x825915f9;
    bytes4 internal constant LTE_FAILED = 0xb5c6fd70;
    uint8 internal constant OP_EXPLODE = 2;
    uint8 internal constant RPN_ADD = 0;
    uint8 internal constant V = 0x7A; // void register

    // params 0-6 | account 7 | spent[0] 8 | paid[0] 9 | scratch 10+
    uint8 constant R_STRIKE = 0;
    uint8 constant R_MAX_AGE = 1;
    uint8 constant R_ONE = 2;
    uint8 constant R_RPN = 3;
    uint8 constant R_RPN_LEN = 4;
    uint8 constant R_NOT_BEFORE = 5;
    uint8 constant R_EXPIRY = 6;
    uint8 constant R_CD_FEED = 10;
    uint8 constant R_ROUND = 11;
    uint8 constant R_ANSWER = 12;
    uint8 constant R_UPDATED = 13;
    uint8 constant R_CD_NOW = 14;
    uint8 constant R_NOW = 15;
    uint8 constant R_CD_RPN = 16;
    uint8 constant R_DEADLINE = 17;
    uint8 constant R_CD_ASSERT = 18;

    CatapultarFactory factory;
    CATValidatorV2 validator;
    MockFill swap;
    address executor;

    function setUp() external {
        forkBaseIfConfigured();
        if (!hasBaseFork()) return;
        factory = new CatapultarFactory();
        validator = CATValidatorV2(BASE_VALIDATOR_V2);
        swap = new MockFill();
        executor = makeAddr("executor");
        deal(WETH_, DELIVERY, 0);
    }

    function _cdb(
        bytes4 sel,
        uint8 dest,
        bytes memory bp
    ) internal pure returns (VMCommand memory) {
        return VMCommand({ op: PB.OP_CALLDATA_BUILD, data: PB.packCallDataBuild(sel, dest, bp) });
    }

    function _call(
        address target,
        uint8 dest,
        uint8 src
    ) internal pure returns (VMCommand memory) {
        return VMCommand({ op: PB.OP_CALL, data: PB.packCall(target, PB.CALLTYPE_STATICCALL, dest, src, 0) });
    }

    /// EXPLODE latestRoundData's 5 words: roundId->void, answer, startedAt->void, updatedAt, answeredInRound->void.
    function _explodeRound(
        uint8 src,
        uint8 answer,
        uint8 updated
    ) internal pure returns (VMCommand memory) {
        bytes32 w = bytes32(uint256(src)) << 248 | bytes32(uint256(5)) << 240;
        w |= bytes32(uint256(V)) << 232 | bytes32(uint256(answer)) << 224 | bytes32(uint256(V)) << 216;
        w |= bytes32(uint256(updated)) << 208 | bytes32(uint256(V)) << 200;
        return VMCommand({ op: OP_EXPLODE, data: w });
    }

    /// The stop-loss program: 1 <= answer <= strike, now <= updatedAt + maxAge, notBefore <= now <= expiry.
    function stopProgram(
        uint256 strike,
        uint256 maxAge,
        uint256 notBefore,
        uint256 expiry
    ) internal pure returns (VMCommand[] memory p, bytes32[] memory params) {
        bytes memory rpn = abi.encodePacked(PB.RPN_PUSH | 0, PB.RPN_PUSH | 1, RPN_ADD);
        params = new bytes32[](7);
        params[R_STRIKE] = bytes32(strike);
        params[R_MAX_AGE] = bytes32(maxAge);
        params[R_ONE] = bytes32(uint256(1));
        params[R_RPN] = PB.rpnWord(rpn);
        params[R_RPN_LEN] = bytes32(rpn.length);
        params[R_NOT_BEFORE] = bytes32(notBefore);
        params[R_EXPIRY] = bytes32(expiry);

        p = new VMCommand[](13);
        p[0] = _cdb(SEL_LATEST_ROUND, R_CD_FEED, "");
        p[1] = _call(FEED, R_ROUND, R_CD_FEED);
        p[2] = _explodeRound(R_ROUND, R_ANSWER, R_UPDATED);
        p[3] = _cdb(SEL_NOW, R_CD_NOW, "");
        p[4] = _call(MULTICALL3, R_NOW, R_CD_NOW);
        p[5] = _cdb(
            PB.SEL_EVALUATE_RPN,
            R_CD_RPN,
            abi.encodePacked(PB.START_ARRAY_DYNAMIC, R_UPDATED, R_MAX_AGE, PB.END_CONTAINER, R_RPN, R_RPN_LEN)
        );
        p[6] = _call(ARITHMETIC_PROCESSOR, R_DEADLINE, R_CD_RPN);
        p[7] = _cdb(SEL_RANGE, R_CD_ASSERT, abi.encodePacked(R_ANSWER, R_ONE, R_STRIKE));
        p[8] = _call(INVARIANT_CHECKER, V, R_CD_ASSERT);
        p[9] = _cdb(SEL_LTE, R_CD_ASSERT, abi.encodePacked(R_NOW, R_DEADLINE));
        p[10] = _call(INVARIANT_CHECKER, V, R_CD_ASSERT);
        p[11] = _cdb(SEL_RANGE, R_CD_ASSERT, abi.encodePacked(R_NOW, R_NOT_BEFORE, R_EXPIRY));
        p[12] = _call(INVARIANT_CHECKER, V, R_CD_ASSERT);
    }

    function _round() internal view returns (uint256 answer, uint256 updatedAt) {
        (, int256 a,, uint256 u,) = IAggregator(FEED).latestRoundData();
        return (uint256(a), u);
    }

    /* ------------------------------ settlement through CATValidatorV2.entry ------------------------------ */

    function test_stop_triggered_settles() external onlyBaseFork {
        (uint256 answer,) = _round();
        _settle(answer, 3600, block.timestamp - 1, block.timestamp + 1 days, 1, "");
        assertEq(SafeTransferLib.balanceOf(WETH_, DELIVERY), 1 ether, "outcome not delivered");
    }

    function test_stop_notTriggered_reverts() external onlyBaseFork {
        (uint256 answer,) = _round();
        uint256 strike = answer - 1;
        _settle(strike, 3600, 0, type(uint64).max, 2, abi.encodeWithSelector(RANGE_FAILED, answer, 1, strike));
    }

    function test_stop_staleFeed_reverts() external onlyBaseFork {
        (, uint256 updatedAt) = _round();
        uint256 maxAge = 3600;
        vm.warp(updatedAt + maxAge + 1);
        (uint256 answer,) = _round();
        _settle(
            answer,
            maxAge,
            0,
            type(uint64).max,
            3,
            abi.encodeWithSelector(LTE_FAILED, block.timestamp, updatedAt + maxAge)
        );
    }

    function test_stop_negativeAnswer_reverts() external onlyBaseFork {
        vm.mockCall(
            FEED,
            abi.encodeWithSelector(SEL_LATEST_ROUND),
            abi.encode(uint80(1), int256(-5), block.timestamp, block.timestamp, uint80(1))
        );
        uint256 strike = 3000e8;
        _settle(
            strike, 3600, 0, type(uint64).max, 4, abi.encodeWithSelector(RANGE_FAILED, uint256(int256(-5)), 1, strike)
        );
    }

    function test_stop_expired_reverts() external onlyBaseFork {
        (uint256 answer,) = _round();
        uint256 expiry = block.timestamp - 1;
        _settle(answer, 1 days, 0, expiry, 5, abi.encodeWithSelector(RANGE_FAILED, block.timestamp, 0, expiry));
    }

    function test_stop_notYetActive_reverts() external onlyBaseFork {
        (uint256 answer,) = _round();
        uint256 notBefore = block.timestamp + 1;
        _settle(
            answer,
            1 days,
            notBefore,
            type(uint64).max,
            6,
            abi.encodeWithSelector(RANGE_FAILED, block.timestamp, notBefore, type(uint64).max)
        );
    }

    /* --------------------- pair form: (A/B) <= strike/scale  <=>  A*scale <= strike*B --------------------- */

    function pairProgram(
        uint256 strike,
        uint256 scale
    ) internal pure returns (VMCommand[] memory p, bytes32[] memory params) {
        // params: 0 strike, 1 scale, 2 ONE, 3 CAP, 4 rpn(MUL), 5 rpnLen | account 6 | scratch 7+
        bytes memory rpn = abi.encodePacked(PB.RPN_PUSH | 0, PB.RPN_PUSH | 1, PB.RPN_MUL);
        params = new bytes32[](6);
        params[0] = bytes32(strike);
        params[1] = bytes32(scale);
        params[2] = bytes32(uint256(1));
        params[3] = bytes32(uint256(1) << 128);
        params[4] = PB.rpnWord(rpn);
        params[5] = bytes32(rpn.length);
        // scratch: 7 cd, 8 roundA, 9 a, 10 roundB, 11 b, 12 cdAssert, 13 cdRpn, 14 lhs, 15 rhs
        p = new VMCommand[](15);
        p[0] = _cdb(SEL_LATEST_ROUND, 7, "");
        p[1] = _call(FEED, 8, 7);
        p[2] = _explodeRound(8, 9, V);
        p[3] = _call(FEED_BTC, 10, 7);
        p[4] = _explodeRound(10, 11, V);
        p[5] = _cdb(SEL_RANGE, 12, abi.encodePacked(uint8(9), uint8(2), uint8(3)));
        p[6] = _call(INVARIANT_CHECKER, V, 12);
        p[7] = _cdb(SEL_RANGE, 12, abi.encodePacked(uint8(11), uint8(2), uint8(3)));
        p[8] = _call(INVARIANT_CHECKER, V, 12);
        p[9] = _cdb(
            PB.SEL_EVALUATE_RPN,
            13,
            abi.encodePacked(PB.START_ARRAY_DYNAMIC, uint8(9), uint8(1), PB.END_CONTAINER, uint8(4), uint8(5))
        );
        p[10] = _call(ARITHMETIC_PROCESSOR, 14, 13);
        p[11] = _cdb(
            PB.SEL_EVALUATE_RPN,
            13,
            abi.encodePacked(PB.START_ARRAY_DYNAMIC, uint8(0), uint8(11), PB.END_CONTAINER, uint8(4), uint8(5))
        );
        p[12] = _call(ARITHMETIC_PROCESSOR, 15, 13);
        p[13] = _cdb(SEL_LTE, 12, abi.encodePacked(uint8(14), uint8(15)));
        p[14] = _call(INVARIANT_CHECKER, V, 12);
    }

    /// Runs the program exactly as CATValidatorV2._runValidation does: LibValidationVM.buildRegisters + staticcall.
    function _runAsValidator(
        VMCommand[] memory p,
        bytes32[] memory params
    ) internal view returns (bool ok, bytes memory ret) {
        bytes[] memory regs = this.buildRegs(params);
        (ok, ret) = VM_ADDR.staticcall(abi.encodeWithSelector(LibValidationVM.RUN_VM_SELECTOR, p, VMState(regs)));
    }

    function buildRegs(
        bytes32[] calldata params
    ) external view returns (bytes[] memory) {
        return LibValidationVM.buildRegisters(params, address(this), new uint256[](0), new uint256[](0));
    }

    function test_pair_crossMultiplied() external onlyBaseFork {
        (, int256 a,,,) = IAggregator(FEED).latestRoundData();
        (, int256 b,,,) = IAggregator(FEED_BTC).latestRoundData();
        uint256 scale = 1e18;
        uint256 exact = uint256(a) * scale / uint256(b); // ETH/BTC in 1e18, off-chain only
        (VMCommand[] memory p, bytes32[] memory params) = pairProgram(exact + 1, scale);
        (bool ok, bytes memory ret) = _runAsValidator(p, params);
        assertTrue(ok, string.concat("pair stop should pass: ", vm.toString(ret)));

        (p, params) = pairProgram(exact - 1, scale);
        (ok, ret) = _runAsValidator(p, params);
        assertFalse(ok, "pair stop should fail above strike");
        assertEq(bytes4(ret), LTE_FAILED, "wrong failing invariant");
        emit log_named_uint("ETH/BTC 1e18", exact);
        emit log_named_uint("pair program gas-ish commands", p.length);
    }

    /* ---------------------------------------- harness ---------------------------------------- */

    function _settle(
        uint256 strike,
        uint256 maxAge,
        uint256 notBefore,
        uint256 expiry,
        uint256 nonce,
        bytes memory err
    ) internal {
        (VMCommand[] memory program, bytes32[] memory params) = stopProgram(strike, maxAge, notBefore, expiry);
        AllowanceSpend[] memory allowances = new AllowanceSpend[](1);
        allowances[0] = AllowanceSpend({ token: USDC_, allocated: ESCROW_USDC, spend: SPEND_ALL });
        Outcome[] memory outcomes = new Outcome[](1);
        outcomes[0] = Outcome({ token: WETH_, amount: 0.9 ether, destination: DELIVERY });
        deal(WETH_, address(swap), 1 ether);
        address payable account = _deployEscrow(allowances, outcomes, program, params, nonce);

        if (err.length != 0) {
            vm.expectRevert(abi.encodeWithSelector(CATValidatorV2.ValidationFailed.selector, err));
        }
        vm.prank(executor);
        validator.entry(
            address(swap),
            abi.encodeCall(MockFill.fill, (WETH_, address(validator), 1 ether)),
            account,
            nonce,
            allowances,
            outcomes,
            ExecutionBinding({ executionTarget: address(0), payloadHash: bytes32(0) }),
            program,
            params,
            hex""
        );
        assertEq(validator.spentNonces(account, nonce), err.length == 0, "nonce state");
    }

    function _deployEscrow(
        AllowanceSpend[] memory allowances,
        Outcome[] memory outcomes,
        VMCommand[] memory program,
        bytes32[] memory params,
        uint256 nonce
    ) internal returns (address payable account) {
        (address owner,) = makeAddrAndKey(string.concat("owner-", vm.toString(nonce)));
        bytes32 digest = constraintDigest(
            validator.DOMAIN_SEPARATOR(),
            allowances,
            outcomes,
            executor,
            nonce,
            hashProgram(program),
            hashParams(params)
        );
        ERC7821.Call[] memory calls = new ERC7821.Call[](2);
        calls[0] = ERC7821.Call({
            to: USDC_, value: 0, data: abi.encodeCall(IERC20.approve, (address(validator), ESCROW_USDC))
        });
        calls[1] = ERC7821.Call({
            to: address(0),
            value: 0,
            data: abi.encodeCall(Catapultar.setSignature, (digest, Catapultar.DigestApproval.Signature))
        });
        bytes32[] memory keys = new bytes32[](1);
        keys[0] = bytes32(uint256(uint160(owner)));
        account = factory.deployWithDigest(
            KeyedOwnable.PublicKeyType.ECDSAOrSmartContract,
            keys,
            bytes32(bytes20(owner)),
            this.callsTypehash(1, REVERT_MODE, calls),
            false
        );
        Catapultar(account).execute(REVERT_MODE, abi.encode(calls, abi.encodePacked(uint256(1))));
        deal(USDC_, account, ESCROW_USDC);
    }

    function callsTypehash(
        uint256 n,
        bytes32 mode,
        ERC7821.Call[] calldata calls
    ) external pure returns (bytes32) {
        return LibCalls.typehash(n, mode, calls);
    }
}
