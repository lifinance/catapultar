// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { Test } from "forge-std/src/Test.sol";
import { SafeTransferLib } from "solady/src/utils/SafeTransferLib.sol";
import { MockERC20 } from "solady/test/utils/mocks/MockERC20.sol";

import { CATValidator } from "../src/CATValidator.sol";
import { CATValidatorV1_1 } from "../src/CATValidatorV1_1.sol";
import { ICATValidatorV1_1 } from "../src/interfaces/ICATValidatorV1_1.sol";
import { AllowanceSpend, Outcome } from "../src/libs/LibExecutionConstraint.sol";
import { FeeOnTransferERC20, TypehashHelper, ZeroRejectingERC20 } from "./CATValidatorV1_1.t.sol";

/// @dev Execution target: holds funds, and on `deliver` pays each token to the validator, like a solver.
contract DiffTarget {
    function deliver(
        address validator,
        address[] calldata tokens,
        uint256[] calldata amounts
    ) external {
        for (uint256 i; i < tokens.length; ++i) {
            SafeTransferLib.safeTransfer(tokens[i], validator, amounts[i]);
        }
    }
}

/// @dev V1.1's 9-argument `entry` against `CATValidator.entry`, the vendored upstream base it builds on, with the
/// same fuzzed allowances, outcomes and payload. Each side is signed under its own type string and domain and runs on
/// one state snapshot. Everything observable must match except the deltas V1.1 adds: the value `_call` forwards, zero
/// payouts on zero-rejecting tokens, `pulled` and `entryId`.
contract CATValidatorV1_1DifferentialTest is Test {
    uint256 constant CAP = 1e12;
    uint256 constant FUND = 1e13;
    uint256 constant SPEND_MAGIC = 1 << 255;
    uint256 constant TOKENS = 3;

    CATValidator hf;
    CATValidatorV1_1 v11;
    TypehashHelper thh;
    DiffTarget target;
    FeeOnTransferERC20 tFee;
    MockERC20 t0;
    MockERC20 t1;
    ZeroRejectingERC20 zt;
    address[TOKENS] tokens;

    address executor = makeAddr("executor");
    address sink = makeAddr("sink");
    address signer;
    uint256 signerKey;

    struct Spec {
        uint256[3] tok;
        uint256[3] allocated;
        uint256[3] spend;
        bool[3] magic;
        uint8 nAllow;
        uint256[2] outTok;
        uint256[2] outAmount;
        uint256[2] delivered;
        uint8[2] outDest;
        uint8 nOut;
        uint256 nonce;
        bool withPayload;
    }

    struct Case {
        AllowanceSpend[] allowances;
        Outcome[] outcomes;
        address[] deliverTokens;
        uint256[] delivered;
        uint256 nonce;
        bool withPayload;
    }

    struct Result {
        bool ok;
        bytes ret;
        uint256[] balances;
        bool nonceSpent;
        uint256 pulledAfter;
        uint256 entryIdAfter;
    }

    function setUp() external {
        hf = new CATValidator();
        v11 = new CATValidatorV1_1();
        thh = new TypehashHelper();
        target = new DiffTarget();
        t0 = new MockERC20("A", "A", 6);
        t1 = new MockERC20("B", "B", 6);
        tFee = new FeeOnTransferERC20();
        zt = new ZeroRejectingERC20();
        tokens = [address(t0), address(t1), address(tFee)];
        (signer, signerKey) = makeAddrAndKey("signer");

        for (uint256 i; i < TOKENS; ++i) {
            MockERC20(tokens[i]).mint(signer, FUND);
            MockERC20(tokens[i]).mint(address(target), FUND);
            vm.startPrank(signer);
            MockERC20(tokens[i]).approve(address(hf), type(uint256).max);
            MockERC20(tokens[i]).approve(address(v11), type(uint256).max);
            vm.stopPrank();
        }
        zt.mint(signer, FUND);
        vm.startPrank(signer);
        zt.approve(address(hf), type(uint256).max);
        zt.approve(address(v11), type(uint256).max);
        vm.stopPrank();
    }

    function testFuzz_differential_same_outcome_as_the_base(
        Spec memory s
    ) external {
        Case memory c = _case(s);
        (Result memory a, Result memory b) = _both(c);
        _assertSame(a, b);
    }

    function testFuzz_differential_settled_entries_move_the_same_funds(
        Spec memory s
    ) external {
        Case memory c = _case(s);
        c.nonce = bound(s.nonce, 1, 3);
        for (uint256 i; i < c.allowances.length; ++i) {
            c.allowances[i].allocated = type(uint256).max;
        }
        for (uint256 i; i < c.outcomes.length; ++i) {
            c.outcomes[i].amount = 0;
        }
        (Result memory a, Result memory b) = _both(c);
        _assertSame(a, b);
    }

    /// @dev Delta 1: the base forwards its whole native balance to the call, which a non-payable target refuses;
    ///      V1.1 forwards none.
    function test_differential_call_value_is_forwarded_by_the_base_only() external {
        vm.deal(address(hf), 1 wei);
        vm.deal(address(v11), 1 wei);
        Case memory c = _plain(1);
        c.withPayload = true;
        Result memory a = _run(address(hf), false, c);
        Result memory b = _run(address(v11), true, c);
        assertFalse(a.ok, "the base forwarded value to a non-payable target");
        assertTrue(b.ok, "V1.1 forwards no value");
    }

    /// @dev Delta 2: a zero payout on a zero-rejecting token reverts in the base and settles in V1.1.
    function test_differential_zero_payout_on_a_zero_rejecting_token() external {
        Case memory c = _plain(1);
        c.outcomes = new Outcome[](1);
        c.outcomes[0] = Outcome({ token: address(zt), amount: 0, destination: sink });
        Result memory a = _run(address(hf), false, c);
        Result memory b = _run(address(v11), true, c);
        assertFalse(a.ok, "the base pays zero");
        assertEq(bytes4(a.ret), SafeTransferLib.TransferFailed.selector);
        assertTrue(b.ok, "V1.1 skips the zero payout");
    }

    /// @dev Delta 3: V1.1 publishes `pulled` and an entry id only inside its own entry; the base has neither.
    function test_differential_pulled_and_entry_id_are_zero_after_both() external {
        Case memory c = _plain(1);
        (Result memory a, Result memory b) = _both(c);
        assertEq(a.pulledAfter, 0);
        assertEq(b.pulledAfter, 0);
        assertEq(b.entryIdAfter, 0);
    }

    function _assertSame(
        Result memory a,
        Result memory b
    ) internal pure {
        assertEq(a.ok, b.ok, "success differs");
        assertEq(a.ret, b.ret, "revert data differs");
        assertEq(a.nonceSpent, b.nonceSpent, "nonce differs");
        assertEq(a.balances, b.balances, "balances differ");
    }

    function _both(
        Case memory c
    ) internal returns (Result memory a, Result memory b) {
        uint256 snap = vm.snapshotState();
        a = _run(address(hf), false, c);
        vm.revertToState(snap);
        b = _run(address(v11), true, c);
    }

    function _run(
        address validator,
        bool isV11,
        Case memory c
    ) internal returns (Result memory r) {
        bytes32 structHash = isV11
            ? thh.v11(c.allowances, c.outcomes, executor, c.nonce, address(0), 0)
            : thh.v1(c.allowances, c.outcomes, executor, c.nonce);
        bytes32 digest = keccak256(abi.encodePacked(hex"1901", _domainSep(isV11 ? "1.1" : "1", validator), structHash));
        (uint8 v, bytes32 rr, bytes32 ss) = vm.sign(signerKey, digest);
        bytes memory payload =
            c.withPayload ? abi.encodeCall(DiffTarget.deliver, (validator, c.deliverTokens, c.delivered)) : bytes("");
        bytes memory data = isV11
            ? abi.encodeCall(
                ICATValidatorV1_1.entry,
                (
                    address(target),
                    payload,
                    signer,
                    c.nonce,
                    c.allowances,
                    c.outcomes,
                    address(0),
                    bytes32(0),
                    abi.encodePacked(rr, ss, v)
                )
            )
            : abi.encodeCall(
                CATValidator.entry,
                (address(target), payload, signer, c.nonce, c.allowances, c.outcomes, abi.encodePacked(rr, ss, v))
            );
        vm.prank(executor);
        (r.ok, r.ret) = validator.call(data);
        r.balances = _balances(validator);
        r.nonceSpent = CATValidator(payable(validator)).spentNonces(signer, c.nonce);
        if (isV11) {
            r.pulledAfter = v11.pulled(address(t0));
            r.entryIdAfter = v11.entryId();
        }
    }

    function _balances(
        address validator
    ) internal view returns (uint256[] memory out) {
        out = new uint256[](TOKENS * 4 + 1);
        for (uint256 i; i < TOKENS; ++i) {
            MockERC20 t = MockERC20(tokens[i]);
            out[i * 4] = t.balanceOf(signer);
            out[i * 4 + 1] = t.balanceOf(sink);
            out[i * 4 + 2] = t.balanceOf(address(target));
            out[i * 4 + 3] = t.balanceOf(validator);
        }
        out[TOKENS * 4] = signer.balance + sink.balance;
    }

    function _plain(
        uint256 nonce
    ) internal view returns (Case memory c) {
        c.allowances = new AllowanceSpend[](1);
        c.allowances[0] = AllowanceSpend({ token: address(t0), allocated: 10e6, spend: 10e6 });
        c.outcomes = new Outcome[](0);
        c.deliverTokens = new address[](0);
        c.delivered = new uint256[](0);
        c.nonce = nonce;
    }

    function _case(
        Spec memory s
    ) internal view returns (Case memory c) {
        uint256 n = bound(s.nAllow, 0, 3);
        c.allowances = new AllowanceSpend[](n);
        for (uint256 i; i < n; ++i) {
            address t = tokens[s.tok[i] % TOKENS];
            uint256 spend = s.magic[i] ? SPEND_MAGIC : bound(s.spend[i], 0, CAP);
            uint256 allocated = s.magic[i] ? bound(s.allocated[i], 0, 2 * FUND) : bound(s.allocated[i], 0, 2 * CAP);
            c.allowances[i] = AllowanceSpend({ token: t, allocated: allocated, spend: spend });
        }
        uint256 m = bound(s.nOut, 0, 2);
        c.outcomes = new Outcome[](m);
        c.deliverTokens = new address[](m);
        c.delivered = new uint256[](m);
        for (uint256 j; j < m; ++j) {
            address t = tokens[s.outTok[j] % TOKENS];
            c.outcomes[j] = Outcome({
                token: t, amount: bound(s.outAmount[j], 0, CAP), destination: s.outDest[j] % 2 == 0 ? address(0) : sink
            });
            c.deliverTokens[j] = t;
            c.delivered[j] = bound(s.delivered[j], 0, CAP);
        }
        c.nonce = 1 + (s.nonce % 3);
        c.withPayload = s.withPayload;
    }

    function _domainSep(
        string memory version,
        address verifying
    ) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("CAT Validator")),
                keccak256(bytes(version)),
                block.chainid,
                verifying
            )
        );
    }
}
