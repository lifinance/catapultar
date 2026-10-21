// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { Test } from "forge-std/src/Test.sol";
import { SafeTransferLib } from "solady/src/utils/SafeTransferLib.sol";
import { MockERC20 } from "solady/test/utils/mocks/MockERC20.sol";

import { CATValidator } from "../src/CATValidator.sol";
import { CATValidatorV1_1 } from "../src/CATValidatorV1_1.sol";
import { ICATValidatorV1_1 } from "../src/interfaces/ICATValidatorV1_1.sol";
import { AllowanceSpend, Outcome } from "../src/libs/LibExecutionConstraint.sol";
import {
    AnyAccount,
    CallbackERC20,
    EntryIdProbe,
    FeeOnTransferERC20,
    IPulled,
    LongReverter,
    NonPayableExecutor,
    ReceiptProbe,
    RecordingProbe,
    TypehashHelper,
    ZeroRejectingERC20
} from "./CATValidatorV1_1.t.sol";
import { CATValidatorV1_1Standalone } from "./reference/CATValidatorV1_1Standalone.sol";

interface IMint {
    function mint(
        address to,
        uint256 amount
    ) external;
}

interface IApprove {
    function approve(
        address spender,
        uint256 amount
    ) external returns (bool);
}

/// @dev Execution target that pays outcome tokens (and native value) to the validator, as a solver does.
contract OutcomeDeliverer {
    function deliver(
        address instance,
        address[] calldata outTokens,
        uint256[] calldata amounts
    ) external {
        for (uint256 i; i < outTokens.length; ++i) {
            if (amounts[i] == 0) continue;
            if (outTokens[i] == address(0)) SafeTransferLib.safeTransferETH(instance, amounts[i]);
            else SafeTransferLib.safeTransfer(outTokens[i], instance, amounts[i]);
        }
    }

    receive() external payable { }
}

interface IDomainSeparator {
    function DOMAIN_SEPARATOR() external view returns (bytes32);
}

/// @dev Differential fuzz of the subclass against the standalone hold-and-forward reference. Each case runs on a state
/// snapshot, once per instance, so both see identical tokens, balances and callers and only the validator address
/// differs.
contract CATValidatorV1_1EquivalenceTest is Test {
    uint256 constant CAP = 1e12;
    uint256 constant FUND = 1e13;
    uint256 constant SPEND_MAGIC = 1 << 255;
    uint256 constant TOKENS = 5;
    uint256 constant ALLOW_TOKENS = 4;
    uint256 constant HOLDERS = 5;
    bytes4 constant PANIC = 0x4e487b71;

    CATValidatorV1_1Standalone standalone;
    CATValidatorV1_1 subject;
    TypehashHelper thh;
    RecordingProbe probe;
    ReceiptProbe hookProbe;
    NonPayableExecutor nonPayable;
    LongReverter longReverter;
    OutcomeDeliverer deliverer;
    AnyAccount acct;

    MockERC20 t0;
    MockERC20 t1;
    FeeOnTransferERC20 tFee;
    CallbackERC20 tCb;
    ZeroRejectingERC20 tZero;
    address[TOKENS] tokens;

    address executor = makeAddr("executor");
    address sink = makeAddr("sink");
    address plainTarget = makeAddr("plainTarget");
    address signer;
    uint256 signerKey;

    struct Spec {
        uint256[3] tok;
        uint256[3] allocated;
        uint256[3] spend;
        uint8[3] mode;
        uint8 nAllow;
        uint256[2] outTok;
        uint8[2] outDest;
        uint256[2] outAmount;
        uint256[2] delivered;
        uint8 nOut;
        uint256 nonce;
        bool zeroNonce;
        uint8 binding;
        uint8 target;
        uint256 forceFed;
        bool replay;
    }

    struct Case {
        AllowanceSpend[] allowances;
        Outcome[] outcomes;
        uint256[] delivered;
        uint256 nonce;
        uint8 binding;
        uint8 target;
        uint256 forceFed;
        bool replay;
        bool signed;
        uint8 sigMode;
    }

    struct Result {
        bool ok;
        bytes ret;
        bool ok2;
        bytes ret2;
        uint256[] seen;
        uint256[] hookSeen;
        uint256[] pulledAfter;
        uint256[] balances;
        bool nonceSpent;
        uint256 entryIdAfter;
    }

    function setUp() external {
        standalone = new CATValidatorV1_1Standalone();
        subject = new CATValidatorV1_1();
        thh = new TypehashHelper();
        probe = new RecordingProbe();
        hookProbe = new ReceiptProbe();
        nonPayable = new NonPayableExecutor();
        longReverter = new LongReverter();
        deliverer = new OutcomeDeliverer();
        acct = new AnyAccount();
        (signer, signerKey) = makeAddrAndKey("signer");

        t0 = new MockERC20("A", "A", 6);
        t1 = new MockERC20("B", "B", 6);
        tFee = new FeeOnTransferERC20();
        tCb = new CallbackERC20();
        tZero = new ZeroRejectingERC20();
        tokens = [address(t0), address(t1), address(tFee), address(tCb), address(tZero)];
    }

    // ---- fuzz lanes ----

    function testFuzz_equivalence_settles_identically(
        Spec memory s
    ) external {
        Case memory c = _settleCase(s);
        (Result memory a, Result memory b) = _both(c);
        assertTrue(a.ok, "settle case reverted");
        _assertSame(a, b);
    }

    function testFuzz_equivalence_reverts_identically(
        Spec memory s,
        uint8 failKind
    ) external {
        failKind = failKind % 8;
        Case memory c = _failCase(s, failKind);
        (Result memory a, Result memory b) = _both(c);
        _assertSame(a, b);

        if (failKind == 6) {
            assertTrue(a.ok, "first call settles");
            assertFalse(a.ok2, "replayed nonce");
            assertEq(a.ret2, abi.encodePacked(CATValidator.NonceAlreadySpent.selector));
            return;
        }
        assertFalse(a.ok, "case did not revert");
        if (failKind == 0) assertEq(bytes4(a.ret), CATValidator.AllocationTooSmall.selector);
        else if (failKind == 1) assertEq(bytes4(a.ret), CATValidator.InvalidTokenAmount.selector);
        else if (failKind == 2) assertEq(bytes4(a.ret), SafeTransferLib.TransferFromFailed.selector);
        else if (failKind == 3) assertEq(bytes4(a.ret), CATValidatorV1_1.TargetNotCommitted.selector);
        else if (failKind == 4) assertEq(bytes4(a.ret), CATValidatorV1_1.PayloadNotCommitted.selector);
        else if (failKind == 5) assertEq(a.ret.length, 196, "long revert data bubbled whole");
        else assertEq(bytes4(a.ret), CATValidator.InvalidTokenAmount.selector);
    }

    function testFuzz_equivalence_pulled_window_identical(
        Spec memory s
    ) external {
        Case memory c = _settleCase(s);
        uint256 n = bound(s.nAllow, 1, 3);
        uint256[TOKENS] memory expected;
        c.allowances = new AllowanceSpend[](n);
        for (uint256 i; i < n; ++i) {
            uint256 amount = bound(s.spend[i], 1, CAP);
            uint256 idx = s.tok[i] % 2 == 0 ? 3 : (s.tok[i] >> 1) % ALLOW_TOKENS;
            c.allowances[i] = AllowanceSpend({ token: tokens[idx], allocated: amount, spend: amount });
            expected[idx] += amount;
        }
        c.target = 0;
        c.binding = c.nonce == 0 ? 1 : 0;
        c.replay = false;
        for (uint256 i; i < c.outcomes.length; ++i) {
            c.outcomes[i].amount = 0;
        }

        (Result memory a, Result memory b) = _both(c);
        assertTrue(a.ok, "window case reverted");
        _assertSame(a, b);
        for (uint256 i; i < TOKENS; ++i) {
            assertEq(a.seen[i], expected[i], "pulled inside the call is the summed spend");
            assertEq(a.pulledAfter[i], 0, "pulled cleared after entry");
        }
        for (uint256 i; i < a.hookSeen.length; ++i) {
            assertEq(a.hookSeen[i], 0, "token hook reads zero inside the loop");
        }
    }

    function testFuzz_equivalence_signed_identically(
        Spec memory s,
        uint8 sigMode
    ) external {
        Case memory c = _settleCase(s);
        c.signed = true;
        c.sigMode = sigMode % 4;
        (Result memory a, Result memory b) = _both(c);
        _assertSame(a, b);
        if (c.sigMode == 0) {
            assertTrue(a.ok, "valid signature rejected");
        } else {
            assertFalse(a.ok, "invalid signature accepted");
            assertEq(a.ret, abi.encodePacked(CATValidator.BadSignature.selector));
        }
    }

    function test_equivalence_domain_and_selectors() external view {
        (, string memory nameA, string memory versionA,,,,) = standalone.eip712Domain();
        (, string memory nameB, string memory versionB,,,,) = subject.eip712Domain();
        assertEq(nameA, nameB);
        assertEq(versionA, versionB);
        assertEq(versionB, "1.1");

        assertEq(standalone.CALL_PROXY().codehash, subject.CALL_PROXY().codehash, "same call proxy runtime");

        assertEq(ICATValidatorV1_1.entry.selector, bytes4(0x6e84b055));
        assertEq(ICATValidatorV1_1.pulled.selector, bytes4(0x6ea6f87f));
        assertEq(standalone.pulled(address(t0)), subject.pulled(address(t0)));
        assertEq(standalone.spentNonces(address(1), 1), subject.spentNonces(address(1), 1));
    }

    /// @dev Entry ids read inside three consecutive entries match: 1, 2, 3 on both instances.
    function test_equivalence_entry_ids_inside_consecutive_entries() external {
        EntryIdProbe[2] memory probes = [new EntryIdProbe(), new EntryIdProbe()];
        address[2] memory instances = [address(standalone), address(subject)];
        for (uint256 k; k < 2; ++k) {
            bytes memory record = abi.encodeCall(EntryIdProbe.record, (instances[k]));
            for (uint256 n = 1; n <= 3; ++n) {
                vm.prank(executor);
                (bool ok,) = instances[k].call(
                    abi.encodeCall(
                        ICATValidatorV1_1.entry,
                        (
                            address(probes[k]),
                            record,
                            address(acct),
                            n,
                            new AllowanceSpend[](0),
                            new Outcome[](0),
                            address(0),
                            bytes32(0),
                            ""
                        )
                    )
                );
                assertTrue(ok);
            }
        }
        for (uint256 n; n < 3; ++n) {
            assertEq(probes[0].ids(n), n + 1);
            assertEq(probes[1].ids(n), n + 1);
        }
    }

    // ---- case builders ----

    function _settleCase(
        Spec memory s
    ) internal view returns (Case memory c) {
        uint256 n = bound(s.nAllow, 1, 3);
        c.allowances = new AllowanceSpend[](n);
        for (uint256 i; i < n; ++i) {
            uint256 idx = s.tok[i] % ALLOW_TOKENS;
            uint256 allocated = bound(s.allocated[i], 0, CAP);
            uint256 mode = s.mode[i] % 3;
            if (mode == 1 && _tokenUsedElsewhere(s, n, i)) mode = 0;
            if (mode == 0) {
                c.allowances[i] = AllowanceSpend({
                    token: tokens[idx], allocated: allocated, spend: bound(s.spend[i], 0, allocated)
                });
            } else if (mode == 1) {
                c.allowances[i] =
                    AllowanceSpend({ token: tokens[idx], allocated: type(uint256).max, spend: SPEND_MAGIC });
            } else {
                c.allowances[i] = AllowanceSpend({ token: tokens[idx], allocated: allocated, spend: 0 });
            }
        }

        uint8[5] memory kinds = [0, 1, 3, 4, 4];
        c.target = kinds[s.target % 5];
        c.outcomes = new Outcome[](bound(s.nOut, 0, 2));
        c.delivered = new uint256[](c.outcomes.length);
        for (uint256 i; i < c.outcomes.length; ++i) {
            address[5] memory outTokens = [address(t0), address(t1), address(tFee), address(tZero), address(0)];
            bool delivers = c.target == 4;
            c.outcomes[i] = Outcome({
                token: outTokens[s.outTok[i] % 5],
                amount: delivers ? bound(s.outAmount[i], 0, CAP) : 0,
                destination: s.outDest[i] % 2 == 0 ? sink : address(0xD00D)
            });
            c.delivered[i] = delivers ? bound(s.delivered[i], c.outcomes[i].amount, CAP) : 0;
            if (i == 1 && c.outcomes[1].token == c.outcomes[0].token) c.outcomes[1].amount = 0;
        }

        c.nonce = s.zeroNonce ? 0 : bound(s.nonce, 1, type(uint256).max);
        c.binding = c.nonce == 0 ? 1 : s.binding % 2;
        c.forceFed = bound(s.forceFed, 0, 1e18);
        c.replay = s.replay;
    }

    function _failCase(
        Spec memory s,
        uint8 failKind
    ) internal view returns (Case memory c) {
        c = _settleCase(s);
        uint256 amount = bound(s.spend[0], 1, CAP);

        if (failKind == 0) {
            c.allowances[0].allocated = amount;
            c.allowances[0].spend = amount + 1;
        } else if (failKind == 1) {
            c.target = 0;
            c.binding = 0;
            c.outcomes = new Outcome[](1);
            c.outcomes[0] = Outcome({ token: address(t0), amount: amount, destination: sink });
        } else if (failKind == 2) {
            c.allowances[0].allocated = type(uint256).max;
            c.allowances[0].spend = FUND + 1;
        } else if (failKind == 3) {
            c.binding = 2;
        } else if (failKind == 4) {
            c.binding = 3;
        } else if (failKind == 5) {
            c.target = 2;
            c.binding = 0;
        } else if (failKind == 6) {
            c.nonce = bound(s.nonce, 1, type(uint256).max);
            c.replay = true;
        } else {
            c.target = 4;
            c.binding = 0;
            c.outcomes = new Outcome[](1);
            c.outcomes[0] = Outcome({ token: address(t0), amount: amount, destination: sink });
            c.delivered = new uint256[](1);
            c.delivered[0] = amount - 1;
        }
        if (c.nonce == 0 && c.binding == 0) c.binding = 1;
    }

    function _tokenUsedElsewhere(
        Spec memory s,
        uint256 n,
        uint256 index
    ) internal pure returns (bool) {
        for (uint256 j; j < n; ++j) {
            if (j != index && s.tok[j] % ALLOW_TOKENS == s.tok[index] % ALLOW_TOKENS) return true;
        }
        return false;
    }

    // ---- differential runner ----

    function _both(
        Case memory c
    ) internal returns (Result memory a, Result memory b) {
        uint256 snap = vm.snapshotState();
        a = _run(address(standalone), address(subject), c);
        vm.revertToState(snap);
        b = _run(address(subject), address(standalone), c);
    }

    function _run(
        address instance,
        address other,
        Case memory c
    ) internal returns (Result memory r) {
        address account = c.signed ? signer : address(acct);
        (address target, bytes memory payload) = _targetAndPayload(c, instance);
        _prepareWorld(instance, c, account);

        bytes memory cd = _entryCall(instance, other, c, account, target, payload);
        (r.ok, r.ret) = _enter(instance, cd);
        if (c.replay) (r.ok2, r.ret2) = _enter(instance, cd);

        _collect(r, instance, c, account, target);
    }

    function _enter(
        address instance,
        bytes memory cd
    ) internal returns (bool ok, bytes memory ret) {
        vm.prank(executor);
        (ok, ret) = instance.call(cd);
    }

    function _targetAndPayload(
        Case memory c,
        address instance
    ) internal view returns (address target, bytes memory payload) {
        uint8 kind = c.target;
        if (kind == 4) {
            address[] memory outTokens = new address[](c.outcomes.length);
            for (uint256 i; i < outTokens.length; ++i) {
                outTokens[i] = c.outcomes[i].token;
            }
            return (address(deliverer), abi.encodeCall(OutcomeDeliverer.deliver, (instance, outTokens, c.delivered)));
        }
        if (kind == 0) {
            address[] memory list = new address[](TOKENS);
            for (uint256 i; i < TOKENS; ++i) {
                list[i] = tokens[i];
            }
            return (address(probe), abi.encodeCall(RecordingProbe.probeTokens, (instance, list)));
        }
        if (kind == 1) {
            return (address(nonPayable), abi.encodeCall(NonPayableExecutor.executeAndSweep, (address(t0), sink)));
        }
        if (kind == 2) {
            uint256[6] memory words = [uint256(1), 2, 3, 4, 5, 6];
            return (address(longReverter), abi.encodeCall(LongReverter.boom, (words)));
        }
        return (plainTarget, "");
    }

    function _binding(
        uint8 mode,
        address target,
        bytes memory payload
    ) internal pure returns (address executionTarget, bytes32 payloadHash) {
        if (mode == 0) return (address(0), bytes32(0));
        if (mode == 1) return (target, keccak256(payload));
        if (mode == 2) return (address(0xDEAD), keccak256(payload));
        return (target, keccak256(payload) ^ bytes32(uint256(1)));
    }

    function _prepareWorld(
        address instance,
        Case memory c,
        address account
    ) internal {
        for (uint256 i; i < TOKENS; ++i) {
            IMint(tokens[i]).mint(account, FUND);
            if (c.signed) {
                vm.prank(account);
                IApprove(tokens[i]).approve(instance, type(uint256).max);
            } else {
                acct.approveToken(tokens[i], instance);
            }
        }
        vm.deal(instance, c.forceFed);
        vm.deal(address(deliverer), FUND);
        for (uint256 i; i < TOKENS; ++i) {
            IMint(tokens[i]).mint(address(deliverer), FUND);
        }
        hookProbe.config(instance, address(tCb));
        tCb.setHook(address(hookProbe));
    }

    function _entryCall(
        address instance,
        address other,
        Case memory c,
        address account,
        address target,
        bytes memory payload
    ) internal returns (bytes memory) {
        (address executionTarget, bytes32 payloadHash) = _binding(c.binding, target, payload);
        bytes memory signature;
        if (c.signed) signature = _signature(instance, other, c, executionTarget, payloadHash);
        return abi.encodeCall(
            ICATValidatorV1_1.entry,
            (target, payload, account, c.nonce, c.allowances, c.outcomes, executionTarget, payloadHash, signature)
        );
    }

    function _signature(
        address instance,
        address other,
        Case memory c,
        address executionTarget,
        bytes32 payloadHash
    ) internal returns (bytes memory) {
        uint256 key = signerKey;
        address signedExecutor = executor;
        address domainOwner = instance;
        if (c.sigMode == 1) (, key) = makeAddrAndKey("wrongSigner");
        else if (c.sigMode == 2) signedExecutor = makeAddr("otherExecutor");
        else if (c.sigMode == 3) domainOwner = other;
        bytes32 digest = keccak256(
            abi.encodePacked(
                hex"1901",
                IDomainSeparator(domainOwner).DOMAIN_SEPARATOR(),
                thh.v11(c.allowances, c.outcomes, signedExecutor, c.nonce, executionTarget, payloadHash)
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }

    function _collect(
        Result memory r,
        address instance,
        Case memory c,
        address account,
        address target
    ) internal view {
        r.seen = new uint256[](probe.count());
        for (uint256 i; i < r.seen.length; ++i) {
            r.seen[i] = probe.at(i);
        }
        r.hookSeen = new uint256[](hookProbe.count());
        for (uint256 i; i < r.hookSeen.length; ++i) {
            r.hookSeen[i] = hookProbe.at(i);
        }

        r.pulledAfter = new uint256[](TOKENS);
        r.balances = new uint256[]((TOKENS + 1) * HOLDERS);
        address[HOLDERS] memory holders = [account, sink, target, instance, address(0xD00D)];
        for (uint256 i; i < TOKENS; ++i) {
            r.pulledAfter[i] = IPulled(instance).pulled(tokens[i]);
            for (uint256 j; j < HOLDERS; ++j) {
                r.balances[i * HOLDERS + j] = MockERC20(tokens[i]).balanceOf(holders[j]);
            }
        }
        for (uint256 j; j < HOLDERS; ++j) {
            r.balances[TOKENS * HOLDERS + j] = holders[j].balance;
        }
        r.nonceSpent = CATValidator(payable(instance)).spentNonces(account, c.nonce);
        r.entryIdAfter = ICATValidatorV1_1(instance).entryId();
    }

    function _assertSame(
        Result memory a,
        Result memory b
    ) internal pure {
        assertEq(a.ok, b.ok, "ok");
        assertEq(a.ret, b.ret, "revert data");
        assertEq(a.ok2, b.ok2, "replay ok");
        assertEq(a.ret2, b.ret2, "replay revert data");
        assertEq(a.seen, b.seen, "pulled inside the call");
        assertEq(a.hookSeen, b.hookSeen, "pulled inside token hooks");
        assertEq(a.pulledAfter, b.pulledAfter, "pulled after entry");
        assertEq(a.balances, b.balances, "balances");
        assertEq(a.nonceSpent, b.nonceSpent, "nonce effect");
        assertEq(a.entryIdAfter, b.entryIdAfter, "entry id after entry");
        assertEq(a.entryIdAfter, 0, "no entry id outside an entry");
    }
}
