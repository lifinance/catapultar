// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { Vm } from "forge-std/src/Vm.sol";

import { CATValidatorV2 } from "../../src/CATValidatorV2.sol";
import { AllowanceSpend, Outcome } from "../../src/libs/LibExecutionConstraint.sol";
import { LibValidationVM, VMCommand, VMState } from "../../src/libs/LibValidationVM.sol";
import { ProgramBuilder } from "./ProgramBuilder.sol";
import { VcTestBase } from "./VcTestBase.sol";

/// @dev Minimal ERC20 with a fixed, test-known storage layout so a runtime-code
/// `vm.etch` at a pinned address behaves fully: balances at slot 0, allowances
/// at slot 1. Returns `true` so it satisfies solady SafeTransferLib.
contract SimpleERC20 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(
        address to,
        uint256 amount
    ) external {
        balanceOf[to] += amount;
    }

    function approve(
        address spender,
        uint256 amount
    ) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(
        address to,
        uint256 amount
    ) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) external returns (bool) {
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

/// @dev Value sink for the VALUECALL behavioral pin: accepts any call + ether.
contract MockSink {
    fallback() external payable { }
    receive() external payable { }
}

/**
 * @title C3 vm-programs — staticcall accept/reject matrix on the real VM (fork)
 * @notice Proves, against the canonical VirtualMachine deployed on an Ethereum
 * mainnet fork, that hand-authored assert-only validation programs execute
 * through `CATValidatorV2.entry()`'s gas-capped `staticcall` and that every
 * mutating / LOG op class reverts the whole settlement (funds refundable).
 * A behavioral opcode-numbering pin runs the reject-class bodies *non-statically*
 * (a direct call to the VM) to show the op numbers in `vm/src/DataModel.sol`
 * drive the observed effects (SAFE_TRANSFER moves tokens, LOG emits, …).
 *
 * All programs are hand-authored zero-based per the frozen C1 register-layout
 * convention (`registers = validationParams ++ [account] ++ preBalances`), so —
 * unlike the pinned uc1 vector (see the plan's Surprises & Discoveries) — they
 * are fully under this repo's control and unaffected by the GD-7 re-pin.
 *
 * The umbrella fixture `contract/fixtures/vm-programs/vectors.json` (schema
 * `c3-vm-programs/v1`) is the cross-repo authority; it is regenerated from the
 * ProgramBuilder output with `VC_REGEN_VM_FIXTURE=true` and asserted otherwise.
 */
contract VmProgramsTest is VcTestBase {
    string internal constant VM_PROGRAMS_VECTORS = "vm-programs/vectors.json";

    /// @dev Pinned synthetic addresses, baked into the reject-class program
    /// bodies (SAFE_TRANSFER / DEPOSIT_APPROVED / CALL targets must be command
    /// literals — the VM has no register-indirect target). Clearly non-mainnet;
    /// the test etches mock code at them so the pinned bodies stay deterministic.
    address internal constant MOCK_TOKEN = address(uint160(0xCA7E0010));
    address internal constant MOCK_TOKEN2 = address(uint160(0xCA7E0011));
    address internal constant MOCK_SINK = address(uint160(0xCA7E0012));
    address internal constant DELIVERY = 0x1111111111111111111111111111111111111111;

    uint256 internal constant GAS_CAP = 5_000_000;
    uint256 internal constant PRE_BALANCE = 1 ether;

    CATValidatorV2 internal validator;
    address internal signer;
    uint256 internal signerKey;
    address internal executor;

    /* ─────────────────────────── program model
    ────────────────────────── */

    enum Class {
        Accept,
        Fail,
        Reject
    }

    /// @dev Per-program funding requirement, declared on the struct so setup is
    /// data-driven off `_programs()` rather than matched by program name. A new
    /// program is `Funding.None` by construction — surfaced in review, not
    /// silently unfunded (and thus vacuously passing).
    enum Funding {
        None,
        Erc20Delivery, // deal(MOCK_TOKEN, DELIVERY, PRE_BALANCE)
        NativeAccount, // vm.deal(signer, 5 ether)
        DepositApprovedOwner, // mint + approve MOCK_TOKEN2 to the validator (the VM's caller)
        MutatingCallVm // deal(MOCK_TOKEN, VM_ADDR, PRE_BALANCE) so the callee reaches its SSTORE
    }

    struct Prog {
        string name;
        Class class;
        bytes body;
        bytes[] params;
        uint256 preBalanceCount;
        bytes4 innerSelector; // fail class: expected inner revert selector
        Funding funding;
    }

    function setUp() external {
        if (!hasForkRpc()) return;
        forkMainnet();

        validator = new CATValidatorV2(VM_ADDR, GAS_CAP);
        (signer, signerKey) = makeAddrAndKey("vc/vm-programs/signer");
        executor = makeAddr("vc/vm-programs/executor");

        // Etch the fixed-layout mock ERC20 at the pinned addresses baked into the
        // reject-class bodies, plus a value sink for VALUECALL.
        vm.etch(MOCK_TOKEN, address(new SimpleERC20()).code);
        vm.etch(MOCK_TOKEN2, address(new SimpleERC20()).code);
        vm.etch(MOCK_SINK, address(new MockSink()).code);
    }

    /* ═══════════════════════════ fixture parity
    ═══════════════════════════ */

    /// @notice The umbrella C3 fixture is the cross-repo authority: assert the
    /// ProgramBuilder reproduces every pinned body byte-for-byte (and the
    /// self-describing header). Regenerates first when VC_REGEN_VM_FIXTURE=true.
    function test_fixtureParity() external {
        if (vm.envOr("VC_REGEN_VM_FIXTURE", false)) _regenerateFixture();
        // No fork gate: _programs() is pure and the fixture is read from disk, so
        // this byte-for-byte parity check — the cross-repo authority — runs in
        // every CI job, with or without a fork RPC.

        string memory json = readFixture(VM_PROGRAMS_VECTORS);
        assertEq(vm.parseJsonString(json, ".schema"), "c3-vm-programs/v1", "schema mismatch");
        assertEq(vm.parseJsonBytes32(json, ".runVMSelector"), bytes32(RUN_VM_SELECTOR), "runVM selector drift");

        // Guard builder<->fixture opcode-number consistency. (The behavioral
        // pins below are what actually bind these numbers to the deployed VM.)
        assertEq(vm.parseJsonUint(json, ".opcodeNumbering.CALL"), ProgramBuilder.OP_CALL);
        assertEq(vm.parseJsonUint(json, ".opcodeNumbering.CALLDATA_BUILD"), ProgramBuilder.OP_CALLDATA_BUILD);
        assertEq(vm.parseJsonUint(json, ".opcodeNumbering.DEPOSIT_APPROVED"), ProgramBuilder.OP_DEPOSIT_APPROVED);
        assertEq(vm.parseJsonUint(json, ".opcodeNumbering.RETURN"), ProgramBuilder.OP_RETURN);
        assertEq(vm.parseJsonUint(json, ".opcodeNumbering.NATIVE_BALANCE"), ProgramBuilder.OP_NATIVE_BALANCE);
        assertEq(vm.parseJsonUint(json, ".opcodeNumbering.LOG"), ProgramBuilder.OP_LOG);
        assertEq(vm.parseJsonUint(json, ".opcodeNumbering.SAFE_TRANSFER"), ProgramBuilder.OP_SAFE_TRANSFER);

        Prog[] memory progs = _programs();
        uint256 count = jsonArrayLength(json, ".programs");
        assertEq(count, progs.length, "fixture program count drift");

        for (uint256 i; i < progs.length; ++i) {
            string memory p = string.concat(".programs[", vm.toString(i), "]");
            assertEq(vm.parseJsonString(json, string.concat(p, ".name")), progs[i].name, "program name/order drift");
            assertEq(vm.parseJsonBytes(json, string.concat(p, ".body")), progs[i].body, "program body byte drift");
            assertEq(
                vm.parseJsonUint(json, string.concat(p, ".preBalanceCount")),
                progs[i].preBalanceCount,
                "preBalanceCount drift"
            );
            assertEq(vm.parseJsonString(json, string.concat(p, ".expect")), _expectString(progs[i]), "expect drift");
            // Fail-class vectors pin the inner InvariantChecker revert selector
            // the Solidity matrix asserts is wrapped by ValidationFailed.
            if (progs[i].class == Class.Fail) {
                assertEq(
                    vm.parseJsonBytes32(json, string.concat(p, ".innerSelector")),
                    bytes32(progs[i].innerSelector),
                    "inner selector drift"
                );
            }
        }
    }

    /* ═══════════════════════════ entry() matrix
    ═══════════════════════════ */

    function test_acceptProgramsSettleThroughEntry() external {
        if (!hasForkRpc()) return vm.skip(true);
        Prog[] memory progs = _programs();
        for (uint256 i; i < progs.length; ++i) {
            if (progs[i].class != Class.Accept) continue;
            _driveAccept(progs[i], uint256(i) + 1);
        }
    }

    function test_failProgramsRevertRefundableWithInnerSelector() external {
        if (!hasForkRpc()) return vm.skip(true);
        Prog[] memory progs = _programs();
        for (uint256 i; i < progs.length; ++i) {
            if (progs[i].class != Class.Fail) continue;
            _driveFail(progs[i], uint256(i) + 1);
        }
    }

    function test_rejectProgramsRevertUnderStaticcall() external {
        if (!hasForkRpc()) return vm.skip(true);
        Prog[] memory progs = _programs();
        for (uint256 i; i < progs.length; ++i) {
            if (progs[i].class != Class.Reject) continue;
            _driveReject(progs[i], uint256(i) + 1);
        }
    }

    /// @dev FR-V5 bounded grief: a valid accept program run under a 50k gas cap
    /// runs out of gas inside the staticcall and fails closed as ValidationFailed.
    function test_gasCapExhaustionFailsClosed() external {
        if (!hasForkRpc()) return vm.skip(true);
        CATValidatorV2 tinyCap = new CATValidatorV2(VM_ADDR, 50_000);

        Prog memory prog = _erc20Floor("erc20-floor", 0);
        uint256 nonce = 99;
        Outcome[] memory outcomes = _outcomesFor(prog);
        _applyFunding(prog);

        (bool ok, bytes memory ret) = _entryCall(tinyCap, prog, nonce, outcomes);
        assertFalse(ok, "tiny gas cap must fail the valid program closed");
        assertEq(
            bytes4(ret), CATValidatorV2.ValidationFailed.selector, "gas-cap failure must surface as ValidationFailed"
        );
        assertFalse(tinyCap.spentNonces(signer, nonce), "nonce untouched on gas-cap failure");
    }

    /* ═════════════════════ behavioral opcode-numbering pins
    ═══════════════ */

    /// @notice Run reject-class bodies (and RETURN / NATIVE_BALANCE probes)
    /// *non-statically* — a direct call to the VM — to pin that the op numbers in
    /// vm/src/DataModel.sol drive the observed behavior. Under entry()'s
    /// staticcall these same bodies all revert (test_rejectProgramsRevert...).

    function test_behavioral_return_op5() external {
        if (!hasForkRpc()) return vm.skip(true);
        bytes[] memory params = new bytes[](1);
        params[0] = abi.encodePacked(bytes32(uint256(0xC0FFEE)));
        bytes memory body = ProgramBuilder.cmd(ProgramBuilder.OP_RETURN, ProgramBuilder.packReturn(0));

        (bool ok, bytes memory ret) = _vmDirect(body, params, signer, 0);
        assertTrue(ok, "RETURN(op 5) must execute non-statically");
        assertEq(_returnedWord(ret), 0xC0FFEE, "RETURN must echo register 0");
    }

    function test_behavioral_nativeBalance_op8() external {
        if (!hasForkRpc()) return vm.skip(true);
        // params: [] ; account at index 0 ; NATIVE_BALANCE(account) -> reg1 ; RETURN(reg1)
        bytes[] memory params = new bytes[](0);
        address probe = makeAddr("vc/native-balance-probe");
        vm.deal(probe, 7 ether);
        bytes memory body = abi.encodePacked(
            ProgramBuilder.cmd(ProgramBuilder.OP_NATIVE_BALANCE, ProgramBuilder.packNativeBalance(0, 1)),
            ProgramBuilder.cmd(ProgramBuilder.OP_RETURN, ProgramBuilder.packReturn(1))
        );

        (bool ok, bytes memory ret) = _vmDirect(body, params, probe, 0);
        assertTrue(ok, "NATIVE_BALANCE(op 8) must execute non-statically");
        assertEq(_returnedWord(ret), 7 ether, "NATIVE_BALANCE must read the account balance");
    }

    function test_behavioral_safeTransfer_op10_movesTokens() external {
        if (!hasForkRpc()) return vm.skip(true);
        address recipient = makeAddr("vc/safe-transfer-recipient");
        Prog memory prog = _safeTransfer(recipient, 3e18);

        deal(MOCK_TOKEN, VM_ADDR, 5e18);
        (bool ok,) = _vmDirect(prog.body, prog.params, signer, 0);
        assertTrue(ok, "SAFE_TRANSFER(op 10) must execute non-statically");
        assertEq(SimpleERC20(MOCK_TOKEN).balanceOf(recipient), 3e18, "op 10 must move tokens: it IS SAFE_TRANSFER");
        assertEq(SimpleERC20(MOCK_TOKEN).balanceOf(VM_ADDR), 2e18, "VM balance debited");
    }

    function test_behavioral_log_op9_emits() external {
        if (!hasForkRpc()) return vm.skip(true);
        Prog memory prog = _log(0xABCDEF); // LOG STATIC_1 of register 1 (the account)

        vm.recordLogs();
        (bool ok,) = _vmDirect(prog.body, prog.params, signer, 0);
        assertTrue(ok, "LOG(op 9) must execute non-statically");

        // Pin the STATIC_1 sourceRegs byte: the program logs register 1 (the
        // account = signer), NOT register 0 (param0 = 0xABCDEF). A mis-encoded
        // sourceRegs would still emit *an* event, so assert the logged word.
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes32 sig = keccak256("VMLogStatic1(bytes32)");
        bool found;
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].topics.length == 0 || logs[i].topics[0] != sig) continue;
            found = true;
            assertEq(
                abi.decode(logs[i].data, (bytes32)),
                bytes32(uint256(uint160(signer))),
                "op 9 must log register 1 (the account), pinning STATIC_1 register selection"
            );
        }
        assertTrue(found, "op 9 must emit VMLogStatic1: it IS LOG");
    }

    function test_behavioral_mutatingCall_op0_movesState() external {
        if (!hasForkRpc()) return vm.skip(true);
        address recipient = makeAddr("vc/mutating-call-recipient");
        Prog memory prog = _mutatingCall(recipient, 4e18);

        deal(MOCK_TOKEN, VM_ADDR, 10e18);
        (bool ok,) = _vmDirect(prog.body, prog.params, signer, 0);
        assertTrue(ok, "CALL(op 0, CallType.CALL) must execute non-statically");
        assertEq(SimpleERC20(MOCK_TOKEN).balanceOf(recipient), 4e18, "mutating CALL must move state");
    }

    function test_behavioral_valuecall_op0_sendsValue() external {
        if (!hasForkRpc()) return vm.skip(true);
        Prog memory prog = _valueCall(2 ether);

        vm.deal(VM_ADDR, 3 ether);
        (bool ok,) = _vmDirect(prog.body, prog.params, signer, 0);
        assertTrue(ok, "CALL(op 0, CallType.VALUECALL) must execute non-statically");
        assertEq(MOCK_SINK.balance, 2 ether, "VALUECALL must forward ether");
    }

    function test_behavioral_depositApproved_op3_pullsDeposit() external {
        if (!hasForkRpc()) return vm.skip(true);
        Prog memory prog = _depositApproved(1_000e18);

        // Owner slot on the raw VM is zero, so DEPOSIT_APPROVED falls back to
        // caller() — this test contract. Fund + approve it, then call directly.
        SimpleERC20(MOCK_TOKEN2).mint(address(this), 800e18);
        SimpleERC20(MOCK_TOKEN2).approve(VM_ADDR, 800e18);

        (bool ok,) = _vmDirect(prog.body, prog.params, signer, 0);
        assertTrue(ok, "DEPOSIT_APPROVED(op 3) must execute non-statically");
        assertEq(SimpleERC20(MOCK_TOKEN2).balanceOf(VM_ADDR), 800e18, "op 3 must pull the approved deposit");
    }

    /* ═══════════════════════════ program authoring
    ════════════════════════ */

    /// @dev The full C3 program set, in fixture order. Bodies are hand-authored
    /// zero-based per the C1 convention; per-program register layouts are
    /// documented on each builder below.
    function _programs() internal pure returns (Prog[] memory progs) {
        progs = new Prog[](9);
        progs[0] = _erc20Floor("erc20-floor", 0); // accept: min = 0
        progs[1] = _erc20Floor("assert-fails", PRE_BALANCE); // fail: current < preBal0 + min (both operands
        // load-bearing)
        progs[2] = _nativeGte(1 ether); // accept
        progs[3] = _alwaysRevert(); // fail: assertEqual(0,1)
        progs[4] = _safeTransfer(DELIVERY, 1e18); // reject: SAFE_TRANSFER
        progs[5] = _depositApproved(1_000e18); // reject: DEPOSIT_APPROVED
        progs[6] = _log(0xABCDEF); // reject: LOG
        progs[7] = _mutatingCall(DELIVERY, 1e18); // reject: state-mutating CALL (callee SSTORE under staticcall)
        progs[8] = _valueCall(1 ether); // reject: VALUECALL forwarding ether under staticcall
    }

    /// @dev erc20-floor / assert-fails — the uc1 shape, corrected: the RPN word
    /// and operand count live in the committed params (not loose register slots).
    /// Layout: [0]=delivery [1]=min [2]=rpnWord [3]=rpnLen ; account at 4 ; preBal0 at 5.
    /// Reads balanceOf(delivery) on MOCK_TOKEN, computes preBal0+min via
    /// evaluateRPN, then asserts current >= preBal0+min. Accept sets min=0
    /// (passes at current==preBal0); the fail variant sets min==PRE_BALANCE so it
    /// reverts only because preBal0+min exceeds current — making both RPN operands
    /// load-bearing (dropping either would make the fail wrongly pass).
    function _erc20Floor(
        string memory name,
        uint256 minAmount
    ) internal pure returns (Prog memory prog) {
        prog.name = name;
        prog.class = minAmount == 0 ? Class.Accept : Class.Fail;
        prog.preBalanceCount = 1;
        prog.funding = Funding.Erc20Delivery;
        // innerSelector is meaningful only for fail rows (asserted/serialized
        // under Class.Fail); leave accept rows zeroed.
        if (prog.class == Class.Fail) prog.innerSelector = bytes4(keccak256("AssertGteFailed(uint256,uint256)"));

        prog.params = new bytes[](4);
        prog.params[0] = abi.encodePacked(bytes32(uint256(uint160(DELIVERY))));
        prog.params[1] = abi.encodePacked(bytes32(minAmount));
        // RPN stream: 0x80 push regValues[0]=preBal0, 0x81 push regValues[1]=min, 0x00 ADD.
        prog.params[2] = abi.encodePacked(bytes32(uint256(0x808100) << 232));
        prog.params[3] = abi.encodePacked(bytes32(uint256(3)));

        bytes memory bpBalance = abi.encodePacked(ProgramBuilder.bpStatic(0)); // balanceOf(delivery)
        bytes memory bpRpn = abi.encodePacked(
            ProgramBuilder.START_ARRAY_DYNAMIC,
            ProgramBuilder.bpStatic(5), // preBal0
            ProgramBuilder.bpStatic(1), // min
            ProgramBuilder.END_CONTAINER,
            ProgramBuilder.bpStatic(2), // rpnWord
            ProgramBuilder.bpStatic(3) // rpnLen
        );
        bytes memory bpAssert = abi.encodePacked(ProgramBuilder.bpStatic(7), ProgramBuilder.bpStatic(9));

        prog.body = abi.encodePacked(
            ProgramBuilder.cmd(
                ProgramBuilder.OP_CALLDATA_BUILD,
                ProgramBuilder.packCallDataBuild(ProgramBuilder.SEL_BALANCE_OF, 6, bpBalance)
            ),
            ProgramBuilder.cmd(
                ProgramBuilder.OP_CALL, ProgramBuilder.packCall(MOCK_TOKEN, ProgramBuilder.CALLTYPE_STATICCALL, 7, 6, 0)
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

    /// @dev native-gte — NATIVE_BALANCE(account) >= threshold param.
    /// Layout: [0]=threshold ; account at 1 ; scratch 2..4.
    function _nativeGte(
        uint256 threshold
    ) internal pure returns (Prog memory prog) {
        prog.name = "native-gte";
        prog.class = Class.Accept;
        prog.preBalanceCount = 0;
        prog.funding = Funding.NativeAccount;

        prog.params = new bytes[](1);
        prog.params[0] = abi.encodePacked(bytes32(threshold));

        bytes memory bpAssert = abi.encodePacked(ProgramBuilder.bpStatic(2), ProgramBuilder.bpStatic(0));
        prog.body = abi.encodePacked(
            ProgramBuilder.cmd(ProgramBuilder.OP_NATIVE_BALANCE, ProgramBuilder.packNativeBalance(1, 2)),
            ProgramBuilder.cmd(
                ProgramBuilder.OP_CALLDATA_BUILD,
                ProgramBuilder.packCallDataBuild(ProgramBuilder.SEL_ASSERT_GTE, 3, bpAssert)
            ),
            ProgramBuilder.cmd(
                ProgramBuilder.OP_CALL,
                ProgramBuilder.packCall(INVARIANT_CHECKER, ProgramBuilder.CALLTYPE_STATICCALL, 4, 3, 0)
            )
        );
    }

    /// @dev always-revert — assertEqual(0, 1) via params (constant contradiction).
    /// Layout: [0]=0 [1]=1 ; account at 2 ; scratch 3..4.
    function _alwaysRevert() internal pure returns (Prog memory prog) {
        prog.name = "always-revert";
        prog.class = Class.Fail;
        prog.preBalanceCount = 0;
        prog.innerSelector = bytes4(keccak256("AssertEqFailed(uint256,uint256)"));

        prog.params = new bytes[](2);
        prog.params[0] = abi.encodePacked(bytes32(uint256(0)));
        prog.params[1] = abi.encodePacked(bytes32(uint256(1)));

        bytes memory bpAssert = abi.encodePacked(ProgramBuilder.bpStatic(0), ProgramBuilder.bpStatic(1));
        prog.body = abi.encodePacked(
            ProgramBuilder.cmd(
                ProgramBuilder.OP_CALLDATA_BUILD,
                ProgramBuilder.packCallDataBuild(ProgramBuilder.SEL_ASSERT_EQ, 3, bpAssert)
            ),
            ProgramBuilder.cmd(
                ProgramBuilder.OP_CALL,
                ProgramBuilder.packCall(INVARIANT_CHECKER, ProgramBuilder.CALLTYPE_STATICCALL, 4, 3, 0)
            )
        );
    }

    /// @dev reject: SAFE_TRANSFER(MOCK_TOKEN, to, amount) — a token move.
    /// Layout: [0]=to [1]=amount ; account at 2.
    function _safeTransfer(
        address to,
        uint256 amount
    ) internal pure returns (Prog memory prog) {
        prog.name = "safe-transfer";
        prog.class = Class.Reject;
        prog.preBalanceCount = 0;

        prog.params = new bytes[](2);
        prog.params[0] = abi.encodePacked(bytes32(uint256(uint160(to))));
        prog.params[1] = abi.encodePacked(bytes32(amount));

        prog.body =
            ProgramBuilder.cmd(ProgramBuilder.OP_SAFE_TRANSFER, ProgramBuilder.packSafeTransfer(MOCK_TOKEN, 0, 1));
    }

    /// @dev reject: DEPOSIT_APPROVED(MOCK_TOKEN2, dest, maxDeposit) — pulls tokens.
    /// Layout: [0]=maxDeposit ; account at 1 ; scratch 2.
    function _depositApproved(
        uint256 maxDeposit
    ) internal pure returns (Prog memory prog) {
        prog.name = "deposit-approved";
        prog.class = Class.Reject;
        prog.preBalanceCount = 0;
        prog.funding = Funding.DepositApprovedOwner;

        prog.params = new bytes[](1);
        prog.params[0] = abi.encodePacked(bytes32(maxDeposit));

        prog.body = ProgramBuilder.cmd(
            ProgramBuilder.OP_DEPOSIT_APPROVED, ProgramBuilder.packDepositApproved(MOCK_TOKEN2, 2, 0)
        );
    }

    /// @dev reject: LOG STATIC_1 of register 1 (the account) — event emission.
    /// Layout: [0]=data ; account at 1.
    function _log(
        uint256 data
    ) internal pure returns (Prog memory prog) {
        prog.name = "log";
        prog.class = Class.Reject;
        prog.preBalanceCount = 0;

        prog.params = new bytes[](1);
        prog.params[0] = abi.encodePacked(bytes32(data));

        // sourceRegs (unpacked): register index in byte position 0 => reg << 200.
        prog.body = ProgramBuilder.cmd(ProgramBuilder.OP_LOG, ProgramBuilder.packLog(0, uint256(1) << 200));
    }

    /// @dev reject: CALL(CallType.CALL, MOCK_TOKEN.transfer(to, amount)) — a plain
    /// CALL is legal in a static context; the revert comes from the callee SSTORE.
    /// Layout: [0]=to [1]=amount ; account at 2 ; scratch 3..4.
    function _mutatingCall(
        address to,
        uint256 amount
    ) internal pure returns (Prog memory prog) {
        prog.name = "mutating-call";
        prog.class = Class.Reject;
        prog.preBalanceCount = 0;
        prog.funding = Funding.MutatingCallVm;

        prog.params = new bytes[](2);
        prog.params[0] = abi.encodePacked(bytes32(uint256(uint160(to))));
        prog.params[1] = abi.encodePacked(bytes32(amount));

        bytes memory bpTransfer = abi.encodePacked(ProgramBuilder.bpStatic(0), ProgramBuilder.bpStatic(1));
        prog.body = abi.encodePacked(
            ProgramBuilder.cmd(
                ProgramBuilder.OP_CALLDATA_BUILD,
                ProgramBuilder.packCallDataBuild(ProgramBuilder.SEL_TRANSFER, 3, bpTransfer)
            ),
            ProgramBuilder.cmd(
                ProgramBuilder.OP_CALL, ProgramBuilder.packCall(MOCK_TOKEN, ProgramBuilder.CALLTYPE_CALL, 4, 3, 0)
            )
        );
    }

    /// @dev reject: CALL(CallType.VALUECALL, MOCK_SINK) with nonzero value — an
    /// ether-moving call, which reverts under staticcall.
    /// Layout: [0]=value ; account at 1 ; scratch 2..3.
    function _valueCall(
        uint256 value
    ) internal pure returns (Prog memory prog) {
        prog.name = "valuecall";
        prog.class = Class.Reject;
        prog.preBalanceCount = 0;

        prog.params = new bytes[](1);
        prog.params[0] = abi.encodePacked(bytes32(value));

        // Empty-blueprint calldata (selector-only) into reg2; MockSink.fallback accepts it.
        prog.body = abi.encodePacked(
            ProgramBuilder.cmd(ProgramBuilder.OP_CALLDATA_BUILD, ProgramBuilder.packCallDataBuild(bytes4(0), 2, "")),
            ProgramBuilder.cmd(
                ProgramBuilder.OP_CALL, ProgramBuilder.packCall(MOCK_SINK, ProgramBuilder.CALLTYPE_VALUECALL, 3, 2, 0)
            )
        );
    }

    /* ═══════════════════════════ drivers
    ══════════════════════════════════ */

    function _driveAccept(
        Prog memory prog,
        uint256 nonce
    ) internal {
        Outcome[] memory outcomes = _outcomesFor(prog);
        _applyFunding(prog);

        (bool ok, bytes memory ret) = _entryCall(validator, prog, nonce, outcomes);
        assertTrue(ok, string.concat(prog.name, ": accept program did not settle: ", vm.toString(ret)));
        assertTrue(validator.spentNonces(signer, nonce), string.concat(prog.name, ": nonce not spent"));
    }

    function _driveFail(
        Prog memory prog,
        uint256 nonce
    ) internal {
        Outcome[] memory outcomes = _outcomesFor(prog);
        _applyFunding(prog); // same funding as accept; the min/params make it fail

        (bool ok, bytes memory ret) = _entryCall(validator, prog, nonce, outcomes);
        assertFalse(ok, string.concat(prog.name, ": fail program unexpectedly settled"));
        assertEq(
            bytes4(ret), CATValidatorV2.ValidationFailed.selector, string.concat(prog.name, ": not ValidationFailed")
        );

        bytes memory inner = abi.decode(_stripSelector(ret), (bytes));
        assertEq(bytes4(inner), prog.innerSelector, string.concat(prog.name, ": wrong inner selector"));
        assertFalse(validator.spentNonces(signer, nonce), string.concat(prog.name, ": nonce spent despite failure"));
    }

    function _driveReject(
        Prog memory prog,
        uint256 nonce
    ) internal {
        Outcome[] memory outcomes = _outcomesFor(prog);
        _applyFunding(prog);

        (bool ok, bytes memory ret) = _entryCall(validator, prog, nonce, outcomes);
        assertFalse(ok, string.concat(prog.name, ": reject program unexpectedly settled under staticcall"));
        assertEq(
            bytes4(ret),
            CATValidatorV2.ValidationFailed.selector,
            string.concat(prog.name, ": reject not ValidationFailed")
        );
        assertFalse(validator.spentNonces(signer, nonce), string.concat(prog.name, ": nonce spent despite reject"));
    }

    /// @dev Data-driven funding keyed on `prog.funding` (declared per program in
    /// `_programs()`), so adding a program forces an explicit funding choice
    /// rather than silently inheriting no setup.
    function _applyFunding(
        Prog memory prog
    ) internal {
        if (prog.funding == Funding.Erc20Delivery) {
            // erc20-floor family reads balanceOf(DELIVERY) on MOCK_TOKEN.
            deal(MOCK_TOKEN, DELIVERY, PRE_BALANCE);
        } else if (prog.funding == Funding.NativeAccount) {
            // native-gte reads the account's ether.
            vm.deal(signer, 5 ether);
        } else if (prog.funding == Funding.DepositApprovedOwner) {
            // DEPOSIT_APPROVED only attempts a state-changing safeTransferFrom
            // (reverting under staticcall) when the owner has nonzero allowance +
            // balance; during entry()'s staticcall the owner is the validator
            // (msg.sender to the VM), so fund and pre-approve it. Otherwise it
            // short-circuits at amount==0 and settles vacuously.
            SimpleERC20(MOCK_TOKEN2).mint(address(validator), 800e18);
            vm.prank(address(validator));
            SimpleERC20(MOCK_TOKEN2).approve(VM_ADDR, 800e18);
        } else if (prog.funding == Funding.MutatingCallVm) {
            // A plain CALL is legal under staticcall; the revert must come from
            // the callee's SSTORE. Fund the VM so transfer() reaches that write
            // (and would succeed in a non-static context), so the reject pins the
            // static-context protection rather than an incidental balance underflow.
            deal(MOCK_TOKEN, VM_ADDR, PRE_BALANCE);
        }
    }

    function _outcomesFor(
        Prog memory prog
    ) internal pure returns (Outcome[] memory outcomes) {
        if (prog.preBalanceCount == 0) return new Outcome[](0);
        // erc20-floor family: one outcome whose recorded balance is preBalance0.
        outcomes = new Outcome[](1);
        outcomes[0] = Outcome({ token: MOCK_TOKEN, amount: 0, destination: DELIVERY });
    }

    /* ═══════════════════════════ low-level plumbing
    ═══════════════════════ */

    /// @dev Build + sign a V2 constraint committing `prog` and call entry() as the
    /// executor via a raw call so the revert data is inspectable.
    function _entryCall(
        CATValidatorV2 target,
        Prog memory prog,
        uint256 nonce,
        Outcome[] memory outcomes
    ) internal returns (bool ok, bytes memory ret) {
        bytes32 programHash = keccak256(prog.body);
        (bytes32 paramsHash,) = _paramsHash(prog.params);
        bytes memory sig = _sign(target, nonce, outcomes, programHash, paramsHash);

        bytes memory callData = abi.encodeCall(
            CATValidatorV2.entry,
            (
                makeAddr("execTarget"),
                hex"",
                signer,
                nonce,
                new AllowanceSpend[](0),
                outcomes,
                programHash,
                paramsHash,
                prog.body,
                prog.params,
                sig
            )
        );
        vm.prank(executor);
        (ok, ret) = address(target).call(callData);
    }

    /// @dev Direct, non-static VM invocation used by the behavioral pins.
    function _vmDirect(
        bytes memory body,
        bytes[] memory params,
        address account,
        uint256 preBalCount
    ) internal returns (bool ok, bytes memory ret) {
        uint256[] memory preBalances = new uint256[](preBalCount);
        bytes[] memory registers = _buildRegisters(params, account, preBalances);
        (ok, ret) = VM_ADDR.call(_encodeRunVM(body, registers));
    }

    function _sign(
        CATValidatorV2 target,
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

    /* ── memory mirrors of LibValidationVM (its APIs are calldata-typed) ── */

    function _buildRegisters(
        bytes[] memory params,
        address account,
        uint256[] memory preBalances
    ) internal pure returns (bytes[] memory registers) {
        registers = new bytes[](LibValidationVM.NUM_REGISTERS);
        for (uint256 i; i < registers.length; ++i) {
            registers[i] = new bytes(32);
        }
        for (uint256 i; i < params.length; ++i) {
            registers[i] = params[i];
        }
        registers[params.length] = abi.encodePacked(bytes32(uint256(uint160(account))));
        for (uint256 i; i < preBalances.length; ++i) {
            registers[params.length + 1 + i] = abi.encodePacked(bytes32(preBalances[i]));
        }
    }

    function _encodeRunVM(
        bytes memory body,
        bytes[] memory registers
    ) internal pure returns (bytes memory) {
        uint256 numCommands = body.length / LibValidationVM.COMMAND_SIZE;
        VMCommand[] memory commands = new VMCommand[](numCommands);
        for (uint256 i; i < numCommands; ++i) {
            uint256 base = i * LibValidationVM.COMMAND_SIZE;
            bytes32 data;
            for (uint256 j; j < 32; ++j) {
                data |= bytes32(body[base + 1 + j]) >> (j * 8);
            }
            commands[i] = VMCommand({ op: uint8(body[base]), data: data });
        }
        return abi.encodeWithSelector(RUN_VM_SELECTOR, commands, VMState(registers));
    }

    function _paramsHash(
        bytes[] memory params
    ) internal pure returns (bytes32, bool) {
        if (params.length == 0) return (bytes32(0), true);
        bytes memory buffer;
        for (uint256 i; i < params.length; ++i) {
            if (params[i].length != 32) return (bytes32(0), false);
            buffer = abi.encodePacked(buffer, params[i]);
        }
        return (keccak256(buffer), true);
    }

    /// @dev runVM returns ABI-encoded `bytes`; a RETURN opcode's payload is the
    /// raw 32-byte register word. Unwrap both layers to the scalar.
    function _returnedWord(
        bytes memory ret
    ) internal pure returns (uint256) {
        bytes memory payload = abi.decode(ret, (bytes));
        return abi.decode(payload, (uint256));
    }

    function _stripSelector(
        bytes memory data
    ) internal pure returns (bytes memory out) {
        out = new bytes(data.length - 4);
        for (uint256 i; i < out.length; ++i) {
            out[i] = data[i + 4];
        }
    }

    /* ═══════════════════════════ fixture regeneration
    ═════════════════════ */

    function _regenerateFixture() internal {
        Prog[] memory progs = _programs();

        string memory programsJson = "";
        for (uint256 i; i < progs.length; ++i) {
            programsJson = string.concat(programsJson, i == 0 ? "" : ",", _serializeProgram(progs[i]));
        }

        string memory json = string.concat(
            "{\n  \"schema\": \"c3-vm-programs/v1\",",
            "\n  \"runVMSelector\": \"",
            vm.toString(bytes32(RUN_VM_SELECTOR)),
            "\",",
            "\n  \"registerLayoutConvention\": \"registers = validationParams ++ [account] ++ preBalances; remaining slots are 32-byte zero words (123 total)\",",
            "\n  \"platform\": {",
            "\n    \"virtualMachine\": \"",
            vm.toString(VM_ADDR),
            "\",",
            "\n    \"invariantChecker\": \"",
            vm.toString(INVARIANT_CHECKER),
            "\",",
            "\n    \"arithmeticProcessor\": \"",
            vm.toString(ARITHMETIC_PROCESSOR),
            "\"",
            "\n  },",
            _opcodeNumberingJson(),
            "\n  \"programs\": [",
            programsJson,
            "\n  ]\n}\n"
        );

        vm.writeFile(string.concat(fixturesDir(), VM_PROGRAMS_VECTORS), json);
    }

    function _serializeProgram(
        Prog memory prog
    ) internal pure returns (string memory) {
        string memory paramsJson = "";
        for (uint256 i; i < prog.params.length; ++i) {
            paramsJson =
                string.concat(paramsJson, i == 0 ? "" : ", ", "\"", vm.toString(_toBytes32(prog.params[i])), "\"");
        }

        return string.concat(
            "\n    {",
            "\n      \"name\": \"",
            prog.name,
            "\",",
            "\n      \"class\": \"",
            _className(prog.class),
            "\",",
            "\n      \"body\": \"",
            vm.toString(prog.body),
            "\",",
            "\n      \"params\": [",
            paramsJson,
            "],",
            "\n      \"preBalanceCount\": ",
            vm.toString(prog.preBalanceCount),
            ",",
            "\n      \"expect\": \"",
            _expectString(prog),
            "\",",
            "\n      \"innerSelector\": \"",
            vm.toString(prog.innerSelector),
            "\"",
            "\n    }"
        );
    }

    function _opcodeNumberingJson() internal pure returns (string memory) {
        return string.concat(
            "\n  \"opcodeNumbering\": {",
            "\n    \"CALL\": 0, \"CALLDATA_BUILD\": 1, \"EXPLODE\": 2, \"DEPOSIT_APPROVED\": 3,",
            "\n    \"CALLDATA_SURGERY\": 4, \"RETURN\": 5, \"ABI_ENCODE\": 6, \"REMAINING_GAS\": 7,",
            "\n    \"NATIVE_BALANCE\": 8, \"LOG\": 9, \"SAFE_TRANSFER\": 10",
            "\n  },"
        );
    }

    function _className(
        Class class
    ) internal pure returns (string memory) {
        if (class == Class.Accept) return "accept";
        if (class == Class.Fail) return "fail";
        return "reject";
    }

    function _expectString(
        Prog memory prog
    ) internal pure returns (string memory) {
        if (prog.class == Class.Accept) return "success";
        if (prog.class == Class.Fail) return "validationFailed";
        return "staticcallRevert";
    }

    function _toBytes32(
        bytes memory word
    ) internal pure returns (bytes32 out) {
        require(word.length == 32, "param not 32 bytes");
        assembly ("memory-safe") {
            out := mload(add(word, 32))
        }
    }
}
