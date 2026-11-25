// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { Test } from "forge-std/src/Test.sol";

import { ERC7821 } from "solady/src/accounts/ERC7821.sol";
import { Ownable } from "solady/src/auth/Ownable.sol";
import { ReentrancyGuardTransient } from "solady/src/utils/ReentrancyGuardTransient.sol";
import { MockERC20 } from "solady/test/utils/mocks/MockERC20.sol";

import { CATValidator } from "../../src/CATValidator.sol";
import { CATValidatorV2 } from "../../src/CATValidatorV2.sol";
import { Catapultar } from "../../src/Catapultar.sol";
import { CatapultarFactory } from "../../src/CatapultarFactory.sol";
import { IntentExecutor } from "../../src/libs/IntentExecutor.sol";
import { KeyedOwnable } from "../../src/libs/KeyedOwnable.sol";
import { LibCalls } from "../../src/libs/LibCalls.sol";
import { AllowanceSpend, Outcome } from "../../src/libs/LibExecutionConstraint.sol";
import { ExecutionBinding } from "../../src/libs/LibExecutionConstraintV2.sol";
import { VMCommand } from "../../src/libs/LibValidationVM.sol";

import { V2ConstraintDigest } from "../helpers/V2ConstraintDigest.sol";

/// @dev Call-proxy calldata that forwards `payload` to `executor`: the target as one
/// 32-byte word, then the payload.
function proxyCalldata(
    IntentExecutor executor,
    bytes memory payload
) pure returns (bytes memory) {
    return abi.encodePacked(bytes32(uint256(uint160(address(executor)))), payload);
}

/// @dev The V2 `entry` overload, so batches can encode it with abi.encodeCall.
interface IValidatorV2 {
    function entry(
        address execTarget,
        bytes calldata execPayload,
        address account,
        uint256 nonce,
        AllowanceSpend[] calldata allowances,
        Outcome[] calldata outcomes,
        ExecutionBinding calldata binding,
        VMCommand[] calldata validationProgram,
        bytes32[] calldata validationParams,
        bytes calldata signature
    ) external;
}

interface IDomain {
    function DOMAIN_SEPARATOR() external view returns (bytes32);
}

/// @dev Stands in for the LI.FI compose proxy: only its owner (the executor) can move
/// what is parked on it, like the Morpho position the Base proxy held.
contract MockComposeProxy {
    error Unauthorized();

    address public immutable owner;

    constructor(
        address owner_
    ) {
        owner = owner_;
    }

    function withdrawTo(
        MockERC20 token,
        address to,
        uint256 amount
    ) external {
        if (msg.sender != owner) revert Unauthorized();
        token.transfer(to, amount);
    }
}

/// @dev Allowance token whose transferFrom runs attacker code inside the validator's
/// `entry`, before the validator calls the executor.
contract HookToken is MockERC20 {
    address public hookTarget;
    bytes public hookData;
    bool public hookSucceeded;
    bytes public hookReturn;

    constructor() MockERC20("Hook", "HOOK", 18) { }

    function setHook(
        address target,
        bytes calldata data
    ) external {
        hookTarget = target;
        hookData = data;
    }

    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) public override returns (bool) {
        if (hookTarget != address(0)) (hookSucceeded, hookReturn) = hookTarget.call(hookData);
        return super.transferFrom(from, to, amount);
    }
}

/// @dev Called from inside an authorized execution. Replays the same calldata through
/// the validator's call proxy.
contract Reenterer {
    IntentExecutor public immutable executor;
    address public immutable callProxy;
    bytes public payload;
    bool public replaySucceeded;
    bytes public replayReturn;

    constructor(
        IntentExecutor executor_,
        address callProxy_
    ) {
        executor = executor_;
        callProxy = callProxy_;
    }

    function setPayload(
        bytes calldata payload_
    ) external {
        payload = payload_;
    }

    function reenter() external {
        (replaySucceeded, replayReturn) = callProxy.call(proxyCalldata(executor, payload));
    }
}

/// @dev Stands in for a validator whose `entry` runs `execPayload` on `execTarget` a set
/// number of times: 1 like a validator, 0 for an `entry` that never reaches the executor.
contract EntryStub {
    uint256 public runs = 1;

    function setRuns(
        uint256 runs_
    ) external {
        runs = runs_;
    }

    function entry(
        address execTarget,
        bytes calldata execPayload
    ) external {
        for (uint256 i = 0; i < runs; ++i) {
            (bool ok, bytes memory ret) = execTarget.call(execPayload);
            if (!ok) {
                assembly ("memory-safe") {
                    revert(add(ret, 0x20), mload(ret))
                }
            }
        }
    }
}

contract IntentExecutorGateTest is Test {
    bytes32 constant ATOMIC_MODE = bytes32(bytes10(0x01000000000078210001));
    bytes32 constant SKIP_FAILURES_MODE = bytes32(bytes10(0x01010000000078210001));
    uint256 constant POSITION = 1000e6;
    uint256 constant INPUT = 100e18;

    CATValidatorV2 validator;
    address callProxy;
    CatapultarFactory factory;
    IntentExecutor executor;
    MockComposeProxy composeProxy;
    MockERC20 usdc;
    MockERC20 inToken;
    EntryStub entryStub;

    address owner;
    address payable worker;
    uint256 workerKey;
    uint256 workerNonce;
    address user;
    uint256 userKey;
    address destination;
    address solverTreasury;
    address attacker;
    uint256 attackerKey;

    function setUp() external {
        validator = new CATValidatorV2(makeAddr("vm"));
        callProxy = validator.CALL_PROXY();
        factory = new CatapultarFactory();
        entryStub = new EntryStub();

        address workerSigner;
        (workerSigner, workerKey) = makeAddrAndKey("workerKey");
        bytes32[] memory keys = new bytes32[](1);
        keys[0] = bytes32(uint256(uint160(workerSigner)));
        worker = factory.deploy(KeyedOwnable.PublicKeyType.ECDSAOrSmartContract, keys, bytes32(0));

        owner = makeAddr("owner");
        address[] memory solvers = new address[](1);
        solvers[0] = worker;
        executor = new IntentExecutor(owner, solvers);

        usdc = new MockERC20("USD Coin", "USDC", 6);
        inToken = new MockERC20("Input", "IN", 18);
        composeProxy = new MockComposeProxy(address(executor));
        usdc.mint(address(composeProxy), POSITION);

        (user, userKey) = makeAddrAndKey("user");
        destination = makeAddr("destination");
        solverTreasury = makeAddr("solverTreasury");
        (attacker, attackerKey) = makeAddrAndKey("attacker");
    }

    /* ─────────────────────────── helpers
    ─────────────────────────── */

    function typehash(
        uint256 nonce,
        bytes32 mode,
        ERC7821.Call[] calldata calls
    ) external pure returns (bytes32) {
        return LibCalls.typehash(nonce, mode, calls);
    }

    /// @dev Signs `calls` with the worker key and relays them from an unrelated EOA,
    /// as the Base relayer does.
    function runWorkerBatch(
        bytes32 mode,
        ERC7821.Call[] memory calls
    ) internal {
        runWorkerBatch(mode, calls, "");
    }

    /// @dev As above; a non-empty `expectedRevert` must be the batch's revert data.
    function runWorkerBatch(
        bytes32 mode,
        ERC7821.Call[] memory calls,
        bytes memory expectedRevert
    ) internal {
        bytes memory executionData = signBatch(mode, calls);
        address relayer = makeAddr("relayer");
        if (expectedRevert.length != 0) vm.expectRevert(expectedRevert);
        vm.prank(relayer, relayer);
        Catapultar(worker).execute(mode, executionData);
    }

    /// @dev The worker-signed `execute` data for `calls`, which anyone can relay.
    function signBatch(
        bytes32 mode,
        ERC7821.Call[] memory calls
    ) internal returns (bytes memory) {
        uint256 nonce = ++workerNonce;
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", IDomain(worker).DOMAIN_SEPARATOR(), this.typehash(nonce, mode, calls))
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(workerKey, digest);
        return abi.encode(calls, abi.encodePacked(nonce, abi.encodePacked(r, s, v)));
    }

    /// @dev The fill payload: drive the compose proxy to deliver the parked position to
    /// the validator, and sweep the user's input to the solver.
    function fillPayload(
        address deliverTo
    ) internal view returns (bytes memory) {
        IntentExecutor.Call3[] memory calls = new IntentExecutor.Call3[](1);
        calls[0] = IntentExecutor.Call3({
            target: address(composeProxy), allowFailure: false, callData: withdrawCall(deliverTo)
        });
        IntentExecutor.SweepTarget[] memory sweeps = new IntentExecutor.SweepTarget[](1);
        sweeps[0] = IntentExecutor.SweepTarget({ token: address(inToken), recipient: solverTreasury });
        return abi.encodeCall(IntentExecutor.executeAndSweep, (new IntentExecutor.Approval[](0), calls, sweeps));
    }

    /// @dev The compose proxy call that moves the parked position to `to`.
    function withdrawCall(
        address to
    ) internal view returns (bytes memory) {
        return abi.encodeCall(MockComposeProxy.withdrawTo, (usdc, to, POSITION));
    }

    struct Fill {
        AllowanceSpend[] allowances;
        Outcome[] outcomes;
        ExecutionBinding binding;
        bytes signature;
    }

    /// @dev The user's signed V2 constraint for `payload`, bound to the executor and the
    /// payload hash, with the executor as the constraint's executor.
    function signFill(
        address allowanceToken,
        uint256 outcomeAmount,
        bytes memory payload
    ) internal returns (Fill memory fill) {
        MockERC20(allowanceToken).mint(user, INPUT);
        vm.prank(user);
        MockERC20(allowanceToken).approve(address(validator), type(uint256).max);

        fill.allowances = new AllowanceSpend[](1);
        fill.allowances[0] = AllowanceSpend({ token: allowanceToken, allocated: INPUT, spend: INPUT });
        fill.outcomes = new Outcome[](1);
        fill.outcomes[0] = Outcome({ token: address(usdc), amount: outcomeAmount, destination: destination });
        fill.binding = ExecutionBinding({ executionTarget: address(executor), payloadHash: keccak256(payload) });
        bytes32 digest = V2ConstraintDigest.digest(
            validator.DOMAIN_SEPARATOR(), fill.allowances, fill.outcomes, address(executor), 1, fill.binding, 0, 0
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userKey, digest);
        fill.signature = abi.encodePacked(r, s, v);
    }

    /// @dev The validator `entry` calldata for the user's constraint.
    function entryData(
        bytes memory payload,
        Fill memory fill
    ) internal view returns (bytes memory) {
        return abi.encodeCall(
            IValidatorV2.entry,
            (
                address(executor),
                payload,
                user,
                1,
                fill.allowances,
                fill.outcomes,
                fill.binding,
                new VMCommand[](0),
                new bytes32[](0),
                fill.signature
            )
        );
    }

    /// @dev The worker's batch call: fill() with the validator's `entry`.
    function fillCall(
        bytes memory payload,
        Fill memory fill
    ) internal view returns (ERC7821.Call[] memory calls) {
        calls = new ERC7821.Call[](1);
        calls[0] = ERC7821.Call({
            to: address(executor),
            value: 0,
            data: abi.encodeCall(IntentExecutor.fill, (address(validator), entryData(payload, fill)))
        });
    }

    /// @dev The worker fills `payload` through the entry stub.
    function stubFill(
        bytes memory payload
    ) internal {
        vm.prank(worker);
        executor.fill(address(entryStub), abi.encodeCall(EntryStub.entry, (address(executor), payload)));
    }

    /// @dev An executeAndSweep() payload that makes no call and sweeps nothing.
    function emptyPayload() internal pure returns (bytes memory) {
        return abi.encodeCall(
            IntentExecutor.executeAndSweep,
            (new IntentExecutor.Approval[](0), new IntentExecutor.Call3[](0), new IntentExecutor.SweepTarget[](0))
        );
    }

    /// @dev Calls the executor with `payload` through the validator's call proxy.
    function callThroughProxy(
        bytes memory payload
    ) internal returns (bool ok, bytes memory ret) {
        (ok, ret) = callProxy.call(proxyCalldata(executor, payload));
    }

    function notAuthorized() internal pure returns (bytes memory) {
        return abi.encodeWithSelector(IntentExecutor.CallNotAuthorized.selector);
    }

    function notConsumed() internal pure returns (bytes memory) {
        return abi.encodeWithSelector(IntentExecutor.CallNotConsumed.selector);
    }

    /* ─────────────────────────── legitimate fill
    ─────────────────────────── */

    /// @dev worker batch [fill] -> executor -> validator -> CALL_PROXY -> executor ->
    /// compose proxy, end to end.
    function test_fill_workerBatchDrivesProxy() external {
        bytes memory payload = fillPayload(address(validator));
        Fill memory fill = signFill(address(inToken), POSITION, payload);

        runWorkerBatch(ATOMIC_MODE, fillCall(payload, fill));

        assertEq(usdc.balanceOf(destination), POSITION);
        assertEq(usdc.balanceOf(address(composeProxy)), 0);
        assertEq(inToken.balanceOf(solverTreasury), INPUT);
    }

    /// @dev The constraint names the executor, so only fill() can submit it: the solver
    /// calling `entry` itself fails the validator's signature check.
    function test_fill_constraintOnlyThroughExecutor() external {
        bytes memory payload = fillPayload(address(validator));
        Fill memory fill = signFill(address(inToken), POSITION, payload);

        vm.prank(worker);
        (bool ok, bytes memory ret) = address(validator).call(entryData(payload, fill));
        assertFalse(ok);
        assertEq(ret, abi.encodeWithSelector(CATValidator.BadSignature.selector));
        assertEq(usdc.balanceOf(address(composeProxy)), POSITION);
    }

    /// @dev A refund constraint names the same executor and carries an empty payload, so
    /// the validator makes no call: fill() runs it without an authorization.
    function test_fill_refundWithoutPayload() external {
        address refundWallet = makeAddr("refundWallet");
        inToken.mint(user, INPUT);
        vm.prank(user);
        inToken.approve(address(validator), type(uint256).max);

        AllowanceSpend[] memory allowances = new AllowanceSpend[](1);
        allowances[0] = AllowanceSpend({ token: address(inToken), allocated: INPUT, spend: INPUT });
        ExecutionBinding memory binding =
            ExecutionBinding({ executionTarget: refundWallet, payloadHash: keccak256("") });
        bytes32 digest = V2ConstraintDigest.digest(
            validator.DOMAIN_SEPARATOR(), allowances, new Outcome[](0), address(executor), 1, binding, 0, 0
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userKey, digest);

        bytes memory refundEntry = abi.encodeCall(
            IValidatorV2.entry,
            (
                refundWallet,
                "",
                user,
                1,
                allowances,
                new Outcome[](0),
                binding,
                new VMCommand[](0),
                new bytes32[](0),
                abi.encodePacked(r, s, v)
            )
        );
        vm.prank(worker);
        executor.fill(address(validator), refundEntry);

        assertEq(inToken.balanceOf(refundWallet), INPUT);
    }

    /* ─────────────────────────── attacker paths
    ─────────────────────────── */

    function test_attacker_directCall_reverts() external {
        bytes memory payload = fillPayload(attacker);

        vm.prank(attacker);
        (bool ok, bytes memory ret) = address(executor).call(payload);
        assertFalse(ok);
        assertEq(ret, notAuthorized());

        IntentExecutor.Call3Value[] memory calls = new IntentExecutor.Call3Value[](1);
        calls[0] = IntentExecutor.Call3Value({
            target: address(composeProxy), allowFailure: false, value: 0, callData: withdrawCall(attacker)
        });
        vm.prank(attacker);
        vm.expectRevert(notAuthorized());
        executor.executeAndSweepNative(
            new IntentExecutor.Approval[](0), calls, new IntentExecutor.SweepTarget[](0), payable(attacker)
        );

        assertEq(usdc.balanceOf(address(composeProxy)), POSITION);
    }

    /// @dev The validator's CALL_PROXY is a permissionless forwarder, so being called by
    /// it proves nothing.
    function test_attacker_viaCallProxy_reverts() external {
        vm.prank(attacker, attacker);
        (bool ok, bytes memory ret) = callThroughProxy(fillPayload(attacker));
        assertFalse(ok);
        assertEq(ret, notAuthorized());
        assertEq(usdc.balanceOf(address(composeProxy)), POSITION);
    }

    /// @dev The Cantina replay: the attacker signs its own constraint (itself as the
    /// constraint's executor), so the validator calls the executor for it.
    function test_attacker_selfSignedEntry_reverts() external {
        attackerEntry(fillPayload(address(validator)), notAuthorized());

        assertEq(usdc.balanceOf(address(composeProxy)), POSITION);
        assertEq(usdc.balanceOf(attacker), 0);
    }

    /// @dev The attacker's own V2 constraint: itself as account and executor, nonce 0,
    /// no allowances, one USDC outcome to itself. The validator then calls the executor
    /// with `payload` (if any) and forwards its whole USDC balance to the attacker.
    function attackerEntry(
        bytes memory payload,
        bytes memory expectedRevert
    ) internal {
        Outcome[] memory outcomes = new Outcome[](1);
        outcomes[0] = Outcome({ token: address(usdc), amount: 0, destination: attacker });
        ExecutionBinding memory binding = ExecutionBinding({ executionTarget: address(0), payloadHash: bytes32(0) });
        bytes32 digest = V2ConstraintDigest.digest(
            validator.DOMAIN_SEPARATOR(), new AllowanceSpend[](0), outcomes, attacker, 0, binding, 0, 0
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(attackerKey, digest);

        if (expectedRevert.length != 0) vm.expectRevert(expectedRevert);
        vm.prank(attacker, attacker);
        validator.entry(
            address(executor),
            payload,
            attacker,
            0,
            new AllowanceSpend[](0),
            outcomes,
            binding,
            new VMCommand[](0),
            new bytes32[](0),
            abi.encodePacked(r, s, v)
        );
    }

    /// @dev The key is the exact calldata: code running inside the fill (an allowance
    /// token hook) cannot run the authorized arguments with trailing bytes the ABI
    /// decoder ignores.
    function test_attacker_differentEncodingOfAuthorizedCall_reverts() external {
        HookToken hookToken = new HookToken();
        bytes memory payload = fillPayload(address(validator));
        Fill memory fill = signFill(address(hookToken), POSITION, payload);
        hookToken.setHook(callProxy, proxyCalldata(executor, abi.encodePacked(payload, uint256(0))));

        runWorkerBatch(ATOMIC_MODE, fillCall(payload, fill));

        assertFalse(hookToken.hookSucceeded());
        assertEq(hookToken.hookReturn(), notAuthorized());
        assertEq(usdc.balanceOf(destination), POSITION);
    }

    /// @dev A consumed authorization cannot be replayed later in the same transaction.
    function test_attacker_replayAfterFill_reverts() external {
        bytes memory payload = fillPayload(address(validator));
        Fill memory fill = signFill(address(inToken), POSITION, payload);
        runWorkerBatch(ATOMIC_MODE, fillCall(payload, fill));

        usdc.mint(address(composeProxy), POSITION);
        vm.prank(attacker, attacker);
        (bool ok, bytes memory ret) = callThroughProxy(payload);
        assertFalse(ok);
        assertEq(ret, notAuthorized());
        assertEq(usdc.balanceOf(address(composeProxy)), POSITION);
    }

    /// @dev An authorization admits the exact calldata only: an attacker running code
    /// inside the fill (an allowance token hook) cannot run its own payload.
    function test_attacker_hookWithOtherPayload_fails() external {
        HookToken hookToken = new HookToken();
        bytes memory payload = fillPayload(address(validator));
        Fill memory fill = signFill(address(hookToken), POSITION, payload);
        hookToken.setHook(callProxy, proxyCalldata(executor, fillPayload(attacker)));

        runWorkerBatch(ATOMIC_MODE, fillCall(payload, fill));

        assertFalse(hookToken.hookSucceeded());
        assertEq(hookToken.hookReturn(), notAuthorized());
        assertEq(usdc.balanceOf(attacker), 0);
        assertEq(usdc.balanceOf(destination), POSITION);
    }

    /// @dev If the hook spends the authorization on the authorized payload itself, the
    /// legitimate call finds none left, `entry` reverts, and fill() reverts with it:
    /// nothing moves.
    function test_attacker_hookSpendsAuthorization_fillReverts() external {
        HookToken hookToken = new HookToken();
        bytes memory payload = fillPayload(address(validator));
        Fill memory fill = signFill(address(hookToken), POSITION, payload);
        hookToken.setHook(callProxy, proxyCalldata(executor, payload));

        runWorkerBatch(ATOMIC_MODE, fillCall(payload, fill), notAuthorized());

        assertEq(usdc.balanceOf(address(composeProxy)), POSITION);
        assertEq(usdc.balanceOf(address(validator)), 0);
    }

    /* ─────────────────────────── consumption
    ─────────────────────────── */

    /// @dev The authorization is spent before the executor makes any call, and a call
    /// inside the fill cannot run the same calldata again.
    function test_consumption_reuseInsideFillFails() external {
        Reenterer reenterer = new Reenterer(executor, callProxy);
        IntentExecutor.Call3[] memory calls = new IntentExecutor.Call3[](1);
        calls[0] = IntentExecutor.Call3({
            target: address(reenterer), allowFailure: false, callData: abi.encodeCall(Reenterer.reenter, ())
        });
        bytes memory payload = abi.encodeCall(
            IntentExecutor.executeAndSweep,
            (new IntentExecutor.Approval[](0), calls, new IntentExecutor.SweepTarget[](0))
        );
        reenterer.setPayload(payload);

        stubFill(payload);

        assertFalse(reenterer.replaySucceeded());
        assertEq(reenterer.replayReturn(), abi.encodeWithSelector(ReentrancyGuardTransient.Reentrancy.selector));
    }

    /// @dev One fill() admits one execution: an `entry` that runs the payload twice
    /// reverts the fill.
    function test_consumption_oneExecutionPerFill() external {
        entryStub.setRuns(2);
        vm.prank(worker);
        vm.expectRevert(notAuthorized());
        executor.fill(address(entryStub), abi.encodeCall(EntryStub.entry, (address(executor), emptyPayload())));
    }

    /* ─────────────────────────── unconsumed authorizations
    ─────────────────────────── */

    /// @dev A failed `entry` reverts fill() and its authorization with it.
    function test_fill_failedEntryRevertsAuthorization() external {
        bytes memory payload = fillPayload(address(validator));
        // The outcome asks for more than the payload delivers, so `entry` reverts.
        Fill memory fill = signFill(address(inToken), POSITION + 1, payload);

        runWorkerBatch(
            ATOMIC_MODE,
            fillCall(payload, fill),
            abi.encodeWithSelector(CATValidator.InvalidTokenAmount.selector, POSITION + 1, POSITION)
        );

        attackerEntry(payload, notAuthorized());
        assertEq(usdc.balanceOf(address(composeProxy)), POSITION);
    }

    /// @dev A CALL to an address without code succeeds, so an `entry` sent to a
    /// validator that is not deployed on this chain returns without consuming. fill()
    /// reverts instead of leaving the authorization live.
    function test_fill_validatorWithoutCode_reverts() external {
        bytes memory payload = fillPayload(address(validator));
        Fill memory fill = signFill(address(inToken), POSITION, payload);

        vm.prank(worker);
        vm.expectRevert(notConsumed());
        executor.fill(makeAddr("undeployedValidator"), entryData(payload, fill));

        attackerEntry(payload, notAuthorized());
        assertEq(usdc.balanceOf(address(composeProxy)), POSITION);
    }

    /// @dev An `entry` that returns without reaching the executor reverts fill().
    function test_fill_entryNotReachingExecutor_reverts() external {
        entryStub.setRuns(0);
        vm.prank(worker);
        vm.expectRevert(notConsumed());
        executor.fill(address(entryStub), abi.encodeCall(EntryStub.entry, (address(executor), emptyPayload())));
    }

    /// @dev A batch that skips failures skips a fill() that left nothing behind: the
    /// authorized payload cannot run later in the transaction.
    function test_skipFailuresBatch_failedFillLeavesNoAuthorization() external {
        bytes memory payload = fillPayload(address(validator));
        Fill memory fill = signFill(address(inToken), POSITION + 1, payload);

        runWorkerBatch(SKIP_FAILURES_MODE, fillCall(payload, fill));

        attackerEntry(payload, notAuthorized());
        assertEq(usdc.balanceOf(attacker), 0);
        assertEq(usdc.balanceOf(address(composeProxy)), POSITION);
    }

    /// @dev Relays the worker's signed batch from the attacker with `gas` gas.
    function relayWithGas(
        bytes32 mode,
        bytes memory executionData,
        uint256 gas
    ) internal returns (bool ok) {
        vm.prank(attacker, attacker);
        (ok,) = worker.call{ gas: gas }(abi.encodeWithSignature("execute(bytes32,bytes)", mode, executionData));
    }

    /// @dev No relay gas leaves an authorization live in a skipping batch. The sweep
    /// runs from 50k up to the lowest gas that completes the fill, and must pass a gas
    /// at which the batch succeeded but skipped the starved fill, or it proves nothing.
    function test_skipFailuresBatch_noRelayGasLeaksAuthorization() external {
        bytes memory payload = fillPayload(address(validator));
        Fill memory fill = signFill(address(inToken), POSITION, payload);
        bytes memory executionData = signBatch(SKIP_FAILURES_MODE, fillCall(payload, fill));

        bool sawSkippedFill;
        bool sawFill;
        for (uint256 gas = 50_000; gas < 2_000_000 && !sawFill; gas += 1000) {
            uint256 snapshot = vm.snapshotState();
            bool ok = relayWithGas(SKIP_FAILURES_MODE, executionData, gas);
            (bool leaked,) = callThroughProxy(payload);
            assertFalse(leaked, string.concat("authorization leaked at relay gas ", vm.toString(gas)));
            sawFill = usdc.balanceOf(destination) == POSITION;
            if (ok && !sawFill) sawSkippedFill = true;
            vm.revertToState(snapshot);
        }
        assertTrue(sawFill, "fill never completed");
        assertTrue(sawSkippedFill, "no gas skipped the fill");
    }

    /* ─────────────────────────── admin
    ─────────────────────────── */

    function test_admin_constructorSeedsSolversAndOwner() external view {
        assertEq(executor.owner(), owner);
        assertTrue(executor.isSolver(worker));
        assertFalse(executor.isSolver(owner));
    }

    function test_admin_constructorRejectsZeroOwner() external {
        vm.expectRevert(Ownable.NewOwnerIsZeroAddress.selector);
        new IntentExecutor(address(0), new address[](0));
    }

    /// @dev Before Cancun, TSTORE is an undefined opcode, so deployment must fail.
    function test_admin_constructorFailsWithoutTransientStorage() external {
        address[] memory solvers = new address[](1);
        solvers[0] = worker;
        vm.setEvmVersion("shanghai");
        vm.expectRevert();
        new IntentExecutor(owner, solvers);

        vm.setEvmVersion("cancun");
        assertTrue(new IntentExecutor(owner, solvers).isSolver(worker));
    }

    /// @dev The zero address cannot be added, by the constructor or by the owner; removing
    /// it stays allowed.
    function test_admin_zeroSolverRejected() external {
        address[] memory solvers = new address[](2);
        solvers[0] = worker;
        vm.expectRevert(IntentExecutor.ZeroSolver.selector);
        new IntentExecutor(owner, solvers);

        vm.startPrank(owner);
        vm.expectRevert(IntentExecutor.ZeroSolver.selector);
        executor.setSolver(address(0), true);
        executor.setSolver(address(0), false);
        vm.stopPrank();
        assertFalse(executor.isSolver(address(0)));
    }

    function test_admin_nonSolverCannotFill() external {
        vm.prank(owner);
        vm.expectRevert(IntentExecutor.NotSolver.selector);
        executor.fill(address(entryStub), abi.encodeCall(EntryStub.entry, (address(executor), emptyPayload())));
    }

    function test_admin_onlyOwnerSetsSolver() external {
        vm.prank(worker);
        vm.expectRevert(Ownable.Unauthorized.selector);
        executor.setSolver(attacker, true);
        assertFalse(executor.isSolver(attacker));
    }

    /// @dev Rotation: add the new worker, remove the old one.
    function test_admin_rotateSolver() external {
        address newWorker = makeAddr("newWorker");
        vm.startPrank(owner);
        vm.expectEmit(true, false, false, true, address(executor));
        emit IntentExecutor.SolverSet(newWorker, true);
        executor.setSolver(newWorker, true);
        executor.setSolver(worker, false);
        vm.stopPrank();

        bytes memory data = abi.encodeCall(EntryStub.entry, (address(executor), emptyPayload()));
        vm.prank(worker);
        vm.expectRevert(IntentExecutor.NotSolver.selector);
        executor.fill(address(entryStub), data);

        vm.prank(newWorker);
        executor.fill(address(entryStub), data);
    }

    function test_admin_singleStepTransferAndRenounceDisabled() external {
        vm.startPrank(owner);
        vm.expectRevert(IntentExecutor.OwnershipTransferDisabled.selector);
        executor.transferOwnership(attacker);
        vm.expectRevert(IntentExecutor.OwnershipTransferDisabled.selector);
        executor.renounceOwnership();
        vm.stopPrank();
        assertEq(executor.owner(), owner);
    }

    function test_admin_twoStepHandover() external {
        address newOwner = makeAddr("newOwner");

        // The owner alone cannot hand over to an address that never requested it.
        vm.prank(owner);
        vm.expectRevert(Ownable.NoHandoverRequest.selector);
        executor.completeOwnershipHandover(newOwner);

        vm.prank(newOwner);
        executor.requestOwnershipHandover();
        vm.prank(owner);
        executor.completeOwnershipHandover(newOwner);
        assertEq(executor.owner(), newOwner);

        vm.prank(owner);
        vm.expectRevert(Ownable.Unauthorized.selector);
        executor.setSolver(attacker, true);

        vm.prank(newOwner);
        executor.setSolver(attacker, true);
        assertTrue(executor.isSolver(attacker));
    }
}
