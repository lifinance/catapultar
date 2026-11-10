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

/// @dev Called from inside an authorized execution. Reads the remaining authorization
/// and replays the same calldata through the validator's call proxy.
contract Reenterer {
    IntentExecutor public immutable executor;
    address public immutable callProxy;
    bytes public payload;
    uint256 public authorizationsDuringCall;
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
        authorizationsDuringCall = executor.authorizations(keccak256(payload));
        (replaySucceeded, replayReturn) = callProxy.call(proxyCalldata(executor, payload));
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

    /// @dev withdrawCall(to) as the single call of an executeAndSweepNative() payload.
    function withdrawCallsWithValue(
        address to
    ) internal view returns (IntentExecutor.Call3Value[] memory calls) {
        calls = new IntentExecutor.Call3Value[](1);
        calls[0] = IntentExecutor.Call3Value({
            target: address(composeProxy), allowFailure: false, value: 0, callData: withdrawCall(to)
        });
    }

    struct Fill {
        AllowanceSpend[] allowances;
        Outcome[] outcomes;
        ExecutionBinding binding;
        bytes signature;
    }

    /// @dev The user's signed V2 constraint for `payload`, bound to the executor and the
    /// payload hash, with the worker as the constraint's executor.
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
            validator.DOMAIN_SEPARATOR(), fill.allowances, fill.outcomes, worker, 1, fill.binding, 0, 0
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(userKey, digest);
        fill.signature = abi.encodePacked(r, s, v);
    }

    function entryCall(
        bytes memory payload,
        Fill memory fill
    ) internal view returns (ERC7821.Call memory) {
        return entryCall(payload, fill, address(validator));
    }

    /// @dev As above, sent to `to` instead of the validator.
    function entryCall(
        bytes memory payload,
        Fill memory fill,
        address to
    ) internal view returns (ERC7821.Call memory) {
        return ERC7821.Call({
            to: to,
            value: 0,
            data: abi.encodeCall(
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
            )
        });
    }

    function authorizeCall(
        bytes memory payload
    ) internal view returns (ERC7821.Call memory) {
        return authorizeCall(payload, address(validator));
    }

    /// @dev As above, naming `entryValidator` as the validator whose `entry` follows.
    function authorizeCall(
        bytes memory payload,
        address entryValidator
    ) internal view returns (ERC7821.Call memory) {
        return ERC7821.Call({
            to: address(executor),
            value: 0,
            data: abi.encodeCall(IntentExecutor.authorizeCall, (keccak256(payload), entryValidator))
        });
    }

    function authorizeThenEntry(
        bytes memory payload,
        Fill memory fill
    ) internal view returns (ERC7821.Call[] memory calls) {
        calls = new ERC7821.Call[](2);
        calls[0] = authorizeCall(payload);
        calls[1] = entryCall(payload, fill);
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

    /* ─────────────────────────── legitimate fill
    ─────────────────────────── */

    /// @dev worker batch [authorizeCall, entry] -> validator -> CALL_PROXY -> executor ->
    /// compose proxy, end to end.
    function test_fill_workerBatchDrivesProxy() external {
        bytes memory payload = fillPayload(address(validator));
        Fill memory fill = signFill(address(inToken), POSITION, payload);

        runWorkerBatch(ATOMIC_MODE, authorizeThenEntry(payload, fill));

        assertEq(usdc.balanceOf(destination), POSITION);
        assertEq(usdc.balanceOf(address(composeProxy)), 0);
        assertEq(inToken.balanceOf(solverTreasury), INPUT);
        assertEq(executor.authorizations(keccak256(payload)), 0);
    }

    function test_fill_withoutAuthorizationReverts() external {
        bytes memory payload = fillPayload(address(validator));
        Fill memory fill = signFill(address(inToken), POSITION, payload);

        ERC7821.Call[] memory calls = new ERC7821.Call[](1);
        calls[0] = entryCall(payload, fill);
        runWorkerBatch(ATOMIC_MODE, calls, notAuthorized());
    }

    /* ─────────────────────────── attacker paths
    ─────────────────────────── */

    function test_attacker_directCall_reverts() external {
        bytes memory payload = fillPayload(attacker);

        vm.prank(attacker);
        (bool ok, bytes memory ret) = address(executor).call(payload);
        assertFalse(ok);
        assertEq(ret, notAuthorized());

        IntentExecutor.Call3Value[] memory calls = withdrawCallsWithValue(attacker);
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

    /// @dev The key is the exact calldata: the same arguments under the other entry
    /// point, or with trailing bytes the ABI decoder ignores, are not authorized.
    function test_attacker_differentEncodingOfAuthorizedCall_reverts() external {
        bytes memory payload = fillPayload(address(validator));
        vm.prank(worker);
        executor.authorizeCall(keccak256(payload), address(validator));

        (bool ok, bytes memory ret) = callThroughProxy(abi.encodePacked(payload, uint256(0)));
        assertFalse(ok);
        assertEq(ret, notAuthorized());

        IntentExecutor.Call3Value[] memory calls = withdrawCallsWithValue(address(validator));
        IntentExecutor.SweepTarget[] memory sweeps = new IntentExecutor.SweepTarget[](1);
        sweeps[0] = IntentExecutor.SweepTarget({ token: address(inToken), recipient: solverTreasury });
        (ok, ret) = callThroughProxy(
            abi.encodeCall(
                IntentExecutor.executeAndSweepNative,
                (new IntentExecutor.Approval[](0), calls, sweeps, payable(solverTreasury))
            )
        );
        assertFalse(ok);
        assertEq(ret, notAuthorized());

        assertEq(executor.authorizations(keccak256(payload)), 1);
        assertEq(usdc.balanceOf(address(composeProxy)), POSITION);
    }

    /// @dev A consumed authorization cannot be replayed later in the same transaction.
    function test_attacker_replayAfterFill_reverts() external {
        bytes memory payload = fillPayload(address(validator));
        Fill memory fill = signFill(address(inToken), POSITION, payload);
        runWorkerBatch(ATOMIC_MODE, authorizeThenEntry(payload, fill));

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

        runWorkerBatch(ATOMIC_MODE, authorizeThenEntry(payload, fill));

        assertFalse(hookToken.hookSucceeded());
        assertEq(hookToken.hookReturn(), notAuthorized());
        assertEq(usdc.balanceOf(attacker), 0);
        assertEq(usdc.balanceOf(destination), POSITION);
    }

    /// @dev If the hook spends the authorization on the authorized payload itself, the
    /// legitimate call finds none left, `entry` reverts, and the atomic batch reverts
    /// with it: nothing moves.
    function test_attacker_hookSpendsAuthorization_batchReverts() external {
        HookToken hookToken = new HookToken();
        bytes memory payload = fillPayload(address(validator));
        Fill memory fill = signFill(address(hookToken), POSITION, payload);
        hookToken.setHook(callProxy, proxyCalldata(executor, payload));

        ERC7821.Call[] memory calls = authorizeThenEntry(payload, fill);
        runWorkerBatch(ATOMIC_MODE, calls, notAuthorized());

        assertEq(usdc.balanceOf(address(composeProxy)), POSITION);
        assertEq(usdc.balanceOf(address(validator)), 0);
        assertEq(executor.authorizations(keccak256(payload)), 0);
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

        // Two authorizations: the guard, not a missing authorization, must stop the replay.
        vm.startPrank(worker);
        executor.authorizeCall(keccak256(payload), address(validator));
        executor.authorizeCall(keccak256(payload), address(validator));
        vm.stopPrank();

        (bool ok,) = callThroughProxy(payload);
        assertTrue(ok);

        assertEq(reenterer.authorizationsDuringCall(), 1);
        assertFalse(reenterer.replaySucceeded());
        assertEq(reenterer.replayReturn(), abi.encodeWithSelector(ReentrancyGuardTransient.Reentrancy.selector));
        assertEq(executor.authorizations(keccak256(payload)), 1);
    }

    function test_consumption_countsAuthorizations() external {
        bytes memory payload = fillPayload(address(validator));
        usdc.mint(address(composeProxy), POSITION);

        vm.startPrank(worker);
        executor.authorizeCall(keccak256(payload), address(validator));
        executor.authorizeCall(keccak256(payload), address(validator));
        vm.stopPrank();

        (bool ok,) = callThroughProxy(payload);
        assertTrue(ok);
        (ok,) = callThroughProxy(payload);
        assertTrue(ok);
        (bool third, bytes memory ret) = callThroughProxy(payload);
        assertFalse(third);
        assertEq(ret, notAuthorized());
        assertEq(usdc.balanceOf(address(validator)), 2 * POSITION);
    }

    /* ─────────────────────────── batch atomicity
    ─────────────────────────── */

    /// @dev A failed `entry` in an atomic batch rolls the authorization back with it.
    function test_atomicBatch_failedEntryRollsBackAuthorization() external {
        bytes memory payload = fillPayload(address(validator));
        // The outcome asks for more than the payload delivers, so `entry` reverts.
        Fill memory fill = signFill(address(inToken), POSITION + 1, payload);

        ERC7821.Call[] memory calls = authorizeThenEntry(payload, fill);
        runWorkerBatch(
            ATOMIC_MODE, calls, abi.encodeWithSelector(CATValidator.InvalidTokenAmount.selector, POSITION + 1, POSITION)
        );

        assertEq(executor.authorizations(keccak256(payload)), 0);
        vm.prank(attacker, attacker);
        (bool ok, bytes memory ret) = callThroughProxy(payload);
        assertFalse(ok);
        assertEq(ret, notAuthorized());
        assertEq(usdc.balanceOf(address(composeProxy)), POSITION);
    }

    /// @dev A CALL to an address without code succeeds, so an `entry` sent to a
    /// validator that is not deployed on this chain would return without consuming.
    /// authorizeCall refuses such a validator, which reverts the atomic batch.
    function test_atomicBatch_validatorWithoutCode_reverts() external {
        bytes memory payload = fillPayload(address(validator));
        Fill memory fill = signFill(address(inToken), POSITION, payload);
        address undeployed = makeAddr("undeployedValidator");

        ERC7821.Call[] memory calls = new ERC7821.Call[](2);
        calls[0] = authorizeCall(payload, undeployed);
        calls[1] = entryCall(payload, fill, undeployed);
        runWorkerBatch(ATOMIC_MODE, calls, abi.encodeWithSelector(IntentExecutor.ValidatorHasNoCode.selector));

        assertEq(executor.authorizations(keccak256(payload)), 0);
        attackerEntry(payload, notAuthorized());
        assertEq(usdc.balanceOf(address(composeProxy)), POSITION);
    }

    /// @dev Why the signer must pass the address its `entry` calls: the executor checks
    /// only the validator it is given, so an `entry` sent elsewhere to an empty address
    /// still leaves the authorization live in an atomic batch.
    function test_atomicBatch_entryToOtherThanAuthorizedValidatorLeaksPosition() external {
        bytes memory payload = fillPayload(address(validator));
        Fill memory fill = signFill(address(inToken), POSITION, payload);

        ERC7821.Call[] memory calls = new ERC7821.Call[](2);
        calls[0] = authorizeCall(payload);
        calls[1] = entryCall(payload, fill, makeAddr("undeployedValidator"));
        runWorkerBatch(ATOMIC_MODE, calls);
        assertEq(executor.authorizations(keccak256(payload)), 1);

        attackerEntry(payload, "");
        assertEq(usdc.balanceOf(attacker), POSITION);
        assertEq(usdc.balanceOf(address(composeProxy)), 0);
    }

    /// @dev Why authorizeCall and `entry` must share an atomic batch. In a batch that
    /// skips failures, a failed `entry` leaves the authorization live for the rest of
    /// the transaction. Any later code can then run the authorized payload, which
    /// parks the position on the validator, and any account can take a validator
    /// balance with a self-signed constraint.
    function test_skipFailuresBatch_failedEntryLeaksPosition() external {
        bytes memory payload = fillPayload(address(validator));
        Fill memory fill = signFill(address(inToken), POSITION + 1, payload);

        runWorkerBatch(SKIP_FAILURES_MODE, authorizeThenEntry(payload, fill));
        assertEq(executor.authorizations(keccak256(payload)), 1);

        // Only the authorized calldata runs...
        (bool ok, bytes memory ret) = callThroughProxy(fillPayload(attacker));
        assertFalse(ok);
        assertEq(ret, notAuthorized());

        // ...but the authorized calldata runs for anyone, later in the same transaction.
        attackerEntry(payload, "");
        assertEq(usdc.balanceOf(attacker), POSITION);
        assertEq(usdc.balanceOf(address(composeProxy)), 0);
        assertEq(executor.authorizations(keccak256(payload)), 0);
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

    /// @dev The lowest relay gas at which a skipping batch runs authorizeCall but `entry`
    /// runs out of gas. Searched rather than fixed, because the window moves with the
    /// compiler settings (coverage builds are unoptimized). Leaves the state untouched.
    function starvingGas(
        bytes memory payload,
        Fill memory fill
    ) internal returns (uint256 gas) {
        uint256 nonce = workerNonce;
        gas = starvingGas(signBatch(SKIP_FAILURES_MODE, authorizeThenEntry(payload, fill)), payload);
        workerNonce = nonce;
    }

    /// @dev As above for an already signed skipping batch, which can still be relayed
    /// afterwards.
    function starvingGas(
        bytes memory executionData,
        bytes memory payload
    ) internal returns (uint256) {
        for (uint256 gas = 50_000; gas < 2_000_000; gas += 5000) {
            uint256 snapshot = vm.snapshotState();
            bool starved = relayWithGas(SKIP_FAILURES_MODE, executionData, gas)
                && executor.authorizations(keccak256(payload)) == 1 && usdc.balanceOf(destination) == 0;
            vm.revertToState(snapshot);
            if (starved) return gas;
        }
        revert("no starving gas found");
    }

    /// @dev The skipping-batch leak needs no accidental failure: anyone can relay the
    /// worker's signed batch with enough gas for authorizeCall but not for `entry`.
    function test_skipFailuresBatch_attackerStarvesEntry() external {
        bytes memory payload = fillPayload(address(validator));
        Fill memory fill = signFill(address(inToken), POSITION, payload);
        uint256 gas = starvingGas(payload, fill);
        bytes memory executionData = signBatch(SKIP_FAILURES_MODE, authorizeThenEntry(payload, fill));

        assertTrue(relayWithGas(SKIP_FAILURES_MODE, executionData, gas));
        assertEq(executor.authorizations(keccak256(payload)), 1);
        assertEq(usdc.balanceOf(destination), 0);

        attackerEntry(payload, "");
        assertEq(usdc.balanceOf(attacker), POSITION);
    }

    /// @dev The same relay against an atomic batch reverts as a whole.
    function test_atomicBatch_attackerStarvesEntry_reverts() external {
        bytes memory payload = fillPayload(address(validator));
        Fill memory fill = signFill(address(inToken), POSITION, payload);
        uint256 gas = starvingGas(payload, fill);
        bytes memory executionData = signBatch(ATOMIC_MODE, authorizeThenEntry(payload, fill));

        assertFalse(relayWithGas(ATOMIC_MODE, executionData, gas));
        assertEq(executor.authorizations(keccak256(payload)), 0);
        assertEq(usdc.balanceOf(address(composeProxy)), POSITION);
    }

    /* ─────────────────────────── meta transactions (sub-batches)
    ─────────────────────────── */

    /// @dev A sub-batch as the SDK's MetaCatapultarTx encodes it: a self-call to the
    /// worker's `execute` with a 32-byte opData (its own nonce, no signature), which the
    /// account accepts because msg.sender is itself.
    function subBatch(
        bytes32 mode,
        ERC7821.Call[] memory calls
    ) internal returns (ERC7821.Call memory) {
        return ERC7821.Call({
            to: worker,
            value: 0,
            data: abi.encodeWithSignature(
                "execute(bytes32,bytes)", mode, abi.encode(calls, abi.encodePacked(++workerNonce))
            )
        });
    }

    /// @dev The split shape: atomic sub-batches [authorizeCall] and [entry]. Meant for a
    /// SkipRevert outer batch, MetaCatapultarTx's default.
    function splitSubBatches(
        bytes memory payload,
        Fill memory fill
    ) internal returns (ERC7821.Call[] memory outer) {
        ERC7821.Call[] memory first = new ERC7821.Call[](1);
        first[0] = authorizeCall(payload);
        ERC7821.Call[] memory second = new ERC7821.Call[](1);
        second[0] = entryCall(payload, fill);
        outer = new ERC7821.Call[](2);
        outer[0] = subBatch(ATOMIC_MODE, first);
        outer[1] = subBatch(ATOMIC_MODE, second);
    }

    /// @dev The shared shape: one atomic sub-batch [authorizeCall, entry].
    function sharedSubBatch(
        bytes memory payload,
        Fill memory fill
    ) internal returns (ERC7821.Call[] memory outer) {
        outer = new ERC7821.Call[](1);
        outer[0] = subBatch(ATOMIC_MODE, authorizeThenEntry(payload, fill));
    }

    /// @dev Why authorizeCall and `entry` must share a sub-batch. Each sub-batch is
    /// atomic, but the [authorizeCall] sub-batch has already succeeded when the [entry]
    /// sub-batch fails, and the SkipRevert outer batch skips the failure. The
    /// authorization survives and the position leaks as in a flat skipping batch.
    function test_skipFailuresMeta_splitSubBatches_failedEntryLeaksPosition() external {
        bytes memory payload = fillPayload(address(validator));
        Fill memory fill = signFill(address(inToken), POSITION + 1, payload);

        runWorkerBatch(SKIP_FAILURES_MODE, splitSubBatches(payload, fill));
        assertEq(executor.authorizations(keccak256(payload)), 1);

        attackerEntry(payload, "");
        assertEq(usdc.balanceOf(attacker), POSITION);
        assertEq(usdc.balanceOf(address(composeProxy)), 0);
        assertEq(executor.authorizations(keccak256(payload)), 0);
    }

    /// @dev The split shape is open to the gas-starvation relay as well.
    function test_skipFailuresMeta_splitSubBatches_attackerStarvesEntry() external {
        bytes memory payload = fillPayload(address(validator));
        Fill memory fill = signFill(address(inToken), POSITION, payload);
        bytes memory executionData = signBatch(SKIP_FAILURES_MODE, splitSubBatches(payload, fill));
        uint256 gas = starvingGas(executionData, payload);

        assertTrue(relayWithGas(SKIP_FAILURES_MODE, executionData, gas));
        assertEq(executor.authorizations(keccak256(payload)), 1);
        assertEq(usdc.balanceOf(destination), 0);

        attackerEntry(payload, "");
        assertEq(usdc.balanceOf(attacker), POSITION);
    }

    /// @dev With both calls in one atomic sub-batch, a failed `entry` reverts the
    /// sub-batch as a unit, authorization included. The outer batch skips a frame that
    /// left nothing behind.
    function test_skipFailuresMeta_sharedSubBatch_failedEntryRollsBackAuthorization() external {
        bytes memory payload = fillPayload(address(validator));
        Fill memory fill = signFill(address(inToken), POSITION + 1, payload);

        runWorkerBatch(SKIP_FAILURES_MODE, sharedSubBatch(payload, fill));
        assertEq(executor.authorizations(keccak256(payload)), 0);

        attackerEntry(payload, notAuthorized());
        assertEq(usdc.balanceOf(attacker), 0);
        assertEq(usdc.balanceOf(address(composeProxy)), POSITION);
    }

    /// @dev No relay gas leaves the shared sub-batch's authorization live. The sweep runs
    /// from 50k up to the lowest gas that completes the fill, and must pass a gas at
    /// which the outer batch succeeded but skipped the starved sub-batch, or it proves
    /// nothing.
    function test_skipFailuresMeta_sharedSubBatch_noGasLeaksAuthorization() external {
        bytes memory payload = fillPayload(address(validator));
        Fill memory fill = signFill(address(inToken), POSITION, payload);
        bytes memory executionData = signBatch(SKIP_FAILURES_MODE, sharedSubBatch(payload, fill));

        bool sawSkippedFill;
        bool sawFill;
        for (uint256 gas = 50_000; gas < 2_000_000 && !sawFill; gas += 1000) {
            uint256 snapshot = vm.snapshotState();
            bool ok = relayWithGas(SKIP_FAILURES_MODE, executionData, gas);
            assertEq(
                executor.authorizations(keccak256(payload)),
                0,
                string.concat("authorization leaked at relay gas ", vm.toString(gas))
            );
            sawFill = usdc.balanceOf(destination) == POSITION;
            if (ok && !sawFill) sawSkippedFill = true;
            vm.revertToState(snapshot);
        }
        assertTrue(sawFill, "fill never completed");
        assertTrue(sawSkippedFill, "no gas skipped the fill");
    }

    /// forge-config: default.isolate = true
    function test_authorizationEndsWithTransaction() external {
        bytes memory payload = fillPayload(address(validator));
        ERC7821.Call[] memory calls = new ERC7821.Call[](1);
        calls[0] = authorizeCall(payload);
        runWorkerBatch(ATOMIC_MODE, calls);

        // isolate mode runs each top-level call as its own transaction.
        vm.prank(attacker, attacker);
        (bool ok, bytes memory ret) = callThroughProxy(payload);
        assertFalse(ok);
        assertEq(ret, notAuthorized());
        assertEq(usdc.balanceOf(address(composeProxy)), POSITION);
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

    function test_admin_nonSolverCannotAuthorize() external {
        vm.prank(owner);
        vm.expectRevert(IntentExecutor.NotSolver.selector);
        executor.authorizeCall(keccak256("x"), address(validator));
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

        vm.prank(worker);
        vm.expectRevert(IntentExecutor.NotSolver.selector);
        executor.authorizeCall(keccak256("x"), address(validator));

        vm.prank(newWorker);
        executor.authorizeCall(keccak256("x"), address(validator));
        assertEq(executor.authorizations(keccak256("x")), 1);
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
