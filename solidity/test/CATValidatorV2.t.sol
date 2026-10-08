// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { Test } from "forge-std/src/Test.sol";

import { ReentrancyGuard } from "solady/src/utils/ReentrancyGuard.sol";
import { MockERC20 } from "solady/test/utils/mocks/MockERC20.sol";

import { CATValidator } from "../src/CATValidator.sol";
import { CATValidatorV2 } from "../src/CATValidatorV2.sol";
import { AllowanceSpend, Outcome } from "../src/libs/LibExecutionConstraint.sol";
import { LibValidationVM, VMCommand, VMState } from "../src/libs/LibValidationVM.sol";

/// @dev Calldata trampolines for the library's calldata-typed arguments.
contract LibValidationVMHarness {
    function paramsHashOf(
        bytes32[] calldata params
    ) external pure returns (bytes32) {
        return LibValidationVM.paramsHashOf(params);
    }

    function buildRegisters(
        bytes32[] calldata params,
        address account,
        uint256[] calldata spent,
        uint256[] calldata paid
    ) external pure returns (bytes[] memory) {
        return LibValidationVM.buildRegisters(params, account, spent, paid);
    }
}

/// @dev Exposes the transient payment record, which must read 0 outside a
/// program-bearing settlement.
contract CATValidatorV2Harness is CATValidatorV2 {
    constructor(
        address virtualMachine
    ) CATValidatorV2(virtualMachine) { }

    function paidRecord() external view returns (uint256) {
        return _getTstorish(uint256(keccak256("CATValidatorV2.paid")) & ~uint256(0xff));
    }
}

/// @dev Stand-in VMs so the unit tests need no fork.
contract AcceptVM {
    fallback() external { }
}

/// @dev Reverts with its own calldata, so `ValidationFailed(data)` carries the
/// exact `runVM` payload `entry` sent through the staticcall.
contract EchoVM {
    fallback() external {
        assembly ("memory-safe") {
            calldatacopy(0, 0, calldatasize())
            revert(0, calldatasize())
        }
    }
}

/// @dev Halts with INVALID, consuming every unit of forwarded gas.
contract InvalidVM {
    fallback() external {
        assembly ("memory-safe") {
            invalid()
        }
    }
}

/// @dev Loops until the forwarded gas runs out.
contract BurnVM {
    fallback() external {
        while (true) {
            assembly ("memory-safe") {
                pop(keccak256(0, 32))
            }
        }
    }
}

/// @dev A fill reached through the validator's CallProxy. MockERC20's mint is
/// permissionless, so the proxy can mint to any recipient.
contract OutcomeFill {
    function mint(
        MockERC20 outToken,
        address to,
        uint256 amount
    ) external {
        outToken.mint(to, amount);
    }

    function mintTwo(
        MockERC20 outToken,
        address to,
        uint256 amount,
        address other,
        uint256 otherAmount
    ) external {
        outToken.mint(to, amount);
        outToken.mint(other, otherAmount);
    }

    function sendNative(
        address payable to,
        uint256 amount
    ) external {
        (bool ok,) = to.call{ value: amount }("");
        require(ok, "native send failed");
    }

    /// @dev Re-enters the validator's 9-argument entry.
    function reenter(
        CATValidatorV2 validator,
        bytes calldata entryCalldata
    ) external {
        (bool ok, bytes memory ret) = address(validator).call(entryCalldata);
        if (!ok) {
            assembly ("memory-safe") {
                revert(add(ret, 32), mload(ret))
            }
        }
    }
}

/// @dev A destination that, on receiving native value, mints `bonusToken` to
/// `bonusTo`: a callback that changes a later outcome's token mid-payment.
contract CallbackDestination {
    MockERC20 immutable bonusToken;
    address immutable bonusTo;
    uint256 immutable bonusAmount;

    constructor(
        MockERC20 token,
        address to,
        uint256 amount
    ) {
        bonusToken = token;
        bonusTo = to;
        bonusAmount = amount;
    }

    receive() external payable {
        bonusToken.mint(bonusTo, bonusAmount);
    }
}

/// @dev Reverts with 196 bytes, longer than the 64-byte scratch space.
contract LongReverter {
    error LongRevert(uint256[6] words);

    function boom(
        uint256[6] calldata words
    ) external pure {
        revert LongRevert(words);
    }
}

contract CATValidatorV2Test is Test {
    CATValidatorV2Harness validator; // backed by AcceptVM
    CATValidatorV2 echoValidator; // backed by EchoVM
    LibValidationVMHarness lib;

    address signer;
    uint256 signerKey;
    address executor;
    address destination;
    MockERC20 token;
    MockERC20 inToken;
    OutcomeFill fill;

    function setUp() external {
        validator = new CATValidatorV2Harness(address(new AcceptVM()));
        echoValidator = new CATValidatorV2(address(new EchoVM()));
        lib = new LibValidationVMHarness();

        (signer, signerKey) = makeAddrAndKey("signer");
        executor = makeAddr("executor");
        destination = makeAddr("destination");
        token = new MockERC20("Outcome", "OUT", 18);
        inToken = new MockERC20("Allowance", "IN", 18);
        fill = new OutcomeFill();
    }

    /* ─────────────────────────── LibValidationVM
    ─────────────────────────── */

    function test_paramsHashOf_emptyIsZero() external view {
        assertEq(lib.paramsHashOf(new bytes32[](0)), bytes32(0));
    }

    function test_paramsHashOf_concatKeccak(
        bytes32 a,
        bytes32 b
    ) external view {
        bytes32[] memory params = new bytes32[](2);
        params[0] = a;
        params[1] = b;
        assertEq(lib.paramsHashOf(params), keccak256(abi.encodePacked(a, b)));
    }

    function test_buildRegisters_layout() external view {
        bytes32[] memory params = new bytes32[](2);
        params[0] = bytes32(uint256(0xAA));
        params[1] = bytes32(uint256(0xBB));
        uint256[] memory spent = new uint256[](2);
        spent[0] = 1 ether;
        spent[1] = 42;
        uint256[] memory paid = new uint256[](1);
        paid[0] = 7;
        address account = address(0xE5c);

        bytes[] memory registers = lib.buildRegisters(params, account, spent, paid);

        assertEq(registers.length, 123, "fixed register-file size");
        assertEq(registers[0], abi.encodePacked(bytes32(uint256(0xAA))), "params[0]");
        assertEq(registers[1], abi.encodePacked(bytes32(uint256(0xBB))), "params[1]");
        assertEq(registers[2], abi.encodePacked(bytes32(uint256(uint160(account)))), "account after params");
        assertEq(registers[3], abi.encodePacked(bytes32(uint256(1 ether))), "spent[0]");
        assertEq(registers[4], abi.encodePacked(bytes32(uint256(42))), "spent[1]");
        assertEq(registers[5], abi.encodePacked(bytes32(uint256(7))), "paid[0]");
        for (uint256 i = 6; i < registers.length; ++i) {
            assertEq(registers[i], new bytes(32), "scratch is a 32-byte zero word");
        }
    }

    /* ─────────────────────────── helpers
    ─────────────────────────── */

    function dummyProgram() internal pure returns (VMCommand[] memory program) {
        program = new VMCommand[](1);
        program[0] = VMCommand({ op: 8, data: bytes32(0) });
    }

    function noProgram() internal pure returns (VMCommand[] memory) {
        return new VMCommand[](0);
    }

    /// @dev The program hash rule; `test_entry_programHashIsKeccakOfAbiEncodedCommands`
    /// pins it against an independently computed vector.
    function hashProgram(
        VMCommand[] memory program
    ) internal pure returns (bytes32) {
        return program.length == 0 ? bytes32(0) : keccak256(abi.encode(program));
    }

    function oneOutcome(
        address outToken,
        uint256 amount,
        address to
    ) internal pure returns (Outcome[] memory outcomes) {
        outcomes = new Outcome[](1);
        outcomes[0] = Outcome({ token: outToken, amount: amount, destination: to });
    }

    function oneAllowance(
        address inTok,
        uint256 spend
    ) internal pure returns (AllowanceSpend[] memory allowances) {
        allowances = new AllowanceSpend[](1);
        allowances[0] = AllowanceSpend({ token: inTok, allocated: type(uint256).max, spend: spend });
    }

    function noAllowances() internal pure returns (AllowanceSpend[] memory) {
        return new AllowanceSpend[](0);
    }

    function noParams() internal pure returns (bytes32[] memory) {
        return new bytes32[](0);
    }

    function words(
        uint256 n
    ) internal pure returns (bytes32[] memory params) {
        params = new bytes32[](n);
        for (uint256 i; i < n; ++i) {
            params[i] = bytes32(i);
        }
    }

    function hashParams(
        bytes32[] memory params
    ) internal pure returns (bytes32) {
        if (params.length == 0) return bytes32(0);
        bytes memory buffer;
        for (uint256 i; i < params.length; ++i) {
            buffer = abi.encodePacked(buffer, params[i]);
        }
        return keccak256(buffer);
    }

    function fundEscrow(
        CATValidatorV2 target,
        uint256 amount
    ) internal {
        inToken.mint(signer, amount);
        vm.prank(signer);
        inToken.approve(address(target), type(uint256).max);
    }

    function expectedRunVM(
        VMCommand[] memory program,
        bytes32[] memory params,
        uint256[] memory spent,
        uint256[] memory paid
    ) internal view returns (bytes memory) {
        return abi.encodeWithSelector(
            CATValidatorV2.ValidationFailed.selector,
            abi.encodeWithSelector(
                LibValidationVM.RUN_VM_SELECTOR, program, VMState(lib.buildRegisters(params, signer, spent, paid))
            )
        );
    }

    /// @dev Signs the V2 typehash with an independent EIP-712 encoding.
    function sign(
        CATValidatorV2 target,
        uint256 nonce,
        AllowanceSpend[] memory allowances,
        Outcome[] memory outcomes,
        bytes32 validationProgramHash,
        bytes32 paramsHash
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
        bytes32[] memory outputHashes = new bytes32[](outcomes.length);
        for (uint256 i; i < outcomes.length; ++i) {
            outputHashes[i] = keccak256(
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
                        "ExecutionConstraint(Allowance[] allowances,Outcome[] outcomes,address executor,uint256 nonce,bytes32 validationProgramHash,bytes32 paramsHash)Allowance(address token,uint256 amount)Outcome(address token,uint256 amount,address destination)"
                    )
                ),
                keccak256(abi.encodePacked(allowanceHashes)),
                keccak256(abi.encodePacked(outputHashes)),
                executor,
                nonce,
                validationProgramHash,
                paramsHash
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", target.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, digest);
        signature = abi.encodePacked(r, s, v);
    }

    /// @dev Signs for the supplied program and params, then calls `entry` as the executor.
    function settle(
        CATValidatorV2 target,
        address execTarget,
        bytes memory payload,
        AllowanceSpend[] memory allowances,
        Outcome[] memory outcomes,
        VMCommand[] memory program,
        bytes32[] memory params
    ) internal {
        bytes memory sig = sign(target, 1, allowances, outcomes, hashProgram(program), hashParams(params));
        vm.prank(executor);
        target.entry(execTarget, payload, signer, 1, allowances, outcomes, program, params, sig);
    }

    function settle(
        CATValidatorV2 target,
        address execTarget,
        bytes memory payload,
        Outcome[] memory outcomes,
        VMCommand[] memory program
    ) internal {
        settle(target, execTarget, payload, noAllowances(), outcomes, program, noParams());
    }

    /* ─────────────────────────── domain and v1 entry
    ─────────────────────────── */

    function test_domainSeparator_isVersion2() external view {
        bytes32 expected = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("CAT Validator"),
                keccak256("2"),
                block.chainid,
                address(validator)
            )
        );
        assertEq(validator.DOMAIN_SEPARATOR(), expected);
    }

    function test_entry_v1OverloadDisabled() external {
        Outcome[] memory outcomes = oneOutcome(address(token), 0, destination);
        vm.prank(executor);
        vm.expectRevert(CATValidatorV2.V1EntryDisabled.selector);
        validator.entry(address(fill), hex"", signer, 1, noAllowances(), outcomes, hex"");
    }

    /* ─────────────────────────── input validation
    ─────────────────────────── */

    function test_entry_rejectsParamsWithoutProgram() external {
        bytes32[] memory params = words(1);
        Outcome[] memory outcomes = oneOutcome(address(token), 0, destination);
        bytes memory sig = sign(validator, 1, noAllowances(), outcomes, bytes32(0), hashParams(params));
        vm.prank(executor);
        vm.expectRevert(CATValidatorV2.BadValidationParams.selector);
        validator.entry(address(fill), hex"", signer, 1, noAllowances(), outcomes, noProgram(), params, sig);
    }

    function test_entry_rejectsPrefixPastVoidRegister() external {
        // 121 params + account + paid[0] = highest index 122, the void register.
        Outcome[] memory outcomes = oneOutcome(address(token), 0, destination);
        VMCommand[] memory program = dummyProgram();
        bytes32[] memory params = words(121);
        bytes memory sig = sign(validator, 1, noAllowances(), outcomes, hashProgram(program), hashParams(params));
        vm.prank(executor);
        vm.expectRevert(CATValidatorV2.BadValidationParams.selector);
        validator.entry(address(fill), hex"", signer, 1, noAllowances(), outcomes, program, params, sig);
    }

    function test_entry_acceptsPrefixEndingAtMax() external {
        // 120 params + account + paid[0] = highest index 121 == MAX_PREFIX_END.
        settle(
            validator,
            address(fill),
            hex"",
            noAllowances(),
            oneOutcome(address(token), 0, destination),
            dummyProgram(),
            words(120)
        );
        assertTrue(validator.spentNonces(signer, 1));
    }

    /* ─────────────────────────── commitment
    ─────────────────────────── */

    function test_entry_signatureCommitsProgramHash() external {
        // A signature over the empty program does not authorize a program.
        Outcome[] memory outcomes = oneOutcome(address(token), 0, destination);
        VMCommand[] memory program = dummyProgram();
        bytes memory sig = sign(validator, 1, noAllowances(), outcomes, bytes32(0), bytes32(0));
        vm.prank(executor);
        vm.expectRevert(CATValidator.BadSignature.selector);
        validator.entry(address(fill), hex"", signer, 1, noAllowances(), outcomes, program, noParams(), sig);
    }

    function test_entry_signatureCommitsParamsHash() external {
        // The same program with different params is a different digest.
        Outcome[] memory outcomes = oneOutcome(address(token), 0, destination);
        VMCommand[] memory program = dummyProgram();
        bytes32[] memory supplied = new bytes32[](1);
        supplied[0] = bytes32(uint256(99));
        bytes memory sig = sign(validator, 1, noAllowances(), outcomes, hashProgram(program), hashParams(words(1)));
        vm.prank(executor);
        vm.expectRevert(CATValidator.BadSignature.selector);
        validator.entry(address(fill), hex"", signer, 1, noAllowances(), outcomes, program, supplied, sig);
    }

    function test_entry_programHashIsKeccakOfAbiEncodedCommands() external {
        // The pinned hash is `cast keccak $(cast abi-encode "f((uint8,bytes32)[])"
        // "[(8,0x…0104),(0,0x…beef)]")`, computed outside Solidity. The SDK spec pins
        // the same vector.
        VMCommand[] memory program = new VMCommand[](2);
        program[0] = VMCommand({ op: 8, data: bytes32(uint256(0x0104)) });
        program[1] = VMCommand({ op: 0, data: bytes32(uint256(0xBEEF)) });
        bytes32 pinned = 0x6c12f1a4273f6fa591a0943ebadbd27d46496a9090c3ee169da9e3df911845d5;
        Outcome[] memory outcomes = oneOutcome(address(token), 0, destination);
        bytes memory sig = sign(validator, 1, noAllowances(), outcomes, pinned, bytes32(0));

        vm.prank(executor);
        validator.entry(address(fill), hex"", signer, 1, noAllowances(), outcomes, program, noParams(), sig);

        assertTrue(validator.spentNonces(signer, 1), "the pinned program hash settles");
    }

    function test_entry_v1DigestNotAccepted() external {
        // A signature over the v1 typehash (no commitment fields) under the V2 domain is rejected.
        Outcome[] memory outcomes = oneOutcome(address(token), 0, destination);
        bytes32[] memory outcomeHashes = new bytes32[](1);
        outcomeHashes[0] = keccak256(
            abi.encode(
                keccak256(bytes("Outcome(address token,uint256 amount,address destination)")),
                outcomes[0].token,
                outcomes[0].amount,
                outcomes[0].destination
            )
        );
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256(
                    bytes(
                        "ExecutionConstraint(Allowance[] allowances,Outcome[] outcomes,address executor,uint256 nonce)Allowance(address token,uint256 amount)Outcome(address token,uint256 amount,address destination)"
                    )
                ),
                keccak256(abi.encodePacked(new bytes32[](0))),
                keccak256(abi.encodePacked(outcomeHashes)),
                executor,
                uint256(1)
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", validator.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.prank(executor);
        vm.expectRevert(CATValidator.BadSignature.selector);
        validator.entry(address(fill), hex"", signer, 1, noAllowances(), outcomes, noProgram(), noParams(), sig);
    }

    /* ─────────────────────────── empty program = v1
    ─────────────────────────── */

    function test_entry_emptyProgramSettlesLikeV1() external {
        bytes memory payload = abi.encodeCall(OutcomeFill.mint, (token, address(validator), 1.5 ether));
        settle(validator, address(fill), payload, oneOutcome(address(token), 1 ether, destination), noProgram());

        assertEq(token.balanceOf(destination), 1.5 ether, "full held balance forwarded");
        assertEq(token.balanceOf(address(validator)), 0);
        assertTrue(validator.spentNonces(signer, 1));
        assertEq(validator.paidRecord(), 0, "no payment record outside a program-bearing settlement");
    }

    function test_entry_emptyProgramNeverTouchesVm() external {
        // A codeless VM address is fine when no program is committed.
        CATValidatorV2 codeless = new CATValidatorV2(makeAddr("codelessVm"));
        bytes memory payload = abi.encodeCall(OutcomeFill.mint, (token, address(codeless), 1 ether));
        settle(codeless, address(fill), payload, oneOutcome(address(token), 1 ether, destination), noProgram());
        assertTrue(codeless.spentNonces(signer, 1));
    }

    function test_entry_deliveryToDestinationRejected() external {
        // Paid in full, but not through the validator: the floor reads the validator's own balance.
        bytes memory payload = abi.encodeCall(OutcomeFill.mint, (token, destination, 1 ether));
        Outcome[] memory outcomes = oneOutcome(address(token), 1 ether, destination);
        bytes memory sig = sign(validator, 1, noAllowances(), outcomes, bytes32(0), bytes32(0));
        vm.prank(executor);
        vm.expectRevert(abi.encodeWithSelector(CATValidator.InvalidTokenAmount.selector, 1 ether, 0));
        validator.entry(address(fill), payload, signer, 1, noAllowances(), outcomes, noProgram(), noParams(), sig);
    }

    /* ─────────────────────────── register file
    ─────────────────────────── */

    function test_entry_registerFileCarriesSpentAndPaid() external {
        // The escrow holds 3 IN with a magic spend. The fill mints 2 OUT to the
        // validator and 5 OUT straight to the destination. The program sees
        // spent[0] = 3 (the escrow balance) and paid[0] = 2 (what the validator
        // forwarded, not what the destination holds).
        fundEscrow(echoValidator, 3 ether);
        AllowanceSpend[] memory allowances = oneAllowance(address(inToken), 1 << 255);
        Outcome[] memory outcomes = oneOutcome(address(token), 1 ether, destination);
        VMCommand[] memory program = dummyProgram();
        bytes32[] memory params = words(2);
        bytes memory payload =
            abi.encodeCall(OutcomeFill.mintTwo, (token, address(echoValidator), 2 ether, destination, 5 ether));

        uint256[] memory spent = new uint256[](1);
        spent[0] = 3 ether;
        uint256[] memory paid = new uint256[](1);
        paid[0] = 2 ether;

        bytes memory sig = sign(echoValidator, 1, allowances, outcomes, hashProgram(program), hashParams(params));
        bytes memory expected = expectedRunVM(program, params, spent, paid);
        vm.prank(executor);
        vm.expectRevert(expected);
        echoValidator.entry(address(fill), payload, signer, 1, allowances, outcomes, program, params, sig);
    }

    function test_entry_literalSpendIsRecordedAsSpent() external {
        fundEscrow(echoValidator, 3 ether);
        AllowanceSpend[] memory allowances = oneAllowance(address(inToken), 1 ether);
        Outcome[] memory outcomes = new Outcome[](0);
        VMCommand[] memory program = dummyProgram();

        uint256[] memory spent = new uint256[](1);
        spent[0] = 1 ether;

        bytes memory sig = sign(echoValidator, 1, allowances, outcomes, hashProgram(program), bytes32(0));
        bytes memory expected = expectedRunVM(program, noParams(), spent, new uint256[](0));
        vm.prank(executor);
        vm.expectRevert(expected);
        echoValidator.entry(address(fill), hex"", signer, 1, allowances, outcomes, program, noParams(), sig);
    }

    function test_entry_repeatedMagicSpendSeesRemainingBalance() external {
        // Two allowances of one token: a literal 1 then a magic spend. v1 pulls 1,
        // then the remaining 2. The registers must say the same.
        fundEscrow(echoValidator, 3 ether);
        AllowanceSpend[] memory allowances = new AllowanceSpend[](3);
        allowances[0] = AllowanceSpend({ token: address(inToken), allocated: type(uint256).max, spend: 1 ether });
        allowances[1] = AllowanceSpend({ token: address(inToken), allocated: type(uint256).max, spend: 1 << 255 });
        allowances[2] = AllowanceSpend({ token: address(inToken), allocated: type(uint256).max, spend: 1 << 255 });
        Outcome[] memory outcomes = new Outcome[](0);
        VMCommand[] memory program = dummyProgram();

        uint256[] memory spent = new uint256[](3);
        spent[0] = 1 ether;
        spent[1] = 2 ether;
        spent[2] = 0;

        bytes memory sig = sign(echoValidator, 1, allowances, outcomes, hashProgram(program), bytes32(0));
        bytes memory expected = expectedRunVM(program, noParams(), spent, new uint256[](0));
        vm.prank(executor);
        vm.expectRevert(expected);
        echoValidator.entry(address(fill), hex"", signer, 1, allowances, outcomes, program, noParams(), sig);
        assertEq(inToken.balanceOf(signer), 3 ether, "reverted settlement leaves the escrow intact");
    }

    function test_entry_paidIsTheAmountForwardedAtItsOwnIteration() external {
        // Outcome 0 is 1 ETH to a destination whose receive() mints 4 OUT to the
        // validator. Outcome 1 is OUT. v1 reads OUT when it reaches outcome 1, so it
        // forwards 1 + 4 = 5 OUT, and paid[1] must be 5, not the 1 held before the
        // payment step began.
        CallbackDestination cb = new CallbackDestination(token, address(echoValidator), 4 ether);
        vm.deal(address(fill), 1 ether);
        Outcome[] memory outcomes = new Outcome[](2);
        outcomes[0] = Outcome({ token: address(0), amount: 1 ether, destination: address(cb) });
        outcomes[1] = Outcome({ token: address(token), amount: 1 ether, destination: destination });
        VMCommand[] memory program = dummyProgram();
        bytes memory payload = abi.encodeCall(OutcomeFill.sendNative, (payable(address(echoValidator)), 1 ether));
        token.mint(address(echoValidator), 1 ether);

        uint256[] memory paid = new uint256[](2);
        paid[0] = 1 ether;
        paid[1] = 5 ether;

        bytes memory sig = sign(echoValidator, 1, noAllowances(), outcomes, hashProgram(program), bytes32(0));
        bytes memory expected = expectedRunVM(program, noParams(), new uint256[](0), paid);
        vm.prank(executor);
        vm.expectRevert(expected);
        echoValidator.entry(address(fill), payload, signer, 1, noAllowances(), outcomes, program, noParams(), sig);
    }

    /* ─────────────────────────── program execution
    ─────────────────────────── */

    function test_entry_programRunsAfterPaymentAndSettles() external {
        bytes memory payload = abi.encodeCall(OutcomeFill.mint, (token, address(validator), 1 ether));
        settle(validator, address(fill), payload, oneOutcome(address(token), 1 ether, destination), dummyProgram());

        assertEq(token.balanceOf(destination), 1 ether);
        assertTrue(validator.spentNonces(signer, 1));
        assertEq(validator.paidRecord(), 0, "payment record cleared after the program ran");
    }

    function test_entry_failingProgramRevertsRefundable() external {
        fundEscrow(echoValidator, 5 ether);
        AllowanceSpend[] memory allowances = oneAllowance(address(inToken), 5 ether);
        Outcome[] memory outcomes = oneOutcome(address(token), 1 ether, destination);
        VMCommand[] memory program = dummyProgram();
        bytes memory payload = abi.encodeCall(OutcomeFill.mint, (token, address(echoValidator), 1 ether));
        bytes memory sig = sign(echoValidator, 1, allowances, outcomes, hashProgram(program), bytes32(0));

        vm.prank(executor);
        vm.expectRevert(); // ValidationFailed(payload); the payload is asserted above
        echoValidator.entry(address(fill), payload, signer, 1, allowances, outcomes, program, noParams(), sig);

        assertFalse(echoValidator.spentNonces(signer, 1), "nonce unspent after a validation failure");
        assertEq(inToken.balanceOf(signer), 5 ether, "escrow funds untouched after a validation failure");
        assertEq(token.balanceOf(destination), 0, "nothing forwarded after a validation failure");
    }

    function test_entry_floorFailsBeforeProgramRuns() external {
        // EchoVM would surface ValidationFailed; the floor reverts first.
        Outcome[] memory outcomes = oneOutcome(address(token), 1 ether, destination);
        VMCommand[] memory program = dummyProgram();
        bytes memory sig = sign(echoValidator, 1, noAllowances(), outcomes, hashProgram(program), bytes32(0));
        vm.prank(executor);
        vm.expectRevert(abi.encodeWithSelector(CATValidator.InvalidTokenAmount.selector, 1 ether, 0));
        echoValidator.entry(address(fill), hex"", signer, 1, noAllowances(), outcomes, program, noParams(), sig);
    }

    function test_entry_vmInvalidOpcodeFailsClosed() external {
        CATValidatorV2 target = new CATValidatorV2(address(new InvalidVM()));
        Outcome[] memory outcomes = oneOutcome(address(token), 0, destination);
        VMCommand[] memory program = dummyProgram();
        bytes memory sig = sign(target, 1, noAllowances(), outcomes, hashProgram(program), bytes32(0));
        vm.prank(executor);
        vm.expectRevert(abi.encodeWithSelector(CATValidatorV2.ValidationFailed.selector, hex""));
        target.entry(address(fill), hex"", signer, 1, noAllowances(), outcomes, program, noParams(), sig);
    }

    function test_entry_vmOutOfGasFailsClosed() external {
        // The VM burns all forwarded gas; the 1/64 the caller keeps is enough to
        // wrap the failure, and nothing settles.
        CATValidatorV2 target = new CATValidatorV2(address(new BurnVM()));
        Outcome[] memory outcomes = oneOutcome(address(token), 0, destination);
        VMCommand[] memory program = dummyProgram();
        bytes memory sig = sign(target, 1, noAllowances(), outcomes, hashProgram(program), bytes32(0));
        vm.prank(executor);
        vm.expectRevert(abi.encodeWithSelector(CATValidatorV2.ValidationFailed.selector, hex""));
        target.entry{ gas: 3_000_000 }(
            address(fill), hex"", signer, 1, noAllowances(), outcomes, program, noParams(), sig
        );
        assertFalse(target.spentNonces(signer, 1));
    }

    function test_entry_codelessVmWithProgramFailsClosed() external {
        CATValidatorV2 codeless = new CATValidatorV2(makeAddr("codelessVm"));
        Outcome[] memory outcomes = oneOutcome(address(token), 0, destination);
        VMCommand[] memory program = dummyProgram();
        bytes memory sig = sign(codeless, 1, noAllowances(), outcomes, hashProgram(program), bytes32(0));
        vm.prank(executor);
        vm.expectRevert(CATValidatorV2.InvalidVirtualMachine.selector);
        codeless.entry(address(fill), hex"", signer, 1, noAllowances(), outcomes, program, noParams(), sig);
        assertFalse(codeless.spentNonces(signer, 1));
    }

    /* ─────────────────────────── fill boundary
    ─────────────────────────── */

    function test_entry_strayNativeBalanceDoesNotBlockNonPayableFill() external {
        // Anyone can send 1 wei to the validator; a non-payable fill still settles.
        vm.deal(address(validator), 1 wei);
        bytes memory payload = abi.encodeCall(OutcomeFill.mint, (token, address(validator), 1 ether));
        settle(validator, address(fill), payload, oneOutcome(address(token), 1 ether, destination), noProgram());

        assertEq(token.balanceOf(destination), 1 ether);
        assertEq(address(validator).balance, 1 wei, "the fill received no native value");
    }

    function test_entry_fillCannotReenter() external {
        Outcome[] memory outcomes = oneOutcome(address(token), 0, destination);
        bytes memory inner = abi.encodeWithSignature(
            "entry(address,bytes,address,uint256,(address,uint256,uint256)[],(address,uint256,address)[],(uint8,bytes32)[],bytes32[],bytes)",
            address(fill),
            hex"",
            signer,
            2,
            noAllowances(),
            outcomes,
            noProgram(),
            noParams(),
            hex""
        );
        bytes memory payload = abi.encodeCall(OutcomeFill.reenter, (validator, inner));
        bytes memory sig = sign(validator, 1, noAllowances(), outcomes, bytes32(0), bytes32(0));
        vm.prank(executor);
        vm.expectRevert(ReentrancyGuard.Reentrancy.selector);
        validator.entry(address(fill), payload, signer, 1, noAllowances(), outcomes, noProgram(), noParams(), sig);
    }

    function test_entry_bubblesLongRevertDataVerbatim() external {
        LongReverter target = new LongReverter();
        uint256[6] memory w;
        for (uint256 i; i < w.length; ++i) {
            w[i] = uint256(keccak256(abi.encode(i)));
        }
        bytes memory expected = abi.encodeWithSelector(LongReverter.LongRevert.selector, w);
        assertEq(expected.length, 196);

        Outcome[] memory outcomes = new Outcome[](0);
        bytes memory sig = sign(validator, 1, noAllowances(), outcomes, bytes32(0), bytes32(0));
        vm.prank(executor);
        vm.expectRevert(expected);
        validator.entry(
            address(target),
            abi.encodeCall(LongReverter.boom, (w)),
            signer,
            1,
            noAllowances(),
            outcomes,
            noProgram(),
            noParams(),
            sig
        );
    }
}
