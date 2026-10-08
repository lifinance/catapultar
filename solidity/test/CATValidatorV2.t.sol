// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { Test } from "forge-std/src/Test.sol";

import { MockERC20 } from "solady/test/utils/mocks/MockERC20.sol";

import { CATValidatorV2 } from "../src/CATValidatorV2.sol";
import { AllowanceSpend, Outcome } from "../src/libs/LibExecutionConstraint.sol";
import { LibValidationVM, VMCommand, VMState } from "../src/libs/LibValidationVM.sol";

contract CATValidatorV2Mock is CATValidatorV2 {
    constructor(
        address virtualMachine,
        uint256 validationGasCap
    ) CATValidatorV2(virtualMachine, validationGasCap) { }

    function paramsHashOf(
        bytes[] calldata params
    ) external pure returns (bytes32 h, bool ok) {
        return LibValidationVM.paramsHashOf(params);
    }

    function buildRegisters(
        bytes[] calldata params,
        address account,
        uint256[] calldata preBalances
    ) external pure returns (bytes[] memory) {
        return LibValidationVM.buildRegisters(params, account, preBalances);
    }

    function encodeRunVM(
        bytes calldata body,
        bytes[] memory registers
    ) external pure returns (bytes memory) {
        return LibValidationVM.encodeRunVM(body, registers);
    }

    function runValidation(
        address account,
        bytes32 validationProgramHash,
        bytes32 paramsHash,
        bytes calldata validationProgram,
        bytes[] calldata validationParams,
        uint256[] calldata preBalances
    ) external view {
        _runValidation(account, validationProgramHash, paramsHash, validationProgram, validationParams, preBalances);
    }
}

/// @dev Stand-in VMs so unit tests need no fork. The real-VM matrix lives in
/// test/vc/VmPrograms.t.sol.
contract AcceptVM {
    fallback() external { }
}

/// @dev Reverts with its own calldata, letting tests capture the exact runVM
/// payload entry() sent through the staticcall (as ValidationFailed data).
contract EchoVM {
    fallback() external {
        assembly ("memory-safe") {
            calldatacopy(0, 0, calldatasize())
            revert(0, calldatasize())
        }
    }
}

contract GasBurnVM {
    fallback() external {
        while (true) {
            // burn everything forwarded
            assembly ("memory-safe") {
                pop(keccak256(0, 32))
            }
        }
    }
}

contract CATValidatorV2Test is Test {
    CATValidatorV2Mock validator; // backed by AcceptVM
    CATValidatorV2Mock echoValidator; // backed by EchoVM
    CATValidatorV2Mock burnValidator; // backed by GasBurnVM, tiny cap

    address signer;
    uint256 signerKey;
    address executor;
    MockERC20 token;

    function setUp() external {
        validator = new CATValidatorV2Mock(address(new AcceptVM()), 5_000_000);
        echoValidator = new CATValidatorV2Mock(address(new EchoVM()), 5_000_000);
        burnValidator = new CATValidatorV2Mock(address(new GasBurnVM()), 100_000);

        (signer, signerKey) = makeAddrAndKey("signer");
        executor = makeAddr("executor");
        token = new MockERC20("Outcome", "OUT", 18);
    }

    /* ─────────────────────────── LibValidationVM units
    ─────────────────────────── */

    function test_paramsHashOf_emptyIsZero() external view {
        bytes[] memory params = new bytes[](0);
        (bytes32 h, bool ok) = this.exposedParamsHashOf(params);
        assertTrue(ok);
        assertEq(h, bytes32(0));
    }

    function test_paramsHashOf_concatKeccak(
        bytes32 a,
        bytes32 b
    ) external view {
        bytes[] memory params = new bytes[](2);
        params[0] = abi.encodePacked(a);
        params[1] = abi.encodePacked(b);
        (bytes32 h, bool ok) = this.exposedParamsHashOf(params);
        assertTrue(ok);
        assertEq(h, keccak256(abi.encodePacked(a, b)));
    }

    function test_paramsHashOf_rejectsNonWordElement() external view {
        bytes[] memory params = new bytes[](1);
        params[0] = hex"deadbeef";
        (, bool ok) = this.exposedParamsHashOf(params);
        assertFalse(ok);
    }

    function exposedParamsHashOf(
        bytes[] calldata params
    ) external view returns (bytes32, bool) {
        return validator.paramsHashOf(params);
    }

    function test_buildRegisters_layout() external {
        bytes[] memory params = new bytes[](3);
        params[0] = abi.encodePacked(bytes32(uint256(0xAA)));
        params[1] = abi.encodePacked(bytes32(uint256(0xBB)));
        params[2] = abi.encodePacked(bytes32(uint256(0xCC)));
        uint256[] memory preBalances = new uint256[](2);
        preBalances[0] = 1 ether;
        preBalances[1] = 42;
        address account = makeAddr("escrow");

        bytes[] memory registers = validator.buildRegisters(params, account, preBalances);

        assertEq(registers.length, 123, "fixed register-file size");
        assertEq(registers[0], params[0]);
        assertEq(registers[1], params[1]);
        assertEq(registers[2], params[2]);
        assertEq(registers[3], abi.encodePacked(bytes32(uint256(uint160(account)))), "account after params");
        assertEq(registers[4], abi.encodePacked(bytes32(uint256(1 ether))));
        assertEq(registers[5], abi.encodePacked(bytes32(uint256(42))));
        for (uint256 i = 6; i < registers.length; ++i) {
            assertEq(registers[i], new bytes(32), "scratch is a 32-byte zero word");
        }
    }

    function test_encodeRunVM_roundTrip() external {
        // Two commands, tight-packed 33 bytes each.
        bytes memory body = abi.encodePacked(uint8(8), bytes32(uint256(0x0104)), uint8(0), bytes32(uint256(0xBEEF)));
        bytes[] memory registers = validator.buildRegisters(new bytes[](0), makeAddr("a"), new uint256[](0));

        bytes memory payload = validator.encodeRunVM(body, registers);

        assertEq(bytes4(payload), LibValidationVM.RUN_VM_SELECTOR);
        bytes memory args = new bytes(payload.length - 4);
        for (uint256 i; i < args.length; ++i) {
            args[i] = payload[i + 4];
        }
        (VMCommand[] memory commands, VMState memory state) = abi.decode(args, (VMCommand[], VMState));
        assertEq(commands.length, 2);
        assertEq(commands[0].op, 8);
        assertEq(commands[0].data, bytes32(uint256(0x0104)));
        assertEq(commands[1].op, 0);
        assertEq(commands[1].data, bytes32(uint256(0xBEEF)));
        assertEq(state.registers.length, 123);
    }

    /* ─────────────────────────── _runValidation units
    ─────────────────────────── */

    function dummyBody() internal pure returns (bytes memory) {
        // One NATIVE_BALANCE command; content is irrelevant against the stub VMs.
        return abi.encodePacked(uint8(8), bytes32(0));
    }

    function noPreBalances() internal pure returns (uint256[] memory) {
        return new uint256[](0);
    }

    function test_runValidation_zeroHashSkips() external view {
        validator.runValidation(signer, bytes32(0), bytes32(0), hex"", new bytes[](0), noPreBalances());
    }

    function test_runValidation_zeroHashRejectsStrayProgram() external {
        vm.expectRevert(CATValidatorV2.BadValidationProgram.selector);
        validator.runValidation(signer, bytes32(0), bytes32(0), dummyBody(), new bytes[](0), noPreBalances());
    }

    function test_runValidation_zeroHashRejectsStrayParams() external {
        bytes[] memory params = new bytes[](1);
        params[0] = abi.encodePacked(bytes32(0));
        vm.expectRevert(CATValidatorV2.BadValidationParams.selector);
        validator.runValidation(signer, bytes32(0), bytes32(0), hex"", params, noPreBalances());

        vm.expectRevert(CATValidatorV2.BadValidationParams.selector);
        validator.runValidation(signer, bytes32(0), bytes32(uint256(1)), hex"", new bytes[](0), noPreBalances());
    }

    function test_runValidation_badLength() external {
        bytes memory body = hex"08deadbeef"; // not a multiple of 33
        vm.expectRevert(CATValidatorV2.BadValidationProgram.selector);
        validator.runValidation(signer, keccak256(body), bytes32(0), body, new bytes[](0), noPreBalances());
    }

    function test_runValidation_hashMismatch() external {
        bytes memory body = dummyBody();
        vm.expectRevert(CATValidatorV2.BadValidationProgram.selector);
        validator.runValidation(
            signer, keccak256(abi.encodePacked(body, hex"00")), bytes32(0), body, new bytes[](0), noPreBalances()
        );
    }

    function test_runValidation_paramsHashMismatch() external {
        bytes memory body = dummyBody();
        bytes[] memory params = new bytes[](1);
        params[0] = abi.encodePacked(bytes32(uint256(7)));
        vm.expectRevert(CATValidatorV2.BadValidationParams.selector);
        validator.runValidation(signer, keccak256(body), bytes32(uint256(1)), body, params, noPreBalances());
    }

    function test_runValidation_malformedParamWord() external {
        bytes memory body = dummyBody();
        bytes[] memory params = new bytes[](1);
        params[0] = hex"01";
        vm.expectRevert(CATValidatorV2.BadValidationParams.selector);
        validator.runValidation(signer, keccak256(body), keccak256(hex"01"), body, params, noPreBalances());
    }

    function test_runValidation_prefixTooLarge() external {
        bytes memory body = dummyBody();
        uint256 numParams = 122; // params + account end past index 121
        bytes[] memory params = new bytes[](numParams);
        bytes memory buffer;
        for (uint256 i; i < numParams; ++i) {
            params[i] = abi.encodePacked(bytes32(i));
            buffer = abi.encodePacked(buffer, params[i]);
        }
        vm.expectRevert(CATValidatorV2.BadValidationParams.selector);
        validator.runValidation(signer, keccak256(body), keccak256(buffer), body, params, noPreBalances());
    }

    function test_runValidation_prefixExactlyMaxAccepted() external view {
        // Positive boundary: params + account occupy indices 0..121, so the
        // highest written index equals MAX_PREFIX_END (121) exactly. With no
        // pre-balances, validationParams.length + preBalances.length == 121,
        // which is NOT > MAX_PREFIX_END, so validation runs against the
        // accepting stub VM (no BadValidationParams).
        bytes memory body = dummyBody();
        uint256 numParams = 121; // account lands at register index 121 == MAX_PREFIX_END
        bytes[] memory params = new bytes[](numParams);
        bytes memory buffer;
        for (uint256 i; i < numParams; ++i) {
            params[i] = abi.encodePacked(bytes32(i));
            buffer = abi.encodePacked(buffer, params[i]);
        }
        assertEq(numParams + noPreBalances().length, LibValidationVM.MAX_PREFIX_END, "prefix ends exactly at bound");
        validator.runValidation(signer, keccak256(body), keccak256(buffer), body, params, noPreBalances());
    }

    function test_runValidation_acceptingVmSettles() external view {
        bytes memory body = dummyBody();
        validator.runValidation(signer, keccak256(body), bytes32(0), body, new bytes[](0), noPreBalances());
    }

    function test_runValidation_revertWrappedWithPayload() external {
        bytes memory body = dummyBody();
        bytes[] memory params = new bytes[](1);
        params[0] = abi.encodePacked(bytes32(uint256(0xD1)));
        uint256[] memory preBalances = new uint256[](1);
        preBalances[0] = 3;

        // EchoVM reverts with its calldata, so the wrapped data must be the
        // exact runVM payload — pinning the register layout through the
        // staticcall path.
        bytes memory expectedPayload =
            echoValidator.encodeRunVM(body, echoValidator.buildRegisters(params, signer, preBalances));

        vm.expectRevert(abi.encodeWithSelector(CATValidatorV2.ValidationFailed.selector, expectedPayload));
        echoValidator.runValidation(
            signer, keccak256(body), keccak256(abi.encodePacked(bytes32(uint256(0xD1)))), body, params, preBalances
        );
    }

    function test_runValidation_gasCapExhaustionFailsClosed() external {
        bytes memory body = dummyBody();
        vm.expectRevert(abi.encodeWithSelector(CATValidatorV2.ValidationFailed.selector, hex""));
        burnValidator.runValidation(signer, keccak256(body), bytes32(0), body, new bytes[](0), noPreBalances());
    }

    /* ─────────────────────────── codeless-VM fail-closed guard
    ─────────────────────────── */

    function test_entry_codelessVmCommittedProgramFailsClosed() external {
        // STATICCALL to a codeless address returns success + empty returndata,
        // so without the guard a committed program would SILENTLY PASS. The
        // verified path must fail closed: revert InvalidVirtualMachine and leave
        // the settlement fully reverted (nonce unspent, funds refundable).
        address codeless = makeAddr("codelessVm");
        assertEq(codeless.code.length, 0, "fixture address must be codeless");
        CATValidatorV2Mock codelessValidator = new CATValidatorV2Mock(codeless, 5_000_000);

        Outcome[] memory outcomes = simpleOutcomes();
        bytes memory body = dummyBody();
        bytes memory sig = signedEntryArgs(codelessValidator, 1, outcomes, keccak256(body), bytes32(0));

        vm.prank(executor);
        vm.expectRevert(CATValidatorV2.InvalidVirtualMachine.selector);
        codelessValidator.entry(
            makeAddr("target"),
            hex"",
            signer,
            1,
            new AllowanceSpend[](0),
            outcomes,
            keccak256(body),
            bytes32(0),
            body,
            new bytes[](0),
            sig
        );
        assertFalse(codelessValidator.spentNonces(signer, 1), "settlement reverted, nonce unspent");
    }

    /* ─────────────────────────── constructor guards
    ───────────────────────────
    */

    function test_constructor_rejectsZeroGasCap() external {
        // A cap of 0 does NOT starve the staticcall: EVM 63/64 rules forward
        // nearly all remaining gas whatever the requested amount, so `gas: 0`
        // silently unbounds the very thing the cap exists to bound. Reject the
        // misconfiguration at deploy time.
        address vmAddr = address(new AcceptVM());
        vm.expectRevert(CATValidatorV2.InvalidValidationGasCap.selector);
        new CATValidatorV2Mock(vmAddr, 0);
    }

    function test_entry_codelessVmZeroHashStillSettles() external {
        // The guard is scoped to the verified path (hash != 0): a codeless VM
        // must not affect the v1 / no-commitment fast path, which never touches
        // the VM. Byte-identical v1 behavior.
        CATValidatorV2Mock codelessValidator = new CATValidatorV2Mock(makeAddr("codelessVm"), 5_000_000);

        Outcome[] memory outcomes = simpleOutcomes();
        bytes memory sig = signedEntryArgs(codelessValidator, 1, outcomes, bytes32(0), bytes32(0));

        vm.prank(executor);
        codelessValidator.entry(
            makeAddr("target"),
            hex"",
            signer,
            1,
            new AllowanceSpend[](0),
            outcomes,
            bytes32(0),
            bytes32(0),
            hex"",
            new bytes[](0),
            sig
        );
        assertTrue(codelessValidator.spentNonces(signer, 1), "v1 path settles regardless of VM code");
    }

    /* ─────────────────────────── entry() end-to-end (stub VM)
    ─────────────────────────── */

    function signedEntryArgs(
        CATValidatorV2 target,
        uint256 nonce,
        Outcome[] memory outcomes,
        bytes32 validationProgramHash,
        bytes32 paramsHash
    ) internal view returns (bytes memory signature) {
        bytes32[] memory allowanceHashes = new bytes32[](0);
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

    function simpleOutcomes() internal returns (Outcome[] memory outcomes) {
        outcomes = new Outcome[](1);
        outcomes[0] = Outcome({ token: address(token), amount: 0, destination: makeAddr("destination") });
    }

    function test_entry_zeroHashV1Semantics() external {
        Outcome[] memory outcomes = simpleOutcomes();
        bytes memory sig = signedEntryArgs(validator, 1, outcomes, bytes32(0), bytes32(0));

        vm.prank(executor);
        validator.entry(
            makeAddr("target"),
            hex"",
            signer,
            1,
            new AllowanceSpend[](0),
            outcomes,
            bytes32(0),
            bytes32(0),
            hex"",
            new bytes[](0),
            sig
        );
        assertTrue(validator.spentNonces(signer, 1));
    }

    function test_entry_committedHashInDigest() external {
        // A signature over the zero-hash constraint must NOT authorize a
        // constraint committing a program hash: the committed fields are part
        // of the digest.
        Outcome[] memory outcomes = simpleOutcomes();
        bytes memory body = dummyBody();
        bytes memory sig = signedEntryArgs(validator, 1, outcomes, bytes32(0), bytes32(0));

        vm.prank(executor);
        vm.expectRevert(CATValidatorV2.BadSignature.selector);
        validator.entry(
            makeAddr("target"),
            hex"",
            signer,
            1,
            new AllowanceSpend[](0),
            outcomes,
            keccak256(body),
            bytes32(0),
            body,
            new bytes[](0),
            sig
        );
    }

    function test_entry_committedProgramRunsAfterFloor() external {
        Outcome[] memory outcomes = simpleOutcomes();
        bytes memory body = dummyBody();
        bytes memory sig = signedEntryArgs(validator, 1, outcomes, keccak256(body), bytes32(0));

        vm.prank(executor);
        validator.entry(
            makeAddr("target"),
            hex"",
            signer,
            1,
            new AllowanceSpend[](0),
            outcomes,
            keccak256(body),
            bytes32(0),
            body,
            new bytes[](0),
            sig
        );
        assertTrue(validator.spentNonces(signer, 1));
    }

    function test_entry_mismatchedProgramReverts() external {
        Outcome[] memory outcomes = simpleOutcomes();
        bytes memory body = dummyBody();
        bytes memory otherBody = abi.encodePacked(uint8(8), bytes32(uint256(1)));
        bytes memory sig = signedEntryArgs(validator, 1, outcomes, keccak256(body), bytes32(0));

        vm.prank(executor);
        vm.expectRevert(CATValidatorV2.BadValidationProgram.selector);
        validator.entry(
            makeAddr("target"),
            hex"",
            signer,
            1,
            new AllowanceSpend[](0),
            outcomes,
            keccak256(body),
            bytes32(0),
            otherBody,
            new bytes[](0),
            sig
        );
        // Whole settlement reverted: nonce not spent, funds untouched.
        assertFalse(validator.spentNonces(signer, 1));
    }

    function test_entry_failingValidationRevertsRefundable() external {
        Outcome[] memory outcomes = simpleOutcomes();
        bytes memory body = dummyBody();
        bytes memory sig = signedEntryArgs(echoValidator, 1, outcomes, keccak256(body), bytes32(0));

        token.mint(signer, 5 ether);

        vm.prank(executor);
        vm.expectRevert(); // ValidationFailed(payload); payload asserted in the unit test above
        echoValidator.entry(
            makeAddr("target"),
            hex"",
            signer,
            1,
            new AllowanceSpend[](0),
            outcomes,
            keccak256(body),
            bytes32(0),
            body,
            new bytes[](0),
            sig
        );

        assertFalse(echoValidator.spentNonces(signer, 1), "nonce must remain unspent after validation failure");
        assertEq(token.balanceOf(signer), 5 ether, "funds untouched after validation failure");
    }
}
