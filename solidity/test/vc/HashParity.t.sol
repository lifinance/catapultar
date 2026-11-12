// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { LibValidationVM, VMCommand, VMState } from "../../src/libs/LibValidationVM.sol";
import { VcTestBase } from "./VcTestBase.sol";

/**
 * @notice Encoding parity between LI.FI's compose compiler and the validator. The
 * fixture `test/vc/fixtures/hash-parity/vectors.json` (schema
 * `c1-hash-parity/v2`) is produced by the compiler, which asserts the same
 * vectors on its side. This suite proves three things against that output:
 * the compiler's `validationProgram` is the ABI encoding of its `commands` and
 * hashes to the pinned `validationProgramHash` under the validator's rule
 * (`keccak256(abi.encode(commands))`); the params hash rule (concatenated
 * 32-byte words, zero when empty) reproduces the pinned `paramsHash`; and the
 * `runVM` encoding the validator sends, `RUN_VM_SELECTOR` with the command
 * array and the register file, reproduces the compiler's `runVM` calldata byte
 * for byte. Executing the pinned uc1 program on the canonical VM is covered by
 * `test/vc/IntegrationV2.t.sol`.
 */
contract HashParityTest is VcTestBase {
    string json;

    function setUp() external {
        json = readFixture(HASH_PARITY_VECTORS);
    }

    /* ─────────────────────────── programVectors
    ─────────────────────────── */

    function test_programVectors_runVMCalldataAndParamsParity() external view {
        uint256 count = jsonArrayLength(json, ".programVectors");
        assertGt(count, 0, "fixture has no programVectors");

        for (uint256 i; i < count; ++i) {
            string memory p = string.concat(".programVectors[", vm.toString(i), "]");
            string memory name = vm.parseJsonString(json, string.concat(p, ".name"));

            // The committed params hash, through the production paramsHashOf.
            bytes memory canonicalParams = vm.parseJsonBytes(json, string.concat(p, ".canonicalParams"));
            bytes32 pinnedParamsHash = vm.parseJsonBytes32(json, string.concat(p, ".paramsHash"));
            _assertParamsHashParity(name, canonicalParams, pinnedParamsHash);

            // The committed program: the compiler's wire bytes are the ABI encoding
            // of its commands, and both sides hash them to the same value.
            VMCommand[] memory commands = _commands(p);
            assertGt(commands.length, 0, string.concat(name, ": no commands"));
            assertEq(
                abi.encode(commands),
                vm.parseJsonBytes(json, string.concat(p, ".validationProgram")),
                string.concat(name, ": validationProgram is not abi.encode(commands)")
            );
            assertEq(
                hashProgram(commands),
                vm.parseJsonBytes32(json, string.concat(p, ".validationProgramHash")),
                string.concat(name, ": program hash mismatch")
            );

            // The validator's runVM encoding of the fixture's commands and register
            // file must reproduce the production compiler's runVM calldata
            // byte for byte. This pins RUN_VM_SELECTOR and the VMCommand and
            // VMState ABI shapes against real compiler output.
            bytes[] memory registers = vm.parseJsonBytesArray(json, string.concat(p, ".registers"));
            assertEq(
                abi.encodeWithSelector(LibValidationVM.RUN_VM_SELECTOR, commands, VMState(registers)),
                vm.parseJsonBytes(json, string.concat(p, ".calldata")),
                string.concat(name, ": runVM calldata mismatch")
            );
        }
    }

    /// @dev Body sharing: the same operation for two users has one program hash
    /// and distinct params hashes — per-user values live only in params.
    function test_programVectors_uc1BodySharing() external view {
        assertEq(vm.parseJsonString(json, ".programVectors[0].name"), "uc1-user-a", "unexpected fixture vector order");
        assertEq(vm.parseJsonString(json, ".programVectors[1].name"), "uc1-user-b", "unexpected fixture vector order");
        assertEq(
            hashProgram(_commands(".programVectors[0]")),
            hashProgram(_commands(".programVectors[1]")),
            "uc1 users must share one program hash"
        );
        assertNotEq(
            vm.parseJsonBytes32(json, ".programVectors[0].paramsHash"),
            vm.parseJsonBytes32(json, ".programVectors[1].paramsHash"),
            "uc1 users must have distinct params hashes"
        );
    }

    /* ─────────────────────────── paramsVectors
    ──────────────────────────── */

    function test_paramsVectors_hashRule() external view {
        uint256 count = jsonArrayLength(json, ".paramsVectors");
        assertGt(count, 0, "fixture has no paramsVectors");

        for (uint256 i; i < count; ++i) {
            string memory p = string.concat(".paramsVectors[", vm.toString(i), "]");
            string memory name = vm.parseJsonString(json, string.concat(p, ".name"));
            bytes memory canonicalParams = vm.parseJsonBytes(json, string.concat(p, ".canonicalParams"));
            bytes32 pinnedParamsHash = vm.parseJsonBytes32(json, string.concat(p, ".paramsHash"));
            _assertParamsHashParity(name, canonicalParams, pinnedParamsHash);
        }
    }

    /* ─────────────────────────── helpers
    ────────────────────────────────── */

    /// @dev Splits the pinned concatenation into 32-byte words and runs them
    /// through the production `paramsHashOf`, covering both the empty →
    /// bytes32(0) rule and the concat-keccak rule with fixture data.
    function _assertParamsHashParity(
        string memory name,
        bytes memory canonicalParams,
        bytes32 pinnedParamsHash
    ) internal view {
        assertEq(canonicalParams.length % 32, 0, string.concat(name, ": canonicalParams not word-aligned"));

        uint256 numWords = canonicalParams.length / 32;
        bytes32[] memory words = new bytes32[](numWords);
        for (uint256 i; i < numWords; ++i) {
            bytes32 word;
            assembly ("memory-safe") {
                word := mload(add(add(canonicalParams, 32), shl(5, i)))
            }
            words[i] = word;
        }

        assertEq(this.exposedParamsHashOf(words), pinnedParamsHash, string.concat(name, ": params hash mismatch"));
        if (numWords == 0) assertEq(pinnedParamsHash, bytes32(0), string.concat(name, ": empty params must pin zero"));
    }

    /// @dev The fixture's decoded `commands` of the vector at `vectorPath`.
    function _commands(
        string memory vectorPath
    ) internal view returns (VMCommand[] memory commands) {
        string memory path = string.concat(vectorPath, ".commands");
        commands = new VMCommand[](jsonArrayLength(json, path));
        for (uint256 i; i < commands.length; ++i) {
            string memory c = string.concat(path, "[", vm.toString(i), "]");
            uint256 op = vm.parseJsonUint(json, string.concat(c, ".op"));
            assertLt(op, 256, "command op is not a uint8");
            // forge-lint: disable-next-line(unsafe-typecast)
            commands[i] = VMCommand({ op: uint8(op), data: vm.parseJsonBytes32(json, string.concat(c, ".data")) });
        }
    }

    /// @dev calldata trampolines for the library's calldata-typed arguments.
    function exposedParamsHashOf(
        bytes32[] calldata params
    ) external pure returns (bytes32) {
        return LibValidationVM.paramsHashOf(params);
    }
}
