// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { LibValidationVM } from "../../src/libs/LibValidationVM.sol";
import { VcTestBase } from "./VcTestBase.sol";

/**
 * @notice C1 hash-parity — the Solidity side of the cross-repo seam
 * (umbrella `contract/fixtures/hash-parity/vectors.json`, schema
 * `c1-hash-parity/v1`). The TS side (yggdrasil, GD-2) asserts the same
 * vectors; this suite proves the Foundry/on-chain hashing reproduces them:
 * `keccak256(canonicalBody)` for the program hash, concatenated 32-byte words
 * (zero when empty) for the params hash, and `LibValidationVM.encodeRunVM`
 * reproducing the production compiler's `runVM` calldata byte-for-byte.
 *
 * These are pure encoding/hash identities — no VM execution — so they are
 * unaffected by the uc1 register-convention defect (see the plan's
 * `Surprises & Discoveries`; execution asserts live in test/vc/VmPrograms.t.sol
 * and gate on the GD-7 re-pin).
 */
contract HashParityTest is VcTestBase {
    string json;

    function setUp() external {
        json = readFixture(HASH_PARITY_VECTORS);
    }

    /* ─────────────────────────── programVectors
    ─────────────────────────── */

    function test_programVectors_bodyHashAndCalldataParity() external view {
        uint256 count = jsonArrayLength(json, ".programVectors");
        assertGt(count, 0, "fixture has no programVectors");

        for (uint256 i; i < count; ++i) {
            string memory p = string.concat(".programVectors[", vm.toString(i), "]");
            string memory name = vm.parseJsonString(json, string.concat(p, ".name"));

            bytes memory body = vm.parseJsonBytes(json, string.concat(p, ".canonicalBody"));
            assertGt(body.length, 0, string.concat(name, ": empty body"));
            assertEq(body.length % LibValidationVM.COMMAND_SIZE, 0, string.concat(name, ": body not 33-byte packed"));

            // The committed program hash is keccak256 of exactly the canonical body.
            bytes32 pinnedBodyHash = vm.parseJsonBytes32(json, string.concat(p, ".validationProgramHash"));
            assertEq(keccak256(body), pinnedBodyHash, string.concat(name, ": body hash mismatch"));

            // The committed params hash, through the production paramsHashOf.
            bytes memory canonicalParams = vm.parseJsonBytes(json, string.concat(p, ".canonicalParams"));
            bytes32 pinnedParamsHash = vm.parseJsonBytes32(json, string.concat(p, ".paramsHash"));
            _assertParamsHashParity(name, canonicalParams, pinnedParamsHash);

            // The fixture's decoded `commands` decomposition must stay in sync
            // with the canonical body it claims to decode (33-byte framing:
            // uint8 op ++ bytes32 data per command).
            _assertCommandsMatchBody(name, string.concat(p, ".commands"), body);

            // Re-encoding the body against the fixture's own register file must
            // reproduce the production compiler's runVM calldata byte-for-byte.
            // This pins RUN_VM_SELECTOR and the command/register ABI encoding
            // against real compiler output, independent of execution semantics.
            bytes memory registersEncoded =
                this.exposedEncodeRunVM(body, vm.parseJsonBytesArray(json, string.concat(p, ".registers")));
            bytes memory pinnedCalldata = vm.parseJsonBytes(json, string.concat(p, ".calldata"));
            assertEq(registersEncoded, pinnedCalldata, string.concat(name, ": runVM calldata mismatch"));
            assertEq(bytes4(pinnedCalldata), RUN_VM_SELECTOR, string.concat(name, ": selector mismatch"));
        }
    }

    /// @dev G6 body-sharing: the same operation for two users pins one body
    /// hash and distinct params hashes — per-user values live only in params.
    function test_programVectors_uc1BodySharing() external view {
        bytes32 hashA = vm.parseJsonBytes32(json, ".programVectors[0].validationProgramHash");
        bytes32 hashB = vm.parseJsonBytes32(json, ".programVectors[1].validationProgramHash");
        bytes32 paramsA = vm.parseJsonBytes32(json, ".programVectors[0].paramsHash");
        bytes32 paramsB = vm.parseJsonBytes32(json, ".programVectors[1].paramsHash");

        assertEq(vm.parseJsonString(json, ".programVectors[0].name"), "uc1-user-a", "unexpected fixture vector order");
        assertEq(vm.parseJsonString(json, ".programVectors[1].name"), "uc1-user-b", "unexpected fixture vector order");
        assertEq(hashA, hashB, "uc1 users must share one body hash");
        assertNotEq(paramsA, paramsB, "uc1 users must have distinct params hashes");
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
        bytes[] memory words = new bytes[](numWords);
        for (uint256 i; i < numWords; ++i) {
            bytes memory word = new bytes(32);
            for (uint256 j; j < 32; ++j) {
                word[j] = canonicalParams[i * 32 + j];
            }
            words[i] = word;
        }

        (bytes32 h, bool ok) = this.exposedParamsHashOf(words);
        assertTrue(ok, string.concat(name, ": paramsHashOf rejected fixture words"));
        assertEq(h, pinnedParamsHash, string.concat(name, ": params hash mismatch"));
        if (numWords == 0) assertEq(pinnedParamsHash, bytes32(0), string.concat(name, ": empty params must pin zero"));
    }

    function _assertCommandsMatchBody(
        string memory name,
        string memory commandsPath,
        bytes memory body
    ) internal view {
        uint256 numCommands = jsonArrayLength(json, commandsPath);
        assertEq(numCommands, body.length / LibValidationVM.COMMAND_SIZE, string.concat(name, ": command count"));

        for (uint256 i; i < numCommands; ++i) {
            string memory c = string.concat(commandsPath, "[", vm.toString(i), "]");
            uint256 base = i * LibValidationVM.COMMAND_SIZE;

            assertEq(
                uint256(uint8(body[base])),
                vm.parseJsonUint(json, string.concat(c, ".op")),
                string.concat(name, ": command op drift")
            );
            bytes32 data;
            for (uint256 j; j < 32; ++j) {
                data |= bytes32(body[base + 1 + j]) >> (j * 8);
            }
            assertEq(
                data, vm.parseJsonBytes32(json, string.concat(c, ".data")), string.concat(name, ": command data drift")
            );
        }
    }

    /// @dev calldata trampolines for the library's calldata-typed arguments.
    function exposedParamsHashOf(
        bytes[] calldata params
    ) external pure returns (bytes32, bool) {
        return LibValidationVM.paramsHashOf(params);
    }

    function exposedEncodeRunVM(
        bytes calldata body,
        bytes[] memory registers
    ) external pure returns (bytes memory) {
        return LibValidationVM.encodeRunVM(body, registers);
    }
}
