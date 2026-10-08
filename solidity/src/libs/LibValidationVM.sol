// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

/**
 * @notice ABI mirror of the LI.FI VirtualMachine's command structure
 * (`src/DataModel.sol` in the VirtualMachine sources). The VM sources are never imported: the
 * validator only needs to re-encode a canonical validation-program byte string
 * into the `runVM` calldata shape and let the deployed VM interpret it.
 */
struct VMCommand {
    uint8 op;
    bytes32 data;
}

/// @notice ABI mirror of the VM's `VMState` (a register file of raw byte blobs).
struct VMState {
    bytes[] registers;
}

/**
 * @title LibValidationVM
 * @notice Encoding and register-file construction for committed validation
 * programs (verified continuations).
 *
 * A validation program travels as its canonical body: the `runVM` command array
 * tight-packed at 33 bytes per command (`uint8 op ++ bytes32 data`,
 * concatenated). `keccak256` of exactly those bytes is the committed
 * `validationProgramHash`. Committed per-user parameters travel as a vector of
 * 32-byte words; `keccak256` of their concatenation is the committed
 * `paramsHash` (`bytes32(0)` for an empty vector).
 *
 * The initial register file follows the frozen register-layout convention:
 * `registers = validationParams ++ [account] ++ preBalances`, pre-balances in
 * committed-outcomes order, remaining registers zero (32-byte zero words, so an
 * unwritten scratch read behaves identically to a compiler-embedded zero
 * register). The escrow address and pre-balances are validator-injected at
 * settlement — never body literals and never committed params, because the
 * escrow address transitively depends on `validationProgramHash`.
 */
library LibValidationVM {
    /// @dev `runVM((uint8,bytes32)[],(bytes[]))` on the canonical VirtualMachine
    /// (`src/VirtualMachine.sol` in the VirtualMachine sources). Pinned; asserted against the
    /// shared hash-parity fixture's real compiler calldata in the test suite.
    bytes4 internal constant RUN_VM_SELECTOR = 0x00a32e6c;

    /// @dev Canonical encoding: one command = 1 op byte + 32 data bytes.
    uint256 internal constant COMMAND_SIZE = 33;

    /// @dev Fixed register-file size. The VM addresses registers with a 7-bit
    /// index and treats 0x7A (122) as a void register (reads zero, swallows
    /// writes); reads/writes at index >= file length revert inside the VM.
    /// 123 slots make every meaningful index (0-121, plus the void 122)
    /// addressable, so the validator never needs to know a program's register
    /// usage in advance.
    uint256 internal constant NUM_REGISTERS = 123;

    /// @dev Highest register index the injected prefix may occupy (121; 122 is
    /// the void register, which would silently read as zero).
    uint256 internal constant MAX_PREFIX_END = 121;

    /// @notice Computes the committed params hash for a supplied params vector.
    /// @return h `bytes32(0)` when empty, else `keccak256` of the concatenated words.
    /// @return ok False when any element is not exactly 32 bytes (malformed vector).
    function paramsHashOf(
        bytes[] calldata params
    ) internal pure returns (bytes32 h, bool ok) {
        uint256 numParams = params.length;
        if (numParams == 0) return (bytes32(0), true);

        bytes memory buffer = new bytes(numParams * 32);
        for (uint256 i; i < numParams; ++i) {
            bytes calldata word = params[i];
            if (word.length != 32) return (bytes32(0), false);
            uint256 dest;
            assembly ("memory-safe") {
                dest := add(add(buffer, 32), shl(5, i))
                calldatacopy(dest, word.offset, 32)
            }
        }
        return (keccak256(buffer), true);
    }

    /// @notice Builds the initial register file per the frozen register-layout
    /// convention. The caller must have validated the params vector (32-byte
    /// words) and that `params.length + preBalances.length` (the highest written
    /// register index — the account occupies `params.length`, the last
    /// pre-balance `params.length + preBalances.length`) is at or below
    /// `MAX_PREFIX_END`.
    function buildRegisters(
        bytes[] calldata params,
        address account,
        uint256[] memory preBalances
    ) internal pure returns (bytes[] memory registers) {
        registers = new bytes[](NUM_REGISTERS);
        // Distinct zero-word buffers per slot: CALLDATA_SURGERY mutates register
        // contents in place and is legal under staticcall, so sharing one buffer
        // could corrupt across registers.
        for (uint256 i; i < NUM_REGISTERS; ++i) {
            registers[i] = new bytes(32);
        }
        uint256 numParams = params.length;
        for (uint256 i; i < numParams; ++i) {
            registers[i] = params[i];
        }
        registers[numParams] = abi.encodePacked(bytes32(uint256(uint160(account))));
        for (uint256 i; i < preBalances.length; ++i) {
            registers[numParams + 1 + i] = abi.encodePacked(bytes32(preBalances[i]));
        }
    }

    /// @notice Re-encodes a canonical program body + register file into the
    /// `runVM` calldata the VirtualMachine expects. The body is the exact
    /// `keccak256` preimage of the committed hash; the caller must have
    /// verified `body.length` is a nonzero multiple of `COMMAND_SIZE`.
    function encodeRunVM(
        bytes calldata body,
        bytes[] memory registers
    ) internal pure returns (bytes memory) {
        uint256 numCommands = body.length / COMMAND_SIZE;
        VMCommand[] memory commands = new VMCommand[](numCommands);
        for (uint256 i; i < numCommands; ++i) {
            uint256 base = i * COMMAND_SIZE;
            commands[i] = VMCommand({ op: uint8(body[base]), data: bytes32(body[base + 1:base + COMMAND_SIZE]) });
        }
        return abi.encodeWithSelector(RUN_VM_SELECTOR, commands, VMState(registers));
    }
}
