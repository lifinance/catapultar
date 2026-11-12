// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.25;

/**
 * @notice ABI mirror of the LI.FI VirtualMachine's command structure
 * (`src/DataModel.sol` in the VirtualMachine sources). The VM sources are never
 * imported: the validator passes the committed command array to the deployed VM
 * in the `runVM` calldata shape and lets the VM interpret it.
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
 * programs.
 *
 * A validation program travels as the `runVM` command array itself.
 * `keccak256(abi.encode(commands))` is the committed `validationProgramHash`
 * (`bytes32(0)` for an empty array). Committed per-user parameters travel as a
 * `bytes32[]`; `keccak256` of their concatenation is the committed `paramsHash`
 * (`bytes32(0)` for an empty vector).
 *
 * The initial register file is `params ++ [account] ++ spent ++ paid`, then
 * zero words up to `NUM_REGISTERS`. `account` is the escrow address, `spent[i]`
 * the amount the validator pulled from the escrow for allowance `i`, and
 * `paid[j]` the amount the validator forwarded for outcome `j`. The validator
 * measures all three at settlement; a program cannot carry them as command
 * literals or params, because the escrow address depends on
 * `validationProgramHash`.
 */
library LibValidationVM {
    /// @dev `runVM((uint8,bytes32)[],(bytes[]))` on the VirtualMachine
    /// (`src/VirtualMachine.sol` in the VirtualMachine sources). Pinned and
    /// asserted against the hash-parity fixture's compiler calldata in tests.
    bytes4 internal constant RUN_VM_SELECTOR = 0x00a32e6c;

    /// @dev Fixed register-file size. The VM addresses registers with a 7-bit
    /// index and treats 0x7A (122) as a void register (reads zero, swallows
    /// writes); reads or writes at an index >= file length revert inside the
    /// VM. 123 slots make every meaningful index (0-121, plus the void 122)
    /// addressable, so the validator never needs to know a program's register
    /// usage in advance.
    uint256 internal constant NUM_REGISTERS = 123;

    /// @dev Highest register index the injected prefix may occupy (121; 122 is
    /// the void register, which would silently read as zero).
    uint256 internal constant MAX_PREFIX_END = 121;

    /// @notice Computes the committed params hash for a supplied params vector.
    /// @return `bytes32(0)` when empty, else `keccak256` of the concatenated words.
    function paramsHashOf(
        bytes32[] calldata params
    ) internal pure returns (bytes32) {
        return params.length == 0 ? bytes32(0) : keccak256(abi.encodePacked(params));
    }

    /// @notice Builds the initial register file. The caller must have checked
    /// that the highest written index, `params.length + spent.length +
    /// paid.length`, is at most `MAX_PREFIX_END`.
    function buildRegisters(
        bytes32[] calldata params,
        address account,
        uint256[] memory spent,
        uint256[] memory paid
    ) internal pure returns (bytes[] memory registers) {
        registers = new bytes[](NUM_REGISTERS);
        // Distinct zero-word buffers per slot: CALLDATA_SURGERY mutates register
        // contents in place and is legal under staticcall, so sharing one buffer
        // could corrupt across registers.
        for (uint256 i; i < NUM_REGISTERS; ++i) {
            registers[i] = new bytes(32);
        }
        uint256 next;
        for (; next < params.length; ++next) {
            registers[next] = abi.encodePacked(params[next]);
        }
        registers[next++] = abi.encodePacked(bytes32(uint256(uint160(account))));
        for (uint256 i; i < spent.length; ++i) {
            registers[next++] = abi.encodePacked(bytes32(spent[i]));
        }
        for (uint256 i; i < paid.length; ++i) {
            registers[next++] = abi.encodePacked(bytes32(paid[i]));
        }
    }
}
