// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { ERC7821 } from "solady/src/accounts/ERC7821.sol";

/**
 * @notice Opinioned batch executor.
 * @author Alexander @ LIFI (https://li.fi)
 * @author Solady (https://github.com/vectorized/solady/blob/main/src/accounts/ERC7821.sol)
 * @dev This contract is intended to be insert into smart accounts to provide them batch execution ability using an
 * ERC7821 compatible interface. An implementing contract is intended to override _validateOpData to signal whether
 * calls are approved.
 */
abstract contract ERC7821LIFI is ERC7821 {
    error TooManyCalls();
    error InvalidOpData();
    error OpDataTooSmall();

    event CallReverted(bytes32 extraData, bytes revertData);

    /// @dev keccak256(bytes("CallReverted(bytes32,bytes)"));
    bytes32 constant _CALL_REVERTED_EVENT_SIGNATURE = 0xa5ef9b4d75ffdec5840bf221dba12f4a744e8b60aeb23da25fbd8c487a97924d;

    /// @notice Validation function that validate opData for a specific call.
    function _validateOpData(
        bytes32 mode,
        Call[] calldata calls,
        bytes calldata opData
    ) internal virtual returns (bool);

    /**
     * @notice Returns whether or not the revert flag has been set in the leftmost byte
     * @dev Carries the revert flag forward, does not check whether or not the revert flag has a specific value.
     * @param mode Execution mode
     * @return flag A revert flag indication set in the leftmost byte.
     */
    function _executionModeRevert(
        bytes32 mode
    ) internal view virtual returns (bytes32 flag) {
        assembly ("memory-safe") {
            // shr: Get rid of the 30 right bytes
            // shl: Get rid of the 1 + 30 left bytes.
            // revertFlag is in leftmost byte.
            flag := shl(mul(31, 8), shr(mul(30, 8), mode))
        }
    }

    /**
     * @dev
     * Unsupported: 0: invalid mode, 1: no `opData` support,
     * Supported: 2: with `opData` support, 3: batch of batches
     */
    function _executionModeId(
        bytes32 mode
    ) internal view virtual override returns (uint256 id) {
        // Only supports atomic batched executions.
        // For the encoding scheme, see: https://eips.ethereum.org/EIPS/eip-7579
        // Bytes Layout:
        // - [0]      ( 1 byte )  `0x01` for batch call.
        // - [1]      ( 1 byte )  `0x00` for revert on any failure.
        // - [2..5]   ( 4 bytes)  Reserved by ERC7579 for future standardization.
        // - [6..9]   ( 4 bytes)  `0x00000000` or `0x78210001` or `0x78210002`.
        // - [10..31] (22 bytes)  Unused. Free for use.
        assembly ("memory-safe") {
            let m := and(shr(mul(22, 8), mode), 0xffff00000000ffffffff)
            id := or(shl(1, eq(m, 0x01000000000078210001)), id) // 2.
            id := or(shl(1, eq(m, 0x01010000000078210001)), id) // 2.
            id := or(mul(3, eq(m, 0x01000000000078210002)), id) // 3.
        }
    }

    // extraData has the following format:
    // [0] revert flag
    // [1 .. 22] Nonce extract
    // [23 .. 31] Index

    /**
     * @notice Executes the provides calls after validating opData
     * @dev Embeds the mode and the part of opData into the extraData provided to be used to execute the calls.
     */
    function _execute(
        bytes32 mode,
        bytes calldata,
        Call[] calldata calls,
        bytes calldata opData
    ) internal virtual override {
        if (opData.length < 32) revert OpDataTooSmall();
        // Validate the opData
        if (!_validateOpData(mode, calls, opData)) revert InvalidOpData();

        bytes32 extraData = _executionModeRevert(mode);
        // Add the last 23 bytes of the first words of opData to extraData
        assembly ("memory-safe") {
            let word := calldataload(opData.offset)
            extraData := or(extraData, shr(8, shl(mul(9, 8), word)))
        }

        return _execute(calls, extraData);
    }

    /**
     * @notice Iterates over the provides calls to execute them.
     * @dev Embed the index of the call into extraData as the rightmost bytes.
     * Because _only_ 8 bytes is reserved for the index, the function cannot take more than type(uint64).max calls. This
     * limit exceeds the memory limit of the EVM so it is not a problem in practise.
     */
    function _execute(Call[] calldata calls, bytes32 extraData) internal virtual override {
        unchecked {
            uint256 i;
            if (calls.length == uint256(0)) return;
            // It should not be possible to allocate this amount of memory but this check ensures that if it becomes
            // possible, then it will be caught
            if (calls.length > type(uint64).max) revert TooManyCalls();
            do {
                (address to, uint256 value, bytes calldata data) = _get(calls, i);
                bytes32 executeExtraData;
                assembly ("memory-safe") {
                    executeExtraData := or(extraData, i)
                }
                _execute(to, value, data, executeExtraData);
            } while (++i != calls.length);
        }
    }

    /**
     * @notice Executes provided call.
     * @dev Uses the revert flag set in the leftmost byte to decide whether to bubble up a revert.
     * The function will always emit a CallReverted event if the transaction reverted.
     * @param to Contract to call.
     * @param value Amount of native to send with the call.
     * @param data Calldata to execute.
     * @param extraData Data to emit on transaction failure. If the leftmost byte is 0, will bubble up a reverted call.
     */
    function _execute(address to, uint256 value, bytes calldata data, bytes32 extraData) internal virtual override {
        assembly ("memory-safe") {
            let m := mload(0x40) // Grab the free memory pointer.
            calldatacopy(m, data.offset, data.length)
            let success := call(gas(), to, value, m, data.length, codesize(), 0x00)
            if iszero(success) {
                mstore(m, extraData) // Place extraData
                mstore(add(m, 0x20), 0x40) // Set offset for bytes
                // Compute the padded length for ABI alignment. (rdsize + rdsize % 32)
                let sizeAfterPad := and(add(returndatasize(), 31), not(31))
                mstore(add(add(m, 0x40), sizeAfterPad), 0) // Clear out potential overflowing returndata.
                mstore(add(m, 0x40), returndatasize()) // Place length of returndata
                returndatacopy(add(m, 0x60), 0x00, returndatasize()) // Place returndata
                // Emit CallReverted(bytes32 extraData, bytes revertData).
                log1(m, add(0x60, sizeAfterPad), _CALL_REVERTED_EVENT_SIGNATURE)

                if iszero(shr(mul(31, 8), extraData)) {
                    // Bubble up the revert if the call reverts and the skip revert flag has not been set
                    revert(add(m, 0x60), returndatasize())
                }
            }
        }
    }
}
