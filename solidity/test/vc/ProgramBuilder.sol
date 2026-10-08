// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

/**
 * @title ProgramBuilder
 * @notice Test-only helpers that pack canonical validation-program commands
 * exactly as the deployed VirtualMachine expects (umbrella
 * `vm/src/CommandPacking.sol`) and concatenate them into the 33-bytes-per-command
 * canonical body (`uint8 op ++ bytes32 data`).
 *
 * The VM sources are never imported: each packer mirrors the layout documented
 * in the referenced `CommandPacking.pack*`/`unpack*` function so the hand-authored
 * C3 `vm-programs` fixture is fully under this repo's control. Op numbers follow
 * `vm/src/DataModel.sol`'s frozen `OP` enum.
 *
 * Blueprints follow the `BlueprintEncoder` DSL (umbrella
 * `vm/src/BlueprintEncoder.sol`): static register token = index (0x00-0x79),
 * dynamic register token = index | 0x80, container tokens 0x7B-0x7F.
 */
library ProgramBuilder {
    /* ─────────────────────────── OP numbers
    (vm/src/DataModel.sol) ─────────── */

    uint8 internal constant OP_CALL = 0;
    uint8 internal constant OP_CALLDATA_BUILD = 1;
    uint8 internal constant OP_DEPOSIT_APPROVED = 3;
    uint8 internal constant OP_RETURN = 5;
    uint8 internal constant OP_NATIVE_BALANCE = 8;
    uint8 internal constant OP_LOG = 9;
    uint8 internal constant OP_SAFE_TRANSFER = 10;

    /* ─────────────────────────── CallType (vm/src/DataModel.sol)
    ───────────── */

    uint8 internal constant CALLTYPE_CALL = 1;
    uint8 internal constant CALLTYPE_STATICCALL = 2;
    uint8 internal constant CALLTYPE_VALUECALL = 3;

    /* ─────────────────────────── Blueprint DSL tokens
    ─────────────────────── */

    uint8 internal constant DYN_MASK = 0x80;
    uint8 internal constant START_ARRAY_DYNAMIC = 0x7C;
    uint8 internal constant END_CONTAINER = 0x7B;

    /* ─────────────────────────── Selectors
    ────────────────────────────────── */

    bytes4 internal constant SEL_BALANCE_OF = 0x70a08231; // balanceOf(address)
    bytes4 internal constant SEL_TRANSFER = 0xa9059cbb; // transfer(address,uint256)
    bytes4 internal constant SEL_EVALUATE_RPN = 0xfe79e115; // evaluateRPN(uint256[],bytes32,uint8)
    bytes4 internal constant SEL_ASSERT_GTE = 0xe1f0273e; // assertGreaterThanEqual(uint256,uint256)
    bytes4 internal constant SEL_ASSERT_EQ = 0xad207fd7; // assertEqual(uint256,uint256)

    /* ─────────────────────────── Command packers
    ──────────────────────────── */

    /// @dev Mirrors CommandPacking.packCall: byte 0 callType, bytes 1-20 target,
    /// byte 21 destReg, byte 22 srcReg, byte 23 valueReg.
    function packCall(
        address target,
        uint8 callType,
        uint8 destReg,
        uint8 srcReg,
        uint8 valueReg
    ) internal pure returns (bytes32 packed) {
        assembly ("memory-safe") {
            packed := shl(248, callType)
            packed := or(packed, shl(88, target))
            packed := or(packed, shl(80, destReg))
            packed := or(packed, shl(72, srcReg))
            packed := or(packed, shl(64, valueReg))
        }
    }

    /// @dev Mirrors CommandPacking.packCallDataBuild: bytes 0-3 selector, byte 4
    /// destReg, byte 5 blueprint length, bytes 6+ blueprint.
    function packCallDataBuild(
        bytes4 selector,
        uint8 destReg,
        bytes memory blueprint
    ) internal pure returns (bytes32 packed) {
        require(blueprint.length <= 22, "blueprint > MAX_CDB_BP");
        packed = bytes32(uint256(uint32(selector))) << 224;
        packed |= bytes32(uint256(destReg)) << 216;
        packed |= bytes32(uint256(blueprint.length)) << 208;
        for (uint256 i; i < blueprint.length; ++i) {
            packed |= bytes32(uint256(uint8(blueprint[i]))) << ((25 - i) * 8);
        }
    }

    /// @dev Mirrors CommandPacking.packSafeTransfer: bytes 0-19 token, byte 20
    /// toReg, byte 21 amountReg.
    function packSafeTransfer(
        address token,
        uint8 toReg,
        uint8 amountReg
    ) internal pure returns (bytes32 packed) {
        assembly ("memory-safe") {
            packed := shl(96, token)
            packed := or(packed, shl(88, toReg))
            packed := or(packed, shl(80, amountReg))
        }
    }

    /// @dev Mirrors CommandPacking.packDepositApproved: bytes 0-19 token, byte 20
    /// destReg, byte 21 maxDepositReg.
    function packDepositApproved(
        address token,
        uint8 destReg,
        uint8 maxDepositReg
    ) internal pure returns (bytes32 packed) {
        assembly ("memory-safe") {
            packed := shl(96, token)
            packed := or(packed, shl(88, destReg))
            packed := or(packed, shl(80, maxDepositReg))
        }
    }

    /// @dev Mirrors CommandPacking.packLog: byte 0 variant, bytes 1-26 packed
    /// source registers (unpacked value shifted left by 40 bits).
    function packLog(
        uint8 variant,
        uint256 sourceRegs
    ) internal pure returns (bytes32 packed) {
        assembly ("memory-safe") {
            packed := shl(248, variant)
            packed := or(packed, shl(40, sourceRegs))
        }
    }

    /// @dev Mirrors CommandPacking.packNativeBalance: byte 0 addrReg, byte 1 destReg.
    function packNativeBalance(
        uint8 addrReg,
        uint8 destReg
    ) internal pure returns (bytes32 packed) {
        assembly ("memory-safe") {
            packed := shl(248, addrReg)
            packed := or(packed, shl(240, destReg))
        }
    }

    /// @dev Mirrors CommandPacking.packReturn: byte 0 sourceReg.
    function packReturn(
        uint8 sourceReg
    ) internal pure returns (bytes32 packed) {
        assembly ("memory-safe") {
            packed := shl(248, sourceReg)
        }
    }

    /* ─────────────────────────── Body assembly
    ────────────────────────────── */

    /// @dev One canonical command: op byte followed by the 32-byte data word.
    function cmd(
        uint8 op,
        bytes32 data
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(op, data);
    }

    /* ─────────────────────────── Blueprint helpers
    ────────────────────────── */

    /// @dev Static register token (expects the register to hold exactly 32 bytes).
    function bpStatic(
        uint8 reg
    ) internal pure returns (bytes1) {
        require(reg < DYN_MASK, "static reg index too high");
        return bytes1(reg);
    }
}
