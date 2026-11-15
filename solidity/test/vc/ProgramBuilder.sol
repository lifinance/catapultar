// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

/**
 * @title ProgramBuilder
 * @notice Test-only helpers that pack the data words of validation-program
 * commands exactly as the deployed VirtualMachine expects. A test program is a
 * `VMCommand[]` built from these words. Paths of the form `vm/src/...` refer to
 * the LI.FI VirtualMachine sources; packing follows `vm/src/CommandPacking.sol`.
 *
 * The VM sources are never imported: each packer mirrors the layout documented
 * in the referenced `CommandPacking.pack*` function, so a test program is fully
 * under this repository's control. Op numbers follow the `OP` enum in
 * `vm/src/DataModel.sol`.
 *
 * Blueprints follow the `BlueprintEncoder` DSL (`vm/src/BlueprintEncoder.sol`):
 * a static register token is the register index (0x00-0x79), a dynamic register
 * token is `index | 0x80`, and container tokens are 0x7B-0x7F.
 *
 * RPN words follow `ArithmeticProcessor.evaluateRPN`
 * (`vm/src/RPNArithmetic.sol`): one byte per step, read from the most
 * significant byte; `0x80 | i` pushes `regValues[i]`, any other byte is an
 * operator that pops two operands.
 */
library ProgramBuilder {
    /* ─────────────────────────── OP numbers
    (vm/src/DataModel.sol)
    ─────────── */

    uint8 internal constant OP_CALL = 0;
    uint8 internal constant OP_CALLDATA_BUILD = 1;

    /* ─────────────────────────── CallType (vm/src/DataModel.sol)
    ───────────── */

    uint8 internal constant CALLTYPE_STATICCALL = 2;

    /* ─────────────────────────── Blueprint DSL tokens
    ─────────────────────── */

    uint8 internal constant DYN_MASK = 0x80;
    uint8 internal constant START_ARRAY_DYNAMIC = 0x7C;
    uint8 internal constant END_CONTAINER = 0x7B;

    /* ─────────────────────────── RPN (vm/src/RPNArithmetic.sol)
    ───────────── */

    uint8 internal constant RPN_PUSH = 0x80;
    uint8 internal constant RPN_MUL = 2;
    uint8 internal constant RPN_DIV_UP = 4;

    /* ─────────────────────────── Selectors
    ────────────────────────────────── */

    bytes4 internal constant SEL_EVALUATE_RPN = 0xfe79e115; // evaluateRPN(uint256[],bytes32,uint8)
    bytes4 internal constant SEL_ASSERT_GTE = 0xe1f0273e; // assertGreaterThanEqual(uint256,uint256)

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

    /* ─────────────────────────── Blueprint and RPN tokens
    ────────────────────────────── */

    /// @dev Static register token (the register must hold exactly 32 bytes).
    function bpStatic(
        uint8 reg
    ) internal pure returns (bytes1) {
        require(reg < DYN_MASK, "static reg index too high");
        return bytes1(reg);
    }

    /// @dev Left-aligns an RPN step sequence into the `rpnStream` word.
    function rpnWord(
        bytes memory steps
    ) internal pure returns (bytes32 word) {
        require(steps.length <= 32, "rpn > 32 steps");
        for (uint256 i; i < steps.length; ++i) {
            word |= bytes32(steps[i]) >> (i * 8);
        }
    }
}
