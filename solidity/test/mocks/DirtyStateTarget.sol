// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

/// Target for estimation-twin state-fidelity tests: an atomic (RaiseRevert)
/// group [setFlag, revertWithData] must leave `flag` unset after it reverts,
/// so a later group's `expensiveIfFlagUnset` branches the same way during
/// estimation as on-chain.
contract DirtyStateTarget {
    error IntentAlreadyFilled();
    error FlagWasSet();

    event Finished(uint256 calls);

    bool public flag;
    uint256 public finishedCalls;

    function setFlag() external {
        flag = true;
    }

    function revertWithData() external pure {
        revert IntentAlreadyFilled();
    }

    function expensiveIfFlagUnset(
        uint256 rounds
    ) external {
        if (flag) revert FlagWasSet();
        bytes32 digest;
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            for { let i := 0 } lt(i, rounds) { i := add(i, 1) } {
                mstore(ptr, digest)
                mstore(add(ptr, 0x20), i)
                digest := keccak256(ptr, 0x40)
            }
        }
        unchecked {
            ++finishedCalls;
        }
        emit Finished(finishedCalls);
    }
}
