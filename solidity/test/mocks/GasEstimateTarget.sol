// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

contract GasEstimateTarget {
    error ExpensiveFailure(bytes32 digest);

    event Healthy(uint256 calls);

    uint256 public healthyCalls;

    function expensiveThenRevert(
        uint256 rounds
    ) external pure {
        bytes32 digest;
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            for { let i := 0 } lt(i, rounds) { i := add(i, 1) } {
                mstore(ptr, digest)
                mstore(add(ptr, 0x20), i)
                digest := keccak256(ptr, 0x40)
            }
        }
        revert ExpensiveFailure(digest);
    }

    function healthy() external {
        unchecked {
            ++healthyCalls;
        }
        emit Healthy(healthyCalls);
    }
}
