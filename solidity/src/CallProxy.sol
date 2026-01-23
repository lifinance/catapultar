// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

/**
 * @title Proxies call such that arbitrary calls are safe to execute.
 * @author Alexander @ LIFI (https://li.fi)
 */
contract CallProxy {
    /**
     * @dev This contract expects to receive calldata of type: abi.encodePacked(bytes32(target), bytes)
     * This data looks like:
     * 000000000000000000000000f79Db8d4E9baF5266B2578790363F027AE550B7a
     * 2b096926.... // Payload
     */
    fallback() external payable {
        assembly ("memory-safe") {
            // get the free memory pointer.
            let m := mload(0x40)

            // Copy call into memory
            calldatacopy(m, 32, sub(calldatasize(), 32))

            let target := calldataload(0)
            let success := call(gas(), target, callvalue(), m, sub(calldatasize(), 32), codesize(), 0x00)

            // Handle return data
            returndatacopy(0x00, 0x00, returndatasize())
            if iszero(success) { revert(0x00, returndatasize()) }
            return(0x00, returndatasize())
        }
    }
}
