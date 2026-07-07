// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.25;

/**
 * @title Proxies call such that arbitrary calls are safe to execute.
 * @author Alexander @ LIFI (https://li.fi)
 * @notice Stateless call forwarder. Deployers of this contract can execute arbitrary payloads from this contract
 * instead of themselves, isolating any token approvals or other permissions granted to the deployer from the
 * arbitrary call. The called target observes this contract — not the deployer — as msg.sender.
 * @dev Threat model: the fallback is intentionally permissionless. Safety relies on this contract never holding
 * balances, token approvals, or privileges of any kind:
 * - No token approvals may ever be granted to this contract. A direct caller could spend them freely.
 * - Assets must not be left in this contract. Ether sent alongside a call is forwarded in full via callvalue(),
 *   and a direct caller can only forward the value they themselves attach — the contract's own balance is
 *   never spent — but nothing should be parked here.
 * - The contract holds no storage and makes no assumptions about the caller or target.
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
