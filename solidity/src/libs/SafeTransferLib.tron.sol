// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import { SafeTransferLib } from "solady/src/utils/SafeTransferLib.sol";

/// @notice Tron-compatible safeTransfer wrapper.
/// @author LI.FI
/// @dev Tron USDT's transfer() returns false (32 bytes of zeros) on success.
///      Solady's safeTransfer reverts because it expects true or empty returndata.
///      This wrapper replaces safeTransfer with approve(self) + transferFrom(self),
///      bypassing the broken transfer() entirely.
///      Import this alongside Solady's SafeTransferLib; use tronSafeTransfer inplace of safeTransfer()
library SafeTransferLibTron {
    /// @dev Sends `amount` of ERC20 `token` from the current contract to `to`.
    ///      Uses approve(self) + transferFrom(self) to bypass broken transfer().
    function tronSafeTransfer(
        address token,
        address to,
        uint256 amount
    ) internal {
        if (_selfAllowance(token) < amount) SafeTransferLib.safeApprove(token, address(this), amount);
        SafeTransferLib.safeTransferFrom(token, address(this), to, amount);
    }

    /// @dev Returns the ERC20 allowance of this contract for itself. Returns 0 on failure.
    function _selfAllowance(
        address token
    ) private view returns (uint256 amount) {
        assembly ("memory-safe") {
            let m := mload(0x40)
            let self := address()
            mstore(0x34, self)
            mstore(0x14, self)
            mstore(0x00, 0xdd62ed3e000000000000000000000000) // allowance(address,address)
            amount := mul(
                mload(0x00),
                and(gt(returndatasize(), 0x1f), staticcall(gas(), token, 0x10, 0x44, 0x00, 0x20))
            )
            mstore(0x40, m)
        }
    }
}
