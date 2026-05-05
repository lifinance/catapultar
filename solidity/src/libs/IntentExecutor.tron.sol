// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import { SafeTransferLibTron } from "./SafeTransferLib.tron.sol";

import { IntentExecutor } from "./IntentExecutor.sol";

/// @title IntentExecutorTron
/// @author LI.FI / Intent Factory
/// @notice Tron variant of IntentExecutor. Overrides _transfer to bypass
///         broken transfer() return values (Tron USDT) via approve(self) + transferFrom(self).
contract IntentExecutorTron is IntentExecutor {
    function _transfer(
        address token,
        address to,
        uint256 amount
    ) internal override {
        SafeTransferLibTron.safeTransfer(token, to, amount);
    }
}
