// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { SafeTransferLibTron } from "./SafeTransferLib.tron.sol";

import { IntentExecutor } from "./IntentExecutor.sol";

/// @title IntentExecutorTron
/// @author LI.FI / Intent Factory
/// @notice Tron variant of IntentExecutor. Overrides _transfer to bypass
///         broken transfer() return values (Tron USDT) via approve(self) + transferFrom(self).
///         The solver gate is inherited unchanged and needs TVM Cancun (TLOAD/TSTORE),
///         which Tron activated through committee proposal 103.
contract IntentExecutorTron is IntentExecutor {
    constructor(
        address owner_,
        address[] memory solvers
    ) IntentExecutor(owner_, solvers) { }

    function _transfer(
        address token,
        address to,
        uint256 amount
    ) internal override {
        SafeTransferLibTron.safeTransfer(token, to, amount);
    }
}
