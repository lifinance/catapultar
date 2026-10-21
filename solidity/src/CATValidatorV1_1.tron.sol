// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { SafeTransferLib } from "solady/src/utils/SafeTransferLib.sol";

import { CATValidatorV1_1 } from "./CATValidatorV1_1.sol";
import { SafeTransferLibTron } from "./libs/SafeTransferLib.tron.sol";

/// @title Constrained Asset Transaction Validator v1.1 (Tron)
/// @author Alexander @ LIFI (https://li.fi)
/// @notice Tron variant of CATValidatorV1_1. Pays outcomes through approve(self) + transferFrom(self) to bypass broken
/// transfer() return values (Tron USDT).
contract CATValidatorV1_1Tron is CATValidatorV1_1 {
    function _payout(
        address token,
        uint256 amount,
        address dest
    ) internal override {
        token == address(0)
            ? SafeTransferLib.safeTransferETH(dest, amount)
            : SafeTransferLibTron.safeTransfer(token, dest, amount);
    }
}
