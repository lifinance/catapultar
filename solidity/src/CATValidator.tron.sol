// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.25;

import { SafeTransferLib } from "solady/src/utils/SafeTransferLib.sol";

import { SafeTransferLibTron } from "./libs/SafeTransferLib.tron.sol";

import { CATValidator } from "./CATValidator.sol";

/// @title Constrained Asset Transaction Validator – C.A.T Validator (Tron)
/// @author Alexander @ LIFI (https://li.fi)
/// @notice Tron variant of CATValidator. Overrides _transfer to bypass
/// broken transfer() return values (Tron USDT) via approve(self) + transferFrom(self).
contract CATValidatorTron is CATValidator {
    function _transfer(
        address token,
        uint256 amount,
        address dest
    ) internal override {
        token == address(0)
            ? SafeTransferLib.safeTransferETH(dest, amount)
            : SafeTransferLibTron.safeTransfer(token, dest, amount);
    }
}
