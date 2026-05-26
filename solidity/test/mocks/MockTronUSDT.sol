// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import { MockERC20 } from "solady/test/utils/mocks/MockERC20.sol";

/// @dev Simulates Tron USDT: transfer() returns false (32 bytes of zeros)
///      despite successfully moving balances. approve() and transferFrom() work normally.
contract MockTronUSDT is MockERC20 {
    constructor() MockERC20("Tether USD", "USDT", 6) { }

    function transfer(
        address to,
        uint256 amount
    ) public override returns (bool) {
        super.transfer(to, amount);
        return false;
    }
}
