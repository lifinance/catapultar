// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { ExecutorLIFITest } from "./ExecutorLIFI.base.t.sol";

contract ExecutorLIFINoCallsTest is ExecutorLIFITest {
    function enableCalls() internal pure override returns (bool) {
        return false;
    }
}
