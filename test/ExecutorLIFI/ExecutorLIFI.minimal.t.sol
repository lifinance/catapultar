// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { LibClone } from "solady/src/utils/LibClone.sol";

import { MockExecutorLIFI } from "../mocks/MockExecutorLIFI.sol";
import { ExecutorLIFITest } from "./ExecutorLIFI.base.t.sol";

contract ExecutorLIFIMinimalTest is ExecutorLIFITest {
    function deploy() internal override returns (address template, address proxied) {
        template = address(new MockExecutorLIFI(false));
        proxied = LibClone.cloneDeterministic_PUSH0(template, bytes32(0));
    }

    function upgradable() internal pure override returns (bool) {
        return false;
    }

    function embeddedCalls() internal pure override returns (bool) {
        return false;
    }
}
