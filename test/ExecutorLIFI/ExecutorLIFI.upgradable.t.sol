// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { LibClone } from "solady/src/utils/LibClone.sol";

import { ExecutorLIFI } from "../../src/ExecutorLIFI.sol";

import { MockExecutorLIFI } from "../mocks/MockExecutorLIFI.sol";
import { ExecutorLIFITest } from "./ExecutorLIFI.base.t.sol";

contract ExecutorLIFIUpgradableTest is ExecutorLIFITest {
    function deploy() internal override returns (address template, address proxied) {
        template = address(new MockExecutorLIFI(false));
        proxied = LibClone.deployDeterministicERC1967(template, bytes32(0));
    }

    function upgradable() internal pure override returns (bool) {
        return true;
    }

    function embeddedCalls() internal pure override returns (bool) {
        return false;
    }

    function test_revert_init_with_embedded_calls() external {
        address template = address(new MockExecutorLIFI(true));
        address proxied = LibClone.deployDeterministicERC1967(template, bytes32(0));

        vm.expectRevert(abi.encodeWithSelector(ExecutorLIFI.CannotBeUpgradeable.selector));
        MockExecutorLIFI(payable(proxied)).init(makeAddr("owner"));
    }
}
