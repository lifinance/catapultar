// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { LibClone } from "solady/src/utils/LibClone.sol";

import { Catapultar } from "../../src/Catapultar.sol";
import { KeyedOwnable } from "../../src/libs/KeyedOwnable.sol";

import { MockCatapultar } from "../mocks/MockCatapultar.sol";
import { CatapultarTest } from "./Catapultar.base.t.sol";

contract CatapultarUpgradeableTest is CatapultarTest {
    function deploy() internal override returns (address template, address proxied) {
        template = address(new MockCatapultar(false));
        proxied = LibClone.deployERC1967(template);
    }

    function upgradeable() internal pure override returns (bool) {
        return true;
    }

    function embeddedCalls() internal pure override returns (bool) {
        return false;
    }

    function test_revert_init_with_embedded_calls() external {
        address template = address(new MockCatapultar(true));
        address proxied = LibClone.deployERC1967(template);

        vm.expectRevert(abi.encodeWithSelector(Catapultar.CannotBeUpgradeable.selector));
        bytes32[] memory keys = new bytes32[](1);
        keys[0] = bytes32(uint256(uint160(makeAddr("owner"))));
        MockCatapultar(payable(proxied)).init(KeyedOwnable.KeyType.ECDSAThenSmartContract, keys);
    }
}
