// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { LibClone } from "solady/src/utils/LibClone.sol";

import { Catapultar } from "../../src/Catapultar.sol";
import { KeyedOwnable } from "../../src/libs/KeyedOwnable.sol";

import { MockCatapultar } from "../mocks/MockCatapultar.sol";
import { CatapultarTest } from "./Catapultar.base.t.sol";

contract CatapultarUpgradeableTest is CatapultarTest {
    function deploy() internal override returns (address template, address proxied) {
        template = address(new MockCatapultar());
        proxied = LibClone.deployERC1967(template);
    }

    function upgradeable() internal pure override returns (bool) {
        return true;
    }
}
