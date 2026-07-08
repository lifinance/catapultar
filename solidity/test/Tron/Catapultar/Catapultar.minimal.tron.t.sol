// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { LibCloneTron } from "../../../src/libs/LibClone.tron.sol";

import { CatapultarTest } from "../../Catapultar/Catapultar.base.t.sol";
import { MockCatapultar } from "../../mocks/MockCatapultar.sol";

contract CatapultarMinimalTronTest is CatapultarTest {
    function deploy() internal override returns (address template, address proxied) {
        template = address(new MockCatapultar());
        proxied = LibCloneTron.cloneDeterministic_PUSH0(template, bytes32(0));
    }

    function upgradeable() internal pure override returns (bool) {
        return false;
    }
}
