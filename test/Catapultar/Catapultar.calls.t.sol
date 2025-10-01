// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { LibClone } from "solady/src/utils/LibClone.sol";

import { MockCatapultar } from "../mocks/MockCatapultar.sol";
import { CatapultarTest } from "./Catapultar.base.t.sol";

contract CatapultarCallsTest is CatapultarTest {
    function deploy() internal override returns (address template, address proxied) {
        template = address(new MockCatapultar(true));
        proxied = LibClone.clone(template, abi.encodePacked(bytes32(0)));
    }

    function upgradeable() internal pure override returns (bool) {
        return false;
    }

    function embeddedCalls() internal pure override returns (bool) {
        return true;
    }
}
