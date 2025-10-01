// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { Test } from "forge-std/Test.sol";

import { CatapultarFactory } from "../src/CatapultarFactory.sol";

contract CatapultarFactoryTest is Test {
    CatapultarFactory factory;

    function setUp() external {
        factory = new CatapultarFactory();
    }
}
