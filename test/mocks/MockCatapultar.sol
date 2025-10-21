// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import { Catapultar } from "../../src/Catapultar.sol";

contract MockCatapultar is Catapultar {
    constructor()  { }

    function validateOpData(bytes32 mode, Call[] calldata calls, bytes calldata opData) external returns (bool) {
        return _validateOpData(mode, calls, opData);
    }

    function useUnorderedNonce(
        uint256 nonce
    ) external {
        _useUnorderedNonce(nonce);
    }
}
