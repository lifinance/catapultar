    // SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import { ExecutorLIFI } from "../../src/ExecutorLIFI.sol";

contract MockExecutorLIFI is ExecutorLIFI {
    constructor(
        bool allowOneTimeCall
    ) ExecutorLIFI(allowOneTimeCall) { }

    function validateOpData(bytes32 mode, Call[] calldata calls, bytes calldata opData) external returns (bool) {
        return _validateOpData(mode, calls, opData);
    }

    function useUnorderedNonce(
        uint256 nonce
    ) external {
        _useUnorderedNonce(nonce);
    }
}
