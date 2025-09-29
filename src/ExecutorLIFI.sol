// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import {LibZip} from "solady/src/utils/LibZip.sol";
import {Ownable} from "solady/src/auth/Ownable.sol";
import {Initializable} from "solady/src/utils/Initializable.sol";
import {UUPSUpgradeable} from "solady/src/utils/UUPSUpgradeable.sol";
import {SignatureCheckerLib} from "solady/src/utils/SignatureCheckerLib.sol";

import {EIP712} from "solady/src/utils/EIP712.sol";

import {ERC7821LIFI} from "./ERC7821LIFI.sol";
import {BitmapNonce} from "./BitmapNonce.sol";
import {LibCalls} from "./LibCalls.sol";

/**
 * @title LI.FI Executor
 * @author LIFI
 * @notice Simple batch executing smart account with simple signature validation logic.
 * This batch execution account supports ERC-7821 interfaces and supports the failure mode flag 01.
 * If provided, each call in a batch will be tried individually and the contract emits a event with the revert data.
 *
 * Intended use case is:
 * - 0x01000000000078210001: Exeucting a set of conditional trasactions.
 *         If 1 transaction in a set fails, the entire set should fail. This can allow for retrying the transaction at a later time since the nonce is not spent.
 * - 0x01010000000078210001: Executing a set of individual transactions.
 *         If 1 or more transactions in a set fails, the remaining transactions in the set should be executed. 
 * - 0x01000000000078210001 inside 0x01010000000078210001: Executing a large set of individual transactions containing conditional transactions.
 *         Each 0x01000000000078210001 batch can be retried in the future if it fails with each 0x01010000000078210001 only being executable once. A batch executor can schedule a set of transaction to be executed. The entire set should be executed individually (0x01010000000078210001) but each sub-batch or transaction needs to be exeucted conditionally (0x01000000000078210001).
 *
 * Additionally, as an account it supports initialising a call that anyone can make.
 */
contract ExecutorLIFI is ERC7821LIFI, EIP712, BitmapNonce, Ownable, Initializable, UUPSUpgradeable {
    error SmartAccountEmbeddedCallsDisabled();

    /**
     * @dev Determines whether pre-configured calls are allowed.
     * The intended use-case is to save gas if the functionality is not needed.
     */
    bool immutable ALLOW_ONE_TIME_CALL;

    /**
     * @dev If allowed, a typehash of the embedded calls.
     */
    bytes32 oneTimeCallTypeHash;

    constructor(bool allowOneTimeCall) {
        ALLOW_ONE_TIME_CALL = allowOneTimeCall;
        _disableInitializers();
    }

    function init(address owner, bytes32 callTypeHash) external initializer {
        if (!ALLOW_ONE_TIME_CALL) {
            if (callTypeHash != bytes32(0)) {
                revert SmartAccountEmbeddedCallsDisabled();
            }
        } else {
            oneTimeCallTypeHash = callTypeHash;
        }
        _initializeOwner(owner);
    }

    function _authorizeUpgrade(address) internal override onlyOwner {}

    function _domainNameAndVersion() internal pure override returns (string memory name, string memory version) {
        name = "ExecutorLIFI";
        version = "1";
    }

    function _validateOpData(bytes32 mode, Call[] calldata calls, bytes calldata opData)
        internal
        override
        returns (bool)
    {
        uint256 nonce;
        assembly ("memory-safe") {
            nonce := calldataload(opData.offset)
        }
        _useUnorderedNonce(nonce);
        // If there are only 32 bytes of opdata, there is no signature. The simplest case is if we called ourself in a batch.
        if (opData.length == 32) {
            if (address(this) == msg.sender) return true;
        }

        bytes32 callTypeHash = LibCalls.typehash(mode, nonce, calls);
        // If ALLOW_ONE_TIME_CALL is allowed (and no signature), then we check if the one time use hash has been embedded.
        if (ALLOW_ONE_TIME_CALL) {
            if (opData.length == 32) return callTypeHash == oneTimeCallTypeHash;
        }
        bytes32 digest = _hashTypedData(callTypeHash);
        return SignatureCheckerLib.isValidSignatureNowCalldata(owner(), digest, opData[0x20:]);
    }

    // Allow us to use LibZip for gas efficiency savings on cheap execution but expensive calldata chains.
    fallback() external payable override receiverFallback {
        LibZip.cdFallback();
    }
}
