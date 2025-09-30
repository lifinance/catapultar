// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { Ownable } from "solady/src/auth/Ownable.sol";
import { Initializable } from "solady/src/utils/Initializable.sol";

import { LibClone } from "solady/src/utils/LibClone.sol";
import { LibZip } from "solady/src/utils/LibZip.sol";
import { SignatureCheckerLib } from "solady/src/utils/SignatureCheckerLib.sol";
import { UUPSUpgradeable } from "solady/src/utils/UUPSUpgradeable.sol";

import { EIP712 } from "solady/src/utils/EIP712.sol";

import { BitmapNonce } from "./BitmapNonce.sol";
import { ERC7821LIFI } from "./ERC7821LIFI.sol";
import { LibCalls } from "./LibCalls.sol";

import { console } from "forge-std/console.sol";

/**
 * @title LI.FI Executor
 * @author LIFI
 * @notice Simple batch executing smart account with simple signature validation logic.
 * This batch execution account supports ERC-7821 interfaces and supports the failure mode flag 01.
 * If provided, each call in a batch will be tried individually and the contract emits a event with the revert data.
 *
 * Intended use case is:
 * - 0x01000000000078210001: Exeucting a set of conditional trasactions.
 *         If 1 transaction in a set fails, the entire set should fail. This can allow for retrying the transaction at a
 * later time since the nonce is not spent.
 * - 0x01010000000078210001: Executing a set of individual transactions.
 *         If 1 or more transactions in a set fails, the remaining transactions in the set should be executed.
 * - 0x01000000000078210001 inside 0x01010000000078210001: Executing a large set of individual transactions containing
 * conditional transactions.
 *         Each 0x01000000000078210001 batch can be retried in the future if it fails with each 0x01010000000078210001
 * only being executable once. A batch executor can schedule a set of transaction to be executed. The entire set should
 * be executed individually (0x01010000000078210001) but each sub-batch or transaction needs to be exeucted
 * conditionally (0x01000000000078210001).
 *
 * Additionally, as an account it supports initialising a call that anyone can make.
 *
 * The contract is intended to be used via 3 cloning strategies:
 * - Non-upgradable minimal proxy clone for minimal cost.
 * - Non-upgradable proxy with embedded calldata as immutable args to allow anyone to execute a predetermined call.
 * - Upgradable proxy to allow ownership handover. An upgradable proxy cannot have embedded calldata.
 */
contract ExecutorLIFI is ERC7821LIFI, EIP712, BitmapNonce, Ownable, Initializable, UUPSUpgradeable {
    error NotUpgradeable();
    /**
     * @dev Determines whether pre-configured calls are allowed.
     * The intended use-case is to save gas if the functionality is not needed.
     */

    bool immutable ALLOW_ONE_TIME_CALL;

    constructor(
        bool allowOneTimeCall
    ) {
        ALLOW_ONE_TIME_CALL = allowOneTimeCall;
        _disableInitializers();
    }

    /**
     * @dev If ALLOW_ONE_TIME_CALL is true and the contract is being cloned through a upgradable contract, the function
     * will revert.
     */
    function init(
        address owner
    ) external initializer {
        _initializeOwner(owner);
        if (ALLOW_ONE_TIME_CALL && _upgradable()) revert NotUpgradeable();
    }

    // --- Proxy / Clone Helpers --- //

    /**
     * @notice Returns immutable calldata attatched to a proxy.
     * @dev This function must only be called from a proxy deployed with LibClone.createDeterministicClone.
     * @return bytes32 Embedded call as the first 32 bytes of the immutable args attatched to the proxy.
     */
    function _embeddedCall() internal view returns (bytes32) {
        return bytes32(LibClone.argsOnClone(address(this), 0, 32));
    }

    function embeddedCall() external view returns (bytes32) {
        if (!ALLOW_ONE_TIME_CALL) return bytes32(0);
        return _embeddedCall();
    }

    /**
     * @notice Returns whether the contract has been cloned as a upgradable proxy.
     * @dev This function only returns true if the code has been deployed using LibClone.deployERC1967. There may be
     * situations where the contract is technically upgradable but this contract returns false.
     */
    function _upgradable() internal view returns (bool) {
        address implementation = LibClone.implementationOf(address(this));
        return address(this).codehash == LibClone.initCodeHashERC1967(implementation);
    }

    /**
     * @dev Returns the storage slot used by the implementation,
     *  as specified in [ERC1822](https://eips.ethereum.org/EIPS/eip-1822).
     *
     * If the contract has not been deployed as an upgradable contract, returns 0.
     */
    function proxiableUUID() public view override notDelegated returns (bytes32) {
        return _upgradable() ? _ERC1967_IMPLEMENTATION_SLOT : bytes32(0);
    }

    /**
     * @notice Allow the owner to upgrade the contract.
     * @dev If the proxy used to clone the contract is not specifically LibClone.deployERC1967 then _authorizeUpgrade
     * will revert.
     */
    function _authorizeUpgrade(
        address
    ) internal view override onlyOwner {
        if (!_upgradable()) revert NotUpgradeable();
    }

    // --- Call Validation Logic --- //

    function _domainNameAndVersion() internal pure override returns (string memory name, string memory version) {
        name = "ExecutorLIFI";
        version = "1";
    }

    function _validateOpData(
        bytes32 mode,
        Call[] calldata calls,
        bytes calldata opData
    ) internal override returns (bool) {
        uint256 nonce;
        assembly ("memory-safe") {
            nonce := calldataload(opData.offset)
        }
        _useUnorderedNonce(nonce);
        // If there are only 32 bytes of opdata, there is no signature. The simplest case is if we called ourself in a
        // batch.
        if (opData.length == 32) if (address(this) == msg.sender) return true;

        bytes32 callTypeHash = LibCalls.typehash(nonce, mode, calls);
        // If ALLOW_ONE_TIME_CALL is allowed (and no signature), then we check if the one time use hash has been
        // embedded.
        if (ALLOW_ONE_TIME_CALL) if (opData.length == 32) return callTypeHash == _embeddedCall();
        bytes32 digest = _hashTypedData(callTypeHash);
        return SignatureCheckerLib.isValidSignatureNowCalldata(owner(), digest, opData[0x20:]);
    }

    // Allow us to use LibZip for gas efficiency savings on cheap execution but expensive calldata chains.
    fallback() external payable override receiverFallback {
        LibZip.cdFallback();
    }
}
