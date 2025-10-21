// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { Ownable } from "solady/src/auth/Ownable.sol";

import { EIP712 } from "solady/src/utils/EIP712.sol";
import { EfficientHashLib } from "solady/src/utils/EfficientHashLib.sol";
import { Initializable } from "solady/src/utils/Initializable.sol";
import { LibClone } from "solady/src/utils/LibClone.sol";
import { LibZip } from "solady/src/utils/LibZip.sol";
import { SignatureCheckerLib } from "solady/src/utils/SignatureCheckerLib.sol";
import { UUPSUpgradeable } from "solady/src/utils/UUPSUpgradeable.sol";

import { BitmapNonce } from "./libs/BitmapNonce.sol";
import { ERC7821LIFI } from "./libs/ERC7821LIFI.sol";
import { LibCalls } from "./libs/LibCalls.sol";

/**
 * @title For throwing transactions into the mempool – Catapultar
 * @author Alexander @ LIFI (https://li.fi)
 * @custom:version 0.0.1
 * @notice Batch executing smart account with ECDSA and ERC1271 signature validation logic.
 * This batch execution account supports ERC-7821 interfaces and supports the failure mode flag 01.
 * If provided, each call in a batch will be tried individually and the contract emits a event with the revert data.
 *
 * Intended use case is:
 * - 0x01000000000078210001: Executing a set of conditional trasactions.
 * If 1 transaction in a set fails, the entire set should fail. This can allow for retrying the transaction at a later
 * time since the nonce is not spent.
 *
 * - 0x01010000000078210001: Executing a set of individual transactions.
 * If 1 or more transactions in a set fails, the remaining transactions in the set should be executed.
 *
 * - 0x01000000000078210001 inside 0x01010000000078210001: Executing a large set of individual transactions containing
 * conditional transactions.
 * Each 0x01000000000078210001 batch can be retried in the future if it fails with each 0x01010000000078210001 only
 * being executable once. A batch executor can schedule a set of transaction to be executed. The entire set should be
 * executed individually (0x01010000000078210001) but each sub-batch or transaction needs to be executed conditionally
 * (0x01000000000078210001).
 *
 * Additionally, as an account it can be initialised with a call that anyone can make.
 *
 * The contract is intended to be used via 3 cloning strategies:
 * - Non-upgradeable minimal proxy clone for minimal cost.
 * - Upgradeable proxy to allow ownership handover.
 *
 * For ERC-1271 signatures verified from the owner, they should be rehashed in a replay protection envelope:
 * keccak256(
 *  keccak256(bytes("Replay(address account,bytes32 payload)")),
 *  address(account),
 *  payloadHash
 * )
 * This ensures that each signed payload is only valid for a specific account.
 */
contract Catapultar is ERC7821LIFI, EIP712, BitmapNonce, Ownable, Initializable, UUPSUpgradeable {
    error NotUpgradeable();

    /**
     * @dev Used to uniquely rehash ERC1271 signatures to identify them as originating from this account.
     */
    bytes32 constant REPLAY_PROTECTION = keccak256(bytes("Replay(address account,bytes32 payload)"));

    /**
     * @notice Only allows owner or this contract to call.
     */
    modifier onlyOwnerOrSelf() {
        assembly ("memory-safe") {
            // Check if sender is this contract.
            if iszero(eq(caller(), address())) {
                // If the caller is not the stored owner, revert.
                if iszero(eq(caller(), sload(_OWNER_SLOT))) {
                    mstore(0x00, 0x82b42900) // `Unauthorized()`.
                    revert(0x1c, 0x04)
                }
            }
        }
        _;
    }

    constructor() {
        _disableInitializers();
    }

    function _domainNameAndVersion() internal pure override returns (string memory name, string memory version) {
        name = "Catapultar";
        version = "0.0.1";
    }

    /**
     * @dev While the name and version won't change, when used in a proxy pattern, returning true leads to a shorter
     * path for the domain separator.
     */
    function _domainNameAndVersionMayChange() internal pure override returns (bool result) {
        return true;
    }

    function DOMAIN_SEPARATOR() external view returns (bytes32) {
        return _domainSeparator();
    }

    /**
     * @dev If ALLOW_EMBEDDED_CALLS is true and the contract is being cloned as an upgradeable contract, the function
     * will revert.
     */
    function init(
        address owner
    ) external initializer {
        _initializeOwner(owner);
    }

    /**
     * @notice ERC1271 for signing messages on behalf of this contract.
     * @dev This contract implements a simple replay protection where the hash is rehashed using the contract address to
     * ensure it cannot be replayed on other contracts.
     * When asked to sign a hash (of say a EIP-712 object), compute the hash regularly. Then compute
     * keccak256(abi.encode(REPLAY_PROTECTION, address(this), hash)) and sign the computed hash.
     * @param hash of data that has been signed and to check attestation for.
     * @param signature Bytes that represents the signature of the signed message.
     * @return result 0x1626ba7e if true or 0xffffffff is invalid.
     */
    function isValidSignature(
        bytes32 hash,
        bytes calldata signature
    ) public view virtual returns (bytes4 result) {
        bool success = SignatureCheckerLib.isValidSignatureNowCalldata(
            owner(),
            EfficientHashLib.hash(
                REPLAY_PROTECTION, // Offset hash to ensure no standard payload replicates this structure.
                asUnsafeBytes32(address(this)),
                hash
            ),
            signature
        );
        assembly ("memory-safe") {
            // `success ? bytes4(keccak256("isValidSignature(bytes32,bytes)")) : 0xffffffff`.
            // We use `0xffffffff` for invalid, in convention with the reference implementation.
            result := shl(224, or(0x1626ba7e, sub(0, iszero(success))))
        }
    }

    /**
     * @notice Invalidate nonces using a bitmask allowing for batch invalidation.
     * @dev Can only be called by contract owner or the contract itself. Using batch calls, the contract can call itself
     * to invalidate nonces. This allows owner-signed batch invalidation.
     * @param wordPos Lefmost 248 bits of the nonce.
     * @param mask Bitmask used to invalidate nonces associated with the rightmost 8 bits
     */
    function invalidateUnorderedNonces(
        uint256 wordPos,
        uint256 mask
    ) external onlyOwnerOrSelf {
        nonceBitmap[wordPos] |= mask;

        emit UnorderedNonceInvalidation(wordPos, mask);
    }

    // --- Proxy / Clone Helpers --- //

    /**
     * @notice Returns whether the contract has any storage set in the ERC1967 implementation slot.
     * @dev It is possible for a non-upgradeable contract to return false if the storage slot is overwritten to be 0.
     * Likewise, for an upgradeable contract that does not use the _ERC1967_IMPLEMENTATION_SLOT it may return true.
     * @return nUp Whether the ERC1967 implementation slot is not 0.
     */
    function _notUpgradeable() internal view returns (bool nUp) {
        bytes32 implementation;
        assembly ("memory-safe") {
            implementation := sload(_ERC1967_IMPLEMENTATION_SLOT)
            nUp := eq(implementation, 0)
        }
    }

    /**
     * @notice Returns whether the contract does not have any storage set in the ERC1967 implementation slot.
     * @dev It is possible for a non-upgradeable contract to return true if the storage slot is overwritten to be 0.
     * Likewise, for an upgradeable contract that does not use the _ERC1967_IMPLEMENTATION_SLOT it may return false.
     * @return up Whether the ERC1967 implementation slot is 0.
     */
    function upgradeable() external view returns (bool up) {
        return !_notUpgradeable();
    }

    /**
     * @notice Allow the owner to upgrade the contract.
     * @dev If the proxy used to clone the contract is not specifically LibClone.deployERC1967 then _authorizeUpgrade
     * will revert.
     */
    function _authorizeUpgrade(
        address
    ) internal view override onlyOwnerOrSelf {
        if (_notUpgradeable()) revert NotUpgradeable();
    }

    // --- Call Validation Logic --- //

    /**
     * @notice Validates opData
     * @param mode Execution mode for the transactions.
     * @param calls Batch of calls to be executed.
     * @param opData Data to validate that calls and mode have been correctly issued as well as containing the nonce.
     * Is expected to be encoded as abi.encodePacked(bytes32(nonce), signature);
     */
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
        // If there are only 32 bytes of opdata, there is no signature.
        // The simplest case is if we called ourself in a batch.
        if (opData.length == 32) if (address(this) == msg.sender) return true;

        bytes32 callTypeHash = LibCalls.typehash(nonce, mode, calls);
        bytes32 digest = _hashTypedData(callTypeHash);
        return SignatureCheckerLib.isValidSignatureNowCalldata(owner(), digest, opData[0x20:]);
    }

    /**
     * @notice Unsafe casing of address to bytes32
     * @dev Equivalent to bytes32(uint256(uint160(addr))) except the upper 12 bytes bytes are not cleaned.
     * @param addr Address to be cased into the rightmost 20 bytes of a bytes32.
     * @return b Bytes32 variable with the address in the rightmost 20 bytes.
     */
    function asUnsafeBytes32(
        address addr
    ) internal pure returns (bytes32 b) {
        assembly ("memory-safe") {
            b := addr
        }
    }

    /// @notice LibZip will handle fallbacks for gas efficiency savings on cheap execution but expensive calldata
    /// chains.
    fallback() external payable override receiverFallback {
        LibZip.cdFallback();
    }
}
