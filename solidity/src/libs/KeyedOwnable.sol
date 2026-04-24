// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { DynamicArrayLib } from "solady/src/utils/DynamicArrayLib.sol";
import { EfficientHashLib } from "solady/src/utils/EfficientHashLib.sol";
import { FixedPointMathLib } from "solady/src/utils/FixedPointMathLib.sol";
import { LibBit } from "solady/src/utils/LibBit.sol";
import { LibBytes } from "solady/src/utils/LibBytes.sol";
import { P256 } from "solady/src/utils/P256.sol";
import { SignatureCheckerLib } from "solady/src/utils/SignatureCheckerLib.sol";
import { WebAuthn } from "solady/src/utils/WebAuthn.sol";

/**
 * @notice Complex single owner authorization mixin.
 * @author Alexander @ LIFI (https://li.fi)
 */
contract KeyedOwnable {
    using DynamicArrayLib for uint256[];

    error DirtyEthereumAddress(bytes32);
    error InvalidKey();
    error Unauthorized();

    event OwnershipTransferred(PublicKeyType newKey, bytes32[] newOwner);

    enum PublicKeyType {
        ECDSAOrSmartContract,
        P256,
        WebAuthnP256
    }

    /// @dev The owner slot is given by:
    /// `bytes32(~uint256(uint32(bytes4(keccak256("_OWNER_SLOT_NOT")))))`.
    /// The storage slot is intentionally chosen such that it overlaps with Solady's storage slot.
    /// If an upgradeable contract by misfortune upgrades to an Ownable and not KeyedOwnable contract, then if the key
    /// used is ECDSAOrSmartContract, there is a chance that the account is still in control of someone.
    bytes32 internal constant _OWNER_SLOT = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffff74873927;

    PublicKeyType public publicKeyType;

    /**
     * @notice Sets a slice of a key.
     * @dev This function does not implement bounds check based on publicKeyType.
     */
    function _setPublicKeySlice(
        uint256 index,
        bytes32 val
    ) private {
        assembly ("memory-safe") {
            // Subtract the index so we get away from the "small" space.
            sstore(sub(_OWNER_SLOT, index), val)
        }
    }

    /**
     * @notice Returns a slice of the owner's public key.
     * @dev This function does not implement bounds check based on publicKeyType. If a larger key has been set
     * previously, it will return a dirty word.
     */
    function _getPublicKeySlice(
        uint256 index
    ) internal view returns (bytes32 val) {
        assembly ("memory-safe") {
            // Subtract the index so we get away from the "small" space.
            val := sload(sub(_OWNER_SLOT, index))
        }
    }

    function getPublicKey() public view returns (PublicKeyType keyType, bytes32[] memory key) {
        keyType = publicKeyType;
        uint256 length = _keyTypeLength(keyType);
        uint256[] memory _key = DynamicArrayLib.malloc(length);
        for (uint256 i; i < length; ++i) {
            _key.set(i, _getPublicKeySlice(i));
        }
        key = _key.asBytes32Array();
    }

    /**
     * @notice Returns the number of words that a key should occupy.
     * Should return:
     * PublicKeyType.ECDSAOrSmartContract = 1
     * PublicKeyType.P256 = 2
     * PublicKeyType.WebAuthnP256 = 2
     */
    function _keyTypeLength(
        PublicKeyType keyType
    ) internal pure returns (uint256 len) {
        assembly ("memory-safe") {
            len := add(
                // 0: 1, 1: 2, 2: 2
                keyType,
                lt(keyType, 2) // 0: 1, 1: 1 otherwise 0
            )
        }
    }

    function owner() external view returns (address) {
        return _asAddressNotDirty(_getPublicKeySlice(0));
    }

    modifier onlyOwnerOrSelf() {
        assembly ("memory-safe") {
            if iszero(eq(caller(), address())) {
                // If the caller is not the stored owner, revert.
                // If _OWNER_SLOT has higher bits set (not PublicKeyType.ECDSAOrSmartContract) then this will never be
                // true.
                if iszero(eq(caller(), sload(_OWNER_SLOT))) {
                    mstore(0x00, 0x82b42900) // `Unauthorized()`.
                    revert(0x1c, 0x04)
                }
            }
        }
        _;
    }

    /**
     * @notice Returns whether a boolean for whether the caller is owner or address(this).
     */
    function ownerOrSelf() internal view returns (bool v) {
        assembly ("memory-safe") {
            v := eq(caller(), address())
            if iszero(v) {
                // If _OWNER_SLOT has higher bits set (not PublicKeyType.ECDSAOrSmartContract) then this will never be
                // true.
                v := eq(caller(), sload(_OWNER_SLOT))
            }
        }
    }

    function _isValidKey(
        PublicKeyType keyType,
        bytes32[] calldata key
    ) internal pure returns (bool valid) {
        uint256 expectedKeyLength = _keyTypeLength(keyType);
        address addr;
        assembly ("memory-safe") {
            valid := eq(expectedKeyLength, key.length)

            switch keyType
            case 0 {
                // Load the first element of key
                addr := calldataload(key.offset)
                valid := and(
                    valid,
                    and(
                        // Check the upper 12 bytes
                        eq(shr(mul(8, 20), addr), 0),
                        // Check the lower 20 bytes
                        iszero(eq(shl(mul(8, 12), addr), 0))
                    )
                )
            }
            case 1 {
                valid := and(
                    valid,
                    iszero(
                        or(
                            // Check if first word of key is 0
                            eq(calldataload(key.offset), 0),
                            // Check if second word of key is 0.
                            eq(calldataload(add(key.offset, 0x20)), 0)
                        )
                    )
                )
            }
            case 2 {
                valid := and(
                    valid,
                    iszero(
                        or(
                            // Check if first word of key is 0
                            eq(calldataload(key.offset), 0),
                            // Check if second word of key is 0.
                            eq(calldataload(add(key.offset, 0x20)), 0)
                        )
                    )
                )
            }
        }
    }

    /**
     * @notice Transfer ownership to someone else using a keytype and a key.
     * @param ktp Key type of the provided key.
     * @param nextKey Bytes of the provided key. Keys chunks are encoded based on the key type provided.
     */
    function _transferOwnership(
        PublicKeyType ktp,
        bytes32[] calldata nextKey
    ) internal {
        if (!_isValidKey(ktp, nextKey)) revert InvalidKey();

        uint256 nextKeyLength = nextKey.length;
        // Use max(prevLen, nextLen) so we write every slot that either key occupies,
        // clearing stale slots on downgrade without touching slots neither key uses.
        uint256 slotsToWrite = _keyTypeLength(publicKeyType);
        slotsToWrite = FixedPointMathLib.max(slotsToWrite, nextKeyLength);
        for (uint256 i; i < slotsToWrite; ++i) {
            _setPublicKeySlice(i, i < nextKeyLength ? nextKey[i] : bytes32(0));
        }
        publicKeyType = ktp;
        emit OwnershipTransferred(ktp, nextKey);
    }

    /**
     * @notice Transfer ownership to someone else using a keytype and a key.
     * @param ktp Key type of the provided key.
     * @param nextKey Bytes of the provided key. Keys chunks are encoded based on the key type provided.
     */
    function transferOwnership(
        PublicKeyType ktp,
        bytes32[] calldata nextKey
    ) public payable onlyOwnerOrSelf {
        _transferOwnership(ktp, nextKey);
    }

    /**
     * @notice Transfer ownership to a ECDSAOrSmartContract through the normal transferOwnership interface
     * @dev Can be used to resignate ownership by setting the new owner to 0. Be aware that if an ownership change has
     * been stored in the account, it can be used to bring back the owner again.
     */
    function transferOwnership(
        address newOwner
    ) public payable onlyOwnerOrSelf {
        // Use max(prevLen, 1) so we clear any extra slots from a prior P256/WebAuthn key.
        uint256 slotsToWrite = _keyTypeLength(publicKeyType);
        publicKeyType = PublicKeyType.ECDSAOrSmartContract;
        _setPublicKeySlice(0, bytes32(uint256(uint160(newOwner))));
        for (uint256 i = 1; i < slotsToWrite; ++i) {
            _setPublicKeySlice(i, bytes32(0));
        }

        bytes32[] memory nextKeys = new bytes32[](1);
        nextKeys[0] = bytes32(uint256(uint160(newOwner)));

        emit OwnershipTransferred(PublicKeyType.ECDSAOrSmartContract, nextKeys);
    }

    /**
     * @dev Based on ithacaxyz@account::unwrapAndValidateSignature
     * https://github.com/ithacaxyz/account/blob/7dd8a5d91c162b89316e367f0fb159f47abfeab0/src/IthacaAccount.sol#L491
     * Notice! P256 signatures are 64 bytes long. This contract has been optimised for ECDSA owners.
     * P256 signatures needs to append 2 bytes to their 64 bytes to get the signature to size 66. The last byte is a
     * flag for rehashing the digest with SHA256.
     * @param signature `abi.encodePacked(bytes(signature), bool(prehash))`.
     *   - length 0: no prehash byte; empty signature passed to key-type dispatch.
     *   - length 1: the single byte is the prehash indicator; empty signature passed downstream.
     */
    function _validateSignature(
        bytes32 digest,
        bytes calldata signature
    ) internal view returns (bool) {
        // If the signature's length is 64 or 65, treat the signature like a "Ethereum" signature.
        if (LibBit.or(signature.length == 64, signature.length == 65)) {
            address account = _asAddressNotDirty(_getPublicKeySlice(0));
            return SignatureCheckerLib.isValidSignatureNowCalldata(account, digest, signature);
        }

        // We need to load the signature and identify whether we need to do a sha prehash.
        // If a signature of length 0 is provided, we will process signature as is.
        // If a signature of length > 0 is provided, the last byte will be a signal byte for whether to sha256 hash the digest before signature validation.
        {
            bool digestPrehash;
            assembly ("memory-safe") {
                let n := signature.length

                // Subtract 1 from signature length if n > 0
                signature.length := sub(n, gt(n, 0))

                // Select the last byte of the signature, then check if it is not 0.
                // For n >= 32 this reads the last 32 bytes of the signature (in-bounds).
                // For 1 <= n < 32 the calldataload starts before signature.offset, but & 0xff
                // extracts the rightmost byte of the 32-byte word, which is exactly the byte at
                // (signature.offset + n - 1) — i.e., the true last byte of the signature.
                // The gt(n, 0) guard ensures digestPrehash is always 0 when n = 0.
                digestPrehash := and(iszero(iszero(and(calldataload(sub(add(signature.offset, n), 32)), 0xff))), gt(n, 0))
            }
            if (digestPrehash) {
                digest = EfficientHashLib.sha2(digest); // `sha256(abi.encode(digest))`.
            }
        }

        if (publicKeyType == PublicKeyType.P256) {
            // The try decode functions returns `(0,0)` if the bytes is too short,
            // which will make the signature check fail.
            (bytes32 r, bytes32 s) = P256.tryDecodePointCalldata(signature);
            bytes32 x = _getPublicKeySlice(0);
            bytes32 y = _getPublicKeySlice(1);
            return P256.verifySignature(digest, r, s, x, y);
        }
        if (publicKeyType == PublicKeyType.WebAuthnP256) {
            bytes32 x = _getPublicKeySlice(0);
            bytes32 y = _getPublicKeySlice(1);
            return WebAuthn.verify(
                abi.encode(digest), // Challenge.
                false, // Require user verification optional.
                // This is simply `abi.decode(signature, (WebAuthn.WebAuthnAuth))`.
                WebAuthn.tryDecodeAuth(signature), // Auth.
                x,
                y
            );
        }
        if (publicKeyType == PublicKeyType.ECDSAOrSmartContract) {
            address account = _asAddressNotDirty(_getPublicKeySlice(0));
            return SignatureCheckerLib.isValidSignatureNowCalldata(account, digest, signature);
        }
        return false;
    }

    /**
     * @notice Validates that the most significant bytes are 0.
     * @param elem Bytes32 variable to validate against upper 12 bytes.
     * @return addr 20 Least significant bytes of elem.
     */
    function _asAddressNotDirty(
        bytes32 elem
    ) internal pure returns (address addr) {
        bool dirty;
        assembly ("memory-safe") {
            // Shift away 20 bytes of the address.
            // Check if not 0.
            dirty := iszero(eq(shr(mul(8, 20), elem), 0))
            addr := elem
        }
        if (dirty) revert DirtyEthereumAddress(elem);
    }
}
