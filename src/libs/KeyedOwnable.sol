// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

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
    error KeyTooLong();
    error DirtyEthereumAddress(bytes32);
    error InvalidKey();

    /// @dev The caller is not authorized to call the function.
    error Unauthorized();

    event OwnershipTransferred(KeyType newKey, bytes32[] newOwner);

    enum KeyType {
        ECDSAThenSmartContract,
        P256,
        WebAuthnP256
    }

    /**
     * @dev The largest key currently used is 64=2*32 bytes and is P256 signatures.
     */
    uint256 public constant MAX_KEY_LENGTH = 2;

    /**
     * @dev Number of used words of the owner's key.
     */
    uint48 internal _keyLength;
    KeyType public keyType;
    /**
     * @dev Contains indexable slices for the owner.
     */
    bytes32[MAX_KEY_LENGTH] private _ownerKey;

    /**
     * @notice Returns a slice of the owner's key.
     */
    function ownerKey(
        uint256 index
    ) internal view returns (bytes32) {
        return _ownerKey[index];
    }

    modifier onlyOwnerOrSelf() {
        // if iszero(eq(caller(), address())) {
        //         // If the caller is not the stored owner, revert.
        //         if iszero(eq(caller(), sload(_OWNER_SLOT))) {
        //             mstore(0x00, 0x82b42900) // `Unauthorized()`.
        //             revert(0x1c, 0x04)
        //         }
        //     }
        // Check if self.
        if (msg.sender != address(this)) {
            address owner = _asAddressNotDirty(ownerKey(0));
            if (owner != msg.sender) revert Unauthorized();
        }
        _;
    }

    function owner() external view returns (address) {
        return _asAddressNotDirty(ownerKey(0));
    }

    function _setOwnership(KeyType ktp, bytes32[] calldata nextKey) internal {
        for (uint256 i; i < nextKey.length; ++i) {
            _ownerKey[i] = nextKey[i];
        }
        keyType = ktp;
        _keyLength = uint48(nextKey.length == 1 ? 0 : nextKey.length);
        emit OwnershipTransferred(ktp, nextKey);
    }

    function _transferOwnership(KeyType ktp, bytes32[] calldata nextKey) internal {
        uint256 nextKeyLength = nextKey.length;
        if (ktp == KeyType.ECDSAThenSmartContract) {
            if (nextKeyLength != 1) revert InvalidKey();
            if (_asAddressNotDirty(nextKey[0]) == address(0)) revert InvalidKey();
        } else if (ktp == KeyType.P256 || ktp == KeyType.WebAuthnP256) {
            if (nextKeyLength != 2) revert InvalidKey();
            if (nextKey[0] == bytes32(0)) revert InvalidKey();
            if (nextKey[1] == bytes32(0)) revert InvalidKey();
        } else {
            revert InvalidKey();
        }
        if (nextKey.length > MAX_KEY_LENGTH * 32) revert KeyTooLong();
        uint256 wordsToSet = FixedPointMathLib.max(nextKeyLength, _keyLength);
        for (uint256 i; i < wordsToSet; ++i) {
            _ownerKey[i] = nextKeyLength > i ? nextKey[i] : bytes32(0);
        }
        keyType = ktp;
        _keyLength = uint48(nextKeyLength);
        emit OwnershipTransferred(ktp, nextKey);
    }

    function transferOwnership(
        address newOwner
    ) public payable onlyOwnerOrSelf {
        // We set the keytype as smart contract, because a Secp256k1
        keyType = KeyType.ECDSAThenSmartContract;
        uint256 wordsToSet = _keyLength;
        for (uint256 i = 1; i < wordsToSet; ++i) {
            _ownerKey[i] = bytes32(0);
        }
        _ownerKey[0] = bytes32(uint256(uint160(newOwner)));

        bytes32[] memory nextKeys = new bytes32[](1);
        nextKeys[0] = bytes32(uint256(uint160(newOwner)));
        emit OwnershipTransferred(KeyType.ECDSAThenSmartContract, nextKeys);
    }

    ///
    /// @dev Based on ithacaxyz@account::unwrapAndValidateSignature
    /// https://github.com/ithacaxyz/account/blob/7dd8a5d91c162b89316e367f0fb159f47abfeab0/src/IthacaAccount.sol#L491
    /// @param signature `abi.encodePacked(bytes(signature), bool(prehash))`.
    function _validateSignature(bytes32 digest, bytes calldata signature) internal view returns (bool) {
        // If the signature's length is 64 or 65, treat the signature like a "Ethereum" signature.
        if (LibBit.or(signature.length == 64, signature.length == 65)) {
            address owner = _asAddressNotDirty(ownerKey(0));
            return SignatureCheckerLib.isValidSignatureNowCalldata(owner, digest, signature);
        }

        unchecked {
            uint256 n = signature.length - 1;
            signature = LibBytes.truncatedCalldata(signature, n);
            // Do the prehash if last byte is non-zero.
            if (uint256(LibBytes.loadCalldata(signature, n + 1)) & 0xff != 0) digest = EfficientHashLib.sha2(digest); // `sha256(abi.encode(digest))`.
        }

        if (keyType == KeyType.P256) {
            // The try decode functions returns `(0,0)` if the bytes is too short,
            // which will make the signature check fail.
            (bytes32 r, bytes32 s) = P256.tryDecodePointCalldata(signature);
            bytes32 x = ownerKey(0);
            bytes32 y = ownerKey(1);
            return P256.verifySignature(digest, r, s, x, y);
        } else if (keyType == KeyType.WebAuthnP256) {
            bytes32 x = ownerKey(0);
            bytes32 y = ownerKey(1);
            return WebAuthn.verify(
                abi.encode(digest), // Challenge.
                false, // Require user verification optional.
                // This is simply `abi.decode(signature, (WebAuthn.WebAuthnAuth))`.
                WebAuthn.tryDecodeAuth(signature), // Auth.
                x,
                y
            );
        } else if (keyType == KeyType.ECDSAThenSmartContract) {
            address owner = _asAddressNotDirty(ownerKey(0));

            // TODO: Call isValidSignature
        }
        return false;
    }

    function _asAddressNotDirty(
        bytes32 elem
    ) internal pure returns (address addr) {
        bool dirty;
        assembly ("memory-safe") {
            // Shift away 20 bytes of the addres.
            // Check if not 0.
            dirty := iszero(eq(shr(mul(8, 20), addr), 0))
            addr := elem
        }
        if (dirty) revert DirtyEthereumAddress(elem);
    }
}
