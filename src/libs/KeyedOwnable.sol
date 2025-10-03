// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { EfficientHashLib } from "solady/src/utils/EfficientHashLib.sol";
import { FixedPointMathLib } from "solady/src/utils/FixedPointMathLib.sol";
import { LibBit } from "solady/src/utils/LibBit.sol";
import { LibBytes } from "solady/src/utils/LibBytes.sol";
import { P256 } from "solady/src/utils/P256.sol";
import { SignatureCheckerLib } from "solady/src/utils/SignatureCheckerLib.sol";
import { WebAuthn } from "solady/src/utils/WebAuthn.sol";

import { console } from "forge-std/console.sol";

/**
 * @notice Complex single owner authorization mixin.
 * @author Alexander @ LIFI (https://li.fi)
 */
contract KeyedOwnable {
    error DirtyEthereumAddress(bytes32);
    error InvalidKey();

    event OwnershipTransferred(KeyType newKey, bytes32[] newOwner);

    enum KeyType {
        ECDSAOrSmartContract,
        P256,
        WebAuthnP256
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                          STORAGE                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The owner slot is given by:
    /// `bytes32(~uint256(uint32(bytes4(keccak256("_OWNER_SLOT_NOT")))))`.
    /// The storage slot is intentionally choosen such that it overlaps with Solady's storage slot.
    /// If an upgradeable contract by misfortune upgrades to an Ownable and not KeyedOwnable contract, then if the key
    /// used is ECDSAOrSmartContract, there is a chance that the account is still in control of someone.
    bytes32 internal constant _OWNER_SLOT = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffff74873927;

    KeyType public ownerKeyType;

    function _setOwnerKeySlice(uint256 index, bytes32 val) private {
        assembly ("memory-safe") {
            sstore(sub(_OWNER_SLOT, index), val)
        }
    }

    /**
     * @notice Returns a slice of the owner's key.
     * @dev This function does not implement bounds check based on ownerKeyType. If a larger key has been set
     * previously, it will return a dirty word.
     */
    function _getOwnerKeySlice(
        uint256 index
    ) internal view returns (bytes32 val) {
        assembly ("memory-safe") {
            val := sload(sub(_OWNER_SLOT, index))
        }
    }

    function getOwnerKey() public view returns (KeyType keyType, bytes32[] memory key) {
        keyType = ownerKeyType;
        uint256 length = _keyTypeLength(keyType);
        key = new bytes32[](length);
        for (uint256 i; i < length; ++i) {
            key[i] = _getOwnerKeySlice(i);
        }
    }

    /**
     * @notice Returns the number of words that a key should occopy.
     * Should return:
     * KeyType.ECDSAOrSmartContract = 1
     * KeyType.P256 = 2
     * KeyType.WebAuthnP256 = 2
     */
    function _keyTypeLength(
        KeyType keyType
    ) internal pure returns (uint256 len) {
        assembly ("memory-safe") {
            len :=
                add( // 0: 1, 1: 2, 2: 2
                    keyType,
                    add( // 0: 1, 1: 1, 2: 0
                        eq(keyType, 1), // 1: 1 otherwise 0
                        eq(keyType, 0) // 0: 1 otherwise 0
                    )
                )
        }
    }

    function owner() external view returns (address) {
        return _asAddressNotDirty(_getOwnerKeySlice(0));
    }

    modifier onlyOwnerOrSelf() {
        assembly ("memory-safe") {
            if iszero(eq(caller(), address())) {
                // If the caller is not the stored owner, revert.
                // If _OWNER_SLOT has higher bits set (not KeyType.ECDSAOrSmartContract) then this will never be true.
                if iszero(eq(caller(), sload(_OWNER_SLOT))) {
                    mstore(0x00, 0x82b42900) // `Unauthorized()`.
                    revert(0x1c, 0x04)
                }
            }
        }
        _;
    }

    function _isValidKey(KeyType keyType, bytes32[] calldata key) internal pure returns (bool valid) {
        uint256 expectedKeyLength = _keyTypeLength(keyType);
        address addr;
        assembly ("memory-safe") {
            valid := eq(expectedKeyLength, key.length)

            switch keyType
            case 0 {
                // Load the first element of key
                addr := calldataload(key.offset)
                valid :=
                    and(
                        valid,
                        and(
                            // Check the upper 12 bytes
                            eq(shr(mul(8, 20), addr), 0),
                            // Check the lower 20 bytes
                            not(eq(shl(mul(8, 12), addr), 0))
                        )
                    )
            }
            case 1 {
                valid :=
                    and(
                        valid,
                        not(
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
                valid :=
                    and(
                        valid,
                        not(
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

    function _transferOwnership(KeyType ktp, bytes32[] calldata nextKey) internal {
        if (!_isValidKey(ktp, nextKey)) revert InvalidKey();

        uint256 nextKeyLength = nextKey.length;
        for (uint256 i; i < nextKeyLength; ++i) {
            _setOwnerKeySlice(i, nextKey[i]);
        }
        ownerKeyType = ktp;
        emit OwnershipTransferred(ktp, nextKey);
    }

    /**
     * @notice Transfer ownership to a ECDSAOrSmartContract through standardized interfaces.
     */
    function transferOwnership(
        address newOwner
    ) public payable onlyOwnerOrSelf {
        // We set the keytype as smart contract
        ownerKeyType = KeyType.ECDSAOrSmartContract;
        _setOwnerKeySlice(0, bytes32(uint256(uint160(newOwner))));

        bytes32[] memory nextKeys = new bytes32[](1);
        nextKeys[0] = bytes32(uint256(uint160(newOwner)));

        emit OwnershipTransferred(KeyType.ECDSAOrSmartContract, nextKeys);
    }

    ///
    /// @dev Based on ithacaxyz@account::unwrapAndValidateSignature
    /// https://github.com/ithacaxyz/account/blob/7dd8a5d91c162b89316e367f0fb159f47abfeab0/src/IthacaAccount.sol#L491
    /// @param signature `abi.encodePacked(bytes(signature), bool(prehash))`.
    function _validateSignature(bytes32 digest, bytes calldata signature) internal view returns (bool) {
        // If the signature's length is 64 or 65, treat the signature like a "Ethereum" signature.
        if (LibBit.or(signature.length == 64, signature.length == 65)) {
            address account = _asAddressNotDirty(_getOwnerKeySlice(0));
            return SignatureCheckerLib.isValidSignatureNowCalldata(account, digest, signature);
        }

        unchecked {
            uint256 n = signature.length - 1;
            signature = LibBytes.truncatedCalldata(signature, n);
            // Do the prehash if last byte is non-zero.
            if (uint256(LibBytes.loadCalldata(signature, n + 1)) & 0xff != 0) digest = EfficientHashLib.sha2(digest); // `sha256(abi.encode(digest))`.
        }

        if (ownerKeyType == KeyType.P256) {
            // The try decode functions returns `(0,0)` if the bytes is too short,
            // which will make the signature check fail.
            (bytes32 r, bytes32 s) = P256.tryDecodePointCalldata(signature);
            bytes32 x = _getOwnerKeySlice(0);
            bytes32 y = _getOwnerKeySlice(1);
            return P256.verifySignature(digest, r, s, x, y);
        } else if (ownerKeyType == KeyType.WebAuthnP256) {
            bytes32 x = _getOwnerKeySlice(0);
            bytes32 y = _getOwnerKeySlice(1);
            return WebAuthn.verify(
                abi.encode(digest), // Challenge.
                false, // Require user verification optional.
                // This is simply `abi.decode(signature, (WebAuthn.WebAuthnAuth))`.
                WebAuthn.tryDecodeAuth(signature), // Auth.
                x,
                y
            );
        } else if (ownerKeyType == KeyType.ECDSAOrSmartContract) {
            address account = _asAddressNotDirty(_getOwnerKeySlice(0));

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
