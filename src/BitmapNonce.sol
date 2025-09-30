// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// @author Uniswap (Permit2)
contract BitmapNonce {
    error InvalidNonce();

    event UnorderedNonceInvalidation(uint256 word, uint256 mask);

    mapping(uint256 => uint256) public nonceBitmap;

    function invalidateUnorderedNonces(uint256 wordPos, uint256 mask) external {
        nonceBitmap[wordPos] |= mask;

        emit UnorderedNonceInvalidation(wordPos, mask);
    }

    /// @notice Returns the index of the bitmap and the bit position within the bitmap. Used for unordered nonces
    /// @param nonce The nonce to get the associated word and bit positions
    /// @return wordPos The word position or index into the nonceBitmap
    /// @return bitPos The bit position
    /// @dev The first 248 bits of the nonce value is the index of the desired bitmap
    /// @dev The last 8 bits of the nonce value is the position of the bit in the bitmap
    function bitmapPositions(
        uint256 nonce
    ) private pure returns (uint256 wordPos, uint256 bitPos) {
        wordPos = uint248(nonce >> 8);
        bitPos = uint8(nonce);
    }

    /// @notice Checks whether a nonce is taken and sets the bit at the bit position in the bitmap at the word position
    /// @param nonce The nonce to spend
    function _useUnorderedNonce(
        uint256 nonce
    ) internal {
        (uint256 wordPos, uint256 bitPos) = bitmapPositions(nonce);
        uint256 bit = 1 << bitPos;
        uint256 flipped = nonceBitmap[wordPos] ^= bit;

        if (flipped & bit == 0) revert InvalidNonce();
    }
}
