// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import {LibZip} from "solady/src/utils/LibZip.sol";
import {SignatureCheckerLib} from "solady/src/utils/SignatureCheckerLib.sol";
import {EfficientHashLib} from "solady/src/utils/EfficientHashLib.sol";
import {EIP712} from "solady/src/utils/EIP712.sol";

import {ERC7821LIFI} from "./ERC7821LIFI.sol";
import {BitmapNonce} from "./BitmapNonce.sol";

contract ExecutorLIFI is ERC7821LIFI, EIP712, BitmapNonce {
    using EfficientHashLib for uint256;
    using EfficientHashLib for bytes;
    using EfficientHashLib for bytes32;
    using EfficientHashLib for bytes32[];

    address public immutable OWNER;

    constructor(address owner) {
        OWNER = owner;
    }

    function _domainNameAndVersion() internal pure override returns (string memory name, string memory version) {
        name = "ExecutorLIFI";
        version = "1";
    }

    struct Calls {
        uint256 nonce;
        Call[] calls;
    }

    bytes32 constant CALLS_TYPE_HASH =
        keccak256(bytes("Calls(uint256 nonce,Call[] calls)Call(address to,uint256 value,bytes data)"));

    bytes32 constant CALL_TYPE_HASH = keccak256(bytes("Call(address to,uint256 value,bytes data)"));

    function typehash(uint256 nonce, Call[] calldata calls) internal pure returns (bytes32 messageHash) {
        uint256 numCalls = calls.length;
        bytes32[] memory buffer = numCalls.malloc();
        for (uint256 i; i < numCalls; ++i) {
            Call calldata call = calls[i];
            buffer[i] =
                CALL_TYPE_HASH.hash(bytes32(uint256(uint160(call.to))), bytes32(call.value), call.data.hashCalldata());
        }
        messageHash = CALLS_TYPE_HASH.hash(bytes32(nonce), buffer.hash());
        buffer.free();
    }

    function _validateOpData(Call[] calldata calls, bytes calldata opData) internal override returns (bool) {
        uint256 nonce;
        assembly ("memory-safe") {
            nonce := calldataload(opData.offset)
        }
        _useUnorderedNonce(nonce);
        bytes32 digest = _hashTypedData(typehash(nonce, calls));

        return SignatureCheckerLib.isValidSignatureNowCalldata(OWNER, digest, opData[0x20:]);
    }

    // Allow us to use LibZip for gas efficiency savings on cheap execution but expensive calldata chains.
    fallback() external payable override receiverFallback {
        LibZip.cdFallback();
    }
}
