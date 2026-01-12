// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { EIP712 } from "solady/src/utils/EIP712.sol";
import { SafeTransferLib } from "solady/src/utils/SafeTransferLib.sol";
import { SignatureCheckerLib } from "solady/src/utils/SignatureCheckerLib.sol";

import { CallProxy } from "./CallProxy.sol";
import { InputTarget, LibExecutionConstraint, Output } from "./libs/LibExecutionConstraint.sol";

/**
 * @title Constrained Asset Transaction Validator – C.A.T Validator
 * @author Alexander @ LIFI (https://li.fi)
 * @custom:version 0.1.0
 * @notice Validation of a pre-approved asset allowance
 */
contract CATValidator is EIP712 {
    error InvalidTokenAmount(uint256 expected, uint256 recevied);
    error AllocationTooSmall(uint256 allocated, uint256 spend);
    error NonceAlreadySpent();
    error BadSignature();

    CallProxy public callProxy;

    mapping(address => mapping(uint256 => bool)) public spentNonces;

    constructor() {
        callProxy = new CallProxy();
    }

    function _domainNameAndVersion() internal pure override returns (string memory name, string memory version) {
        name = "CAT Validator";
        version = "1";
    }

    function DOMAIN_SEPARATOR() external view returns (bytes32) {
        return _domainSeparator();
    }

    /**
     * @notice Execute a transaction for an account given a signed execution constraint.
     *
     */
    function entry(
        address executor,
        bytes calldata exec,
        address account,
        uint256 nonce,
        InputTarget[] calldata inputs,
        Output[] calldata deliveries,
        bytes calldata signature
    ) external {
        if (nonce != 0) _checkNonce(account, nonce);

        _validateApproval(account, nonce, inputs, deliveries, signature);

        _handleInputs(executor, account, inputs);

        _call(executor, exec);

        _handleOutputs(account, deliveries);
    }

    function _checkNonce(
        address account,
        uint256 nonce
    ) internal {
        bool spent = spentNonces[account][nonce];
        if (spent) revert NonceAlreadySpent();
        spentNonces[account][nonce] = !spent;
    }

    /**
     * @dev Validate an approval. Requires that the caller is the executor associated with the constraint.
     */
    function _validateApproval(
        address account,
        uint256 nonce,
        InputTarget[] calldata inputs,
        Output[] calldata outputs,
        bytes calldata signature
    ) internal view {
        bytes32 typehash = LibExecutionConstraint.typehash(inputs, outputs, msg.sender, nonce);
        bytes32 digest = _hashTypedData(typehash);

        if (!SignatureCheckerLib.isValidSignatureNowCalldata(account, digest, signature)) revert BadSignature();
    }

    function _handleInputs(
        address destination,
        address source,
        InputTarget[] calldata inputs
    ) internal {
        for (uint256 i = 0; i < inputs.length; ++i) {
            InputTarget calldata input = inputs[i];

            uint256 spend = input.spend == 0 ? SafeTransferLib.balanceOf(input.token, source) : input.spend;
            if (input.allocated != 0 && input.allocated < spend) revert AllocationTooSmall(input.allocated, spend);

            SafeTransferLib.safeTransferFrom(input.token, source, destination, spend);
        }
    }

    /**
     * @notice Makes an arbitrary external call through the call proxy.
     */
    function _call(
        address target,
        bytes calldata payload
    ) internal {
        assembly ("memory-safe") {
            // get the free memory pointer.
            let m := mload(0x40)

            // Copy call into memory
            mstore(m, target)
            calldatacopy(add(m, 32), payload.offset, payload.length)

            let success :=
                call(gas(), sload(callProxy.slot), selfbalance(), m, add(payload.length, 32), codesize(), 0x00)

            if iszero(success) {
                returndatacopy(0x00, 0x00, returndatasize())
                if iszero(success) { revert(0x00, returndatasize()) }
            }
        }
    }

    function _handleOutputs(
        address account,
        Output[] calldata outputs
    ) internal {
        for (uint256 i; i < outputs.length; ++i) {
            Output calldata output = outputs[i];
            if (output.token == address(0)) {
                uint256 ethBalance = address(this).balance;
                if (output.amount < ethBalance) revert InvalidTokenAmount(output.amount, ethBalance);

                SafeTransferLib.safeTransferETH(
                    output.destination == address(0) ? account : output.destination, ethBalance
                );
                continue; // Makes it cheaper for the ERC20 token path.
            }

            uint256 tokenBalance = SafeTransferLib.balanceOf(output.token, address(this));
            if (output.amount < tokenBalance) revert InvalidTokenAmount(output.amount, tokenBalance);

            SafeTransferLib.safeTransfer(
                output.token, output.destination == address(0) ? account : output.destination, tokenBalance
            );
        }
    }
}
