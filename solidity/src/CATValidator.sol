// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { EIP712 } from "solady/src/utils/EIP712.sol";
import { ReentrancyGuard } from "solady/src/utils/ReentrancyGuard.sol";
import { SafeTransferLib } from "solady/src/utils/SafeTransferLib.sol";
import { SignatureCheckerLib } from "solady/src/utils/SignatureCheckerLib.sol";

import { CallProxy } from "./CallProxy.sol";
import { AllowanceSpend, LibExecutionConstraint, Outcome } from "./libs/LibExecutionConstraint.sol";

/**
 * @title Constrained Asset Transaction Validator – C.A.T Validator
 * @author Alexander @ LIFI (https://li.fi)
 * @custom:version 0.1.0
 * @notice Validation of a pre-approved asset allowance to execute a transaction that should result in a specific asset
 * outcome.
 * The intended usecase is in combination with Catapultar with an embedded action. A Catapultar account with an batch
 * transaction of setSignature and approve, allows the configured executor to find calldata to complete the provided
 * description: allowances for outcomes.
 *
 * This contract transiently holds outcome assets during settlement:
 * - Allowances are collected from the signer and delivered to the executor.
 * - The executor must deliver outcome tokens to this contract during execution.
 * - After execution, this contract verifies its own token balance meets each outcome amount,
 *   then forwards the full balance to each outcome's destination.
 * - Fee on transfer tokens will arrive with the amount minus the fee.
 *
 * This contract uses a call proxy for arbitrary call execution. This makes it safe to set approvals to the contract.
 * This contract does not have a fixed callback function. The call proxy address is ::CALL_PROXY().
 *
 * Each approval can only be accessed once, invalidating other approvals by nonce. Except nonce 0 which can be used for
 * long lived approvals like DCAs.
 */
contract CATValidator is EIP712, ReentrancyGuard {
    error InvalidTokenAmount(uint256 expected, uint256 received);
    error AllocationTooSmall(uint256 allocated, uint256 spend);
    error NonceAlreadySpent();
    error BadSignature();
    error BalanceOfFailed(address token);

    address public immutable CALL_PROXY;
    uint256 constant SPEND_BALANCE_OF_MAGIC = 1 << 255;

    mapping(address => mapping(uint256 => bool)) public spentNonces;

    constructor() {
        CALL_PROXY = address(new CallProxy());
    }

    receive() external payable { }

    function _domainNameAndVersion() internal pure override returns (string memory name, string memory version) {
        name = "CAT Validator";
        version = "1";
    }

    function DOMAIN_SEPARATOR() external view returns (bytes32) {
        return _domainSeparator();
    }

    /**
     * @notice Execute a transaction for an account given a signed execution constraint.
     * @dev This function can only be called by the designated executor. The caller check is made by embedding
     * msg.sender as the executor in the typehash. This contract does not support _any_ executor and one has to be
     * provided.
     * If a destination is address(0), it specifies the signer. If a spend is 1 << 255 (SPEND_BALANCE_OF_MAGIC), the
     * current balance of the signer will be used.
     */
    function entry(
        address execTarget,
        bytes calldata execPayload,
        address account,
        uint256 nonce,
        AllowanceSpend[] calldata allowances,
        Outcome[] calldata outcomes,
        bytes calldata signature
    ) external nonReentrant {
        if (nonce != 0) _checkNonce(account, nonce);

        _validateApproval(account, nonce, allowances, outcomes, signature);

        _handleAllowances(execTarget, account, allowances);

        if (execPayload.length != 0) _call(execTarget, execPayload);

        _validatePayment(account, outcomes);
    }

    /**
     * @notice Validate a nonce has not been spent before and then set it as spent.
     * @dev Ensures a signed transaction cannot be used twice.
     * @param account Owner of the nonce to be spend. Nonce will be spent for this address.
     * @param nonce Nonce to validate and spend.
     */
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
     * @param account Signer of the approval.
     * @param nonce Constraint nonce.
     * @param allowances Tokens to be collected for the transaction.
     * @param outcomes Description of deliveries.
     */
    function _validateApproval(
        address account,
        uint256 nonce,
        AllowanceSpend[] calldata allowances,
        Outcome[] calldata outcomes,
        bytes calldata signature
    ) internal view {
        bytes32 typehash = LibExecutionConstraint.typehash(allowances, outcomes, msg.sender, nonce);
        bytes32 digest = _hashTypedData(typehash);

        if (!SignatureCheckerLib.isValidSignatureNowCalldata(account, digest, signature)) revert BadSignature();
    }

    /// @dev Calls token.balanceOf(account). Reverts with BalanceOfFailed if the call
    /// fails or returns fewer than 32 bytes, instead of silently returning zero.
    function _safeBalanceOf(
        address token,
        address account
    ) private view returns (uint256 bal) {
        bool implemented;
        (implemented, bal) = SafeTransferLib.checkBalanceOf(token, account);
        if (!implemented) revert BalanceOfFailed(token);
    }

    /**
     * @notice Returns the balance of `token` held by `target`.
     * @param token ERC20 token address. address(0) returns the native ETH balance of `target`.
     * @param target Account to query.
     */
    function _balanceOf(
        address token,
        address target
    ) internal view returns (uint256 bal) {
        bal = token == address(0) ? target.balance : _safeBalanceOf(token, target);
    }

    /**
     * @notice Transfer `amount` of `token` to `dest`.
     * @dev Handles both ERC-20 and native ETH (token == address(0)).
     * @param token ERC-20 token address, or address(0) for native ETH.
     * @param amount Amount to transfer.
     * @param dest Recipient address.
     */
    function _transfer(
        address token,
        uint256 amount,
        address dest
    ) internal {
        token == address(0)
            ? SafeTransferLib.safeTransferETH(dest, amount)
            : SafeTransferLib.safeTransfer(token, dest, amount);
    }

    /**
     * @notice Verify this contract holds enough of each outcome token, then forward to destinations.
     * @dev The executor is expected to have transferred outcome tokens to address(this) during execution.
     *      The full held balance is forwarded, so any surplus beyond outcome.amount also goes to the destination.
     * @param signer Token recipient if outcome.destination is 0.
     * @param outcomes Tokens and minimum amounts that must be present at address(this).
     */
    function _validatePayment(
        address signer,
        Outcome[] calldata outcomes
    ) internal {
        for (uint256 i; i < outcomes.length; ++i) {
            Outcome calldata outcome = outcomes[i];
            uint256 recordedPayment = _balanceOf(outcome.token, address(this));
            if (recordedPayment < outcome.amount) revert InvalidTokenAmount(outcome.amount, recordedPayment);

            _transfer(outcome.token, recordedPayment, outcome.destination == address(0) ? signer : outcome.destination);
        }
    }

    /**
     * @notice Move spend portions of provided allowances to destination.
     * @param destination Address to receive the tokens.
     * @param source Contract to collect allowances from.
     * @param allowances Signed token allowances & spends.
     */
    function _handleAllowances(
        address destination,
        address source,
        AllowanceSpend[] calldata allowances
    ) internal {
        for (uint256 i = 0; i < allowances.length; ++i) {
            AllowanceSpend calldata allowance = allowances[i];

            uint256 spend =
                allowance.spend == SPEND_BALANCE_OF_MAGIC ? _safeBalanceOf(allowance.token, source) : allowance.spend;
            if (allowance.allocated < spend) revert AllocationTooSmall(allowance.allocated, spend);

            SafeTransferLib.safeTransferFrom(allowance.token, source, destination, spend);
        }
    }

    /**
     * @notice Arbitrary external call using the call proxy.
     * @dev Allows executing any payload on the target. Encodes the external call into:
     * bytes32(execTarget) || bytes(execPayload).
     */
    function _call(
        address execTarget,
        bytes calldata execPayload
    ) internal {
        address callProxy = CALL_PROXY;
        assembly ("memory-safe") {
            // get the free memory pointer.
            let m := mload(0x40)

            // Construct the external calldata.
            // calldata = abi.encodePacked(bytes32(execTarget), execPayload);
            // Place the execution target at m.
            mstore(m, execTarget)
            // Then place calldata at m + 32.
            calldatacopy(add(m, 32), execPayload.offset, execPayload.length)

            let success :=
                call(
                    gas(),
                    callProxy,
                    selfbalance(),
                    m,
                    add(execPayload.length, 32),
                    codesize(),
                    0x00 // Don't copy returndata. IFF failure, we will manually copy into revert.
                )

            if iszero(success) {
                returndatacopy(0x00, 0x00, returndatasize())
                revert(0x00, returndatasize())
            }
        }
    }
}
