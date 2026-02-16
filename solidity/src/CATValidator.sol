// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { DynamicArrayLib } from "solady/src/utils/DynamicArrayLib.sol";
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
 * This contract should never hold assets:
 * - Allowances are collected from the signer and delivered to an executor specified destination.
 * - Outcomes are expected to be delivered directly to the destination specified in the outcome. Initial balances are
 * recorded before allowance transfers and after the external call.
 *
 * This contract uses a call proxy for arbitrary call execution. This makes it safe to set approvals to the contract.
 * This contract does not have a fixed callback function. The call proxy address is ::CALL_PROXY().
 *
 * Each approval can only be accessed once, invalidating other approvals by nonce. Except nonce 0 which can be used for
 * long lived approvals like DCAs.
 */
contract CATValidator is EIP712, ReentrancyGuard {
    using DynamicArrayLib for uint256[];
    error InvalidTokenAmount(uint256 expected, uint256 received);
    error AllocationTooSmall(uint256 allocated, uint256 spend);
    error NonceAlreadySpent();
    error BadSignature();

    address public immutable CALL_PROXY;
    uint256 constant SPEND_BALANCE_OF_MAGIC = 1 << 255;

    mapping(address => mapping(uint256 => bool)) public spentNonces;

    constructor() {
        CALL_PROXY = address(new CallProxy());
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
     * @dev This function can only be called by the designated executor. The caller check is made by embedding
     * msg.sender as the executor in the typehash. This contract does not support _any_ executor and one has to be
     * provided.
     * If a destination is address(0), it specifies the signer. If a spend is 0 the current balance of the signer will
     * be used.
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

        uint256[] memory recordedBalances = _recordBalances(account, outcomes);

        _handleAllowances(execTarget, account, allowances);

        if (execPayload.length != 0) _call(execTarget, execPayload);

        _compareOutcomes(account, outcomes, recordedBalances);
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

    /**
     * @notice Wraps balanceOf call for ERC20 tokens and natives.
     * @param account Fallback address for to read if outcome.destination is 0.
     * @param outcome Description of the balance read: target and token. 0 token is native.
     */
    function _balanceOf(
        address account,
        Outcome calldata outcome
    ) internal view returns (uint256 bal) {
        address destination = outcome.destination == address(0) ? account : outcome.destination;
        bal = outcome.token == address(0) ? destination.balance : SafeTransferLib.balanceOf(outcome.token, destination);
    }

    /**
     * @notice Record balances.
     * @param account Fallback address if outcomes[].destination is 0.
     * @param outcomes Description of balances to read: target and token.
     * @return balances List of current balances of outcomes.
     */
    function _recordBalances(
        address account,
        Outcome[] calldata outcomes
    ) internal view returns (uint256[] memory balances) {
        balances = DynamicArrayLib.malloc(outcomes.length);
        for (uint256 i; i < outcomes.length; ++i) {
            Outcome calldata outcome = outcomes[i];
            balances.set(i, _balanceOf(account, outcome));
        }
    }

    /**
     * @notice Compare current balances to recorded balances.
     * @param account Fallback address if outcomes[].destination is 0.
     * @param outcomes Description of balances to compare: target, token, and difference.
     * @param recordedBalances List of previously recorded balances.
     */
    function _compareOutcomes(
        address account,
        Outcome[] calldata outcomes,
        uint256[] memory recordedBalances
    ) internal view {
        for (uint256 i; i < outcomes.length; ++i) {
            Outcome calldata outcome = outcomes[i];
            uint256 newBalance = _balanceOf(account, outcome);
            unchecked {
                // recordedBalances[i] + outcome.amount overflows, then an invalid balance has been requested (balance
                // excedding type(uint256).max).
                if (newBalance < recordedBalances[i] + outcome.amount) {
                    uint256 diff = newBalance > recordedBalances[i] ? newBalance - recordedBalances[i] : 0;
                    revert InvalidTokenAmount(outcome.amount, diff);
                }
            }
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

            uint256 spend = allowance.spend == SPEND_BALANCE_OF_MAGIC
                ? SafeTransferLib.balanceOf(allowance.token, source)
                : allowance.spend;
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
