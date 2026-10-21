// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { DynamicArrayLib } from "solady/src/utils/DynamicArrayLib.sol";
import { EIP712 } from "solady/src/utils/EIP712.sol";
import { ReentrancyGuard } from "solady/src/utils/ReentrancyGuard.sol";
import { SafeTransferLib } from "solady/src/utils/SafeTransferLib.sol";
import { SignatureCheckerLib } from "solady/src/utils/SignatureCheckerLib.sol";

import { CallProxy } from "../../src/CallProxy.sol";
import { AllowanceSpend, Outcome } from "../../src/libs/LibExecutionConstraint.sol";
import { LibExecutionConstraintV1_1 } from "../../src/libs/LibExecutionConstraintV1_1.sol";

/**
 * @title Constrained Asset Transaction Validator v1.1 – C.A.T Validator V1.1
 * @author Alexander @ LIFI (https://li.fi)
 * @custom:version 1.1.0
 * @notice Validation of a pre-approved asset allowance to execute a transaction that should result in a specific asset
 * outcome.
 * The intended usecase is in combination with Catapultar with an embedded action. A Catapultar account with an batch
 * transaction of setSignature and approve, allows the configured executor to find calldata to complete the provided
 * description: allowances for outcomes.
 *
 * This contract transiently holds outcome assets during settlement:
 * - Allowances are collected from the signer and delivered to an executor specified destination.
 * - The executor delivers outcome tokens to this contract; after the external call it verifies its own balance meets
 * each outcome amount, then forwards the full balance to the outcome's destination.
 *
 * This contract uses a call proxy for arbitrary call execution. This makes it safe to set approvals to the contract.
 * This contract does not have a fixed callback function. The call proxy address is ::CALL_PROXY().
 *
 * Each approval can only be accessed once, invalidating other approvals by nonce. Except nonce 0 which can be used for
 * long lived approvals like DCAs.
 *
 * v1.1 adds `pulled(token)`, `entryId()` and a committed `executionTarget` / `payloadHash`, where zero means
 * unconstrained. `pulled` and the entry id live in transient storage (EIP-1153) only; the constructor reverts on a
 * chain without it.
 *
 * Test-only reference: a standalone hold-and-forward v1.1 written from the same specification as CATValidatorV1_1,
 * which the equivalence suite fuzzes the subclass against.
 */
contract CATValidatorV1_1Standalone is EIP712, ReentrancyGuard {
    using DynamicArrayLib for uint256[];
    error InvalidTokenAmount(uint256 expected, uint256 received);
    error AllocationTooSmall(uint256 allocated, uint256 spend);
    error NonceAlreadySpent();
    error BadSignature();
    error BalanceOfFailed(address token);
    error TargetNotCommitted();
    error PayloadNotCommitted();
    error ZeroDestination();

    address public immutable CALL_PROXY;
    uint256 constant SPEND_BALANCE_OF_MAGIC = 1 << 255;
    uint256 private constant PULLED_SEED = 0x2c3fdc6a4b9e8a2f5d1e7c0b9a8f7e6d5c4b3a291807f6e5d4c3b2a1908f7e6d;
    uint256 private constant COUNTER_SLOT = 0x1d2e3f405162738495a6b7c8d9eafb0c1d2e3f405162738495a6b7c8d9eafb0c;
    uint256 private constant CURRENT_SLOT = 0x8f7e6d5c4b3a291807f6e5d4c3b2a1908f7e6d5c4b3a291807f6e5d4c3b2a190;

    mapping(address => mapping(uint256 => bool)) public spentNonces;

    constructor() {
        bytes32 probe = _pulledSlot(address(0));
        _tstore(probe, 1);
        require(_tload(probe) == 1);
        _tstore(probe, 0);
        CALL_PROXY = address(new CallProxy());
    }

    receive() external payable { }

    function _domainNameAndVersion() internal pure override returns (string memory name, string memory version) {
        name = "CAT Validator";
        version = "1.1";
    }

    function DOMAIN_SEPARATOR() external view returns (bytes32) {
        return _domainSeparator();
    }

    /// @notice Amount of `token` moved out of the escrow by the `entry()` currently executing. Zero outside
    /// `entry()` and inside the allowance transfers.
    function pulled(
        address token
    ) external view returns (uint256) {
        return _tload(_pulledSlot(token));
    }

    /// @notice Id of the `entry()` currently executing, 1, 2, 3, ... within a transaction and never reused; zero
    /// outside.
    function entryId() external view returns (uint256) {
        return _tload(bytes32(CURRENT_SLOT));
    }

    /**
     * @notice Execute a transaction for an account given a signed execution constraint.
     * @dev This function can only be called by the designated executor. The caller check is made by embedding
     * msg.sender as the executor in the typehash. This contract does not support _any_ executor and one has to be
     * provided.
     * If a destination is address(0), it specifies the signer. If a spend is SPEND_BALANCE_OF_MAGIC the current balance
     * of the signer will be used. A spend of 0 pulls nothing.
     * @param executionTarget Committed `execTarget`. Zero means unconstrained.
     * @param payloadHash Committed `keccak256(execPayload)`. Zero means unconstrained.
     */
    function entry(
        address execTarget,
        bytes calldata execPayload,
        address account,
        uint256 nonce,
        AllowanceSpend[] calldata allowances,
        Outcome[] calldata outcomes,
        address executionTarget,
        bytes32 payloadHash,
        bytes calldata signature
    ) external nonReentrant {
        uint256 id = _tload(bytes32(COUNTER_SLOT)) + 1;
        _tstore(bytes32(COUNTER_SLOT), id);
        _tstore(bytes32(CURRENT_SLOT), id);

        if (nonce != 0) _checkNonce(account, nonce);
        if (nonce == 0 && executionTarget == address(0)) revert ZeroDestination();
        if (executionTarget != address(0) && executionTarget != execTarget) revert TargetNotCommitted();
        if (payloadHash != 0 && payloadHash != keccak256(execPayload)) revert PayloadNotCommitted();

        _validateApproval(account, nonce, allowances, outcomes, executionTarget, payloadHash, signature);

        _handleAllowances(execTarget, account, allowances);

        if (execPayload.length != 0) _call(execTarget, execPayload);

        _clearPulled(allowances);

        _validatePayment(account, outcomes);

        _tstore(bytes32(CURRENT_SLOT), 0);
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
        spentNonces[account][nonce] = true;
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
        address executionTarget,
        bytes32 payloadHash,
        bytes calldata signature
    ) internal view {
        bytes32 typehash =
            LibExecutionConstraintV1_1.typehash(allowances, outcomes, msg.sender, nonce, executionTarget, payloadHash);
        bytes32 digest = _hashTypedData(typehash);

        if (!SignatureCheckerLib.isValidSignatureNowCalldata(account, digest, signature)) revert BadSignature();
    }

    /// @dev `token.balanceOf(target)`, reverting when the call fails or returns fewer than 32 bytes.
    function _safeBalanceOf(
        address token,
        address target
    ) internal view returns (uint256 bal) {
        bool implemented;
        (implemented, bal) = SafeTransferLib.checkBalanceOf(token, target);
        if (!implemented) revert BalanceOfFailed(token);
    }

    /// @dev The native balance for address(0).
    function _balanceOf(
        address token,
        address target
    ) internal view returns (uint256) {
        return token == address(0) ? target.balance : _safeBalanceOf(token, target);
    }

    /**
     * @notice Verify this contract holds enough of each outcome token, then forward its whole balance to the
     * destination. A zero payout is skipped.
     */
    function _validatePayment(
        address signer,
        Outcome[] calldata outcomes
    ) internal {
        for (uint256 i; i < outcomes.length; ++i) {
            Outcome calldata outcome = outcomes[i];
            uint256 held = _balanceOf(outcome.token, address(this));
            if (held < outcome.amount) revert InvalidTokenAmount(outcome.amount, held);
            if (held == 0) continue;

            address dest = outcome.destination == address(0) ? signer : outcome.destination;
            if (outcome.token == address(0)) SafeTransferLib.safeTransferETH(dest, held);
            else SafeTransferLib.safeTransfer(outcome.token, dest, held);
        }
    }

    /**
     * @notice Move spend portions of provided allowances to destination.
     * @dev Publishes only after every transfer, so a token hook inside the loop reads zero, never a partial sum.
     * @param destination Address to receive the tokens.
     * @param source Contract to collect allowances from.
     * @param allowances Signed token allowances & spends.
     */
    function _handleAllowances(
        address destination,
        address source,
        AllowanceSpend[] calldata allowances
    ) internal {
        uint256[] memory spends = DynamicArrayLib.malloc(allowances.length);

        for (uint256 i = 0; i < allowances.length; ++i) {
            AllowanceSpend calldata allowance = allowances[i];

            uint256 spend =
                allowance.spend == SPEND_BALANCE_OF_MAGIC ? _safeBalanceOf(allowance.token, source) : allowance.spend;
            if (allowance.allocated < spend) revert AllocationTooSmall(allowance.allocated, spend);

            spends.set(i, spend);
            SafeTransferLib.safeTransferFrom(allowance.token, source, destination, spend);
        }

        for (uint256 i = 0; i < allowances.length; ++i) {
            bytes32 slot = _pulledSlot(allowances[i].token);
            _tstore(slot, _tload(slot) + spends.get(i));
        }
    }

    function _clearPulled(
        AllowanceSpend[] calldata allowances
    ) internal {
        for (uint256 i = 0; i < allowances.length; ++i) {
            _tstore(_pulledSlot(allowances[i].token), 0);
        }
    }

    function _pulledSlot(
        address token
    ) private pure returns (bytes32 s) {
        assembly ("memory-safe") {
            mstore(0x00, token)
            mstore(0x20, PULLED_SEED)
            s := keccak256(0x00, 0x40)
        }
    }

    function _tload(
        bytes32 s
    ) private view returns (uint256 v) {
        assembly ("memory-safe") {
            v := tload(s)
        }
    }

    function _tstore(
        bytes32 s,
        uint256 v
    ) private {
        assembly ("memory-safe") {
            tstore(s, v)
        }
    }

    /**
     * @notice Arbitrary external call using the call proxy.
     * @dev Allows executing any payload on the target. Encodes the external call into:
     * bytes32(execTarget) || bytes(execPayload).
     * Forwards no value: a force-fed native balance must not reach a non-payable execution target.
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
                    0,
                    m,
                    add(execPayload.length, 32),
                    codesize(),
                    0x00 // Don't copy returndata. IFF failure, we will manually copy into revert.
                )

            if iszero(success) {
                returndatacopy(m, 0x00, returndatasize())
                if iszero(success) {
                    revert(m, returndatasize())
                }
            }
        }
    }
}
