// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { DynamicArrayLib } from "solady/src/utils/DynamicArrayLib.sol";
import { SafeTransferLib } from "solady/src/utils/SafeTransferLib.sol";
import { SignatureCheckerLib } from "solady/src/utils/SignatureCheckerLib.sol";

import { CATValidator } from "./CATValidator.sol";
import { AllowanceSpend, Outcome } from "./libs/LibExecutionConstraint.sol";
import { LibExecutionConstraintV1_1 } from "./libs/LibExecutionConstraintV1_1.sol";

/**
 * @title Constrained Asset Transaction Validator v1.1 – C.A.T Validator V1.1
 * @author LIFI (https://li.fi)
 * @custom:version 1.1.0
 * @notice CATValidator plus `pulled(token)`, `entryId()` and a committed `executionTarget` / `payloadHash`, where zero
 * means unconstrained. See CATValidator for the validation model, the call proxy and the nonce rules.
 *
 * `pulled` and the entry id live in transient storage (EIP-1153) only; the constructor reverts on a chain without it.
 * The base's 7-argument `entry` reverts `V1EntryDisabled`.
 */
contract CATValidatorV1_1 is CATValidator {
    using DynamicArrayLib for uint256[];

    error TargetNotCommitted();
    error PayloadNotCommitted();
    error ZeroDestination();
    error V1EntryDisabled();

    /// @dev Arbitrary fixed seed with no derivation. The `pulled` slot of a token is `keccak256(token, PULLED_SEED)`
    /// in transient storage; a hashed slot cannot meet the two entry-id slots, so any value is safe.
    uint256 private constant PULLED_SEED = 0x2c3fdc6a4b9e8a2f5d1e7c0b9a8f7e6d5c4b3a291807f6e5d4c3b2a1908f7e6d;
    bytes32 private constant ENTRY_COUNTER_SLOT = keccak256("com.lifi.catapultar.v1_1.entry-counter");
    bytes32 private constant ENTRY_ID_SLOT = keccak256("com.lifi.catapultar.v1_1.entry-id");

    constructor() {
        bytes32 probe = _pulledSlot(address(0));
        _tstore(probe, 1);
        require(_tload(probe) == 1);
        _tstore(probe, 0);
    }

    function _domainNameAndVersion() internal pure override returns (string memory name, string memory version) {
        name = "CAT Validator";
        version = "1.1";
    }

    /// @notice Amount of `token` moved out of the signer by the `entry()` currently executing. Zero outside
    /// `entry()` and inside the allowance transfers.
    function pulled(
        address token
    ) external view returns (uint256) {
        return _tload(_pulledSlot(token));
    }

    /// @notice Id of the 9-argument `entry()` currently executing: 1, 2, 3, ... within a transaction. A settled
    /// entry's id is not reused; a reverted entry rolls the counter back, so the next entry takes its id. Zero outside
    /// it. A non-zero id is also the entry's reentrancy lock.
    function entryId() external view returns (uint256) {
        return _tload(ENTRY_ID_SLOT);
    }

    /// @dev v1 entry point, disabled: V1.1 accounts sign the V1.1 typehash only.
    function entry(
        address,
        bytes calldata,
        address,
        uint256,
        AllowanceSpend[] calldata,
        Outcome[] calldata,
        bytes calldata
    ) external pure override {
        revert V1EntryDisabled();
    }

    /**
     * @notice Execute a transaction for an account given a signed execution constraint.
     * @dev This function can only be called by the designated executor. The caller check is made by embedding
     * msg.sender as the executor in the typehash. This contract does not support _any_ executor and one has to be
     * provided.
     * If a destination is address(0), it specifies the signer. If a spend is SPEND_BALANCE_OF_MAGIC the current balance
     * of the signer will be used. A spend of 0 still calls `transferFrom` with 0.
     * @param execTarget Target the call proxy calls with `execPayload`; receives the pulled allowances.
     * @param execPayload Calldata for `execTarget`. Empty skips the call.
     * @param account Signer of the constraint and source of the allowances.
     * @param nonce Constraint nonce. A non-zero nonce is spent once; nonce 0 is reusable.
     * @param allowances Signed token allowances and the spends to pull now.
     * @param outcomes Minimum balances this contract must hold after the call; each held balance is forwarded to
     * its destination.
     * @param executionTarget Committed `execTarget`. Zero means unconstrained, except on the reusable nonce 0, where
     * it reverts `ZeroDestination` (a zero refund address would otherwise let the executor sweep to any target).
     * @param payloadHash Committed `keccak256(execPayload)`. Zero means unconstrained.
     * @param signature Signature of `account` over the v1.1 digest: ECDSA, or ERC-1271 data for a contract signer.
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
    ) external {
        if (_tload(ENTRY_ID_SLOT) != 0) revert Reentrancy();
        uint256 id = _tload(ENTRY_COUNTER_SLOT) + 1;
        _tstore(ENTRY_COUNTER_SLOT, id);
        _tstore(ENTRY_ID_SLOT, id);

        if (nonce != 0) _checkNonce(account, nonce);
        if (nonce == 0 && executionTarget == address(0)) revert ZeroDestination();
        if (executionTarget != address(0) && executionTarget != execTarget) revert TargetNotCommitted();
        if (payloadHash != 0 && payloadHash != keccak256(execPayload)) revert PayloadNotCommitted();

        _validateApproval(account, nonce, allowances, outcomes, executionTarget, payloadHash, signature);

        _handleAllowancesPulled(execTarget, account, allowances);

        if (execPayload.length != 0) _call(execTarget, execPayload);

        _clearPulled(allowances);

        _validatePayment(account, outcomes);

        _tstore(ENTRY_ID_SLOT, 0);
    }

    /// @dev A zero payout moves nothing; skipping it keeps `{token, 0, refund}` outcomes on zero-rejecting tokens.
    function _transfer(
        address token,
        uint256 amount,
        address dest
    ) internal virtual override {
        if (amount != 0) super._transfer(token, amount, dest);
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

    /**
     * @notice Move spend portions of provided allowances to destination.
     * @dev Publishes only after every transfer, so a token hook inside the loop reads zero, never a partial sum.
     * @param destination Address to receive the tokens.
     * @param source Contract to collect allowances from.
     * @param allowances Signed token allowances & spends.
     */
    function _handleAllowancesPulled(
        address destination,
        address source,
        AllowanceSpend[] calldata allowances
    ) internal {
        uint256[] memory spends = DynamicArrayLib.malloc(allowances.length);

        for (uint256 i = 0; i < allowances.length; ++i) {
            AllowanceSpend calldata allowance = allowances[i];

            uint256 spend =
                allowance.spend == SPEND_BALANCE_OF_MAGIC ? _strictBalanceOf(allowance.token, source) : allowance.spend;
            if (allowance.allocated < spend) revert AllocationTooSmall(allowance.allocated, spend);

            spends.set(i, spend);
            SafeTransferLib.safeTransferFrom(allowance.token, source, destination, spend);
        }

        for (uint256 i = 0; i < allowances.length; ++i) {
            bytes32 slot = _pulledSlot(allowances[i].token);
            _tstore(slot, _tload(slot) + spends.get(i));
        }
    }

    /// @dev The base's `_safeBalanceOf` is private: same semantics, a failed or short `balanceOf` reverts.
    function _strictBalanceOf(
        address token,
        address account
    ) private view returns (uint256 bal) {
        bool implemented;
        (implemented, bal) = SafeTransferLib.checkBalanceOf(token, account);
        if (!implemented) revert BalanceOfFailed(token);
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
    ) internal override {
        address callProxy = CALL_PROXY;
        assembly ("memory-safe") {
            let m := mload(0x40)

            // calldata = abi.encodePacked(bytes32(execTarget), execPayload);
            mstore(m, execTarget)
            calldatacopy(add(m, 32), execPayload.offset, execPayload.length)

            let success := call(gas(), callProxy, 0, m, add(execPayload.length, 32), codesize(), 0x00)

            if iszero(success) {
                // Revert data can exceed the 64-byte scratch space, so it is copied to free memory.
                returndatacopy(m, 0x00, returndatasize())
                revert(m, returndatasize())
            }
        }
    }
}
