// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.25;

import { SafeTransferLib } from "solady/src/utils/SafeTransferLib.sol";
import { SignatureCheckerLib } from "solady/src/utils/SignatureCheckerLib.sol";
import { Tstorish } from "tstorish/src/Tstorish.sol";

import { CATValidator } from "./CATValidator.sol";
import { AllowanceSpend, Outcome } from "./libs/LibExecutionConstraint.sol";
import { ExecutionBinding, LibExecutionConstraintV2 } from "./libs/LibExecutionConstraintV2.sol";
import { LibValidationVM, VMCommand, VMState } from "./libs/LibValidationVM.sol";

/**
 * @title Constrained Asset Transaction Validator V2 – C.A.T Validator V2
 * @author LIFI (https://li.fi)
 * @custom:version 2.0.0
 * @notice CATValidator with a committed validation program. Settlement is the
 * inherited v1 code: the executor's fill must deliver each committed outcome to
 * this contract, which checks its own balance against the outcome amount and
 * forwards its full balance to the outcome's destination. After that payment
 * step, V2 runs the committed program on the LI.FI VirtualMachine by
 * `staticcall`. A program that reverts reverts the settlement, so the escrow
 * keeps its funds and can refund.
 *
 * The constraint commits `keccak256` of the ABI-encoded program commands and
 * `keccak256` of the per-user parameter words through the EIP-712 digest, and
 * therefore through the escrow's counterfactual address. The hashes are derived
 * from the `validationProgram` and `validationParams` calldata, so `entry` takes
 * neither as an argument. An empty program commits `bytes32(0)` and settles
 * exactly as v1, without touching the VirtualMachine.
 *
 * The program sees, as registers, the committed params, the escrow address,
 * the spend v1 resolved per allowance (`spent`) and the amount v1 forwarded per
 * outcome (`paid`). `paid` is recorded by the `_transfer` hook at the moment v1
 * forwards each outcome, in transient storage through Tstorish. It is the gross
 * amount this contract sent: its complete balance of the outcome token,
 * including any balance it held before the fill. A third party raises that
 * balance by sending tokens to this contract, so only lower-bound (`>=`) checks
 * over `paid` are safe; an exact or upper-bound check fails once anyone sends
 * 1 unit. A fee-on-transfer token credits the destination with less. `spent`
 * is recorded by `_handleAllowancesRecorded`, a copy of v1's allowance loop
 * that this contract runs only when a program is committed: a literal spend as
 * written, a `SPEND_BALANCE_OF_MAGIC` spend as the escrow balance read when the
 * loop reaches that allowance, after the earlier pulls have executed. An empty
 * program runs v1's own loop. `spent[i]` is the amount passed to
 * `transferFrom`. It equals the escrow's debit only for a token that debits
 * exactly the transfer amount; a token that charges the sender a fee on top of
 * the amount debits more.
 *
 * `spent` and `paid` prove that value moved through this contract, not that an
 * application action ran. If an allowance token is also an outcome token and
 * the constraint signs a `0`/`0` binding, the executor can route the pulled
 * allowance straight back to this contract and satisfy the floor and the flow
 * registers without any work. Binding both `executionTarget` and `payloadHash`
 * commits the action.
 *
 * v1 pushes each outcome to its destination in one transfer of this contract's
 * complete balance. Settlement therefore requires that a native destination
 * accepts the value, that the token is not paused and does not blocklist this
 * contract or the destination, and that the token allows a single transfer of
 * the complete balance without charging a sender-side fee on top of the amount.
 * A third party can push this contract's balance of a per-transfer-capped token
 * over the cap by sending tokens to it. A failed push reverts the settlement:
 * the escrow keeps its funds, the nonce stays unspent, and the refund
 * constraint remains the recovery route. Destinations and token callbacks run
 * during the pushes and the program runs after the last push, so the program
 * observes external state as those callbacks left it.
 *
 * Nonces are spent in this contract's storage. Spending nonce `n` here leaves
 * `n` unspent on v1 and on every other validator.
 *
 * The program runs under `staticcall`, so it can only read and revert. Any
 * failure of the program call, including out of gas, reverts
 * `ValidationFailed(bytes)` with the inner revert data. A fill target controls
 * its own revert data and can therefore produce bytes that decode as any of
 * this contract's errors; off-chain classification must not rely on a selector
 * alone.
 *
 * This contract, like the current v1 build, requires a Cancun-compatible VM.
 * Tstorish falls back to SSTORE where TSTORE is missing, but the compiler emits
 * `MCOPY` regardless, so the fallback does not extend chain support.
 *
 * The EIP-712 domain version is "2". The inherited 7-argument `entry` reverts:
 * a V2 escrow signs V2 digests only.
 */
contract CATValidatorV2 is CATValidator, Tstorish {
    /// @dev Params were supplied without a program, or the injected register
    /// prefix would reach the VM's void register.
    error BadValidationParams();
    /// @dev The program call failed. Carries the inner revert data (empty when
    /// the VM ran out of gas or reverted without data).
    error ValidationFailed(bytes revertData);
    /// @dev A program was committed but `VIRTUAL_MACHINE` holds no code. A
    /// `staticcall` to a codeless address succeeds with empty return data, so
    /// the program would pass vacuously; fail closed instead.
    error InvalidVirtualMachine();
    /// @dev The inherited v1 `entry` has no V2 digest to check against.
    error V1EntryDisabled();
    /// @dev The constraint commits an `executionTarget` and the call's `execTarget`
    /// differs from it.
    error TargetNotCommitted();
    /// @dev The constraint commits a `payloadHash` and `keccak256(execPayload)`
    /// differs from it.
    error PayloadNotCommitted();

    /// @notice The VirtualMachine that executes committed programs.
    address public immutable VIRTUAL_MACHINE;

    /// @dev Transient slot holding `1 + number of outcomes forwarded so far` while
    /// a program-bearing settlement records payments, and 0 otherwise. Forwarded
    /// amount `i` lives at `PAID_SLOT + 1 + i`.
    uint256 private constant PAID_SLOT = uint256(keccak256("CATValidatorV2.paid")) & ~uint256(0xff);

    constructor(
        address virtualMachine
    ) {
        VIRTUAL_MACHINE = virtualMachine;
    }

    function _domainNameAndVersion()
        internal
        pure
        virtual
        override
        returns (string memory name, string memory version)
    {
        name = "CAT Validator";
        version = "2";
    }

    /// @dev v1 entry point, disabled: V2 escrows sign the V2 typehash only.
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
     * @notice Execute a transaction for an account given a signed V2 execution constraint.
     * @dev Only the executor embedded in the constraint can call this (as `msg.sender`).
     * Destination `address(0)` means the signer; a spend of `2**255` means the signer's
     * current balance (v1 semantics). The fill must deliver each outcome token to this
     * contract. When `validationProgram` is non-empty, this contract settles as v1
     * while recording the spends and payments, and then runs the program.
     * @param binding The committed `executionTarget` and `payloadHash`. Each field is
     * zero when unconstrained, and is checked against `execTarget` and
     * `keccak256(execPayload)` before any allowance moves. A refund constraint commits
     * its refund wallet and `keccak256("")`, so its allowances can only move to that
     * wallet and no call is made.
     * @param validationProgram The `runVM` command array. Empty commits
     * `validationProgramHash = 0` and settles exactly as v1.
     * @param validationParams Committed parameter words. Must be empty when the
     * program is empty.
     */
    function entry(
        address execTarget,
        bytes calldata execPayload,
        address account,
        uint256 nonce,
        AllowanceSpend[] calldata allowances,
        Outcome[] calldata outcomes,
        ExecutionBinding calldata binding,
        VMCommand[] calldata validationProgram,
        bytes32[] calldata validationParams,
        bytes calldata signature
    ) external nonReentrant {
        _checkBinding(binding, execTarget, execPayload);

        bytes32 validationProgramHash = _programHashOf(validationProgram);
        bytes32 paramsHash = _paramsHashOf(validationParams, validationProgramHash);
        bool verified = validationProgramHash != bytes32(0);
        if (verified && validationParams.length + allowances.length + outcomes.length > LibValidationVM.MAX_PREFIX_END) revert BadValidationParams();

        if (nonce != 0) _checkNonce(account, nonce);

        _validateApprovalV2(account, nonce, allowances, outcomes, binding, validationProgramHash, paramsHash, signature);

        uint256[] memory spent;
        if (verified) spent = _handleAllowancesRecorded(execTarget, account, allowances);
        else _handleAllowances(execTarget, account, allowances);

        if (execPayload.length != 0) _call(execTarget, execPayload);

        if (verified) _setTstorish(PAID_SLOT, 1);

        _validatePayment(account, outcomes);

        if (verified) _runValidation(account, validationProgram, validationParams, spent, _takePaid(outcomes.length));
    }

    /// @dev Reverts unless the call matches each non-zero field of the committed
    /// binding. Runs before any allowance moves.
    function _checkBinding(
        ExecutionBinding calldata binding,
        address execTarget,
        bytes calldata execPayload
    ) internal pure {
        address executionTarget = binding.executionTarget;
        if (executionTarget != address(0) && executionTarget != execTarget) revert TargetNotCommitted();
        bytes32 payloadHash = binding.payloadHash;
        if (payloadHash != bytes32(0) && payloadHash != keccak256(execPayload)) revert PayloadNotCommitted();
    }

    /// @dev `bytes32(0)` for an empty program, else `keccak256` of the ABI-encoded
    /// command array. `abi.encode` of an array of static tuples is canonical, and
    /// `_runValidation` encodes the same calldata commands for the VM, so the
    /// hash commits exactly the commands the VM runs.
    function _programHashOf(
        VMCommand[] calldata validationProgram
    ) internal pure returns (bytes32) {
        return validationProgram.length == 0 ? bytes32(0) : keccak256(abi.encode(validationProgram));
    }

    /// @dev Params hash per `LibValidationVM.paramsHashOf`. Params without a
    /// program are rejected: an empty program commits a zero params hash.
    function _paramsHashOf(
        bytes32[] calldata validationParams,
        bytes32 validationProgramHash
    ) internal pure returns (bytes32) {
        if (validationProgramHash == bytes32(0) && validationParams.length != 0) revert BadValidationParams();
        return LibValidationVM.paramsHashOf(validationParams);
    }

    /**
     * @dev Validate an approval over the V2 typehash. Requires that the caller is
     * the executor embedded in the constraint.
     */
    function _validateApprovalV2(
        address account,
        uint256 nonce,
        AllowanceSpend[] calldata allowances,
        Outcome[] calldata outcomes,
        ExecutionBinding calldata binding,
        bytes32 validationProgramHash,
        bytes32 paramsHash,
        bytes calldata signature
    ) internal view {
        bytes32 typehash = LibExecutionConstraintV2.typehash(
            allowances,
            outcomes,
            msg.sender,
            nonce,
            binding.executionTarget,
            binding.payloadHash,
            validationProgramHash,
            paramsHash
        );
        bytes32 digest = _hashTypedData(typehash);

        if (!SignatureCheckerLib.isValidSignatureNowCalldata(account, digest, signature)) revert BadSignature();
    }

    /// @dev Copy of v1's `_safeBalanceOf`, which is private to v1. Calls
    /// `token.balanceOf(account)` and reverts `BalanceOfFailed` if the call fails
    /// or returns fewer than 32 bytes, instead of silently returning zero.
    function _strictBalanceOf(
        address token,
        address account
    ) private view returns (uint256 bal) {
        bool implemented;
        (implemented, bal) = SafeTransferLib.checkBalanceOf(token, account);
        if (!implemented) revert BalanceOfFailed(token);
    }

    /**
     * @dev v1's allowance loop (`CATValidator._handleAllowances`) with each
     * resolved spend recorded: the amount passed to `transferFrom`, read fresh
     * from the escrow for a `SPEND_BALANCE_OF_MAGIC` spend after the earlier
     * pulls have executed. Keep the loop body in lockstep with v1; the parity
     * test in `test/CATValidatorV2.AllowanceParity.t.sol` checks that the two
     * loops make the same transfers and revert with the same data.
     */
    function _handleAllowancesRecorded(
        address destination,
        address source,
        AllowanceSpend[] calldata allowances
    ) internal returns (uint256[] memory spent) {
        spent = new uint256[](allowances.length);
        for (uint256 i = 0; i < allowances.length; ++i) {
            AllowanceSpend calldata allowance = allowances[i];

            uint256 spend =
                allowance.spend == SPEND_BALANCE_OF_MAGIC ? _strictBalanceOf(allowance.token, source) : allowance.spend;
            if (allowance.allocated < spend) revert AllocationTooSmall(allowance.allocated, spend);

            spent[i] = spend;
            SafeTransferLib.safeTransferFrom(allowance.token, source, destination, spend);
        }
    }

    /**
     * @notice Transfer `amount` of `token` to `dest`, recording `amount` while a
     * program-bearing settlement is in its payment step.
     * @dev v1 calls this once per outcome, in outcome order, with the amount it
     * forwards. The record is the `paid` register file for the program.
     */
    function _transfer(
        address token,
        uint256 amount,
        address dest
    ) internal virtual override {
        uint256 recorded = _getTstorish(PAID_SLOT);
        if (recorded != 0) {
            _setTstorish(PAID_SLOT + recorded, amount);
            _setTstorish(PAID_SLOT, recorded + 1);
        }
        super._transfer(token, amount, dest);
    }

    /// @dev Collects the amounts `_transfer` recorded during `_validatePayment` and
    /// clears the record, so the slot reads 0 outside a program-bearing settlement.
    function _takePaid(
        uint256 numOutcomes
    ) internal returns (uint256[] memory paid) {
        paid = new uint256[](numOutcomes);
        for (uint256 i; i < numOutcomes; ++i) {
            paid[i] = _getTstorish(PAID_SLOT + 1 + i);
            _clearTstorish(PAID_SLOT + 1 + i);
        }
        _clearTstorish(PAID_SLOT);
    }

    /**
     * @dev Run the committed program on the VirtualMachine with the register file
     * `params ++ [account] ++ spent ++ paid`, then zeroed scratch. The call forwards
     * all remaining gas: `staticcall` already confines the program to reads, and a
     * program that runs out of gas fails the settlement like any other revert.
     */
    function _runValidation(
        address account,
        VMCommand[] calldata validationProgram,
        bytes32[] calldata validationParams,
        uint256[] memory spent,
        uint256[] memory paid
    ) internal view {
        if (VIRTUAL_MACHINE.code.length == 0) revert InvalidVirtualMachine();

        bytes[] memory registers = LibValidationVM.buildRegisters(validationParams, account, spent, paid);
        (bool success, bytes memory ret) = VIRTUAL_MACHINE.staticcall(
            abi.encodeWithSelector(LibValidationVM.RUN_VM_SELECTOR, validationProgram, VMState(registers))
        );
        if (!success) revert ValidationFailed(ret);
    }

    /**
     * @notice Arbitrary external call using the call proxy, forwarding no native value.
     * @dev v1 forwards `selfbalance()`. This contract never holds native value of its
     * own before a fill, so the only value v1 could forward is stray or force-fed ETH,
     * and a single wei makes every non-payable fill target revert. Forwarding zero
     * removes that block. Stray native balance is forwarded by an `address(0)` outcome
     * as in v1.
     */
    function _call(
        address execTarget,
        bytes calldata execPayload
    ) internal virtual override {
        address callProxy = CALL_PROXY;
        assembly ("memory-safe") {
            let m := mload(0x40)

            // calldata = abi.encodePacked(bytes32(execTarget), execPayload);
            mstore(m, execTarget)
            calldatacopy(add(m, 32), execPayload.offset, execPayload.length)

            let success := call(gas(), callProxy, 0, m, add(execPayload.length, 32), codesize(), 0x00)

            if iszero(success) {
                // Copy to the free memory pointer, not offset 0: revert data
                // longer than the 64-byte scratch space would otherwise break
                // this block's memory-safe annotation.
                returndatacopy(m, 0x00, returndatasize())
                revert(m, returndatasize())
            }
        }
    }
}
