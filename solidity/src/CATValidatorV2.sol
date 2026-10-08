// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.25;

import { SignatureCheckerLib } from "solady/src/utils/SignatureCheckerLib.sol";
import { Tstorish } from "tstorish/src/Tstorish.sol";

import { CATValidator } from "./CATValidator.sol";
import { AllowanceSpend, Outcome } from "./libs/LibExecutionConstraint.sol";
import { LibExecutionConstraintV2 } from "./libs/LibExecutionConstraintV2.sol";
import { LibValidationVM } from "./libs/LibValidationVM.sol";

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
 * The constraint commits `keccak256` of the program body and `keccak256` of
 * the per-user parameter words through the EIP-712 digest, and therefore
 * through the escrow's counterfactual address. The hashes are derived from the
 * `validationProgram` and `validationParams` calldata, so `entry` takes neither
 * as an argument. An empty program commits `bytes32(0)` and settles exactly as
 * v1, without touching the VirtualMachine.
 *
 * The program sees, as registers, the committed params, the escrow address,
 * the spend v1 resolved per allowance (`spent`) and the amount v1 forwarded per
 * outcome (`paid`). `paid` is recorded by the `_transfer` hook at the moment v1
 * forwards each outcome, in transient storage (Tstorish: TSTORE where the chain
 * supports it, SSTORE otherwise). It is the gross amount this contract sent;
 * a fee-on-transfer token credits the destination with less. `spent` replays
 * the v1 allowance order: a literal spend as written, a `SPEND_BALANCE_OF_MAGIC`
 * spend as the escrow balance that remains at that point of the order.
 *
 * The program runs under `staticcall`, so it can only read and revert. Any
 * failure of the program call, including out of gas, reverts
 * `ValidationFailed(bytes)` with the inner revert data. A fill target controls
 * its own revert data and can therefore produce bytes that decode as any of
 * this contract's errors; off-chain classification must not rely on a selector
 * alone.
 *
 * The EIP-712 domain version is "2". The inherited 7-argument `entry` reverts:
 * a V2 escrow signs V2 digests only.
 */
contract CATValidatorV2 is CATValidator, Tstorish {
    /// @dev The program body length is not a multiple of 33.
    error BadValidationProgram();
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
     * @param validationProgram Canonical program body, 33 bytes per command. Empty
     * commits `validationProgramHash = 0` and settles exactly as v1.
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
        bytes calldata validationProgram,
        bytes32[] calldata validationParams,
        bytes calldata signature
    ) external nonReentrant {
        bytes32 validationProgramHash = _programHashOf(validationProgram);
        bytes32 paramsHash = _paramsHashOf(validationParams, validationProgramHash);
        bool verified = validationProgramHash != bytes32(0);
        if (verified && validationParams.length + allowances.length + outcomes.length > LibValidationVM.MAX_PREFIX_END) revert BadValidationParams();

        if (nonce != 0) _checkNonce(account, nonce);

        _validateApprovalV2(account, nonce, allowances, outcomes, validationProgramHash, paramsHash, signature);

        uint256[] memory spent;
        if (verified) spent = _replaySpends(account, allowances);

        _handleAllowances(execTarget, account, allowances);

        if (execPayload.length != 0) _call(execTarget, execPayload);

        if (verified) _setTstorish(PAID_SLOT, 1);

        _validatePayment(account, outcomes);

        if (verified) _runValidation(account, validationProgram, validationParams, spent, _takePaid(outcomes.length));
    }

    /// @dev `bytes32(0)` for an empty body, else `keccak256` of a body that is a
    /// whole number of commands.
    function _programHashOf(
        bytes calldata validationProgram
    ) internal pure returns (bytes32) {
        uint256 length = validationProgram.length;
        if (length == 0) return bytes32(0);
        if (length % LibValidationVM.COMMAND_SIZE != 0) revert BadValidationProgram();
        return keccak256(validationProgram);
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
        bytes32 validationProgramHash,
        bytes32 paramsHash,
        bytes calldata signature
    ) internal view {
        bytes32 typehash = LibExecutionConstraintV2.typehash(
            allowances, outcomes, msg.sender, nonce, validationProgramHash, paramsHash
        );
        bytes32 digest = _hashTypedData(typehash);

        if (!SignatureCheckerLib.isValidSignatureNowCalldata(account, digest, signature)) revert BadSignature();
    }

    /**
     * @dev The spend `_handleAllowances` resolves per allowance, computed before it
     * runs. A literal spend is taken as written. A `SPEND_BALANCE_OF_MAGIC` spend
     * is the escrow's balance when v1 reaches that allowance: the balance read
     * here, less the spends of earlier allowances of the same token.
     */
    function _replaySpends(
        address account,
        AllowanceSpend[] calldata allowances
    ) internal view returns (uint256[] memory spent) {
        uint256 numAllowances = allowances.length;
        spent = new uint256[](numAllowances);
        for (uint256 i; i < numAllowances; ++i) {
            AllowanceSpend calldata allowance = allowances[i];
            if (allowance.spend != SPEND_BALANCE_OF_MAGIC) {
                spent[i] = allowance.spend;
                continue;
            }
            uint256 remaining = _balanceOf(allowance.token, account);
            for (uint256 j; j < i; ++j) {
                if (allowances[j].token != allowance.token) continue;
                remaining = spent[j] < remaining ? remaining - spent[j] : 0;
            }
            spent[i] = remaining;
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
        bytes calldata validationProgram,
        bytes32[] calldata validationParams,
        uint256[] memory spent,
        uint256[] memory paid
    ) internal view {
        if (VIRTUAL_MACHINE.code.length == 0) revert InvalidVirtualMachine();

        bytes[] memory registers = LibValidationVM.buildRegisters(validationParams, account, spent, paid);
        (bool success, bytes memory ret) =
            VIRTUAL_MACHINE.staticcall(LibValidationVM.encodeRunVM(validationProgram, registers));
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
