// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { DynamicArrayLib } from "solady/src/utils/DynamicArrayLib.sol";
import { EIP712 } from "solady/src/utils/EIP712.sol";
import { ReentrancyGuard } from "solady/src/utils/ReentrancyGuard.sol";
import { SafeTransferLib } from "solady/src/utils/SafeTransferLib.sol";
import { SignatureCheckerLib } from "solady/src/utils/SignatureCheckerLib.sol";

import { CallProxy } from "./CallProxy.sol";
import { AllowanceSpend, Outcome } from "./libs/LibExecutionConstraint.sol";
import { LibExecutionConstraintV2 } from "./libs/LibExecutionConstraintV2.sol";
import { LibValidationVM } from "./libs/LibValidationVM.sol";

/**
 * @title Constrained Asset Transaction Validator v2 – C.A.T Validator V2
 * @author LIFI (https://li.fi)
 * @custom:version 2.0.0
 * @notice CATValidator extended with a committed validation program
 * (verified continuations). The v1 mechanics are unchanged: a pre-approved
 * asset allowance authorizes an executor-supplied transaction that must result
 * in a committed asset outcome (the per-token balance-delta floor).
 *
 * V2 additionally commits, through the EIP-712 constraint digest (and therefore
 * through the escrow account's counterfactual address), the content hash of an
 * assert-only LI.FI VirtualMachine program plus the hash of its per-user
 * parameter vector. After the mandatory outcome floor passes, `entry()` verifies
 * the supplied program bytes and params against the committed hashes and
 * executes the program via `staticcall` on the canonical, unmodified
 * VirtualMachine. The staticcall makes the sandbox an EVM guarantee: the
 * program can only read and revert — token moves (SAFE_TRANSFER,
 * DEPOSIT_APPROVED), state-mutating calls, and LOG all revert, reverting the
 * whole settlement (funds remain refundable).
 *
 * Layering guarantees (never subtractive): the floor always runs, and runs
 * first; the program can only add constraints on top of it. A constraint with
 * `validationProgramHash == 0` behaves exactly like v1.
 *
 * The EIP-712 domain version is "2": v1 and v2 digests can never collide, so
 * existing v1 bundles and escrow addresses are unaffected.
 *
 * This contract is standalone rather than inheriting CATValidator so the
 * audited v1 source stays byte-identical.
 */
contract CATValidatorV2 is EIP712, ReentrancyGuard {
    using DynamicArrayLib for uint256[];

    error InvalidTokenAmount(uint256 expected, uint256 received);
    error AllocationTooSmall(uint256 allocated, uint256 spend);
    error NonceAlreadySpent();
    error BadSignature();
    /// @dev Supplied validation-program bytes are malformed or do not hash to
    /// the committed `validationProgramHash`.
    error BadValidationProgram();
    /// @dev Supplied validation params are malformed, oversized, or do not hash
    /// to the committed `paramsHash`.
    error BadValidationParams();
    /// @dev The validation staticcall reverted (a failed assertion, an attempted
    /// state mutation, or the gas cap was exhausted). Carries the inner revert
    /// data (e.g. the InvariantChecker's AssertGteFailed(a,b)) so a validation
    /// failure is diagnosable and distinguishable from floor failures
    /// (InvalidTokenAmount) and fill reverts (bubbled raw).
    error ValidationFailed(bytes revertData);
    /// @dev A committed validation program was requested but the VirtualMachine
    /// address holds no code. STATICCALL to a codeless address returns success
    /// with empty returndata, so the program would silently pass — fail closed
    /// when the verified path is requested but the VM is missing.
    error InvalidVirtualMachine();
    /// @dev A zero validation gas cap is meaningless: EVM 63/64 rules forward
    /// nearly all remaining gas regardless, so `gas: 0` would leave the
    /// validation staticcall effectively unbounded instead of bounded.
    error InvalidValidationGasCap();
    error BalanceOfFailed(address token);

    address public immutable CALL_PROXY;
    /// @notice The canonical VirtualMachine executing committed validation
    /// programs (deterministically deployed at the same address on every
    /// supported chain).
    address public immutable VIRTUAL_MACHINE;
    /// @notice Gas forwarded to the validation staticcall. Bounds what a
    /// pathological program can cost the executor; running out reverts as a
    /// normal validation failure (ValidationFailed → refund path).
    uint256 public immutable VALIDATION_GAS_CAP;

    uint256 constant SPEND_BALANCE_OF_MAGIC = 1 << 255;

    mapping(address => mapping(uint256 => bool)) public spentNonces;

    constructor(
        address virtualMachine,
        uint256 validationGasCap
    ) {
        if (validationGasCap == 0) revert InvalidValidationGasCap();
        CALL_PROXY = address(new CallProxy());
        VIRTUAL_MACHINE = virtualMachine;
        VALIDATION_GAS_CAP = validationGasCap;
    }

    function _domainNameAndVersion() internal pure override returns (string memory name, string memory version) {
        name = "CAT Validator";
        version = "2";
    }

    function DOMAIN_SEPARATOR() external view returns (bytes32) {
        return _domainSeparator();
    }

    /**
     * @notice Execute a transaction for an account given a signed execution constraint.
     * @dev This function can only be called by the designated executor (embedded as
     * `msg.sender` in the typehash). Destination `address(0)` specifies the signer.
     * The `2**255` spend sentinel uses the signer's current balance; any other
     * spend amount is used as supplied (v1 semantics, unchanged).
     * @param validationProgramHash Committed content hash of the canonical
     * validation-program body (keccak256 of `validationProgram`); bytes32(0)
     * means "no program" and reproduces exact v1 behavior.
     * @param paramsHash Committed hash of the params vector (bytes32(0) when empty).
     * @param validationProgram The canonical program body (33 bytes per command);
     * must be empty when `validationProgramHash` is zero.
     * @param validationParams The committed per-user parameter words (32 bytes
     * each); must be empty when `paramsHash` is zero.
     */
    function entry(
        address execTarget,
        bytes calldata execPayload,
        address account,
        uint256 nonce,
        AllowanceSpend[] calldata allowances,
        Outcome[] calldata outcomes,
        bytes32 validationProgramHash,
        bytes32 paramsHash,
        bytes calldata validationProgram,
        bytes[] calldata validationParams,
        bytes calldata signature
    ) external nonReentrant {
        if (nonce != 0) _checkNonce(account, nonce);

        _validateApproval(account, nonce, allowances, outcomes, validationProgramHash, paramsHash, signature);

        uint256[] memory recordedBalances = _recordBalances(account, outcomes);

        _handleAllowances(execTarget, account, allowances);

        if (execPayload.length != 0) _call(execTarget, execPayload);

        _compareOutcomes(account, outcomes, recordedBalances);

        _runValidation(
            account, validationProgramHash, paramsHash, validationProgram, validationParams, recordedBalances
        );
    }

    /**
     * @notice Verify and execute the committed validation program, layered after
     * the mandatory outcome floor.
     * @dev The initial register file follows the frozen layout convention:
     * committed params, then the authenticated account (the escrow address),
     * then the recorded pre-balances in committed-outcomes order, then zeroed
     * scratch. The escrow address and pre-balances are injected here — they can
     * never be body literals or committed params because the escrow address
     * transitively depends on `validationProgramHash`.
     * @param account Authenticated escrow account injected into the register file.
     * @param validationProgramHash Hash that the program body must match.
     * @param paramsHash Hash that the supplied parameter vector must match.
     * @param validationProgram Canonical program body passed to the VM.
     * @param validationParams Committed 32-byte parameter words injected first.
     * @param preBalances `_recordBalances` snapshot taken before allowance transfers
     * and the fill.
     */
    function _runValidation(
        address account,
        bytes32 validationProgramHash,
        bytes32 paramsHash,
        bytes calldata validationProgram,
        bytes[] calldata validationParams,
        uint256[] memory preBalances
    ) internal view {
        if (validationProgramHash == bytes32(0)) {
            // Exact v1 behavior. Fail fast on stray inputs so mis-threaded
            // integrations surface here instead of silently ignoring bytes.
            if (validationProgram.length != 0) revert BadValidationProgram();
            if (paramsHash != bytes32(0) || validationParams.length != 0) revert BadValidationParams();
            return;
        }

        if (validationProgram.length == 0 || validationProgram.length % LibValidationVM.COMMAND_SIZE != 0) {
            revert BadValidationProgram();
        }
        if (keccak256(validationProgram) != validationProgramHash) revert BadValidationProgram();

        (bytes32 suppliedParamsHash, bool wellFormed) = LibValidationVM.paramsHashOf(validationParams);
        if (!wellFormed || suppliedParamsHash != paramsHash) revert BadValidationParams();
        // The injected prefix (params ++ account ++ preBalances) must end below
        // the VM's void register; anything larger could silently read as zero.
        if (validationParams.length + preBalances.length > LibValidationVM.MAX_PREFIX_END) {
            revert BadValidationParams();
        }

        // Fail closed on a codeless/absent VM. EVM STATICCALL to an address with
        // no code returns success=true with empty returndata, which would let a
        // committed program silently pass. Guarded only on the verified path
        // (hash != 0), so the v1 / no-commitment fast path stays byte-identical.
        if (VIRTUAL_MACHINE.code.length == 0) revert InvalidVirtualMachine();

        bytes[] memory registers = LibValidationVM.buildRegisters(validationParams, account, preBalances);

        (bool success, bytes memory ret) = VIRTUAL_MACHINE.staticcall{ gas: VALIDATION_GAS_CAP }(
            LibValidationVM.encodeRunVM(validationProgram, registers)
        );
        if (!success) revert ValidationFailed(ret);
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
     * @dev Validate an approval. Requires that the caller is the executor associated
     * with the constraint. The v2 typehash commits the validation-program hash and
     * params hash alongside the v1 fields.
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
     * @notice Wraps balanceOf call for ERC20 tokens and natives.
     * @param account Fallback address for to read if outcome.destination is 0.
     * @param outcome Description of the balance read: target and token. 0 token is native.
     */
    function _balanceOf(
        address account,
        Outcome calldata outcome
    ) internal view returns (uint256 bal) {
        address destination = outcome.destination == address(0) ? account : outcome.destination;
        bal = outcome.token == address(0) ? destination.balance : _safeBalanceOf(outcome.token, destination);
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
            uint256 diff = newBalance - recordedBalances[i];
            if (diff < outcome.amount) revert InvalidTokenAmount(outcome.amount, diff);
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
                // Copy to the free memory pointer, not offset 0: return data
                // longer than the 64-byte scratch space would otherwise break
                // this block's memory-safe annotation.
                returndatacopy(m, 0x00, returndatasize())
                revert(m, returndatasize())
            }
        }
    }
}
