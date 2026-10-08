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
 * asset allowance authorizes an executor-supplied transaction that must deliver
 * each committed outcome to this contract, which checks it holds at least the
 * outcome amount and forwards its full balance to the outcome's destination.
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
 * This contract holds outcome assets only during settlement. Tokens sent to it
 * outside `entry()` are forwarded to the next outcome destination of that
 * token. Native value is also sent along with the next execution call, because
 * `_call` forwards this contract's whole balance.
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

    receive() external payable { }

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
     * spend amount is used as supplied (v1 semantics, unchanged). The execution
     * must deliver each outcome token to this contract; the outcome check reads
     * this contract's balance and forwards it to the destination.
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

        _handleAllowances(execTarget, account, allowances);

        if (execPayload.length != 0) _call(execTarget, execPayload);

        uint256[] memory preBalances = _validatePayment(account, outcomes, validationProgramHash != bytes32(0));

        _runValidation(account, validationProgramHash, paramsHash, validationProgram, validationParams, preBalances);
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
     * @param preBalances Destination balances `_validatePayment` read immediately
     * before forwarding each outcome, in committed-outcomes order.
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
     * @notice Returns the balance of `token` held by `target`.
     * @param token ERC20 token address. address(0) returns the native balance of `target`.
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
     * @dev Handles both ERC-20 and native tokens (token == address(0)).
     * @param token ERC-20 token address, or address(0) for the native token.
     * @param amount Amount to transfer.
     * @param dest Recipient address.
     */
    function _transfer(
        address token,
        uint256 amount,
        address dest
    ) internal virtual {
        token == address(0)
            ? SafeTransferLib.safeTransferETH(dest, amount)
            : SafeTransferLib.safeTransfer(token, dest, amount);
    }

    /**
     * @notice Verify this contract holds enough of each outcome token, then forward it to the destination.
     * @dev The executor must deliver outcome tokens to address(this) during execution. The full held
     * balance is forwarded, so any surplus beyond outcome.amount also goes to the destination.
     * When `recordPreBalances` is set, each destination's balance is read immediately before its
     * forward. A committed program that subtracts it from the destination's current balance
     * therefore sees exactly what this contract forwarded, never an unrelated transfer that reached
     * the destination during execution.
     * @param signer Token recipient if outcome.destination is 0.
     * @param outcomes Tokens and minimum amounts that must be present at address(this).
     * @param recordPreBalances Whether to record destination balances for the validation program.
     * @return preBalances Destination balances before each forward, in outcome order; empty when not recorded.
     */
    function _validatePayment(
        address signer,
        Outcome[] calldata outcomes,
        bool recordPreBalances
    ) internal returns (uint256[] memory preBalances) {
        if (recordPreBalances) preBalances = DynamicArrayLib.malloc(outcomes.length);
        for (uint256 i; i < outcomes.length; ++i) {
            Outcome calldata outcome = outcomes[i];
            uint256 payment = _balanceOf(outcome.token, address(this));
            if (payment < outcome.amount) revert InvalidTokenAmount(outcome.amount, payment);

            address destination = outcome.destination == address(0) ? signer : outcome.destination;
            if (recordPreBalances) preBalances.set(i, _balanceOf(outcome.token, destination));
            _transfer(outcome.token, payment, destination);
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
