// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { Test } from "forge-std/src/Test.sol";

import { MockERC20 } from "solady/test/utils/mocks/MockERC20.sol";

import { CATValidator } from "../../src/CATValidator.sol";
import { CATValidatorV2 } from "../../src/CATValidatorV2.sol";
import { AllowanceSpend, LibExecutionConstraint, Outcome } from "../../src/libs/LibExecutionConstraint.sol";
import { LibExecutionConstraintV2 } from "../../src/libs/LibExecutionConstraintV2.sol";

interface IEIP712 {
    function DOMAIN_SEPARATOR() external view returns (bytes32);
}

/// @dev Minimal fill target: delivers a fixed amount of the outcome token.
/// Called through the validator's CallProxy, so msg.sender authority is nil —
/// it just mints (the mock's mint is permissionless).
contract Swapper {
    function swap(
        MockERC20 outToken,
        uint256 outAmount,
        address dest
    ) external {
        outToken.mint(dest, outAmount);
    }
}

/**
 * @title v1/v2 behavioral parity at `validationProgramHash == 0`
 * @notice The "hash == 0 reproduces v1" guarantee, at the observable-behavior
 * level: for identical inputs (modulo the version-2 digest, signed per
 * validator), v1 `CATValidator` and `CATValidatorV2` with empty validation
 * fields must produce identical outcomes — same revert selectors and args,
 * same token movements, same nonce state. Digests intentionally differ (domain
 * version "1" vs "2"), so approvals are per-validator by construction.
 */
contract V1ParityTest is Test {
    CATValidator v1;
    CATValidatorV2 v2;
    Swapper swapper;

    address signer;
    uint256 signerKey;
    address executor;

    MockERC20 inToken;
    MockERC20 outToken;
    address destination;

    uint256 constant SPEND = 3 ether;
    uint256 constant DELIVER = 2 ether;

    function setUp() external {
        v1 = new CATValidator();
        // Stub VM address is never reached at hash == 0; any nonzero address works.
        v2 = new CATValidatorV2(makeAddr("unusedVm"), 5_000_000);
        swapper = new Swapper();

        (signer, signerKey) = makeAddrAndKey("signer");
        executor = makeAddr("executor");
        destination = makeAddr("destination");

        inToken = new MockERC20("In", "IN", 18);
        outToken = new MockERC20("Out", "OUT", 18);
    }

    function constraintParts(
        uint256 deliverAmount
    ) internal view returns (AllowanceSpend[] memory allowances, Outcome[] memory outcomes) {
        allowances = new AllowanceSpend[](1);
        allowances[0] = AllowanceSpend({ token: address(inToken), allocated: SPEND, spend: SPEND });
        outcomes = new Outcome[](1);
        outcomes[0] = Outcome({ token: address(outToken), amount: deliverAmount, destination: destination });
    }

    function sign(
        address validator,
        bool isV2,
        AllowanceSpend[] memory allowances,
        Outcome[] memory outcomes,
        uint256 nonce
    ) internal view returns (bytes memory signature) {
        bytes32[] memory allowanceHashes = new bytes32[](allowances.length);
        for (uint256 i; i < allowances.length; ++i) {
            allowanceHashes[i] = keccak256(
                abi.encode(
                    keccak256(bytes("Allowance(address token,uint256 amount)")),
                    allowances[i].token,
                    allowances[i].allocated
                )
            );
        }
        bytes32[] memory outputHashes = new bytes32[](outcomes.length);
        for (uint256 i; i < outcomes.length; ++i) {
            outputHashes[i] = keccak256(
                abi.encode(
                    keccak256(bytes("Outcome(address token,uint256 amount,address destination)")),
                    outcomes[i].token,
                    outcomes[i].amount,
                    outcomes[i].destination
                )
            );
        }
        bytes32 structHash;
        if (isV2) {
            structHash = keccak256(
                abi.encode(
                    LibExecutionConstraintV2.EXECUTION_CONSTRAINT_V2_TYPE_HASH,
                    keccak256(abi.encodePacked(allowanceHashes)),
                    keccak256(abi.encodePacked(outputHashes)),
                    executor,
                    nonce,
                    bytes32(0),
                    bytes32(0)
                )
            );
        } else {
            structHash = keccak256(
                abi.encode(
                    LibExecutionConstraint.EXECUTION_CONSTRAINT_TYPE_HASH,
                    keccak256(abi.encodePacked(allowanceHashes)),
                    keccak256(abi.encodePacked(outputHashes)),
                    executor,
                    nonce
                )
            );
        }
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", IEIP712(validator).DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, digest);
        signature = abi.encodePacked(r, s, v);
    }

    function settle(
        bool viaV2,
        uint256 nonce,
        uint256 deliverAmount,
        uint256 committedAmount,
        bytes memory signature
    ) internal {
        settleTo(viaV2, nonce, deliverAmount, committedAmount, signature, viaV2 ? address(v2) : address(v1));
    }

    /// @param deliverTo Where the fill sends the outcome token. Both validators
    /// require the validator itself; any other recipient fails the outcome check.
    function settleTo(
        bool viaV2,
        uint256 nonce,
        uint256 deliverAmount,
        uint256 committedAmount,
        bytes memory signature,
        address deliverTo
    ) internal {
        (AllowanceSpend[] memory allowances, Outcome[] memory outcomes) = constraintParts(committedAmount);
        bytes memory payload = abi.encodeCall(Swapper.swap, (outToken, deliverAmount, deliverTo));

        vm.prank(executor);
        if (viaV2) {
            v2.entry(
                address(swapper),
                payload,
                signer,
                nonce,
                allowances,
                outcomes,
                bytes32(0),
                bytes32(0),
                hex"",
                new bytes[](0),
                signature
            );
        } else {
            v1.entry(address(swapper), payload, signer, nonce, allowances, outcomes, signature);
        }
    }

    function prepare(
        address validator
    ) internal {
        inToken.mint(signer, SPEND);
        vm.prank(signer);
        inToken.approve(validator, type(uint256).max);
    }

    function signatureFor(
        bool isV2,
        uint256 nonce,
        uint256 committedAmount
    ) internal view returns (bytes memory) {
        (AllowanceSpend[] memory allowances, Outcome[] memory outcomes) = constraintParts(committedAmount);
        return sign(isV2 ? address(v2) : address(v1), isV2, allowances, outcomes, nonce);
    }

    function test_parity_happyPath() external {
        prepare(address(v1));
        settle(false, 1, DELIVER, DELIVER, signatureFor(false, 1, DELIVER));
        uint256 destAfterV1 = outToken.balanceOf(destination);
        uint256 swapperAfterV1 = inToken.balanceOf(address(swapper));
        assertTrue(v1.spentNonces(signer, 1));

        prepare(address(v2));
        settle(true, 1, DELIVER, DELIVER, signatureFor(true, 1, DELIVER));
        assertTrue(v2.spentNonces(signer, 1));

        assertEq(outToken.balanceOf(destination), destAfterV1 + DELIVER, "identical delivery");
        assertEq(inToken.balanceOf(address(swapper)), swapperAfterV1 + SPEND, "identical allowance pull");
        assertEq(outToken.balanceOf(address(v1)), 0, "v1 forwarded everything");
        assertEq(outToken.balanceOf(address(v2)), 0, "v2 forwarded everything");
    }

    function test_parity_floorViolation() external {
        prepare(address(v1));
        bytes memory sigV1 = signatureFor(false, 1, DELIVER);
        vm.expectRevert(abi.encodeWithSelector(CATValidator.InvalidTokenAmount.selector, DELIVER, DELIVER - 1));
        settle(false, 1, DELIVER - 1, DELIVER, sigV1);

        prepare(address(v2));
        bytes memory sigV2 = signatureFor(true, 1, DELIVER);
        vm.expectRevert(abi.encodeWithSelector(CATValidatorV2.InvalidTokenAmount.selector, DELIVER, DELIVER - 1));
        settle(true, 1, DELIVER - 1, DELIVER, sigV2);
    }

    /// @dev Zenith 6.1.1: a fill that pays the destination directly, bypassing
    /// the validator, fails the outcome check on both validators even though
    /// the destination received the full amount.
    function test_parity_deliveryToDestinationRejected() external {
        prepare(address(v1));
        bytes memory sigV1 = signatureFor(false, 1, DELIVER);
        vm.expectRevert(abi.encodeWithSelector(CATValidator.InvalidTokenAmount.selector, DELIVER, 0));
        settleTo(false, 1, DELIVER, DELIVER, sigV1, destination);

        prepare(address(v2));
        bytes memory sigV2 = signatureFor(true, 1, DELIVER);
        vm.expectRevert(abi.encodeWithSelector(CATValidatorV2.InvalidTokenAmount.selector, DELIVER, 0));
        settleTo(true, 1, DELIVER, DELIVER, sigV2, destination);
    }

    function test_parity_nonceReuse() external {
        prepare(address(v1));
        prepare(address(v1));
        bytes memory sigV1 = signatureFor(false, 7, DELIVER);
        settle(false, 7, DELIVER, DELIVER, sigV1);
        vm.expectRevert(CATValidator.NonceAlreadySpent.selector);
        settle(false, 7, DELIVER, DELIVER, sigV1);

        prepare(address(v2));
        prepare(address(v2));
        bytes memory sigV2 = signatureFor(true, 7, DELIVER);
        settle(true, 7, DELIVER, DELIVER, sigV2);
        vm.expectRevert(CATValidatorV2.NonceAlreadySpent.selector);
        settle(true, 7, DELIVER, DELIVER, sigV2);
    }

    function test_parity_badSignature() external {
        prepare(address(v1));
        vm.expectRevert(CATValidator.BadSignature.selector);
        settle(false, 1, DELIVER, DELIVER, hex"");

        prepare(address(v2));
        vm.expectRevert(CATValidatorV2.BadSignature.selector);
        settle(true, 1, DELIVER, DELIVER, hex"");
    }

    function test_parity_perpetualNonceZero() external {
        prepare(address(v1));
        prepare(address(v1));
        bytes memory sigV1 = signatureFor(false, 0, DELIVER);
        settle(false, 0, DELIVER, DELIVER, sigV1);
        settle(false, 0, DELIVER, DELIVER, sigV1);
        assertFalse(v1.spentNonces(signer, 0), "perpetual nonce never spent");

        prepare(address(v2));
        prepare(address(v2));
        bytes memory sigV2 = signatureFor(true, 0, DELIVER);
        settle(true, 0, DELIVER, DELIVER, sigV2);
        settle(true, 0, DELIVER, DELIVER, sigV2);
        assertFalse(v2.spentNonces(signer, 0), "perpetual nonce never spent");
    }

    /// @dev A signature over the v1 constraint must never authorize the same
    /// fields on v2 (domain version bump): cross-domain replay is impossible.
    function test_parity_noCrossDomainReplay() external {
        prepare(address(v2));
        bytes memory sigV1 = signatureFor(false, 1, DELIVER);
        vm.expectRevert(CATValidatorV2.BadSignature.selector);
        settle(true, 1, DELIVER, DELIVER, sigV1);
    }
}
