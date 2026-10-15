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

/// @dev Token that enforces a per-transfer cap (C2: the validator's
/// full-balance forward exceeds the cap, so the payment step always reverts).
contract CappedToken is MockERC20 {
    uint256 public immutable cap;

    constructor(
        uint256 cap_
    ) MockERC20("Capped", "CAP", 18) {
        cap = cap_;
    }

    function transfer(
        address to,
        uint256 amount
    ) public override returns (bool) {
        require(amount <= cap, "cap exceeded");
        return super.transfer(to, amount);
    }
}

/// @dev Native receiver that always reverts (C7: committed destination becomes
/// unpayable; the push forward bricks every settlement of the constraint).
contract RevertingReceiver {
    receive() external payable {
        revert("no payments accepted");
    }
}

contract LivenessAndSemanticsPoC is Test {
    uint256 constant MAGIC = 1 << 255;

    CATValidatorV2 validator;
    CappedToken capped;
    MockERC20 token;

    address signer;
    uint256 signerKey;
    address executor;
    address destination;

    function setUp() external {
        validator = new CATValidatorV2(address(new AcceptVM()));
        capped = new CappedToken(100 ether);
        token = new MockERC20("Token", "TKN", 18);
        (signer, signerKey) = makeAddrAndKey("signer");
        executor = makeAddr("executor");
        destination = makeAddr("destination");
    }

    function sign(
        AllowanceSpend[] memory alls,
        Outcome[] memory outs
    ) internal view returns (bytes memory) {
        bytes32[] memory allowanceHashes = new bytes32[](alls.length);
        for (uint256 i; i < alls.length; ++i) {
            allowanceHashes[i] = keccak256(
                abi.encode(
                    keccak256(bytes("Allowance(address token,uint256 amount)")), alls[i].token, alls[i].allocated
                )
            );
        }
        bytes32[] memory outcomeHashes = new bytes32[](outs.length);
        for (uint256 i; i < outs.length; ++i) {
            outcomeHashes[i] = keccak256(
                abi.encode(
                    keccak256(bytes("Outcome(address token,uint256 amount,address destination)")),
                    outs[i].token,
                    outs[i].amount,
                    outs[i].destination
                )
            );
        }
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256(
                    bytes(
                        "ExecutionConstraint(Allowance[] allowances,Outcome[] outcomes,address executor,uint256 nonce,address executionTarget,bytes32 payloadHash,bytes32 validationProgramHash,bytes32 paramsHash)Allowance(address token,uint256 amount)Outcome(address token,uint256 amount,address destination)"
                    )
                ),
                keccak256(abi.encodePacked(allowanceHashes)),
                keccak256(abi.encodePacked(outcomeHashes)),
                executor,
                uint256(1),
                address(0),
                bytes32(0),
                bytes32(0),
                bytes32(0)
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", validator.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, digest);
        return abi.encodePacked(r, s, v);
    }

    /// C2: the fill delivers 1000 CAP to the validator, but the token caps
    /// transfers at 100 — `_validatePayment`'s single full-balance forward
    /// reverts, and no settlement of this constraint can ever succeed.
    function test_cappedTokenOutcome_bricksSettlement() external {
        // The fill's delivery to the validator (mint models delivery; the cap
        // applies to transfers only).
        capped.mint(address(validator), 1000 ether);
        Outcome[] memory outs = new Outcome[](1);
        outs[0] = Outcome({ token: address(capped), amount: 900 ether, destination: destination });
        bytes memory sig = sign(new AllowanceSpend[](0), outs);

        vm.prank(executor);
        vm.expectRevert(); // solady SafeTransferLib.TransferFailed(): the forward exceeds the cap
        validator.entry(
            address(0),
            hex"",
            signer,
            1,
            new AllowanceSpend[](0),
            outs,
            ExecutionBinding({ executionTarget: address(0), payloadHash: bytes32(0) }),
            new VMCommand[](0),
            new bytes32[](0),
            sig
        );
    }

    /// C7: a committed native outcome destination that reverts on receipt makes
    /// every settlement revert at the push forward; the constraint is bricked.
    function test_revertingNativeDestination_bricksSettlement() external {
        RevertingReceiver recv = new RevertingReceiver();
        Outcome[] memory outs = new Outcome[](1);
        outs[0] = Outcome({ token: address(0), amount: 1 ether, destination: address(recv) });
        bytes memory sig = sign(new AllowanceSpend[](0), outs);
        vm.deal(address(validator), 1 ether); // the fill's delivery to the validator

        vm.prank(executor);
        vm.expectRevert();
        validator.entry(
            address(0),
            hex"",
            signer,
            1,
            new AllowanceSpend[](0),
            outs,
            ExecutionBinding({ executionTarget: address(0), payloadHash: bytes32(0) }),
            new VMCommand[](0),
            new bytes32[](0),
            sig
        );
    }

    /// C3: a native-token MAGIC allowance computes a spent value in the replay
    /// (via native-aware `_balanceOf`) but the v1 loop it mirrors reverts
    /// `BalanceOfFailed` on the same input; settlement fails closed.
    function test_nativeMagicAllowance_failsClosed() external {
        AllowanceSpend[] memory alls = new AllowanceSpend[](1);
        alls[0] = AllowanceSpend({ token: address(0), allocated: type(uint256).max, spend: MAGIC });
        bytes memory sig = sign(alls, new Outcome[](0));
        vm.deal(signer, 5 ether);

        vm.prank(executor);
        vm.expectRevert(abi.encodeWithSelector(CATValidator.BalanceOfFailed.selector, address(0)));
        validator.entry(
            address(0),
            hex"",
            signer,
            1,
            alls,
            new Outcome[](0),
            ExecutionBinding({ executionTarget: address(0), payloadHash: bytes32(0) }),
            new VMCommand[](0),
            new bytes32[](0),
            sig
        );
    }
}
