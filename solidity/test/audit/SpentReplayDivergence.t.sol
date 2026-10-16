// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { Test } from "forge-std/src/Test.sol";

import { MockERC20 } from "solady/test/utils/mocks/MockERC20.sol";

import { CATValidator } from "../../src/CATValidator.sol";
import { CATValidatorV2 } from "../../src/CATValidatorV2.sol";
import { AllowanceSpend, Outcome } from "../../src/libs/LibExecutionConstraint.sol";
import { ExecutionBinding } from "../../src/libs/LibExecutionConstraintV2.sol";
import { LibValidationVM, VMCommand, VMState } from "../../src/libs/LibValidationVM.sol";

/// @dev Token whose `transferFrom(from, to, amount)` credits `to` with `amount`
/// but debits `from` less than `amount` (1% loss scaled up from stETH-style
/// share rounding, where each transfer can leave the sender's `balanceOf` 1-2
/// wei higher than the nominal amount implies).
contract LossyDebitToken is MockERC20 {
    constructor() MockERC20("Lossy", "LOSS", 18) { }

    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) public override returns (bool) {
        _transfer(from, to, amount);
        _mint(from, amount / 100); // sender is debited 1% less than the nominal amount
        return true;
    }
}

/// @dev Accepts every program.
contract AcceptVM {
    fallback() external { }
}

/// @dev Reverts with its calldata so the test sees the exact registers the VM
/// was called with (wrapped by `ValidationFailed`).
contract EchoVM {
    fallback() external {
        assembly ("memory-safe") {
            calldatacopy(0, 0, calldatasize())
            revert(0, calldatasize())
        }
    }
}

/// @dev `balanceOf` returns no data; `transferFrom` counts its calls and would
/// succeed, so a test can prove the loop never reached it.
contract BrokenBalanceOfToken {
    uint256 public transferFromCalls;

    function balanceOf(
        address
    ) external pure { }

    function transferFrom(
        address,
        address,
        uint256
    ) external returns (bool) {
        ++transferFromCalls;
        return true;
    }
}

/// @dev Its `transferFrom` moves the nominal amount and then, as a hook would,
/// mints `donation` of another token into the sender (the escrow), so a later
/// MAGIC allowance of that token sees a larger balance.
contract DonatingToken is MockERC20 {
    MockERC20 immutable donated;
    uint256 immutable donation;

    constructor(
        MockERC20 donated_,
        uint256 donation_
    ) MockERC20("Donating", "DON", 18) {
        donated = donated_;
        donation = donation_;
    }

    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) public override returns (bool) {
        _transfer(from, to, amount);
        donated.mint(from, donation);
        return true;
    }
}

/**
 * Regression for audit Finding 3: the `spent[]` register matches v1's actual
 * pull for tokens whose `balanceOf` does not move 1:1 with the nominal transfer
 * amount. Run A measures the real pull (901 ether); run B proves the VM register
 * file carries 901 ether, recorded by the allowance loop at pull time instead of
 * simulated from a pre-pull balance read.
 */
contract SpentReplayDivergencePoC is Test {
    uint256 constant MAGIC = 1 << 255;

    LossyDebitToken lossy;
    CATValidatorV2 acceptValidator;
    CATValidatorV2 echoValidator;
    LibValidationVMHarness lib;

    address signer;
    uint256 signerKey;
    address executor;
    address execTarget;

    function setUp() external {
        lossy = new LossyDebitToken();
        acceptValidator = new CATValidatorV2(address(new AcceptVM()));
        echoValidator = new CATValidatorV2(address(new EchoVM()));
        lib = new LibValidationVMHarness();
        (signer, signerKey) = makeAddrAndKey("signer");
        executor = makeAddr("executor");
        execTarget = makeAddr("execTarget");

        lossy.mint(signer, 1000 ether);
        vm.prank(signer);
        lossy.approve(address(acceptValidator), type(uint256).max);
        vm.prank(signer);
        lossy.approve(address(echoValidator), type(uint256).max);
    }

    function oneProgram() internal pure returns (VMCommand[] memory program) {
        program = new VMCommand[](1);
        program[0] = VMCommand({ op: 8, data: bytes32(0) });
    }

    function allowances() internal view returns (AllowanceSpend[] memory alls) {
        alls = new AllowanceSpend[](2);
        alls[0] = AllowanceSpend({ token: address(lossy), allocated: type(uint256).max, spend: 100 ether });
        alls[1] = AllowanceSpend({ token: address(lossy), allocated: type(uint256).max, spend: MAGIC });
    }

    function sign(
        CATValidatorV2 target,
        AllowanceSpend[] memory alls,
        bytes32 programHash
    ) internal view returns (bytes memory) {
        bytes32[] memory allowanceHashes = new bytes32[](alls.length);
        for (uint256 i; i < alls.length; ++i) {
            allowanceHashes[i] = keccak256(
                abi.encode(
                    keccak256(bytes("Allowance(address token,uint256 amount)")), alls[i].token, alls[i].allocated
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
                keccak256(abi.encodePacked(new bytes32[](0))),
                executor,
                uint256(1),
                address(0),
                bytes32(0),
                programHash,
                bytes32(0)
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", target.DOMAIN_SEPARATOR(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, digest);
        return abi.encodePacked(r, s, v);
    }

    /// The escrow actually loses 990 ether: the literal pull moves 100 (escrow
    /// debited 99), the MAGIC pull then resolves to the true balance 901.
    function test_runA_actualPullIs901() external {
        AllowanceSpend[] memory alls = allowances();
        VMCommand[] memory program = oneProgram();
        bytes memory sig = sign(acceptValidator, alls, keccak256(abi.encode(program)));

        vm.prank(executor);
        acceptValidator.entry(
            execTarget,
            hex"",
            signer,
            1,
            alls,
            new Outcome[](0),
            ExecutionBinding({ executionTarget: address(0), payloadHash: bytes32(0) }),
            program,
            new bytes32[](0),
            sig
        );

        assertEq(lossy.balanceOf(execTarget), 1001 ether, "execTarget received literal 100 + magic 901");
        // The MAGIC pull is the in-loop balance read after the literal pull: 901
        // ether, 1 ether (the 1% the first transfer did not debit) more than a
        // pre-pull simulation would claim. Run B pins the register at 901.
        assertEq(lossy.balanceOf(signer), 9.01 ether, "escrow keeps the minted-back rounding");
    }

    /// The register file the VM sees carries spent[1] == 901: the balance the
    /// loop reads when it reaches the MAGIC allowance, after the literal pull
    /// debited the escrow by 99 rather than the nominal 100. A committed rate
    /// check `paid * den >= spent * num` therefore evaluates against the amount
    /// the escrow really lost.
    function test_runB_registerClaims901() external {
        AllowanceSpend[] memory alls = allowances();
        VMCommand[] memory program = oneProgram();
        bytes32 programHash = keccak256(abi.encode(program));
        bytes memory sig = sign(echoValidator, alls, programHash);

        uint256[] memory spent = new uint256[](2);
        spent[0] = 100 ether;
        spent[1] = 901 ether; // recorded at pull time: 1000 - 99 (actual debit)

        bytes memory runVM = abi.encodeWithSelector(
            LibValidationVM.RUN_VM_SELECTOR,
            program,
            VMState(lib.buildRegisters(new bytes32[](0), signer, spent, new uint256[](0)))
        );
        bytes memory expected = abi.encodeWithSelector(CATValidatorV2.ValidationFailed.selector, runVM);

        vm.prank(executor);
        vm.expectRevert(expected);
        echoValidator.entry(
            execTarget,
            hex"",
            signer,
            1,
            alls,
            new Outcome[](0),
            ExecutionBinding({ executionTarget: address(0), payloadHash: bytes32(0) }),
            program,
            new bytes32[](0),
            sig
        );
    }

    /// The allocation check runs against the recorded amount, not a stale
    /// simulation: a MAGIC allowance allocated 900 reverts because the loop reads
    /// 901, and the literal pull before it rolls back.
    function test_magicAllocationChecksTheRecordedAmount() external {
        AllowanceSpend[] memory alls = allowances();
        alls[1].allocated = 900 ether;
        VMCommand[] memory program = oneProgram();
        bytes memory sig = sign(acceptValidator, alls, keccak256(abi.encode(program)));

        vm.prank(executor);
        vm.expectRevert(abi.encodeWithSelector(CATValidator.AllocationTooSmall.selector, 900 ether, 901 ether));
        acceptValidator.entry(
            execTarget,
            hex"",
            signer,
            1,
            alls,
            new Outcome[](0),
            ExecutionBinding({ executionTarget: address(0), payloadHash: bytes32(0) }),
            program,
            new bytes32[](0),
            sig
        );

        assertEq(lossy.balanceOf(execTarget), 0, "the literal pull rolled back");
        assertEq(lossy.balanceOf(signer), 1000 ether, "escrow untouched");
    }

    /// A MAGIC allowance on a token whose `balanceOf` returns no data fails
    /// closed with `BalanceOfFailed`, as in v1, and never reaches `transferFrom`.
    /// The literal pull that ran before it rolls back.
    function test_magicOnBrokenBalanceOfFailsClosed() external {
        BrokenBalanceOfToken broken = new BrokenBalanceOfToken();
        AllowanceSpend[] memory alls = allowances();
        alls[1].token = address(broken);
        VMCommand[] memory program = oneProgram();
        bytes memory sig = sign(acceptValidator, alls, keccak256(abi.encode(program)));

        vm.prank(executor);
        vm.expectRevert(abi.encodeWithSelector(CATValidator.BalanceOfFailed.selector, address(broken)));
        acceptValidator.entry(
            execTarget,
            hex"",
            signer,
            1,
            alls,
            new Outcome[](0),
            ExecutionBinding({ executionTarget: address(0), payloadHash: bytes32(0) }),
            program,
            new bytes32[](0),
            sig
        );

        assertEq(lossy.balanceOf(execTarget), 0, "the literal pull rolled back");
        assertEq(broken.transferFromCalls(), 0, "the broken token was never pulled");
    }

    /// An earlier allowance whose transfer moves the escrow's balance of a later
    /// MAGIC token (a hook donating 5 ether into the escrow) is reported as v1
    /// pulls it: the register carries the balance after the donation, 1005.
    function test_magicAfterDonatingPullRecordsTheDonatedBalance() external {
        DonatingToken donating = new DonatingToken(lossy, 5 ether);
        donating.mint(signer, 100 ether);
        vm.prank(signer);
        donating.approve(address(echoValidator), type(uint256).max);

        AllowanceSpend[] memory alls = allowances();
        alls[0].token = address(donating);
        VMCommand[] memory program = oneProgram();
        bytes memory sig = sign(echoValidator, alls, keccak256(abi.encode(program)));

        uint256[] memory spent = new uint256[](2);
        spent[0] = 100 ether;
        spent[1] = 1005 ether; // 1000 held plus the 5 the first pull donated

        bytes memory runVM = abi.encodeWithSelector(
            LibValidationVM.RUN_VM_SELECTOR,
            program,
            VMState(lib.buildRegisters(new bytes32[](0), signer, spent, new uint256[](0)))
        );

        vm.prank(executor);
        vm.expectRevert(abi.encodeWithSelector(CATValidatorV2.ValidationFailed.selector, runVM));
        echoValidator.entry(
            execTarget,
            hex"",
            signer,
            1,
            alls,
            new Outcome[](0),
            ExecutionBinding({ executionTarget: address(0), payloadHash: bytes32(0) }),
            program,
            new bytes32[](0),
            sig
        );
    }
}

/// @dev Calldata trampoline for the library's calldata-typed params.
contract LibValidationVMHarness {
    function buildRegisters(
        bytes32[] calldata params,
        address account,
        uint256[] calldata spent,
        uint256[] calldata paid
    ) external pure returns (bytes[] memory) {
        return LibValidationVM.buildRegisters(params, account, spent, paid);
    }
}
