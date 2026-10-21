// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { Test } from "forge-std/src/Test.sol";
import { SafeTransferLib } from "solady/src/utils/SafeTransferLib.sol";
import { MockERC20 } from "solady/test/utils/mocks/MockERC20.sol";

import { CATValidator } from "../../src/CATValidator.sol";
import { CATValidatorV1_1 } from "../../src/CATValidatorV1_1.sol";
import { CATValidatorV1_1Tron } from "../../src/CATValidatorV1_1.tron.sol";
import { Catapultar } from "../../src/Catapultar.sol";
import { CatapultarFactory } from "../../src/CatapultarFactory.sol";
import { KeyedOwnable } from "../../src/libs/KeyedOwnable.sol";
import { AllowanceSpend, Outcome } from "../../src/libs/LibExecutionConstraint.sol";
import { LibExecutionConstraintV1_1 } from "../../src/libs/LibExecutionConstraintV1_1.sol";
import { SafeTransferLibTron } from "../../src/libs/SafeTransferLib.tron.sol";

import { MockTronUSDT } from "../mocks/MockTronUSDT.sol";

interface IPulledTron {
    function pulled(
        address token
    ) external view returns (uint256);
}

contract TypehashHelperTron {
    function v11(
        AllowanceSpend[] calldata allowances,
        Outcome[] calldata outcomes,
        address executor,
        uint256 nonce,
        address executionTarget,
        bytes32 payloadHash
    ) external pure returns (bytes32) {
        return LibExecutionConstraintV1_1.typehash(allowances, outcomes, executor, nonce, executionTarget, payloadHash);
    }
}

/// @dev Outcome token that only the validator can forward: `transfer` reverts, so a payout works only through
/// `allowance(validator, validator)` and `transferFrom`, the way the ledger's receipt is paid on Tron.
contract ForwardOnlyToken {
    address public immutable VALIDATOR;
    uint256 public held;
    mapping(address => uint256) public forwarded;

    constructor(
        address validator
    ) {
        VALIDATOR = validator;
    }

    function setHeld(
        uint256 amount
    ) external {
        held = amount;
    }

    function balanceOf(
        address account
    ) external view returns (uint256) {
        return account == VALIDATOR ? held : forwarded[account];
    }

    function allowance(
        address owner,
        address spender
    ) external view returns (uint256) {
        return owner == VALIDATOR && spender == VALIDATOR ? type(uint256).max : 0;
    }

    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) external returns (bool) {
        require(msg.sender == VALIDATOR && from == VALIDATOR && amount == held, "not the validator");
        held = 0;
        forwarded[to] += amount;
        return true;
    }
}

/// @dev Solver executor: records what v1.1 published and holds, then delivers outcomes to the validator as
/// IntentExecutorTron does.
contract MockExecutorTron {
    mapping(address => uint256) public seenPulled;
    mapping(address => uint256) public seenBalance;

    function settle(
        address validator,
        address[] calldata pulledTokens,
        address[] calldata outTokens,
        uint256[] calldata outAmounts
    ) external {
        for (uint256 i; i < pulledTokens.length; ++i) {
            seenPulled[pulledTokens[i]] = IPulledTron(validator).pulled(pulledTokens[i]);
            seenBalance[pulledTokens[i]] = SafeTransferLib.balanceOf(pulledTokens[i], address(this));
        }
        for (uint256 i; i < outTokens.length; ++i) {
            SafeTransferLibTron.safeTransfer(outTokens[i], validator, outAmounts[i]);
        }
    }

    function payWithSolady(
        address token,
        address dest,
        uint256 amount
    ) external {
        SafeTransferLib.safeTransfer(token, dest, amount);
    }
}

contract CATValidatorV1_1TronTest is Test {
    uint256 constant TRON_CHAIN_ID = 728126428;
    uint256 constant DEPOSIT = 1_000e6;
    uint256 constant SPEND_MAGIC = 1 << 255;
    bytes32 constant EMPTY_HASH = keccak256("");
    uint256 constant RESIDUE = 5e6;

    CATValidatorV1_1 v11;
    MockTronUSDT usdt;
    MockERC20 std;
    MockExecutorTron exec;
    CatapultarFactory factory;
    TypehashHelperTron thh;

    address executor = makeAddr("executor");

    function setUp() external {
        vm.chainId(TRON_CHAIN_ID);
        v11 = CATValidatorV1_1(payable(address(new CATValidatorV1_1Tron())));
        usdt = new MockTronUSDT();
        std = new MockERC20("Standard", "STD", 18);
        exec = new MockExecutorTron();
        factory = new CatapultarFactory();
        thh = new TypehashHelperTron();
    }

    function isValidSignature(
        bytes32,
        bytes calldata
    ) public pure returns (bytes4) {
        return bytes4(0x1626ba7e);
    }

    // ---- helpers ----

    function _one(
        address a
    ) internal pure returns (address[] memory r) {
        r = new address[](1);
        r[0] = a;
    }

    function _two(
        address a,
        address b
    ) internal pure returns (address[] memory r) {
        r = new address[](2);
        r[0] = a;
        r[1] = b;
    }

    function _amounts(
        uint256 a
    ) internal pure returns (uint256[] memory r) {
        r = new uint256[](1);
        r[0] = a;
    }

    function _none() internal pure returns (address[] memory r) { }

    function _spend(
        address t,
        uint256 allocated,
        uint256 spend
    ) internal pure returns (AllowanceSpend[] memory a) {
        a = new AllowanceSpend[](1);
        a[0] = AllowanceSpend({ token: t, allocated: allocated, spend: spend });
    }

    function _out(
        address t,
        uint256 amount,
        address dest
    ) internal pure returns (Outcome[] memory o) {
        o = new Outcome[](1);
        o[0] = Outcome({ token: t, amount: amount, destination: dest });
    }

    function _settle(
        address[] memory pulledTokens,
        address[] memory outTokens,
        uint256[] memory outAmounts
    ) internal view returns (bytes memory) {
        return abi.encodeCall(MockExecutorTron.settle, (address(v11), pulledTokens, outTokens, outAmounts));
    }

    function _fundSelf(
        address token,
        uint256 amount
    ) internal {
        MockERC20(token).mint(address(this), amount);
        MockERC20(token).approve(address(v11), type(uint256).max);
    }

    function _v11Digest(
        AllowanceSpend[] memory a,
        Outcome[] memory o,
        uint256 nonce,
        address executionTarget,
        bytes32 payloadHash
    ) internal view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                hex"1901", v11.DOMAIN_SEPARATOR(), thh.v11(a, o, executor, nonce, executionTarget, payloadHash)
            )
        );
    }

    function _deployEscrow(
        address ownerAddr,
        bytes32 digest
    ) internal returns (address payable escrow) {
        bytes32[] memory ownerArr = new bytes32[](1);
        ownerArr[0] = bytes32(uint256(uint160(ownerAddr)));
        bytes32 salt = bytes32(uint256(uint160(ownerAddr)) << 96);
        escrow = factory.deployWithDigest(KeyedOwnable.PublicKeyType.ECDSAOrSmartContract, ownerArr, salt, digest, true);
    }

    function _assertValidatorClean(
        address token,
        address[] memory spenders
    ) internal view {
        assertEq(SafeTransferLib.balanceOf(token, address(v11)), 0, "validator holds nothing");
        for (uint256 i; i < spenders.length; ++i) {
            assertEq(MockERC20(token).allowance(address(v11), spenders[i]), 0, "validator grants no allowance");
        }
        assertEq(v11.pulled(token), 0, "pulled cleared");
    }

    // ---- domain ----

    function test_domain_separator_binds_tron_chain_id() external view {
        bytes32 expected = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("CAT Validator")),
                keccak256(bytes("1.1")),
                TRON_CHAIN_ID,
                address(v11)
            )
        );
        assertEq(v11.DOMAIN_SEPARATOR(), expected);
    }

    // ---- pulls (transferFrom, which Tron USDT answers with true) ----

    function test_fuzz_pull_tronUsdt_pulled_equals_balance_moved(
        uint128 spend
    ) external {
        _fundSelf(address(usdt), spend);

        vm.prank(executor);
        v11.entry(
            address(exec),
            _settle(_one(address(usdt)), _none(), new uint256[](0)),
            address(this),
            1,
            _spend(address(usdt), spend, spend),
            new Outcome[](0),
            address(0),
            0,
            ""
        );

        assertEq(usdt.balanceOf(address(this)), 0, "escrow debited");
        assertEq(exec.seenPulled(address(usdt)), spend, "published pulled");
        assertEq(exec.seenBalance(address(usdt)), spend, "balance moved == pulled");
        _assertValidatorClean(address(usdt), _two(address(exec), address(v11)));
    }

    function test_fuzz_pull_tronUsdt_balance_sweep_magic(
        uint128 balance
    ) external {
        _fundSelf(address(usdt), balance);

        vm.prank(executor);
        v11.entry(
            address(exec),
            _settle(_one(address(usdt)), _none(), new uint256[](0)),
            address(this),
            1,
            _spend(address(usdt), type(uint256).max, SPEND_MAGIC),
            new Outcome[](0),
            address(0),
            0,
            ""
        );

        assertEq(exec.seenPulled(address(usdt)), balance);
        assertEq(exec.seenBalance(address(usdt)), balance);
        assertEq(usdt.balanceOf(address(this)), 0);
        _assertValidatorClean(address(usdt), _one(address(exec)));
    }

    function test_pull_tronUsdt_and_standard_publish_per_token() external {
        _fundSelf(address(usdt), DEPOSIT);
        _fundSelf(address(std), 2 ether);
        AllowanceSpend[] memory a = new AllowanceSpend[](2);
        a[0] = AllowanceSpend({ token: address(usdt), allocated: DEPOSIT, spend: DEPOSIT });
        a[1] = AllowanceSpend({ token: address(std), allocated: 2 ether, spend: 2 ether });

        vm.prank(executor);
        v11.entry(
            address(exec),
            _settle(_two(address(usdt), address(std)), _none(), new uint256[](0)),
            address(this),
            1,
            a,
            new Outcome[](0),
            address(0),
            0,
            ""
        );

        assertEq(exec.seenPulled(address(usdt)), DEPOSIT);
        assertEq(exec.seenBalance(address(usdt)), DEPOSIT);
        assertEq(exec.seenPulled(address(std)), 2 ether);
        assertEq(exec.seenBalance(address(std)), 2 ether);
        _assertValidatorClean(address(usdt), _one(address(exec)));
        _assertValidatorClean(address(std), _one(address(exec)));
    }

    // ---- outcomes (delivered to the validator, forwarded by approve(self) + transferFrom(self)) ----

    function test_fuzz_outcome_tronUsdt_forwarded_by_validator(
        uint128 outAmount
    ) external {
        address dest = makeAddr("dest");
        _fundSelf(address(std), DEPOSIT);
        usdt.mint(address(exec), outAmount);

        vm.prank(executor);
        v11.entry(
            address(exec),
            _settle(_one(address(std)), _one(address(usdt)), _amounts(outAmount)),
            address(this),
            1,
            _spend(address(std), DEPOSIT, DEPOSIT),
            _out(address(usdt), outAmount, dest),
            address(0),
            0,
            ""
        );

        assertEq(usdt.balanceOf(dest), outAmount);
        assertEq(exec.seenPulled(address(std)), DEPOSIT);
        _assertValidatorClean(address(usdt), _two(address(exec), dest));
        if (outAmount != 0) assertEq(usdt.allowance(address(v11), address(v11)), type(uint256).max, "self-allowance");
    }

    /// @dev The validator pays a token whose `transfer` reverts through `allowance(self, self)` and `transferFrom`
    /// alone, never `approve`; the ledger's receipt relies on it.
    function test_outcome_forwarded_through_transferFrom_only() external {
        ForwardOnlyToken receipt = new ForwardOnlyToken(address(v11));
        address commit = makeAddr("commit");
        receipt.setHeld(1);

        vm.prank(executor);
        v11.entry(
            address(exec),
            "",
            address(this),
            1,
            new AllowanceSpend[](0),
            _out(address(receipt), 1, commit),
            address(0),
            0,
            ""
        );

        assertEq(receipt.forwarded(commit), 1);
        assertEq(receipt.held(), 0);
    }

    /// @dev A zero outcome settles through the Tron payout without paying anything.
    function test_zero_outcome_is_skipped_on_the_tron_payout() external {
        vm.prank(executor);
        v11.entry(
            address(exec),
            "",
            address(this),
            1,
            new AllowanceSpend[](0),
            _out(address(usdt), 0, makeAddr("dest")),
            address(0),
            0,
            ""
        );
    }

    function test_outcome_tronUsdt_short_reverts_InvalidTokenAmount() external {
        address dest = makeAddr("dest");
        _fundSelf(address(std), DEPOSIT);
        usdt.mint(address(exec), DEPOSIT);

        vm.prank(executor);
        vm.expectRevert(abi.encodeWithSelector(CATValidator.InvalidTokenAmount.selector, DEPOSIT, DEPOSIT - 1));
        v11.entry(
            address(exec),
            _settle(_none(), _one(address(usdt)), _amounts(DEPOSIT - 1)),
            address(this),
            1,
            _spend(address(std), DEPOSIT, DEPOSIT),
            _out(address(usdt), DEPOSIT, dest),
            address(0),
            0,
            ""
        );
    }

    function test_outcome_tronUsdt_zero_destination_pays_account() external {
        _fundSelf(address(std), DEPOSIT);
        usdt.mint(address(exec), DEPOSIT);

        vm.prank(executor);
        v11.entry(
            address(exec),
            _settle(_none(), _one(address(usdt)), _amounts(DEPOSIT)),
            address(this),
            1,
            _spend(address(std), DEPOSIT, DEPOSIT),
            _out(address(usdt), DEPOSIT, address(0)),
            address(0),
            0,
            ""
        );

        assertEq(usdt.balanceOf(address(this)), DEPOSIT);
    }

    function test_outcome_tronUsdt_and_standard_mixed() external {
        address destA = makeAddr("destA");
        address destB = makeAddr("destB");
        _fundSelf(address(usdt), DEPOSIT);
        usdt.mint(address(exec), DEPOSIT);
        std.mint(address(exec), 2 ether);

        Outcome[] memory o = new Outcome[](2);
        o[0] = Outcome({ token: address(usdt), amount: DEPOSIT, destination: destA });
        o[1] = Outcome({ token: address(std), amount: 2 ether, destination: destB });
        uint256[] memory amounts = new uint256[](2);
        amounts[0] = DEPOSIT;
        amounts[1] = 2 ether;

        vm.prank(executor);
        v11.entry(
            address(exec),
            _settle(_one(address(usdt)), _two(address(usdt), address(std)), amounts),
            address(this),
            1,
            _spend(address(usdt), DEPOSIT, DEPOSIT),
            o,
            address(0),
            0,
            ""
        );

        assertEq(usdt.balanceOf(destA), DEPOSIT);
        assertEq(std.balanceOf(destB), 2 ether);
        assertEq(exec.seenPulled(address(usdt)), DEPOSIT);
        _assertValidatorClean(address(usdt), _one(address(exec)));
        _assertValidatorClean(address(std), _one(address(exec)));
    }

    /// @dev The quirk sits in whichever contract calls `transfer()`: an executor on Solady's `safeTransfer` reverts.
    function test_executor_on_solady_safeTransfer_reverts_on_tronUsdt() external {
        address dest = makeAddr("dest");
        _fundSelf(address(std), DEPOSIT);
        usdt.mint(address(exec), DEPOSIT);

        vm.prank(executor);
        vm.expectRevert(SafeTransferLib.TransferFailed.selector);
        v11.entry(
            address(exec),
            abi.encodeCall(MockExecutorTron.payWithSolady, (address(usdt), address(v11), DEPOSIT)),
            address(this),
            1,
            _spend(address(std), DEPOSIT, DEPOSIT),
            _out(address(usdt), DEPOSIT, dest),
            address(0),
            0,
            ""
        );
    }

    // ---- executor wrapper: self-allowance only, standard ERC-20 unchanged ----

    function test_wrapper_self_allowance_not_spendable_by_others() external {
        address dest = makeAddr("dest");
        address attacker = makeAddr("attacker");
        _fundSelf(address(std), DEPOSIT);
        usdt.mint(address(exec), DEPOSIT + 1);

        vm.prank(executor);
        v11.entry(
            address(exec),
            _settle(_none(), _one(address(usdt)), _amounts(DEPOSIT)),
            address(this),
            1,
            _spend(address(std), DEPOSIT, DEPOSIT),
            _out(address(usdt), DEPOSIT, dest),
            address(0),
            0,
            ""
        );

        assertEq(usdt.allowance(address(exec), address(exec)), type(uint256).max, "self-allowance only");
        assertEq(usdt.allowance(address(exec), address(v11)), 0);
        assertEq(usdt.allowance(address(exec), attacker), 0);
        vm.prank(attacker);
        vm.expectRevert();
        usdt.transferFrom(address(exec), attacker, 1);
        _assertValidatorClean(address(usdt), _two(address(exec), attacker));
    }

    function test_wrapper_standard_erc20_outcome() external {
        address dest = makeAddr("dest");
        _fundSelf(address(usdt), DEPOSIT);
        std.mint(address(exec), 2 ether);

        vm.prank(executor);
        v11.entry(
            address(exec),
            _settle(_one(address(usdt)), _one(address(std)), _amounts(2 ether)),
            address(this),
            1,
            _spend(address(usdt), DEPOSIT, DEPOSIT),
            _out(address(std), 2 ether, dest),
            address(0),
            0,
            ""
        );

        assertEq(std.balanceOf(dest), 2 ether);
        assertEq(std.balanceOf(address(exec)), 0);
        _assertValidatorClean(address(std), _two(address(exec), dest));
    }

    // ---- refund path: nonce-0 sweep from a real escrow ----

    function test_refund_nonce0_sweep_tronUsdt_real_escrow() external {
        (address ownerAddr,) = makeAddrAndKey("tronRefundDepositor");
        address refund = makeAddr("tronRefund");
        address sink = makeAddr("sink");

        AllowanceSpend[] memory execA = _spend(address(usdt), DEPOSIT, DEPOSIT);
        Outcome[] memory execO = new Outcome[](0);
        AllowanceSpend[] memory refA = _spend(address(usdt), type(uint256).max, SPEND_MAGIC);
        Outcome[] memory refO = _out(address(usdt), 0, refund);

        address payable escrow = _deployEscrow(ownerAddr, _v11Digest(execA, execO, 1, address(0), 0));
        bytes32 refundDigest = _v11Digest(refA, refO, 0, refund, EMPTY_HASH);
        vm.prank(ownerAddr);
        Catapultar(escrow).setSignature(refundDigest, Catapultar.DigestApproval.Signature);
        vm.prank(escrow);
        usdt.approve(address(v11), type(uint256).max);
        usdt.mint(escrow, DEPOSIT + RESIDUE);

        vm.startPrank(executor);
        v11.entry(sink, "", escrow, 1, execA, execO, address(0), 0, "");
        assertEq(usdt.balanceOf(sink), DEPOSIT);

        v11.entry(refund, "", escrow, 0, refA, refO, refund, EMPTY_HASH, "");
        assertEq(usdt.balanceOf(refund), RESIDUE, "residue swept");

        usdt.mint(escrow, 123e6);
        v11.entry(refund, "", escrow, 0, refA, refO, refund, EMPTY_HASH, "");
        assertEq(usdt.balanceOf(refund), RESIDUE + 123e6, "late deposit swept");

        v11.entry(refund, "", escrow, 0, refA, refO, refund, EMPTY_HASH, "");
        vm.stopPrank();
        assertEq(usdt.balanceOf(refund), RESIDUE + 123e6, "empty sweep is a no-op");
        assertEq(usdt.balanceOf(escrow), 0);
        _assertValidatorClean(address(usdt), _three(sink, refund, escrow));
    }

    function test_zero_refund_address_fails_closed_on_tron() external {
        (address ownerAddr,) = makeAddrAndKey("tronZeroRefundDepositor");
        AllowanceSpend[] memory refA = _spend(address(usdt), type(uint256).max, SPEND_MAGIC);
        Outcome[] memory refO = _out(address(usdt), 0, address(0));
        address payable escrow = _deployEscrow(
            ownerAddr, _v11Digest(_spend(address(usdt), DEPOSIT, DEPOSIT), new Outcome[](0), 1, address(0), 0)
        );
        bytes32 refundDigest = _v11Digest(refA, refO, 0, address(0), keccak256(""));
        vm.prank(ownerAddr);
        Catapultar(escrow).setSignature(refundDigest, Catapultar.DigestApproval.Signature);
        vm.prank(escrow);
        usdt.approve(address(v11), type(uint256).max);
        usdt.mint(escrow, DEPOSIT);

        address attacker = makeAddr("attacker");
        vm.prank(executor);
        vm.expectRevert(CATValidatorV1_1.ZeroDestination.selector);
        v11.entry(attacker, "", escrow, 0, refA, refO, address(0), keccak256(""), "");
        assertEq(usdt.balanceOf(escrow), DEPOSIT);
    }

    function _three(
        address a,
        address b,
        address c
    ) internal pure returns (address[] memory r) {
        r = new address[](3);
        r[0] = a;
        r[1] = b;
        r[2] = c;
    }
}
