// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { SafeTransferLib } from "solady/src/utils/SafeTransferLib.sol";
import { MockERC20 } from "solady/test/utils/mocks/MockERC20.sol";

import { MockTronUSDT } from "../mocks/MockTronUSDT.sol";

import { LibExecutionConstraintTest } from "./libs/LibExecutionConstraint.t.sol";

import { CATValidator } from "../../src/CATValidator.sol";
import { AllowanceSpend, Outcome } from "../../src/libs/LibExecutionConstraint.sol";

interface EIP712 {
    function DOMAIN_SEPARATOR() external view returns (bytes32);
}

/// Simulates an external protocol (swap router, airdrop, OpenSea settlement, etc.)
/// that holds output tokens and can send them to any address during execution.
contract MockTokenSender {
    function sendTo(
        address token,
        uint256 amount,
        address recipient
    ) external {
        SafeTransferLib.safeTransfer(token, recipient, amount);
    }
}

contract CATValidatorMock is CATValidator {
    uint256 public constant MAGIC_BALANCE = SPEND_BALANCE_OF_MAGIC;

    function checkNonce(
        address account,
        uint256 nonce
    ) external {
        return _checkNonce(account, nonce);
    }

    function validateApproval(
        address account,
        uint256 nonce,
        AllowanceSpend[] calldata allowances,
        Outcome[] calldata outcomes,
        bytes calldata signature
    ) external view {
        return _validateApproval(account, nonce, allowances, outcomes, signature);
    }

    function handleAllowances(
        address destination,
        address source,
        AllowanceSpend[] calldata allowances
    ) external {
        return _handleAllowances(destination, source, allowances);
    }

    function call(
        address target,
        bytes calldata payload
    ) external {
        return _call(target, payload);
    }

    function validatePayment(
        address signer,
        Outcome[] calldata outcomes
    ) external {
        return _validatePayment(signer, outcomes);
    }

    function balanceOf(
        address token,
        address target
    ) external view returns (uint256) {
        return _balanceOf(token, target);
    }
}

contract CATValidatorTest is LibExecutionConstraintTest {
    CATValidatorMock validator;

    function setUp() external {
        validator = new CATValidatorMock();
    }

    // -----------------------------------------------------------------------
    // Nonce
    // -----------------------------------------------------------------------

    function test_checkNonce() external {
        address a = makeAddr("a");
        address b = makeAddr("b");

        validator.checkNonce(a, 1);
        vm.expectRevert(abi.encodeWithSelector(CATValidator.NonceAlreadySpent.selector));
        validator.checkNonce(a, 1);
        validator.checkNonce(a, 2);
        validator.checkNonce(b, 1);

        validator.checkNonce(b, 100);
        validator.checkNonce(b, 101);
        vm.expectRevert(abi.encodeWithSelector(CATValidator.NonceAlreadySpent.selector));
        validator.checkNonce(b, 100);
    }

    // -----------------------------------------------------------------------
    // validateApproval
    // -----------------------------------------------------------------------

    function test_validateApproval(
        AllowanceSpend[] memory allowances,
        Outcome[] memory outcomes,
        address executor,
        uint256 nonce
    ) external {
        uint8 v;
        bytes32 r;
        bytes32 s;
        address signer;
        {
            bytes32 th = typehashReference(allowances, outcomes, executor, nonce);

            bytes32 domainSeparator = EIP712(address(validator)).DOMAIN_SEPARATOR();
            bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, th));

            uint256 key;
            (signer, key) = makeAddrAndKey("signer");

            (v, r, s) = vm.sign(key, digest);
        }

        vm.startPrank(executor);

        validator.validateApproval(signer, nonce, allowances, outcomes, abi.encodePacked(r, s, v));

        vm.expectRevert(abi.encodeWithSelector(CATValidator.BadSignature.selector));
        validator.validateApproval(signer, nonce, allowances, outcomes, abi.encodePacked(bytes32(uint256(r) + 1), s, v));

        vm.expectRevert(abi.encodeWithSelector(CATValidator.BadSignature.selector));
        validator.validateApproval(signer, nonce, allowances, outcomes, hex"");
    }

    // -----------------------------------------------------------------------
    // handleAllowances
    // -----------------------------------------------------------------------

    function test_fuzz_handleAllowances(
        uint256[] calldata amounts
    ) external {
        address destination = makeAddr("destination");
        address account = makeAddr("account");

        address[] memory tokens = new address[](amounts.length);
        for (uint256 i; i < tokens.length; ++i) {
            string memory vv = string(abi.encode(keccak256(abi.encode(i))));
            tokens[i] = address(new MockERC20(vv, vv, 18));
            MockERC20(tokens[i]).mint(account, amounts[i]);
            vm.prank(account);
            MockERC20(tokens[i]).approve(address(validator), amounts[i]);
        }

        AllowanceSpend[] memory allowances = new AllowanceSpend[](amounts.length);
        for (uint256 i; i < allowances.length; ++i) {
            allowances[i] = AllowanceSpend({ token: tokens[i], allocated: amounts[i], spend: amounts[i] });
        }

        for (uint256 i; i < allowances.length; ++i) {
            assertEq(amounts[i], MockERC20(allowances[i].token).balanceOf(account));
        }
        for (uint256 i; i < allowances.length; ++i) {
            vm.expectCall(
                allowances[i].token, abi.encodeCall(MockERC20.transferFrom, (account, destination, amounts[i]))
            );
        }
        validator.handleAllowances(destination, account, allowances);

        for (uint256 i; i < allowances.length; ++i) {
            assertEq(0, MockERC20(allowances[i].token).balanceOf(account));
            assertEq(amounts[i], MockERC20(allowances[i].token).balanceOf(destination));
        }
    }

    function test_handleAllowances_half_spend(
        uint256[] calldata amounts
    ) external {
        address destination = makeAddr("destination");
        address account = makeAddr("account");

        address[] memory tokens = new address[](amounts.length);
        for (uint256 i; i < tokens.length; ++i) {
            vm.assume(amounts[i] >= 2);
            string memory vv = string(abi.encode(keccak256(abi.encode(i))));
            tokens[i] = address(new MockERC20(vv, vv, 18));
            MockERC20(tokens[i]).mint(account, amounts[i]);
            vm.prank(account);
            MockERC20(tokens[i]).approve(address(validator), amounts[i]);
        }

        AllowanceSpend[] memory allowances = new AllowanceSpend[](amounts.length);
        for (uint256 i; i < allowances.length; ++i) {
            allowances[i] = AllowanceSpend({ token: tokens[i], allocated: amounts[i], spend: amounts[i] / 2 });
        }

        for (uint256 i; i < allowances.length; ++i) {
            assertEq(amounts[i], MockERC20(allowances[i].token).balanceOf(account));
        }
        for (uint256 i; i < allowances.length; ++i) {
            vm.expectCall(
                allowances[i].token, abi.encodeCall(MockERC20.transferFrom, (account, destination, amounts[i] / 2))
            );
        }
        validator.handleAllowances(destination, account, allowances);

        for (uint256 i; i < allowances.length; ++i) {
            uint256 spend = amounts[i] / 2;
            assertEq(amounts[i] - spend, MockERC20(allowances[i].token).balanceOf(account));
            assertEq(spend, MockERC20(allowances[i].token).balanceOf(destination));
        }
    }

    function test_revert_handleAllowances_exceed_allocation(
        uint256 amount
    ) external {
        address destination = makeAddr("destination");
        address account = makeAddr("account");
        vm.assume(amount != type(uint256).max);
        vm.assume(amount != 0);
        vm.assume(amount != (1 << 255) - 1);

        address token = address(new MockERC20("Test Token", "TT", 18));
        MockERC20(token).mint(account, amount);
        vm.prank(account);
        MockERC20(token).approve(address(validator), amount);

        AllowanceSpend[] memory allowances = new AllowanceSpend[](1);
        allowances[0] = AllowanceSpend({ token: token, allocated: amount, spend: amount + 1 });

        vm.expectRevert(abi.encodeWithSelector(CATValidator.AllocationTooSmall.selector, amount, amount + 1));
        validator.handleAllowances(destination, account, allowances);
    }

    function test_handleAllowances_magic_spend_uses_balanceOf(
        uint256 amount
    ) external {
        address destination = makeAddr("destination");
        address account = makeAddr("account");

        address token = address(new MockERC20("Test Token", "TT", 18));
        MockERC20(token).mint(account, amount);
        vm.prank(account);
        MockERC20(token).approve(address(validator), amount);

        AllowanceSpend[] memory allowances = new AllowanceSpend[](1);
        allowances[0] = AllowanceSpend({ token: token, allocated: type(uint256).max, spend: validator.MAGIC_BALANCE() });

        vm.expectCall(token, abi.encodeCall(MockERC20.transferFrom, (account, destination, amount)));
        validator.handleAllowances(destination, account, allowances);
    }

    // -----------------------------------------------------------------------
    // _call / CallProxy
    // -----------------------------------------------------------------------

    function test_revert_call_transfer() external {
        address account = makeAddr("account");
        address target = makeAddr("target");
        uint256 amount = uint256(keccak256(bytes("amount")));

        address token = address(new MockERC20("Test Token", "TT", 18));
        MockERC20(token).mint(account, amount);
        vm.prank(account);
        MockERC20(token).approve(address(validator), amount);

        bytes memory cd = abi.encodeCall(MockERC20.transferFrom, (account, target, amount));

        vm.expectCall(token, cd);
        vm.expectRevert(abi.encodeWithSignature("InsufficientAllowance()"));
        validator.call(token, cd);
    }

    function test_call_transfer() external {
        address account = makeAddr("account");
        address target = makeAddr("target");
        address proxy = validator.CALL_PROXY();
        uint256 amount = uint256(keccak256(bytes("amount")));

        address token = address(new MockERC20("Test Token", "TT", 18));
        MockERC20(token).mint(account, amount);
        vm.prank(account);
        MockERC20(token).approve(proxy, amount);

        bytes memory cd = abi.encodeCall(MockERC20.transferFrom, (account, target, amount));

        vm.expectCall(token, cd);
        validator.call(token, cd);
    }

    // -----------------------------------------------------------------------
    // _validatePayment
    // -----------------------------------------------------------------------

    /// Executor deposits tokens to CATValidator; they are forwarded to destination.
    function test_validatePayment_success() external {
        address dest = makeAddr("dest");
        uint256 amount = 1 ether;
        address token = address(new MockERC20("T", "T", 18));

        MockERC20(token).mint(address(validator), amount);

        Outcome[] memory outcomes = new Outcome[](1);
        outcomes[0] = Outcome({ token: token, amount: amount, destination: dest });

        validator.validatePayment(address(this), outcomes);

        assertEq(MockERC20(token).balanceOf(dest), amount);
        assertEq(MockERC20(token).balanceOf(address(validator)), 0);
    }

    /// CATValidator holds less than required → exact InvalidTokenAmount.
    function test_validatePayment_revert_insufficient() external {
        address dest = makeAddr("dest");
        uint256 required = 1 ether;
        address token = address(new MockERC20("T", "T", 18));

        MockERC20(token).mint(address(validator), required - 1);

        Outcome[] memory outcomes = new Outcome[](1);
        outcomes[0] = Outcome({ token: token, amount: required, destination: dest });

        vm.expectRevert(abi.encodeWithSelector(CATValidator.InvalidTokenAmount.selector, required, required - 1));
        validator.validatePayment(address(this), outcomes);
    }

    /// Zero-amount outcome passes trivially.
    function test_validatePayment_zero_amount_passes() external {
        address dest = makeAddr("dest");
        address token = address(new MockERC20("T", "T", 18));

        Outcome[] memory outcomes = new Outcome[](1);
        outcomes[0] = Outcome({ token: token, amount: 0, destination: dest });

        validator.validatePayment(address(this), outcomes);
    }

    // -----------------------------------------------------------------------
    // Audit 6.1.1 regression tests
    // -----------------------------------------------------------------------

    function _signEntry(
        address account,
        uint256 signerKey,
        address executor,
        uint256 nonce,
        AllowanceSpend[] memory allowances,
        Outcome[] memory outcomes
    ) internal view returns (bytes memory sig) {
        bytes32 th = typehashReference(allowances, outcomes, executor, nonce);
        bytes32 domainSeparator = EIP712(address(validator)).DOMAIN_SEPARATOR();
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, th));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, digest);
        sig = abi.encodePacked(r, s, v);
    }

    /// During real execution a mock protocol sends output tokens to `dest` directly.
    /// CATValidator receives nothing → outcome check fails even though dest was paid.
    function test_audit_611_execution_delivers_to_dest_rejected() external {
        (address account, uint256 key) = makeAddrAndKey("account");
        address executor = makeAddr("executor");
        address dest = makeAddr("dest");
        uint256 amount = 1 ether;

        address inToken = address(new MockERC20("In", "IN", 18));
        address outToken = address(new MockERC20("Out", "OUT", 18));

        MockERC20(inToken).mint(account, amount);
        vm.prank(account);
        MockERC20(inToken).approve(address(validator), amount);

        // MockTokenSender holds output tokens and will send them wherever told.
        MockTokenSender sender = new MockTokenSender();
        MockERC20(outToken).mint(address(sender), amount);

        AllowanceSpend[] memory allowances = new AllowanceSpend[](1);
        allowances[0] = AllowanceSpend({ token: inToken, allocated: amount, spend: amount });

        Outcome[] memory outcomes = new Outcome[](1);
        outcomes[0] = Outcome({ token: outToken, amount: amount, destination: dest });

        bytes memory sig = _signEntry(account, key, executor, 1, allowances, outcomes);
        // Executor instructs sender to deliver to `dest` — not to CATValidator.
        bytes memory execPayload = abi.encodeCall(MockTokenSender.sendTo, (outToken, amount, dest));

        vm.prank(executor);
        vm.expectRevert(abi.encodeWithSelector(CATValidator.InvalidTokenAmount.selector, amount, 0));
        validator.entry(address(sender), execPayload, account, 1, allowances, outcomes, sig);
    }

    /// During real execution a mock protocol sends output tokens to CATValidator.
    /// Outcome check passes and tokens are forwarded to `dest`.
    function test_audit_611_execution_delivers_to_validator_accepted() external {
        (address account, uint256 key) = makeAddrAndKey("account");
        address executor = makeAddr("executor");
        address dest = makeAddr("dest");
        uint256 amount = 1 ether;

        address inToken = address(new MockERC20("In", "IN", 18));
        address outToken = address(new MockERC20("Out", "OUT", 18));

        MockERC20(inToken).mint(account, amount);
        vm.prank(account);
        MockERC20(inToken).approve(address(validator), amount);

        MockTokenSender sender = new MockTokenSender();
        MockERC20(outToken).mint(address(sender), amount);

        AllowanceSpend[] memory allowances = new AllowanceSpend[](1);
        allowances[0] = AllowanceSpend({ token: inToken, allocated: amount, spend: amount });

        Outcome[] memory outcomes = new Outcome[](1);
        outcomes[0] = Outcome({ token: outToken, amount: amount, destination: dest });

        bytes memory sig = _signEntry(account, key, executor, 1, allowances, outcomes);
        // Executor instructs sender to deliver to CATValidator — correct.
        bytes memory execPayload = abi.encodeCall(MockTokenSender.sendTo, (outToken, amount, address(validator)));

        vm.prank(executor);
        validator.entry(address(sender), execPayload, account, 1, allowances, outcomes, sig);

        assertEq(MockERC20(outToken).balanceOf(dest), amount);
        assertEq(MockERC20(outToken).balanceOf(address(validator)), 0);
    }

    function test_revert_balanceOf_when_token_reverts() external {
        address token = address(new RevertingBalanceOf());
        address target = makeAddr("target");

        vm.expectRevert(abi.encodeWithSelector(CATValidator.BalanceOfFailed.selector, token));
        validator.balanceOf(token, target);
    }

    function test_revert_validatePayment_when_balanceOf_reverts() external {
        address signer = makeAddr("signer");
        address token = address(new RevertingBalanceOf());

        Outcome[] memory outcomes = new Outcome[](1);
        outcomes[0] = Outcome({ token: token, amount: 0, destination: address(0) });

        vm.expectRevert(abi.encodeWithSelector(CATValidator.BalanceOfFailed.selector, token));
        validator.validatePayment(signer, outcomes);
    }

    // Reproduces the attack from issue 6.2.1: a token whose balanceOf() fails,
    // which under the old Solady balanceOf() would silently return 0.
    //
    // Attack path (old behavior):
    //   1. balanceOf silently returns 0 because the call reverts.
    //   2. Attacker alters external state so post-execution balanceOf now succeeds.
    //   3. validatePayment observes a balance ≥ required → fraudulent pass.
    //
    // With the fix, the revert propagates via BalanceOfFailed, blocking the attack.
    function test_issue_6_2_1_failed_balanceOf_cannot_be_exploited() external {
        address target = makeAddr("target");
        ToggleableBalanceOf token = new ToggleableBalanceOf();

        uint256 realBalance = 100e18;
        token.setBalance(target, realBalance);
        // token starts with failing == true, so balanceOf() reverts

        // balanceOf must revert — attack is blocked before it can progress.
        vm.expectRevert(abi.encodeWithSelector(CATValidator.BalanceOfFailed.selector, address(token)));
        validator.balanceOf(address(token), target);

        // Demonstrate that once the token stops failing, balanceOf works correctly.
        token.setFailing(false);
        assertEq(validator.balanceOf(address(token), target), realBalance);
    }

    // -----------------------------------------------------------------------
    // Tron USDT regression: safeTransfer reverts on false-returning token
    // -----------------------------------------------------------------------

    /// @dev Confirms that the standard CATValidator cannot forward MockTronUSDT as an outcome.
    ///      This is the failure mode that CATValidatorTron was created to fix.
    function testRevert_validatePayment_tronUsdtBreaksStandardContract() external {
        address dest = makeAddr("dest");
        uint256 amount = 1000e6;
        MockTronUSDT tronUsdt = new MockTronUSDT();
        tronUsdt.mint(address(validator), amount);

        Outcome[] memory outcomes = new Outcome[](1);
        outcomes[0] = Outcome({ token: address(tronUsdt), amount: amount, destination: dest });

        vm.expectRevert();
        validator.validatePayment(address(this), outcomes);
    }
}

contract RevertingBalanceOf {
    function balanceOf(
        address
    ) external pure returns (uint256) {
        revert("balanceOf reverts");
    }
}

/// @dev Token whose balanceOf() can be toggled between failing and succeeding.
/// Models a token whose behavior depends on external state changeable mid-execution.
contract ToggleableBalanceOf {
    bool public failing = true;
    mapping(address => uint256) private _balances;

    function setBalance(
        address account,
        uint256 amount
    ) external {
        _balances[account] = amount;
    }

    function setFailing(
        bool _failing
    ) external {
        failing = _failing;
    }

    function balanceOf(
        address account
    ) external view returns (uint256) {
        require(!failing, "balanceOf: disabled");
        return _balances[account];
    }
}
