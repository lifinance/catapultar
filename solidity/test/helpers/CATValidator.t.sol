// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { MockERC20 } from "solady/test/utils/mocks/MockERC20.sol";

import { LibExecutionConstraintTest } from "./libs/LibExecutionConstraint.t.sol";

import { CATValidator } from "../../src/CATValidator.sol";
import { AllowanceSpend, Outcome } from "../../src/libs/LibExecutionConstraint.sol";

interface EIP712 {
    function DOMAIN_SEPARATOR() external view returns (bytes32);
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

    function recordBalances(
        address account,
        Outcome[] calldata outcomes
    ) external view returns (uint256[] memory balances) {
        return _recordBalances(account, outcomes);
    }

    function compareOutcomes(
        address account,
        Outcome[] calldata outcomes,
        uint256[] calldata balances
    ) external view {
        return _compareOutcomes(account, outcomes, balances);
    }
}

contract CATValidatorTest is LibExecutionConstraintTest {
    CATValidatorMock validator;

    function setUp() external {
        validator = new CATValidatorMock();
    }

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

    function test_validateApproval(
        AllowanceSpend[] memory allowances,
        Outcome[] memory outcomes,
        address executor,
        uint256 nonce
    ) external {
        // Tested function.
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

        // Sets msg.sender for the test
        vm.startPrank(executor);

        validator.validateApproval(signer, nonce, allowances, outcomes, abi.encodePacked(r, s, v));

        vm.expectRevert(abi.encodeWithSelector(CATValidator.BadSignature.selector));
        validator.validateApproval(signer, nonce, allowances, outcomes, abi.encodePacked(bytes32(uint256(r) + 1), s, v));

        vm.expectRevert(abi.encodeWithSelector(CATValidator.BadSignature.selector));
        validator.validateApproval(signer, nonce, allowances, outcomes, hex"");
    }

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
                allowances[i].token,
                abi.encodeCall(MockERC20.transferFrom, (account, destination, amounts[i] / 2))
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

    function test_revert_call_transfer() external {
        address account = makeAddr("account");
        address target = makeAddr("target");
        uint256 amount = uint256(keccak256(bytes("amount")));

        // set allowance to validator. This can "technically" be claimed if we could execute transferFrom from the
        // validator.
        address token = address(new MockERC20("Test Token", "TT", 18));
        MockERC20(token).mint(account, amount);
        vm.prank(account);
        MockERC20(token).approve(address(validator), amount);

        // Tell validator to execute transferFrom.
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

        // set allowance to the proxy. This is bad, since anyone can call from the proxy.
        address token = address(new MockERC20("Test Token", "TT", 18));
        MockERC20(token).mint(account, amount);
        vm.prank(account);
        MockERC20(token).approve(proxy, amount);

        // Tell validator to execute transferFrom.
        bytes memory cd = abi.encodeCall(MockERC20.transferFrom, (account, target, amount));

        vm.expectCall(token, cd);
        validator.call(token, cd);
    }

    struct AmountAndDestination {
        address destination;
        uint128 amount;
    }

    function test_fuzz_recordBalances(
        AmountAndDestination[] calldata ad
    ) external {
        address account = makeAddr("account");

        Outcome[] memory outcomes = new Outcome[](ad.length);
        for (uint256 i; i < outcomes.length; ++i) {
            address dest = ad[i].destination == address(0) ? account : ad[i].destination;
            if (i == 2) {
                vm.deal(dest, ad[i].amount);
                outcomes[i] = Outcome({ amount: ad[i].amount, destination: ad[i].destination, token: address(0) });
                continue;
            }
            string memory vv = string(abi.encode(keccak256(abi.encode(i))));
            address token = address(new MockERC20(vv, vv, 18));
            MockERC20(token).mint(dest, ad[i].amount);
            outcomes[i] = Outcome({ amount: ad[i].amount, destination: ad[i].destination, token: token });
        }

        uint256[] memory balances = validator.recordBalances(account, outcomes);

        assertEq(balances.length, outcomes.length);
        for (uint256 i; i < outcomes.length; ++i) {
            assertEq(balances[i], outcomes[i].amount);
        }
    }

    function test_fuzz_compareOutcomes(
        AmountAndDestination[] calldata ad
    ) external {
        address account = makeAddr("account");
        vm.assume(ad.length > 0);
        vm.assume(ad[0].amount != 0);

        Outcome[] memory outcomes = new Outcome[](ad.length);
        for (uint256 i; i < outcomes.length; ++i) {
            address dest = ad[i].destination == address(0) ? account : ad[i].destination;
            if (i == 2) {
                vm.deal(dest, ad[i].amount);
                outcomes[i] = Outcome({ amount: ad[i].amount, destination: ad[i].destination, token: address(0) });
                continue;
            }
            string memory vv = string(abi.encode(keccak256(abi.encode(i))));
            address token = address(new MockERC20(vv, vv, 18));
            MockERC20(token).mint(dest, ad[i].amount);
            outcomes[i] = Outcome({ amount: ad[i].amount, destination: ad[i].destination, token: token });
        }

        uint256[] memory balances = validator.recordBalances(account, outcomes);

        // If we run compareOutcomes it should fail immediately on the first entry.
        vm.expectRevert(abi.encodeWithSelector(CATValidator.InvalidTokenAmount.selector, ad[0].amount, 0));
        validator.compareOutcomes(account, outcomes, balances);

        // However, if we give a 0 array, then it should pass.
        uint256[] memory zeroBalances = new uint256[](outcomes.length);
        validator.compareOutcomes(account, outcomes, zeroBalances);

        // Lets send another batch so the amounts will be 2x ad[i].amount.
        for (uint256 i; i < outcomes.length; ++i) {
            address dest = ad[i].destination == address(0) ? account : ad[i].destination;
            if (i == 2) {
                vm.deal(dest, uint256(ad[i].amount) * 2);

                continue;
            }
            MockERC20(outcomes[i].token).mint(dest, ad[i].amount);
        }

        // Neither reverts.
        validator.compareOutcomes(account, outcomes, balances);
        validator.compareOutcomes(account, outcomes, zeroBalances);
    }

    function test_revert_recordBalances_when_balanceOf_reverts() external {
        address account = makeAddr("account");
        address token = address(new RevertingBalanceOf());

        Outcome[] memory outcomes = new Outcome[](1);
        outcomes[0] = Outcome({ token: token, amount: 0, destination: address(0) });

        vm.expectRevert(abi.encodeWithSelector(CATValidator.BalanceOfFailed.selector, token));
        validator.recordBalances(account, outcomes);
    }

    function test_revert_compareOutcomes_when_balanceOf_reverts() external {
        address account = makeAddr("account");
        address token = address(new RevertingBalanceOf());

        Outcome[] memory outcomes = new Outcome[](1);
        outcomes[0] = Outcome({ token: token, amount: 0, destination: address(0) });

        uint256[] memory balances = new uint256[](1);
        balances[0] = 0;

        vm.expectRevert(abi.encodeWithSelector(CATValidator.BalanceOfFailed.selector, token));
        validator.compareOutcomes(account, outcomes, balances);
    }

    // Reproduces the attack from issue 6.2.1: a token whose balanceOf() fails on the
    // pre-execution read but succeeds post-execution, producing a spurious positive diff.
    //
    // Attack path (old behavior):
    //   1. recordBalances silently returns 0 because pre-execution balanceOf reverts.
    //   2. Attacker alters external state so post-execution balanceOf now succeeds.
    //   3. compareOutcomes observes diff = realBalance − 0 ≥ required → fraudulent pass.
    //
    // With the fix, step 1 reverts with BalanceOfFailed, blocking the attack entirely.
    function test_issue_6_2_1_failed_first_balanceOf_cannot_produce_spurious_diff() external {
        address account = makeAddr("account");
        address destination = makeAddr("destination");
        ToggleableBalanceOf token = new ToggleableBalanceOf();

        uint256 realBalance = 100e18;
        uint256 requiredIncrease = 1; // attacker only needs a tiny required amount
        token.setBalance(destination, realBalance);
        // token starts with failing == true, so pre-execution balanceOf() reverts

        Outcome[] memory outcomes = new Outcome[](1);
        outcomes[0] = Outcome({ token: address(token), amount: requiredIncrease, destination: destination });

        // Pre-execution read must revert — attack is blocked before it can progress.
        vm.expectRevert(abi.encodeWithSelector(CATValidator.BalanceOfFailed.selector, address(token)));
        validator.recordBalances(account, outcomes);

        // Demonstrate concretely why the old silent-zero was exploitable:
        // simulate the attacker enabling balanceOf mid-execution (state change between reads).
        token.setFailing(false);

        // compareOutcomes with the fraudulent zero snapshot passes because diff = 100e18 >= 1.
        // This confirms the attack would have worked without the fix.
        uint256[] memory silentZeroSnapshot = new uint256[](1); // what old code would have recorded
        validator.compareOutcomes(account, outcomes, silentZeroSnapshot);
    }
}

contract RevertingBalanceOf {
    function balanceOf(address) external pure returns (uint256) {
        revert("balanceOf reverts");
    }
}

/// @dev Token whose balanceOf() can be toggled between failing and succeeding.
/// Models a token whose behavior depends on external state changeable mid-execution.
contract ToggleableBalanceOf {
    bool public failing = true;
    mapping(address => uint256) private _balances;

    function setBalance(address account, uint256 amount) external {
        _balances[account] = amount;
    }

    function setFailing(bool _failing) external {
        failing = _failing;
    }

    function balanceOf(address account) external view returns (uint256) {
        require(!failing, "balanceOf: disabled");
        return _balances[account];
    }
}
