// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { MockERC20 } from "solady/test/utils/mocks/MockERC20.sol";

import { LibExecutionConstraintTest } from "./libs/LibExecutionConstraint.t.sol";

import { AllowanceSpend, CATValidator, Outcome } from "../../src/helpers/CATValidator.sol";

interface EIP712 {
    function DOMAIN_SEPARATOR() external view returns (bytes32);
}

contract CATValidatorMock is CATValidator {
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
            bytes32 th = typehashReference(allowanceSpendToAllowance(allowances), outcomes, executor, nonce);

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

        AllowanceSpend[] memory targets = new AllowanceSpend[](amounts.length);
        for (uint256 i; i < targets.length; ++i) {
            targets[i] = AllowanceSpend({ token: tokens[i], allocated: amounts[i], spend: amounts[i] });
        }

        for (uint256 i; i < targets.length; ++i) {
            assertEq(amounts[i], MockERC20(targets[i].token).balanceOf(account));
        }
        for (uint256 i; i < targets.length; ++i) {
            vm.expectCall(targets[i].token, abi.encodeCall(MockERC20.transferFrom, (account, destination, amounts[i])));
        }
        validator.handleAllowances(destination, account, targets);

        for (uint256 i; i < targets.length; ++i) {
            assertEq(0, MockERC20(targets[i].token).balanceOf(account));
            assertEq(amounts[i], MockERC20(targets[i].token).balanceOf(destination));
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

        AllowanceSpend[] memory targets = new AllowanceSpend[](amounts.length);
        for (uint256 i; i < targets.length; ++i) {
            targets[i] = AllowanceSpend({ token: tokens[i], allocated: amounts[i], spend: amounts[i] / 2 });
        }

        for (uint256 i; i < targets.length; ++i) {
            assertEq(amounts[i], MockERC20(targets[i].token).balanceOf(account));
        }
        for (uint256 i; i < targets.length; ++i) {
            vm.expectCall(
                targets[i].token, abi.encodeCall(MockERC20.transferFrom, (account, destination, amounts[i] / 2))
            );
        }
        validator.handleAllowances(destination, account, targets);

        for (uint256 i; i < targets.length; ++i) {
            uint256 spend = amounts[i] / 2;
            assertEq(amounts[i] - spend, MockERC20(targets[i].token).balanceOf(account));
            assertEq(spend, MockERC20(targets[i].token).balanceOf(destination));
        }
    }

    function test_revert_handleAllowances_exceed_allowance(
        uint256 amount
    ) external {
        address destination = makeAddr("destination");
        address account = makeAddr("account");
        vm.assume(amount != type(uint256).max);
        vm.assume(amount != 0);

        address token = address(new MockERC20("Test Token", "TT", 18));
        MockERC20(token).mint(account, amount);
        vm.prank(account);
        MockERC20(token).approve(address(validator), amount);

        AllowanceSpend[] memory targets = new AllowanceSpend[](1);
        targets[0] = AllowanceSpend({ token: token, allocated: amount, spend: amount + 1 });

        vm.expectRevert(abi.encodeWithSelector(CATValidator.AllocationTooSmall.selector, amount, amount + 1));
        validator.handleAllowances(destination, account, targets);
    }

    function test_handleAllowances_0_spend_balanceOf(
        uint248 amount
    ) external {
        address destination = makeAddr("destination");
        address account = makeAddr("account");

        address token = address(new MockERC20("Test Token", "TT", 18));
        MockERC20(token).mint(account, amount);
        vm.prank(account);
        MockERC20(token).approve(address(validator), amount);

        AllowanceSpend[] memory targets = new AllowanceSpend[](1);
        targets[0] = AllowanceSpend({ token: token, allocated: 1 << 255, spend: 0 });

        vm.expectCall(token, abi.encodeCall(MockERC20.transferFrom, (account, destination, amount)));
        validator.handleAllowances(destination, account, targets);
    }

    function test_revert_handleAllowances_0_spend_fix_allowance(
        uint256 amount
    ) external {
        address destination = makeAddr("destination");
        address account = makeAddr("account");
        vm.assume(amount != 0);
        vm.assume(amount != type(uint256).max);

        address token = address(new MockERC20("Test Token", "TT", 18));
        MockERC20(token).mint(account, amount + 1);
        vm.prank(account);
        MockERC20(token).approve(address(validator), amount + 1);

        AllowanceSpend[] memory targets = new AllowanceSpend[](1);
        targets[0] = AllowanceSpend({ token: token, allocated: amount, spend: 0 });

        vm.expectRevert(abi.encodeWithSelector(CATValidator.AllocationTooSmall.selector, amount, amount + 1));
        validator.handleAllowances(destination, account, targets);
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

        // If we run compare outcomes it should fail immediately on the first entry.
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
}
