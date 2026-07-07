// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { ReentrancyGuard } from "solady/src/utils/ReentrancyGuard.sol";
import { SafeTransferLib } from "solady/src/utils/SafeTransferLib.sol";
import { MockERC20 } from "solady/test/utils/mocks/MockERC20.sol";

import { LibExecutionConstraintTest } from "./libs/LibExecutionConstraint.t.sol";

import { AllowanceSpend, CATValidator, Outcome } from "../src/CATValidator.sol";

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

    function validatePayment(
        address signer,
        Outcome[] calldata outcomes
    ) external {
        return _validatePayment(signer, outcomes);
    }
}

// ---------------------------------------------------------------------------
// MockExecutor — simulates a solver that can deliver tokens to CATValidator
// (correct) or to some other address (incorrect).
// ---------------------------------------------------------------------------
contract MockExecutor {
    address public immutable validator;

    constructor(
        address _validator
    ) {
        validator = _validator;
    }

    /// Sends `amount` of `token` to CATValidator — the correct behaviour.
    function executeAndDeliverToValidator(
        address token,
        uint256 amount
    ) external {
        SafeTransferLib.safeTransfer(token, validator, amount);
    }

    /// Sends `amount` of `token` to an arbitrary address — incorrect; CATValidator
    /// receives nothing so the outcome check must fail.
    function executeAndDeliverElsewhere(
        address token,
        uint256 amount,
        address wrongDest
    ) external {
        SafeTransferLib.safeTransfer(token, wrongDest, amount);
    }

    /// Sends ETH to CATValidator — for testing native ETH output outcomes.
    function executeAndDeliverETHToValidator(
        uint256 amount
    ) external {
        SafeTransferLib.safeTransferETH(validator, amount);
    }

    /// Attempts to re-enter CATValidator::entry from within an execution payload.
    function executeAndReenter() external {
        AllowanceSpend[] memory allowances = new AllowanceSpend[](0);
        Outcome[] memory outcomes = new Outcome[](0);
        CATValidator(payable(validator)).entry(address(0), hex"", address(this), 1, allowances, outcomes, hex"");
    }

    receive() external payable { }
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
            bytes32 th = typehashReference(allowanceSpendToAllowance(allowances), outcomes, executor, nonce);

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
        vm.assume(amount != (1 << 255) - 1);

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
        targets[0] = AllowanceSpend({
            token: token,
            allocated: 1 << 255,
            spend: 57896044618658097711785492504343953926634992332820282019728792003956564819968
        });

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
        targets[0] = AllowanceSpend({
            token: token,
            allocated: amount,
            spend: 57896044618658097711785492504343953926634992332820282019728792003956564819968
        });

        vm.expectRevert(abi.encodeWithSelector(CATValidator.AllocationTooSmall.selector, amount, amount + 1));
        validator.handleAllowances(destination, account, targets);
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

    /// Executor deposits more than required; the full deposited balance is forwarded.
    function test_validatePayment_excess_balance_forwarded() external {
        address dest = makeAddr("dest");
        uint256 required = 1 ether;
        uint256 deposited = 2 ether;

        address token = address(new MockERC20("T", "T", 18));
        MockERC20(token).mint(address(validator), deposited);

        Outcome[] memory outcomes = new Outcome[](1);
        outcomes[0] = Outcome({ token: token, amount: required, destination: dest });

        validator.validatePayment(address(this), outcomes);

        assertEq(MockERC20(token).balanceOf(dest), deposited);
        assertEq(MockERC20(token).balanceOf(address(validator)), 0);
    }

    /// Multiple outcomes — each token is checked and forwarded independently.
    function test_validatePayment_multiple_outcomes() external {
        address destA = makeAddr("destA");
        address destB = makeAddr("destB");
        uint256 amountA = 1 ether;
        uint256 amountB = 2 ether;

        address tokenA = address(new MockERC20("A", "A", 18));
        address tokenB = address(new MockERC20("B", "B", 18));
        MockERC20(tokenA).mint(address(validator), amountA);
        MockERC20(tokenB).mint(address(validator), amountB);

        Outcome[] memory outcomes = new Outcome[](2);
        outcomes[0] = Outcome({ token: tokenA, amount: amountA, destination: destA });
        outcomes[1] = Outcome({ token: tokenB, amount: amountB, destination: destB });

        validator.validatePayment(address(this), outcomes);

        assertEq(MockERC20(tokenA).balanceOf(destA), amountA);
        assertEq(MockERC20(tokenB).balanceOf(destB), amountB);
    }

    /// CATValidator balance below required → InvalidTokenAmount with exact values.
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

    /// Fuzz: any non-zero amount with empty CATValidator always reverts.
    function test_fuzz_validatePayment_revert_empty_validator(
        uint128 amount
    ) external {
        vm.assume(amount > 0);
        address dest = makeAddr("dest");
        address token = address(new MockERC20("T", "T", 18));

        Outcome[] memory outcomes = new Outcome[](1);
        outcomes[0] = Outcome({ token: token, amount: amount, destination: dest });

        vm.expectRevert(abi.encodeWithSelector(CATValidator.InvalidTokenAmount.selector, amount, 0));
        validator.validatePayment(address(this), outcomes);
    }

    /// Zero-amount outcome is satisfied trivially; safeTransfer(0) is a no-op.
    function test_validatePayment_zero_amount_passes() external {
        address dest = makeAddr("dest");
        address token = address(new MockERC20("T", "T", 18));

        Outcome[] memory outcomes = new Outcome[](1);
        outcomes[0] = Outcome({ token: token, amount: 0, destination: dest });

        validator.validatePayment(address(this), outcomes);
    }

    /// outcome.destination == address(0) routes tokens to the signer, not to address(0).
    function test_validatePayment_zero_destination_routes_to_signer() external {
        address signer = makeAddr("signer");
        uint256 amount = 1 ether;
        address token = address(new MockERC20("T", "T", 18));
        MockERC20(token).mint(address(validator), amount);

        Outcome[] memory outcomes = new Outcome[](1);
        outcomes[0] = Outcome({ token: token, amount: amount, destination: address(0) });

        validator.validatePayment(signer, outcomes);

        assertEq(MockERC20(token).balanceOf(signer), amount);
        assertEq(MockERC20(token).balanceOf(address(validator)), 0);
    }

    // -----------------------------------------------------------------------
    // entry() end-to-end tests
    // -----------------------------------------------------------------------

    function _signEntry(
        address account,
        uint256 signerKey,
        address executor,
        uint256 nonce,
        AllowanceSpend[] memory allowances,
        Outcome[] memory outcomes
    ) internal view returns (bytes memory sig) {
        bytes32 th = typehashReference(allowanceSpendToAllowance(allowances), outcomes, executor, nonce);
        bytes32 domainSeparator = EIP712(address(validator)).DOMAIN_SEPARATOR();
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, th));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerKey, digest);
        sig = abi.encodePacked(r, s, v);
    }

    function _setupEntryFixture(
        uint256 amount
    )
        internal
        returns (
            address account,
            uint256 key,
            address executor,
            address dest,
            address inToken,
            address outToken,
            MockExecutor exec
        )
    {
        (account, key) = makeAddrAndKey("account");
        executor = makeAddr("executor");
        dest = makeAddr("dest");

        inToken = address(new MockERC20("In", "IN", 18));
        outToken = address(new MockERC20("Out", "OUT", 18));

        MockERC20(inToken).mint(account, amount);
        vm.prank(account);
        MockERC20(inToken).approve(address(validator), amount);

        exec = new MockExecutor(address(validator));
        MockERC20(outToken).mint(address(exec), amount);
    }

    /// Happy path: executor delivers outcome tokens to CATValidator;
    /// CATValidator forwards them to destination.
    function test_entry_success() external {
        uint256 amount = 1 ether;
        (
            address account,
            uint256 key,
            address executor,
            address dest,
            address inToken,
            address outToken,
            MockExecutor exec
        ) = _setupEntryFixture(amount);

        AllowanceSpend[] memory allowances = new AllowanceSpend[](1);
        allowances[0] = AllowanceSpend({ token: inToken, allocated: amount, spend: amount });

        Outcome[] memory outcomes = new Outcome[](1);
        outcomes[0] = Outcome({ token: outToken, amount: amount, destination: dest });

        bytes memory sig = _signEntry(account, key, executor, 1, allowances, outcomes);
        bytes memory execPayload = abi.encodeCall(MockExecutor.executeAndDeliverToValidator, (outToken, amount));

        vm.prank(executor);
        validator.entry(address(exec), execPayload, account, 1, allowances, outcomes, sig);

        assertEq(MockERC20(outToken).balanceOf(dest), amount);
        assertEq(MockERC20(inToken).balanceOf(address(exec)), amount);
        assertEq(MockERC20(outToken).balanceOf(address(validator)), 0);
    }

    /// Executor sends output tokens to a wrong address; CATValidator holds nothing → revert.
    function test_entry_executor_sends_to_wrong_address_reverts() external {
        uint256 amount = 1 ether;
        (
            address account,
            uint256 key,
            address executor,
            address dest,
            address inToken,
            address outToken,
            MockExecutor exec
        ) = _setupEntryFixture(amount);

        address wrongDest = makeAddr("wrongDest");

        AllowanceSpend[] memory allowances = new AllowanceSpend[](1);
        allowances[0] = AllowanceSpend({ token: inToken, allocated: amount, spend: amount });

        Outcome[] memory outcomes = new Outcome[](1);
        outcomes[0] = Outcome({ token: outToken, amount: amount, destination: dest });

        bytes memory sig = _signEntry(account, key, executor, 1, allowances, outcomes);
        bytes memory execPayload =
            abi.encodeCall(MockExecutor.executeAndDeliverElsewhere, (outToken, amount, wrongDest));

        vm.prank(executor);
        vm.expectRevert(abi.encodeWithSelector(CATValidator.InvalidTokenAmount.selector, amount, 0));
        validator.entry(address(exec), execPayload, account, 1, allowances, outcomes, sig);
    }

    /// Wrong executor (msg.sender ≠ signed executor) → BadSignature before any state change.
    function test_entry_bad_executor_reverts() external {
        uint256 amount = 1 ether;
        (
            address account,
            uint256 key,
            address executor,
            address dest,
            address inToken,
            address outToken,
            MockExecutor exec
        ) = _setupEntryFixture(amount);

        AllowanceSpend[] memory allowances = new AllowanceSpend[](1);
        allowances[0] = AllowanceSpend({ token: inToken, allocated: amount, spend: amount });

        Outcome[] memory outcomes = new Outcome[](1);
        outcomes[0] = Outcome({ token: outToken, amount: amount, destination: dest });

        bytes memory sig = _signEntry(account, key, executor, 1, allowances, outcomes);
        bytes memory execPayload = abi.encodeCall(MockExecutor.executeAndDeliverToValidator, (outToken, amount));

        vm.prank(makeAddr("wrongCaller"));
        vm.expectRevert(abi.encodeWithSelector(CATValidator.BadSignature.selector));
        validator.entry(address(exec), execPayload, account, 1, allowances, outcomes, sig);
    }

    /// Non-zero nonce is consumed after a successful call; replaying reverts with NonceAlreadySpent.
    function test_entry_nonce_consumed_after_success() external {
        uint256 amount = 1 ether;
        (
            address account,
            uint256 key,
            address executor,
            address dest,
            address inToken,
            address outToken,
            MockExecutor exec
        ) = _setupEntryFixture(amount);

        // Mint extra so the second call can also attempt allowances.
        MockERC20(inToken).mint(account, amount);
        vm.prank(account);
        MockERC20(inToken).approve(address(validator), amount * 2);
        MockERC20(outToken).mint(address(exec), amount);

        AllowanceSpend[] memory allowances = new AllowanceSpend[](1);
        allowances[0] = AllowanceSpend({ token: inToken, allocated: amount, spend: amount });

        Outcome[] memory outcomes = new Outcome[](1);
        outcomes[0] = Outcome({ token: outToken, amount: amount, destination: dest });

        bytes memory sig = _signEntry(account, key, executor, 1, allowances, outcomes);
        bytes memory execPayload = abi.encodeCall(MockExecutor.executeAndDeliverToValidator, (outToken, amount));

        vm.prank(executor);
        validator.entry(address(exec), execPayload, account, 1, allowances, outcomes, sig);

        vm.prank(executor);
        vm.expectRevert(abi.encodeWithSelector(CATValidator.NonceAlreadySpent.selector));
        validator.entry(address(exec), execPayload, account, 1, allowances, outcomes, sig);
    }

    /// Nonce 0 is never stored — can be used for long-lived approvals (e.g. DCAs).
    function test_entry_nonce_zero_is_long_lived() external {
        uint256 amount = 1 ether;
        (
            address account,
            uint256 key,
            address executor,
            address dest,
            address inToken,
            address outToken,
            MockExecutor exec
        ) = _setupEntryFixture(amount);

        // Mint enough for two rounds.
        MockERC20(inToken).mint(account, amount);
        vm.prank(account);
        MockERC20(inToken).approve(address(validator), amount * 2);
        MockERC20(outToken).mint(address(exec), amount);

        AllowanceSpend[] memory allowances = new AllowanceSpend[](1);
        allowances[0] = AllowanceSpend({ token: inToken, allocated: amount, spend: amount });

        Outcome[] memory outcomes = new Outcome[](1);
        outcomes[0] = Outcome({ token: outToken, amount: amount, destination: dest });

        bytes memory sig = _signEntry(account, key, executor, 0, allowances, outcomes);
        bytes memory execPayload = abi.encodeCall(MockExecutor.executeAndDeliverToValidator, (outToken, amount));

        // First call succeeds.
        vm.prank(executor);
        validator.entry(address(exec), execPayload, account, 0, allowances, outcomes, sig);

        // Second call with nonce 0 also succeeds — no NonceAlreadySpent.
        vm.prank(executor);
        validator.entry(address(exec), execPayload, account, 0, allowances, outcomes, sig);

        assertEq(MockERC20(outToken).balanceOf(dest), amount * 2);
    }

    /// A reverted transaction rolls back the nonce; the same nonce can be retried.
    function test_entry_nonce_not_consumed_on_revert() external {
        uint256 amount = 1 ether;
        (
            address account,
            uint256 key,
            address executor,
            address dest,
            address inToken,
            address outToken,
            MockExecutor exec
        ) = _setupEntryFixture(amount);

        // Mint extra for the second attempt.
        MockERC20(inToken).mint(account, amount);
        vm.prank(account);
        MockERC20(inToken).approve(address(validator), amount * 2);
        MockERC20(outToken).mint(address(exec), amount);

        AllowanceSpend[] memory allowances = new AllowanceSpend[](1);
        allowances[0] = AllowanceSpend({ token: inToken, allocated: amount, spend: amount });

        Outcome[] memory outcomes = new Outcome[](1);
        outcomes[0] = Outcome({ token: outToken, amount: amount, destination: dest });

        bytes memory sig = _signEntry(account, key, executor, 1, allowances, outcomes);
        {
            // Wrong delivery: executor sends to wrongDest, CATValidator gets nothing.
            address wrongDest = makeAddr("wrongDest");
            bytes memory failPayload =
                abi.encodeCall(MockExecutor.executeAndDeliverElsewhere, (outToken, amount, wrongDest));

            // First call: fails at _validatePayment → all state rolled back including nonce.
            vm.prank(executor);
            vm.expectRevert(abi.encodeWithSelector(CATValidator.InvalidTokenAmount.selector, amount, 0));
            validator.entry(address(exec), failPayload, account, 1, allowances, outcomes, sig);
        }
        bytes memory goodPayload = abi.encodeCall(MockExecutor.executeAndDeliverToValidator, (outToken, amount));

        // Second call: nonce 1 is available again; executor delivers correctly this time.
        MockERC20(outToken).mint(address(exec), amount); // replenish exec's outToken
        vm.prank(executor);
        validator.entry(address(exec), goodPayload, account, 1, allowances, outcomes, sig);

        assertEq(MockERC20(outToken).balanceOf(dest), amount);
    }

    /// The execution payload cannot re-enter entry(): the nonReentrant guard fires
    /// on the inner call and the revert bubbles up through CallProxy and _call.
    function test_entry_reentrancy_via_proxy_reverts() external {
        (address account, uint256 key) = makeAddrAndKey("account");
        address executor = makeAddr("executor");

        MockExecutor exec = new MockExecutor(address(validator));

        AllowanceSpend[] memory allowances = new AllowanceSpend[](0);
        Outcome[] memory outcomes = new Outcome[](0);

        bytes memory sig = _signEntry(account, key, executor, 1, allowances, outcomes);
        bytes memory execPayload = abi.encodeCall(MockExecutor.executeAndReenter, ());

        vm.prank(executor);
        vm.expectRevert(ReentrancyGuard.Reentrancy.selector);
        validator.entry(address(exec), execPayload, account, 1, allowances, outcomes, sig);
    }

    /// ERC-20 input, native ETH output: signer approves an ERC-20 and requests ETH back.
    /// Executor is pre-loaded with ETH and delivers it to CATValidator; validator forwards to dest.
    function test_entry_erc20_in_eth_out() external {
        uint256 amount = 1 ether;
        (address account, uint256 key) = makeAddrAndKey("account");
        address executor = makeAddr("executor");
        address dest = makeAddr("dest");

        // Input: random ERC-20 approved by signer to validator
        address inToken = address(new MockERC20("In", "IN", 18));
        MockERC20(inToken).mint(account, amount);
        vm.prank(account);
        MockERC20(inToken).approve(address(validator), amount);

        // Executor holds ETH that it will "swap" and deliver
        MockExecutor exec = new MockExecutor(address(validator));
        vm.deal(address(exec), amount);

        AllowanceSpend[] memory allowances = new AllowanceSpend[](1);
        allowances[0] = AllowanceSpend({ token: inToken, allocated: amount, spend: amount });

        // Output: native ETH to dest
        Outcome[] memory outcomes = new Outcome[](1);
        outcomes[0] = Outcome({ token: address(0), amount: amount, destination: dest });

        bytes memory sig = _signEntry(account, key, executor, 1, allowances, outcomes);
        bytes memory execPayload = abi.encodeCall(MockExecutor.executeAndDeliverETHToValidator, (amount));

        uint256 destBefore = dest.balance;
        vm.prank(executor);
        validator.entry(address(exec), execPayload, account, 1, allowances, outcomes, sig);

        // ETH forwarded to dest, validator drained, executor received the ERC-20
        assertEq(dest.balance - destBefore, amount);
        assertEq(address(validator).balance, 0);
        assertEq(MockERC20(inToken).balanceOf(address(exec)), amount);
    }

    // -----------------------------------------------------------------------
    // _validatePayment — native ETH outcomes
    // -----------------------------------------------------------------------

    /// Executor deposits ETH to CATValidator; it is forwarded to destination.
    function test_validatePayment_nativeETH_success() external {
        address dest = makeAddr("dest");
        uint256 amount = 1 ether;

        vm.deal(address(validator), amount);

        Outcome[] memory outcomes = new Outcome[](1);
        outcomes[0] = Outcome({ token: address(0), amount: amount, destination: dest });

        uint256 destBefore = dest.balance;
        validator.validatePayment(address(this), outcomes);

        assertEq(dest.balance - destBefore, amount);
        assertEq(address(validator).balance, 0);
    }

    /// ETH outcome with address(0) destination routes to signer.
    function test_validatePayment_nativeETH_zero_destination_routes_to_signer() external {
        address signer = makeAddr("signer");
        uint256 amount = 1 ether;

        vm.deal(address(validator), amount);

        Outcome[] memory outcomes = new Outcome[](1);
        outcomes[0] = Outcome({ token: address(0), amount: amount, destination: address(0) });

        uint256 signerBefore = signer.balance;
        validator.validatePayment(signer, outcomes);

        assertEq(signer.balance - signerBefore, amount);
        assertEq(address(validator).balance, 0);
    }

    /// ETH balance below required → InvalidTokenAmount.
    function test_validatePayment_nativeETH_revert_insufficient() external {
        address dest = makeAddr("dest");
        uint256 required = 1 ether;

        vm.deal(address(validator), required - 1);

        Outcome[] memory outcomes = new Outcome[](1);
        outcomes[0] = Outcome({ token: address(0), amount: required, destination: dest });

        vm.expectRevert(abi.encodeWithSelector(CATValidator.InvalidTokenAmount.selector, required, required - 1));
        validator.validatePayment(address(this), outcomes);
    }

    /// Mixed ETH + ERC-20 outcomes in a single call.
    function test_validatePayment_mixed_eth_and_erc20() external {
        address destETH = makeAddr("destETH");
        address destERC = makeAddr("destERC");
        uint256 ethAmount = 0.5 ether;
        uint256 ercAmount = 100e18;

        vm.deal(address(validator), ethAmount);
        address token = address(new MockERC20("T", "T", 18));
        MockERC20(token).mint(address(validator), ercAmount);

        Outcome[] memory outcomes = new Outcome[](2);
        outcomes[0] = Outcome({ token: address(0), amount: ethAmount, destination: destETH });
        outcomes[1] = Outcome({ token: token, amount: ercAmount, destination: destERC });

        validator.validatePayment(address(this), outcomes);

        assertEq(destETH.balance, ethAmount);
        assertEq(MockERC20(token).balanceOf(destERC), ercAmount);
        assertEq(address(validator).balance, 0);
        assertEq(MockERC20(token).balanceOf(address(validator)), 0);
    }

    function isValidSignature(
        bytes32,
        bytes calldata
    ) public view returns (bytes4) {
        return bytes4(0x1626ba7e);
    }

    receive() external payable { }
}
