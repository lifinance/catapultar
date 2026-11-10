// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import { Test } from "forge-std/src/Test.sol";

import { Ownable } from "solady/src/auth/Ownable.sol";
import { ERC20 } from "solady/src/tokens/ERC20.sol";
import { SafeTransferLib } from "solady/src/utils/SafeTransferLib.sol";
import { MockERC20 } from "solady/test/utils/mocks/MockERC20.sol";

import { IntentExecutor } from "../../src/libs/IntentExecutor.sol";

import { MockTronUSDT } from "../mocks/MockTronUSDT.sol";

/// @dev USDT-style token: reverts when approving a non-zero amount over an existing non-zero allowance.
contract MockUSDT is MockERC20 {
    constructor() MockERC20("Tether USD", "USDT", 6) { }

    function approve(
        address spender,
        uint256 amount
    ) public override returns (bool) {
        if (amount > 0 && allowance(msg.sender, spender) > 0) revert("USDT: non-zero to non-zero");
        return super.approve(spender, amount);
    }
}

/// @dev BNB-style token: reverts when approving zero.
contract MockZeroApproveReverts is MockERC20 {
    constructor() MockERC20("BNB", "BNB", 18) { }

    function approve(
        address spender,
        uint256 amount
    ) public override returns (bool) {
        if (amount == 0) revert("BNB: zero approve");
        return super.approve(spender, amount);
    }
}

contract IntentExecutorTest is Test {
    event Approval(address indexed owner, address indexed spender, uint256 amount);
    IntentExecutor executor;
    MockERC20 tokenA;
    MockERC20 tokenB;
    address user;
    address recipient;
    address feeCollector;

    function setUp() external {
        address[] memory solvers = new address[](1);
        solvers[0] = address(this);
        executor = new IntentExecutor(makeAddr("owner"), solvers);
        tokenA = new MockERC20("Token A", "TKA", 18);
        tokenB = new MockERC20("Token B", "TKB", 18);
        user = makeAddr("user");
        recipient = makeAddr("recipient");
        feeCollector = makeAddr("feeCollector");
    }

    // -- executeAndSweep --

    function test_executeAndSweep_sweepsFullBalance() external {
        uint256 amount = 1 ether;
        tokenA.mint(address(executor), amount);

        IntentExecutor.Approval[] memory approvals = new IntentExecutor.Approval[](0);
        IntentExecutor.Call3[] memory calls = new IntentExecutor.Call3[](0);
        IntentExecutor.SweepTarget[] memory sweeps = new IntentExecutor.SweepTarget[](1);
        sweeps[0] = IntentExecutor.SweepTarget({ token: address(tokenA), recipient: recipient });

        authorize(abi.encodeCall(IntentExecutor.executeAndSweep, (approvals, calls, sweeps)));
        vm.expectEmit(true, true, false, true);
        emit IntentExecutor.Swept(address(tokenA), recipient, amount);

        executor.executeAndSweep(approvals, calls, sweeps);

        assertEq(tokenA.balanceOf(recipient), amount);
        assertEq(tokenA.balanceOf(address(executor)), 0);
    }

    function test_executeAndSweep_multiTokenSweep() external {
        uint256 amountA = 1 ether;
        uint256 amountB = 2 ether;
        tokenA.mint(address(executor), amountA);
        tokenB.mint(address(executor), amountB);

        IntentExecutor.Approval[] memory approvals = new IntentExecutor.Approval[](0);
        IntentExecutor.Call3[] memory calls = new IntentExecutor.Call3[](0);
        IntentExecutor.SweepTarget[] memory sweeps = new IntentExecutor.SweepTarget[](2);
        sweeps[0] = IntentExecutor.SweepTarget({ token: address(tokenA), recipient: recipient });
        sweeps[1] = IntentExecutor.SweepTarget({ token: address(tokenB), recipient: recipient });

        authorize(abi.encodeCall(IntentExecutor.executeAndSweep, (approvals, calls, sweeps)));
        executor.executeAndSweep(approvals, calls, sweeps);

        assertEq(tokenA.balanceOf(recipient), amountA);
        assertEq(tokenB.balanceOf(recipient), amountB);
        assertEq(tokenA.balanceOf(address(executor)), 0);
        assertEq(tokenB.balanceOf(address(executor)), 0);
    }

    function test_executeAndSweep_skipsZeroBalance() external {
        // tokenA has 0 balance — should not emit Swept
        IntentExecutor.Approval[] memory approvals = new IntentExecutor.Approval[](0);
        IntentExecutor.Call3[] memory calls = new IntentExecutor.Call3[](0);
        IntentExecutor.SweepTarget[] memory sweeps = new IntentExecutor.SweepTarget[](1);
        sweeps[0] = IntentExecutor.SweepTarget({ token: address(tokenA), recipient: recipient });

        authorize(abi.encodeCall(IntentExecutor.executeAndSweep, (approvals, calls, sweeps)));
        vm.recordLogs();
        executor.executeAndSweep(approvals, calls, sweeps);

        assertEq(vm.getRecordedLogs().length, 0);
    }

    function test_executeAndSweep_approvesAndExecutesCall() external {
        uint256 amount = 1 ether;
        tokenA.mint(address(executor), amount);

        // Approve tokenA to this test contract, then call transferFrom via executor
        IntentExecutor.Approval[] memory approvals = new IntentExecutor.Approval[](1);
        approvals[0] = IntentExecutor.Approval({ token: address(tokenA), spender: address(this) });

        IntentExecutor.Call3[] memory calls = new IntentExecutor.Call3[](1);
        calls[0] = IntentExecutor.Call3({
            target: address(tokenA),
            allowFailure: false,
            callData: abi.encodeCall(MockERC20.transfer, (feeCollector, amount / 10))
        });

        IntentExecutor.SweepTarget[] memory sweeps = new IntentExecutor.SweepTarget[](1);
        sweeps[0] = IntentExecutor.SweepTarget({ token: address(tokenA), recipient: recipient });

        authorize(abi.encodeCall(IntentExecutor.executeAndSweep, (approvals, calls, sweeps)));
        executor.executeAndSweep(approvals, calls, sweeps);

        assertEq(tokenA.balanceOf(feeCollector), amount / 10);
        assertEq(tokenA.balanceOf(recipient), amount - amount / 10);
        assertEq(tokenA.balanceOf(address(executor)), 0);
    }

    function test_fuzz_executeAndSweep_sweepsArbitraryAmount(
        uint256 amount
    ) external {
        vm.assume(amount > 0);
        tokenA.mint(address(executor), amount);

        IntentExecutor.Approval[] memory approvals = new IntentExecutor.Approval[](0);
        IntentExecutor.Call3[] memory calls = new IntentExecutor.Call3[](0);
        IntentExecutor.SweepTarget[] memory sweeps = new IntentExecutor.SweepTarget[](1);
        sweeps[0] = IntentExecutor.SweepTarget({ token: address(tokenA), recipient: recipient });

        authorize(abi.encodeCall(IntentExecutor.executeAndSweep, (approvals, calls, sweeps)));
        executor.executeAndSweep(approvals, calls, sweeps);

        assertEq(tokenA.balanceOf(recipient), amount);
        assertEq(tokenA.balanceOf(address(executor)), 0);
    }

    // -- executeAndSweepNative --

    function test_executeAndSweepNative_sweepsNativeToRecipient() external {
        uint256 amount = 1 ether;
        vm.deal(address(executor), amount);

        IntentExecutor.Approval[] memory approvals = new IntentExecutor.Approval[](0);
        IntentExecutor.Call3Value[] memory calls = new IntentExecutor.Call3Value[](0);
        IntentExecutor.SweepTarget[] memory sweeps = new IntentExecutor.SweepTarget[](0);

        authorize(abi.encodeCall(IntentExecutor.executeAndSweepNative, (approvals, calls, sweeps, payable(recipient))));
        vm.expectEmit(true, false, false, true);
        emit IntentExecutor.SweptNative(recipient, amount);

        executor.executeAndSweepNative(approvals, calls, sweeps, payable(recipient));

        assertEq(recipient.balance, amount);
        assertEq(address(executor).balance, 0);
    }

    /// @dev A zero native recipient reverts, even with nothing to sweep: through a validator,
    /// a fallback to msg.sender would send the ETH to its CALL_PROXY, which never spends it.
    function testRevert_executeAndSweepNative_zeroNativeRecipient() external {
        vm.deal(address(executor), 1 ether);

        IntentExecutor.Approval[] memory approvals = new IntentExecutor.Approval[](0);
        IntentExecutor.Call3Value[] memory calls = new IntentExecutor.Call3Value[](0);
        IntentExecutor.SweepTarget[] memory sweeps = new IntentExecutor.SweepTarget[](0);

        authorize(abi.encodeCall(IntentExecutor.executeAndSweepNative, (approvals, calls, sweeps, payable(address(0)))));
        vm.expectRevert(IntentExecutor.ZeroRecipient.selector);
        executor.executeAndSweepNative(approvals, calls, sweeps, payable(address(0)));
        assertEq(address(executor).balance, 1 ether);
    }

    function test_executeAndSweepNative_sweepsBothERC20AndNative() external {
        uint256 nativeAmount = 1 ether;
        uint256 tokenAmount = 2 ether;
        vm.deal(address(executor), nativeAmount);
        tokenA.mint(address(executor), tokenAmount);

        IntentExecutor.Approval[] memory approvals = new IntentExecutor.Approval[](0);
        IntentExecutor.Call3Value[] memory calls = new IntentExecutor.Call3Value[](0);
        IntentExecutor.SweepTarget[] memory sweeps = new IntentExecutor.SweepTarget[](1);
        sweeps[0] = IntentExecutor.SweepTarget({ token: address(tokenA), recipient: recipient });

        authorize(abi.encodeCall(IntentExecutor.executeAndSweepNative, (approvals, calls, sweeps, payable(recipient))));
        executor.executeAndSweepNative(approvals, calls, sweeps, payable(recipient));

        assertEq(tokenA.balanceOf(recipient), tokenAmount);
        assertEq(recipient.balance, nativeAmount);
        assertEq(tokenA.balanceOf(address(executor)), 0);
        assertEq(address(executor).balance, 0);
    }

    function test_executeAndSweepNative_skipsNativeSweepWhenZeroBalance() external {
        // No native balance — should not emit SweptNative
        IntentExecutor.Approval[] memory approvals = new IntentExecutor.Approval[](0);
        IntentExecutor.Call3Value[] memory calls = new IntentExecutor.Call3Value[](0);
        IntentExecutor.SweepTarget[] memory sweeps = new IntentExecutor.SweepTarget[](0);

        authorize(abi.encodeCall(IntentExecutor.executeAndSweepNative, (approvals, calls, sweeps, payable(recipient))));
        vm.recordLogs();
        executor.executeAndSweepNative(approvals, calls, sweeps, payable(recipient));

        assertEq(vm.getRecordedLogs().length, 0);
    }

    function test_executeAndSweepNative_acceptsPayableValue() external {
        IntentExecutor.Approval[] memory approvals = new IntentExecutor.Approval[](0);
        IntentExecutor.Call3Value[] memory calls = new IntentExecutor.Call3Value[](0);
        IntentExecutor.SweepTarget[] memory sweeps = new IntentExecutor.SweepTarget[](0);

        vm.deal(address(this), 1 ether);
        authorize(abi.encodeCall(IntentExecutor.executeAndSweepNative, (approvals, calls, sweeps, payable(recipient))));
        executor.executeAndSweepNative{ value: 1 ether }(approvals, calls, sweeps, payable(recipient));

        assertEq(recipient.balance, 1 ether);
    }

    // -- Call execution --

    function test_callExecution_revertsOnFailedCall() external {
        IntentExecutor.Approval[] memory approvals = new IntentExecutor.Approval[](0);
        IntentExecutor.Call3[] memory calls = new IntentExecutor.Call3[](1);
        calls[0] = IntentExecutor.Call3({
            target: address(tokenA),
            allowFailure: false,
            callData: abi.encodeCall(MockERC20.transfer, (recipient, 999 ether)) // no balance
        });
        IntentExecutor.SweepTarget[] memory sweeps = new IntentExecutor.SweepTarget[](0);

        authorize(abi.encodeCall(IntentExecutor.executeAndSweep, (approvals, calls, sweeps)));
        vm.expectRevert();
        executor.executeAndSweep(approvals, calls, sweeps);
    }

    function test_callExecution_allowFailureSwallowsRevert() external {
        IntentExecutor.Approval[] memory approvals = new IntentExecutor.Approval[](0);
        IntentExecutor.Call3[] memory calls = new IntentExecutor.Call3[](1);
        calls[0] = IntentExecutor.Call3({
            target: address(tokenA),
            allowFailure: true,
            callData: abi.encodeCall(MockERC20.transfer, (recipient, 999 ether)) // no balance
        });
        IntentExecutor.SweepTarget[] memory sweeps = new IntentExecutor.SweepTarget[](0);

        authorize(abi.encodeCall(IntentExecutor.executeAndSweep, (approvals, calls, sweeps)));
        IntentExecutor.Result[] memory results = executor.executeAndSweep(approvals, calls, sweeps);

        assertEq(results.length, 1);
        assertEq(results[0].success, false);
    }

    function test_callExecution_returnsResultsForSuccessfulCalls() external {
        uint256 amount = 1 ether;
        tokenA.mint(address(executor), amount);

        IntentExecutor.Approval[] memory approvals = new IntentExecutor.Approval[](0);
        IntentExecutor.Call3[] memory calls = new IntentExecutor.Call3[](1);
        calls[0] = IntentExecutor.Call3({
            target: address(tokenA),
            allowFailure: false,
            callData: abi.encodeCall(MockERC20.transfer, (recipient, amount))
        });
        IntentExecutor.SweepTarget[] memory sweeps = new IntentExecutor.SweepTarget[](0);

        authorize(abi.encodeCall(IntentExecutor.executeAndSweep, (approvals, calls, sweeps)));
        IntentExecutor.Result[] memory results = executor.executeAndSweep(approvals, calls, sweeps);

        assertEq(results.length, 1);
        assertEq(results[0].success, true);
    }

    function test_callExecution_withValue() external {
        uint256 amount = 1 ether;
        vm.deal(address(executor), amount);

        IntentExecutor.Approval[] memory approvals = new IntentExecutor.Approval[](0);
        IntentExecutor.Call3Value[] memory calls = new IntentExecutor.Call3Value[](1);
        calls[0] = IntentExecutor.Call3Value({ target: recipient, allowFailure: false, value: amount, callData: hex"" });
        IntentExecutor.SweepTarget[] memory sweeps = new IntentExecutor.SweepTarget[](0);

        authorize(abi.encodeCall(IntentExecutor.executeAndSweepNative, (approvals, calls, sweeps, payable(recipient))));
        executor.executeAndSweepNative(approvals, calls, sweeps, payable(recipient));

        assertEq(recipient.balance, amount);
    }

    function test_callExecution_withValue_revertsOnFailedCall() external {
        vm.deal(address(executor), 1 ether);

        IntentExecutor.Approval[] memory approvals = new IntentExecutor.Approval[](0);
        IntentExecutor.Call3Value[] memory calls = new IntentExecutor.Call3Value[](1);
        // Send value to a contract that can't receive ETH (tokenA has no receive/fallback)
        calls[0] = IntentExecutor.Call3Value({
            target: address(tokenA), allowFailure: false, value: 1 ether, callData: hex""
        });
        IntentExecutor.SweepTarget[] memory sweeps = new IntentExecutor.SweepTarget[](0);

        authorize(abi.encodeCall(IntentExecutor.executeAndSweepNative, (approvals, calls, sweeps, payable(recipient))));
        vm.expectRevert();
        executor.executeAndSweepNative{ value: 1 ether }(approvals, calls, sweeps, payable(recipient));
    }

    // -- Sweep guards --

    function testRevert_sweepToZeroAddress() external {
        tokenA.mint(address(executor), 1 ether);

        IntentExecutor.Approval[] memory approvals = new IntentExecutor.Approval[](0);
        IntentExecutor.Call3[] memory calls = new IntentExecutor.Call3[](0);
        IntentExecutor.SweepTarget[] memory sweeps = new IntentExecutor.SweepTarget[](1);
        sweeps[0] = IntentExecutor.SweepTarget({ token: address(tokenA), recipient: address(0) });

        authorize(abi.encodeCall(IntentExecutor.executeAndSweep, (approvals, calls, sweeps)));
        vm.expectRevert(abi.encodeWithSelector(IntentExecutor.ZeroRecipient.selector));
        executor.executeAndSweep(approvals, calls, sweeps);
    }

    // -- Approvals --

    /// @dev The spender can pull during the calls; afterwards the allowance is zero and
    ///      a later pull of what the executor holds reverts.
    function test_approval_spenderPullsOnlyDuringCall() external {
        uint256 amount = 1 ether;
        tokenA.mint(address(executor), amount);

        IntentExecutor.Approval[] memory approvals = oneApproval(address(tokenA), address(this));
        IntentExecutor.Call3[] memory calls = new IntentExecutor.Call3[](1);
        calls[0] = IntentExecutor.Call3({
            target: address(this), allowFailure: false, callData: abi.encodeCall(this.pull, (tokenA, amount / 2))
        });
        IntentExecutor.SweepTarget[] memory sweeps = new IntentExecutor.SweepTarget[](0);

        authorize(abi.encodeCall(IntentExecutor.executeAndSweep, (approvals, calls, sweeps)));
        executor.executeAndSweep(approvals, calls, sweeps);

        assertEq(tokenA.balanceOf(address(this)), amount / 2);
        assertEq(tokenA.allowance(address(executor), address(this)), 0);
        vm.expectRevert(ERC20.InsufficientAllowance.selector);
        this.pull(tokenA, amount / 2);
    }

    function test_approval_nativeRevokesAfterCall() external {
        uint256 amount = 1 ether;
        tokenA.mint(address(executor), amount);

        IntentExecutor.Approval[] memory approvals = oneApproval(address(tokenA), address(this));
        IntentExecutor.Call3Value[] memory calls = new IntentExecutor.Call3Value[](1);
        calls[0] = IntentExecutor.Call3Value({
            target: address(this), allowFailure: false, value: 0, callData: abi.encodeCall(this.pull, (tokenA, amount))
        });
        IntentExecutor.SweepTarget[] memory sweeps = new IntentExecutor.SweepTarget[](0);

        authorize(abi.encodeCall(IntentExecutor.executeAndSweepNative, (approvals, calls, sweeps, payable(recipient))));
        executor.executeAndSweepNative(approvals, calls, sweeps, payable(recipient));

        assertEq(tokenA.balanceOf(address(this)), amount);
        assertEq(tokenA.allowance(address(executor), address(this)), 0);
    }

    /// @dev A failed call that allowFailure swallows still ends with the allowance revoked.
    function test_approval_revokedAfterAllowedFailure() external {
        IntentExecutor.Approval[] memory approvals = oneApproval(address(tokenA), address(this));
        IntentExecutor.Call3[] memory calls = new IntentExecutor.Call3[](1);
        calls[0] = IntentExecutor.Call3({
            target: address(this), allowFailure: true, callData: abi.encodeCall(this.pull, (tokenA, 1 ether))
        });
        IntentExecutor.SweepTarget[] memory sweeps = new IntentExecutor.SweepTarget[](0);

        authorize(abi.encodeCall(IntentExecutor.executeAndSweep, (approvals, calls, sweeps)));
        IntentExecutor.Result[] memory results = executor.executeAndSweep(approvals, calls, sweeps);

        assertFalse(results[0].success);
        assertEq(tokenA.allowance(address(executor), address(this)), 0);
    }

    /// @dev An allowance granted before this version is overwritten with max for the call,
    ///      then revoked.
    function test_approval_revokesEarlierAllowance() external {
        address spender = makeAddr("spender");
        vm.prank(address(executor));
        tokenA.approve(spender, type(uint256).max);

        IntentExecutor.Approval[] memory approvals = oneApproval(address(tokenA), spender);
        IntentExecutor.Call3[] memory calls = new IntentExecutor.Call3[](0);
        IntentExecutor.SweepTarget[] memory sweeps = new IntentExecutor.SweepTarget[](0);

        authorize(abi.encodeCall(IntentExecutor.executeAndSweep, (approvals, calls, sweeps)));
        vm.expectEmit(true, true, false, true, address(tokenA));
        emit Approval(address(executor), spender, type(uint256).max);
        vm.expectEmit(true, true, false, true, address(tokenA));
        emit Approval(address(executor), spender, 0);
        executor.executeAndSweep(approvals, calls, sweeps);

        assertEq(tokenA.allowance(address(executor), spender), 0);
    }

    /// @dev USDT-style token with an earlier non-zero allowance: safeApproveWithRetry resets
    ///      it to 0 before approving max, and the revocation leaves it at 0.
    function test_approval_usdtStyle_handlesEarlierAllowance() external {
        MockUSDT usdt = new MockUSDT();
        uint256 amount = 500e6;
        usdt.mint(address(executor), amount);
        vm.prank(address(executor));
        usdt.approve(address(this), 1);

        IntentExecutor.Approval[] memory approvals = oneApproval(address(usdt), address(this));
        IntentExecutor.Call3[] memory calls = new IntentExecutor.Call3[](1);
        calls[0] = IntentExecutor.Call3({
            target: address(this), allowFailure: false, callData: abi.encodeCall(this.pull, (usdt, amount))
        });
        IntentExecutor.SweepTarget[] memory sweeps = new IntentExecutor.SweepTarget[](0);

        authorize(abi.encodeCall(IntentExecutor.executeAndSweep, (approvals, calls, sweeps)));
        executor.executeAndSweep(approvals, calls, sweeps);

        assertEq(usdt.balanceOf(address(this)), amount);
        assertEq(usdt.allowance(address(executor), address(this)), 0);
    }

    /// @dev A pair listed twice: the second approve meets the first's non-zero allowance,
    ///      which a USDT-style token only accepts through the retry.
    function test_approval_usdtStyle_duplicatePair() external {
        MockUSDT usdt = new MockUSDT();
        IntentExecutor.Approval[] memory approvals = new IntentExecutor.Approval[](2);
        approvals[0] = IntentExecutor.Approval({ token: address(usdt), spender: address(this) });
        approvals[1] = approvals[0];
        IntentExecutor.Call3[] memory calls = new IntentExecutor.Call3[](0);
        IntentExecutor.SweepTarget[] memory sweeps = new IntentExecutor.SweepTarget[](0);

        authorize(abi.encodeCall(IntentExecutor.executeAndSweep, (approvals, calls, sweeps)));
        executor.executeAndSweep(approvals, calls, sweeps);

        assertEq(usdt.allowance(address(executor), address(this)), 0);
    }

    /// @dev A token that rejects approve(0) cannot be approved: the allowance could not be
    ///      revoked, so the call reverts instead of leaving it behind.
    function test_approval_revertsWhenRevocationFails() external {
        MockZeroApproveReverts bnb = new MockZeroApproveReverts();
        IntentExecutor.Approval[] memory approvals = oneApproval(address(bnb), address(this));
        IntentExecutor.Call3[] memory calls = new IntentExecutor.Call3[](0);
        IntentExecutor.SweepTarget[] memory sweeps = new IntentExecutor.SweepTarget[](0);

        authorize(abi.encodeCall(IntentExecutor.executeAndSweep, (approvals, calls, sweeps)));
        vm.expectRevert(SafeTransferLib.ApproveFailed.selector);
        executor.executeAndSweep(approvals, calls, sweeps);

        assertEq(bnb.allowance(address(executor), address(this)), 0);
    }

    // -- revokeApprovals --

    /// @dev An allowance granted through `calls` outlives the call; the owner revokes it.
    function test_revokeApprovals_clearsAllowanceGrantedByCall() external {
        address spender = makeAddr("spender");
        IntentExecutor.Approval[] memory approvals = new IntentExecutor.Approval[](0);
        IntentExecutor.Call3[] memory calls = new IntentExecutor.Call3[](1);
        calls[0] = IntentExecutor.Call3({
            target: address(tokenA),
            allowFailure: false,
            callData: abi.encodeCall(ERC20.approve, (spender, type(uint256).max))
        });
        IntentExecutor.SweepTarget[] memory sweeps = new IntentExecutor.SweepTarget[](0);

        authorize(abi.encodeCall(IntentExecutor.executeAndSweep, (approvals, calls, sweeps)));
        executor.executeAndSweep(approvals, calls, sweeps);
        assertEq(tokenA.allowance(address(executor), spender), type(uint256).max);

        vm.prank(executor.owner());
        executor.revokeApprovals(oneApproval(address(tokenA), spender));

        assertEq(tokenA.allowance(address(executor), spender), 0);
    }

    function test_revokeApprovals_onlyOwner() external {
        address spender = makeAddr("spender");
        vm.prank(address(executor));
        tokenA.approve(spender, type(uint256).max);

        vm.expectRevert(Ownable.Unauthorized.selector);
        executor.revokeApprovals(oneApproval(address(tokenA), spender));

        assertEq(tokenA.allowance(address(executor), spender), type(uint256).max);
    }

    // -- Receive --

    function test_receiveAcceptsEth() external {
        vm.deal(address(this), 1 ether);
        (bool ok,) = address(executor).call{ value: 1 ether }("");
        assertTrue(ok);
        assertEq(address(executor).balance, 1 ether);
    }

    // -- End-to-end: approve, swap, fee, sweep --

    function test_endToEnd_approveSwapFeeSweep() external {
        uint256 inputAmount = 10 ether;
        uint256 feeAmount = inputAmount / 100; // 1%
        uint256 swapOutput = 9 ether;
        tokenA.mint(address(executor), inputAmount);

        // Phase 1: Approve tokenA to this contract (simulating DEX approval)
        IntentExecutor.Approval[] memory approvals = new IntentExecutor.Approval[](1);
        approvals[0] = IntentExecutor.Approval({ token: address(tokenA), spender: address(this) });

        // Phase 2: Two calls — fee transfer + simulated swap (mint output token)
        IntentExecutor.Call3[] memory calls = new IntentExecutor.Call3[](2);
        // Fee transfer
        calls[0] = IntentExecutor.Call3({
            target: address(tokenA),
            allowFailure: false,
            callData: abi.encodeCall(MockERC20.transfer, (feeCollector, feeAmount))
        });
        // Simulated swap: burn input, mint output to executor
        calls[1] = IntentExecutor.Call3({
            target: address(tokenB),
            allowFailure: false,
            callData: abi.encodeCall(MockERC20.mint, (address(executor), swapOutput))
        });

        // Phase 3: Sweep output token to recipient
        IntentExecutor.SweepTarget[] memory sweeps = new IntentExecutor.SweepTarget[](1);
        sweeps[0] = IntentExecutor.SweepTarget({ token: address(tokenB), recipient: recipient });

        authorize(abi.encodeCall(IntentExecutor.executeAndSweep, (approvals, calls, sweeps)));
        executor.executeAndSweep(approvals, calls, sweeps);

        assertEq(tokenA.balanceOf(feeCollector), feeAmount);
        assertEq(tokenB.balanceOf(recipient), swapOutput);
        assertEq(tokenB.balanceOf(address(executor)), 0);
    }

    // -- Tron USDT regression: safeTransfer reverts on false-returning token --

    /// @dev Confirms that the standard IntentExecutor cannot sweep MockTronUSDT.
    ///      This is the failure mode that IntentExecutorTron was created to fix.
    function testRevert_executeAndSweep_tronUsdtBreaksStandardContract() external {
        MockTronUSDT tronUsdt = new MockTronUSDT();
        uint256 amount = 1000e6;
        tronUsdt.mint(address(executor), amount);

        IntentExecutor.Approval[] memory approvals = new IntentExecutor.Approval[](0);
        IntentExecutor.Call3[] memory calls = new IntentExecutor.Call3[](0);
        IntentExecutor.SweepTarget[] memory sweeps = new IntentExecutor.SweepTarget[](1);
        sweeps[0] = IntentExecutor.SweepTarget({ token: address(tronUsdt), recipient: recipient });

        authorize(abi.encodeCall(IntentExecutor.executeAndSweep, (approvals, calls, sweeps)));
        vm.expectRevert();
        executor.executeAndSweep(approvals, calls, sweeps);
    }

    // -- Helpers --

    /// @dev This test contract is a solver: authorize one execution of `data`. These tests
    /// call the executor directly, so any address with code stands in for the validator.
    function authorize(
        bytes memory data
    ) internal {
        executor.authorizeCall(keccak256(data), address(this));
    }

    function oneApproval(
        address token,
        address spender
    ) internal pure returns (IntentExecutor.Approval[] memory approvals) {
        approvals = new IntentExecutor.Approval[](1);
        approvals[0] = IntentExecutor.Approval({ token: token, spender: spender });
    }

    /// @dev Stands in for a DEX: spends this contract's allowance on the executor.
    function pull(
        MockERC20 token,
        uint256 amount
    ) external {
        token.transferFrom(address(executor), address(this), amount);
    }

    receive() external payable { }
}
