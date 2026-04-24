// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import { Test } from "forge-std/src/Test.sol";
import { VmSafe } from "forge-std/src/Vm.sol";

import { MockERC20 } from "solady/test/utils/mocks/MockERC20.sol";

import { IntentExecutor } from "../../src/libs/IntentExecutor.sol";

/// @dev USDT-style token: reverts when approving a non-zero amount over an existing non-zero allowance.
contract MockUSDT is MockERC20 {
    constructor() MockERC20("Tether USD", "USDT", 6) { }

    function approve(address spender, uint256 amount) public override returns (bool) {
        if (amount > 0 && allowance(msg.sender, spender) > 0) revert("USDT: non-zero to non-zero");
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
        executor = new IntentExecutor();
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

        vm.expectEmit(true, false, false, true);
        emit IntentExecutor.SweptNative(recipient, amount);

        executor.executeAndSweepNative(approvals, calls, sweeps, payable(recipient));

        assertEq(recipient.balance, amount);
        assertEq(address(executor).balance, 0);
    }

    function test_executeAndSweepNative_fallsBackToMsgSender() external {
        uint256 amount = 1 ether;
        vm.deal(address(executor), amount);

        IntentExecutor.Approval[] memory approvals = new IntentExecutor.Approval[](0);
        IntentExecutor.Call3Value[] memory calls = new IntentExecutor.Call3Value[](0);
        IntentExecutor.SweepTarget[] memory sweeps = new IntentExecutor.SweepTarget[](0);

        uint256 callerBalanceBefore = address(this).balance;

        executor.executeAndSweepNative(approvals, calls, sweeps, payable(address(0)));

        assertEq(address(this).balance, callerBalanceBefore + amount);
        assertEq(address(executor).balance, 0);
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

        vm.recordLogs();
        executor.executeAndSweepNative(approvals, calls, sweeps, payable(recipient));

        assertEq(vm.getRecordedLogs().length, 0);
    }

    function test_executeAndSweepNative_acceptsPayableValue() external {
        IntentExecutor.Approval[] memory approvals = new IntentExecutor.Approval[](0);
        IntentExecutor.Call3Value[] memory calls = new IntentExecutor.Call3Value[](0);
        IntentExecutor.SweepTarget[] memory sweeps = new IntentExecutor.SweepTarget[](0);

        vm.deal(address(this), 1 ether);
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

        executor.executeAndSweepNative(approvals, calls, sweeps, payable(address(0)));

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

        vm.expectRevert();
        executor.executeAndSweepNative{ value: 1 ether }(approvals, calls, sweeps, payable(address(0)));
    }

    // -- Sweep guards --

    function testRevert_sweepToZeroAddress() external {
        tokenA.mint(address(executor), 1 ether);

        IntentExecutor.Approval[] memory approvals = new IntentExecutor.Approval[](0);
        IntentExecutor.Call3[] memory calls = new IntentExecutor.Call3[](0);
        IntentExecutor.SweepTarget[] memory sweeps = new IntentExecutor.SweepTarget[](1);
        sweeps[0] = IntentExecutor.SweepTarget({ token: address(tokenA), recipient: address(0) });

        vm.expectRevert(abi.encodeWithSelector(IntentExecutor.ZeroRecipient.selector));
        executor.executeAndSweep(approvals, calls, sweeps);
    }

    // -- Approvals --

    /// @dev Verify the guard skips approve entirely when allowance is already max.
    /// The Approval event is the definitive proof — if it's not emitted, no approve call was made.
    function test_approval_skipsApproveWhenAlreadyMax() external {
        IntentExecutor.Approval[] memory approvals = new IntentExecutor.Approval[](1);
        approvals[0] = IntentExecutor.Approval({ token: address(tokenA), spender: address(this) });
        IntentExecutor.Call3[] memory calls = new IntentExecutor.Call3[](0);
        IntentExecutor.SweepTarget[] memory sweeps = new IntentExecutor.SweepTarget[](0);

        // First call sets max allowance.
        executor.executeAndSweep(approvals, calls, sweeps);
        assertEq(tokenA.allowance(address(executor), address(this)), type(uint256).max);

        // Second call: allowance already max — no Approval event should be emitted.
        vm.recordLogs();
        executor.executeAndSweep(approvals, calls, sweeps);
        assertEq(vm.getRecordedLogs().length, 0);
        assertEq(tokenA.allowance(address(executor), address(this)), type(uint256).max);
    }

    /// @dev Verify approve IS called when allowance is below max.
    function test_approval_approvesWhenBelowMax() external {
        address spender = address(this);

        // Manually set a partial allowance on the executor.
        vm.prank(address(executor));
        tokenA.approve(spender, 1 ether);
        assertEq(tokenA.allowance(address(executor), spender), 1 ether);

        IntentExecutor.Approval[] memory approvals = new IntentExecutor.Approval[](1);
        approvals[0] = IntentExecutor.Approval({ token: address(tokenA), spender: spender });
        IntentExecutor.Call3[] memory calls = new IntentExecutor.Call3[](0);
        IntentExecutor.SweepTarget[] memory sweeps = new IntentExecutor.SweepTarget[](0);

        vm.expectEmit(true, true, false, true, address(tokenA));
        emit Approval(address(executor), spender, type(uint256).max);
        executor.executeAndSweep(approvals, calls, sweeps);

        assertEq(tokenA.allowance(address(executor), spender), type(uint256).max);
    }

    /// @dev With multiple pairs in one call, only the pairs not already at max should approve.
    function test_approval_multiPairs_onlyApprovesNonMax() external {
        address spenderA = makeAddr("spenderA");
        address spenderB = makeAddr("spenderB");

        // Pre-approve spenderA to max; spenderB stays at zero.
        vm.prank(address(executor));
        tokenA.approve(spenderA, type(uint256).max);

        IntentExecutor.Approval[] memory approvals = new IntentExecutor.Approval[](2);
        approvals[0] = IntentExecutor.Approval({ token: address(tokenA), spender: spenderA });
        approvals[1] = IntentExecutor.Approval({ token: address(tokenA), spender: spenderB });
        IntentExecutor.Call3[] memory calls = new IntentExecutor.Call3[](0);
        IntentExecutor.SweepTarget[] memory sweeps = new IntentExecutor.SweepTarget[](0);

        // Only spenderB should trigger an Approval event.
        vm.recordLogs();
        executor.executeAndSweep(approvals, calls, sweeps);

        VmSafe.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 1);
        // The single Approval event must be for spenderB (topic[2] = spender).
        assertEq(logs[0].topics[2], bytes32(uint256(uint160(spenderB))));

        assertEq(tokenA.allowance(address(executor), spenderA), type(uint256).max);
        assertEq(tokenA.allowance(address(executor), spenderB), type(uint256).max);
    }

    /// @dev USDT-style token: guard prevents the revert that would occur if approve were called
    ///      over an existing non-zero allowance.
    function test_approval_usdtStyle_skipsApproveWhenAlreadyMax() external {
        MockUSDT usdt = new MockUSDT();
        address spender = address(this);

        // First call: sets max allowance via safeApproveWithRetry.
        IntentExecutor.Approval[] memory approvals = new IntentExecutor.Approval[](1);
        approvals[0] = IntentExecutor.Approval({ token: address(usdt), spender: spender });
        IntentExecutor.Call3[] memory calls = new IntentExecutor.Call3[](0);
        IntentExecutor.SweepTarget[] memory sweeps = new IntentExecutor.SweepTarget[](0);

        executor.executeAndSweep(approvals, calls, sweeps);
        assertEq(usdt.allowance(address(executor), spender), type(uint256).max);

        // Second call: guard skips approve entirely — USDT would revert if approve were called.
        executor.executeAndSweep(approvals, calls, sweeps);
        assertEq(usdt.allowance(address(executor), spender), type(uint256).max);
    }

    /// @dev USDT-style token with a partial allowance: safeApproveWithRetry must reset to 0
    ///      before setting max. Guard correctly lets the call through when allowance < max.
    function test_approval_usdtStyle_handlesPartialAllowance() external {
        MockUSDT usdt = new MockUSDT();
        address spender = address(this);

        // Set a non-zero, non-max allowance directly on the executor.
        vm.prank(address(executor));
        usdt.approve(spender, 500e6);
        assertEq(usdt.allowance(address(executor), spender), 500e6);

        IntentExecutor.Approval[] memory approvals = new IntentExecutor.Approval[](1);
        approvals[0] = IntentExecutor.Approval({ token: address(usdt), spender: spender });
        IntentExecutor.Call3[] memory calls = new IntentExecutor.Call3[](0);
        IntentExecutor.SweepTarget[] memory sweeps = new IntentExecutor.SweepTarget[](0);

        // safeApproveWithRetry should reset to 0, then approve max.
        executor.executeAndSweep(approvals, calls, sweeps);
        assertEq(usdt.allowance(address(executor), spender), type(uint256).max);
    }

    function test_approvalSetsMaxAllowance() external {
        IntentExecutor.Approval[] memory approvals = new IntentExecutor.Approval[](1);
        approvals[0] = IntentExecutor.Approval({ token: address(tokenA), spender: address(this) });

        IntentExecutor.Call3[] memory calls = new IntentExecutor.Call3[](0);
        IntentExecutor.SweepTarget[] memory sweeps = new IntentExecutor.SweepTarget[](0);

        executor.executeAndSweep(approvals, calls, sweeps);

        assertEq(tokenA.allowance(address(executor), address(this)), type(uint256).max);
    }

    function test_repeatApprovalSavesGas() external {
        IntentExecutor.Approval[] memory approvals = new IntentExecutor.Approval[](1);
        approvals[0] = IntentExecutor.Approval({ token: address(tokenA), spender: address(this) });
        IntentExecutor.Call3[] memory calls = new IntentExecutor.Call3[](0);
        IntentExecutor.SweepTarget[] memory sweeps = new IntentExecutor.SweepTarget[](0);

        // First call — cold SSTORE
        uint256 gasBefore1 = gasleft();
        executor.executeAndSweep(approvals, calls, sweeps);
        uint256 gasUsed1 = gasBefore1 - gasleft();

        // Second call — already max approved, should be cheaper (SLOAD only)
        uint256 gasBefore2 = gasleft();
        executor.executeAndSweep(approvals, calls, sweeps);
        uint256 gasUsed2 = gasBefore2 - gasleft();

        assertLt(gasUsed2, gasUsed1);
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

        executor.executeAndSweep(approvals, calls, sweeps);

        assertEq(tokenA.balanceOf(feeCollector), feeAmount);
        assertEq(tokenB.balanceOf(recipient), swapOutput);
        assertEq(tokenB.balanceOf(address(executor)), 0);
    }

    // -- Helpers --

    receive() external payable { }
}
