// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import { Test } from "forge-std/src/Test.sol";

import { MockERC20 } from "solady/test/utils/mocks/MockERC20.sol";

import { IntentExecutor } from "../../src/libs/IntentExecutor.sol";

contract IntentExecutorTest is Test {
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
