// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import { Test } from "forge-std/src/Test.sol";
import { VmSafe } from "forge-std/src/Vm.sol";

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

contract IntentExecutorTest is Test {
    event Approval(address indexed owner, address indexed spender, uint256 amount);
    IntentExecutor executor;
    MockERC20 tokenA;
    MockERC20 tokenB;
    address user;
    address recipient;
    address feeCollector;
    /// @dev Native value entry() forwards to the executor. A test sets it before run().
    uint256 internal entryValue;
    /// @dev Return data of the executor call entry() made, read back by run().
    bytes internal entryReturnData;

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

        vm.expectEmit(true, true, false, true);
        emit IntentExecutor.Swept(address(tokenA), recipient, amount);

        run(abi.encodeCall(IntentExecutor.executeAndSweep, (approvals, calls, sweeps)));

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

        run(abi.encodeCall(IntentExecutor.executeAndSweep, (approvals, calls, sweeps)));

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
        run(abi.encodeCall(IntentExecutor.executeAndSweep, (approvals, calls, sweeps)));

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

        run(abi.encodeCall(IntentExecutor.executeAndSweep, (approvals, calls, sweeps)));

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

        run(abi.encodeCall(IntentExecutor.executeAndSweep, (approvals, calls, sweeps)));

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

        run(abi.encodeCall(IntentExecutor.executeAndSweepNative, (approvals, calls, sweeps, payable(recipient))));

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

        vm.expectRevert(IntentExecutor.ZeroRecipient.selector);
        run(abi.encodeCall(IntentExecutor.executeAndSweepNative, (approvals, calls, sweeps, payable(address(0)))));
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

        run(abi.encodeCall(IntentExecutor.executeAndSweepNative, (approvals, calls, sweeps, payable(recipient))));

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
        run(abi.encodeCall(IntentExecutor.executeAndSweepNative, (approvals, calls, sweeps, payable(recipient))));

        assertEq(vm.getRecordedLogs().length, 0);
    }

    function test_executeAndSweepNative_acceptsPayableValue() external {
        IntentExecutor.Approval[] memory approvals = new IntentExecutor.Approval[](0);
        IntentExecutor.Call3Value[] memory calls = new IntentExecutor.Call3Value[](0);
        IntentExecutor.SweepTarget[] memory sweeps = new IntentExecutor.SweepTarget[](0);

        vm.deal(address(this), 1 ether);
        entryValue = 1 ether;
        run(abi.encodeCall(IntentExecutor.executeAndSweepNative, (approvals, calls, sweeps, payable(recipient))));

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
        run(abi.encodeCall(IntentExecutor.executeAndSweep, (approvals, calls, sweeps)));
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

        IntentExecutor.Result[] memory results = abi.decode(
            run(abi.encodeCall(IntentExecutor.executeAndSweep, (approvals, calls, sweeps))), (IntentExecutor.Result[])
        );

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

        IntentExecutor.Result[] memory results = abi.decode(
            run(abi.encodeCall(IntentExecutor.executeAndSweep, (approvals, calls, sweeps))), (IntentExecutor.Result[])
        );

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

        run(abi.encodeCall(IntentExecutor.executeAndSweepNative, (approvals, calls, sweeps, payable(recipient))));

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

        entryValue = 1 ether;
        vm.expectRevert();
        run(abi.encodeCall(IntentExecutor.executeAndSweepNative, (approvals, calls, sweeps, payable(recipient))));
    }

    // -- Sweep guards --

    function testRevert_sweepToZeroAddress() external {
        tokenA.mint(address(executor), 1 ether);

        IntentExecutor.Approval[] memory approvals = new IntentExecutor.Approval[](0);
        IntentExecutor.Call3[] memory calls = new IntentExecutor.Call3[](0);
        IntentExecutor.SweepTarget[] memory sweeps = new IntentExecutor.SweepTarget[](1);
        sweeps[0] = IntentExecutor.SweepTarget({ token: address(tokenA), recipient: address(0) });

        vm.expectRevert(abi.encodeWithSelector(IntentExecutor.ZeroRecipient.selector));
        run(abi.encodeCall(IntentExecutor.executeAndSweep, (approvals, calls, sweeps)));
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
        run(abi.encodeCall(IntentExecutor.executeAndSweep, (approvals, calls, sweeps)));
        assertEq(tokenA.allowance(address(executor), address(this)), type(uint256).max);

        // Second call: allowance already max — no Approval event should be emitted.
        vm.recordLogs();
        run(abi.encodeCall(IntentExecutor.executeAndSweep, (approvals, calls, sweeps)));
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
        run(abi.encodeCall(IntentExecutor.executeAndSweep, (approvals, calls, sweeps)));

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
        run(abi.encodeCall(IntentExecutor.executeAndSweep, (approvals, calls, sweeps)));

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

        run(abi.encodeCall(IntentExecutor.executeAndSweep, (approvals, calls, sweeps)));
        assertEq(usdt.allowance(address(executor), spender), type(uint256).max);

        // Second call: guard skips approve entirely — USDT would revert if approve were called.
        run(abi.encodeCall(IntentExecutor.executeAndSweep, (approvals, calls, sweeps)));
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
        run(abi.encodeCall(IntentExecutor.executeAndSweep, (approvals, calls, sweeps)));
        assertEq(usdt.allowance(address(executor), spender), type(uint256).max);
    }

    function test_approvalSetsMaxAllowance() external {
        IntentExecutor.Approval[] memory approvals = new IntentExecutor.Approval[](1);
        approvals[0] = IntentExecutor.Approval({ token: address(tokenA), spender: address(this) });

        IntentExecutor.Call3[] memory calls = new IntentExecutor.Call3[](0);
        IntentExecutor.SweepTarget[] memory sweeps = new IntentExecutor.SweepTarget[](0);

        run(abi.encodeCall(IntentExecutor.executeAndSweep, (approvals, calls, sweeps)));

        assertEq(tokenA.allowance(address(executor), address(this)), type(uint256).max);
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

        run(abi.encodeCall(IntentExecutor.executeAndSweep, (approvals, calls, sweeps)));

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

        vm.expectRevert();
        run(abi.encodeCall(IntentExecutor.executeAndSweep, (approvals, calls, sweeps)));
    }

    // -- Helpers --

    /// @dev This test contract is both the solver and the validator stand-in: fill()
    /// authorizes one execution of `data`, calls entry() below, and entry() runs `data`
    /// against the executor. Returns the executor's return data.
    function run(
        bytes memory data
    ) internal returns (bytes memory ret) {
        executor.fill(address(this), abi.encodeCall(this.entry, (address(executor), data)));
        ret = entryReturnData;
    }

    /// @dev Stands in for a CAT validator's `entry`: calls `execTarget` with `execPayload`,
    /// forwarding any `entryValue` the test set, and bubbles a revert verbatim.
    function entry(
        address execTarget,
        bytes calldata execPayload
    ) external {
        require(msg.sender == address(executor), "entry: not executor");
        (bool success, bytes memory ret) = execTarget.call{ value: entryValue }(execPayload);
        if (!success) {
            assembly ("memory-safe") {
                revert(add(ret, 0x20), mload(ret))
            }
        }
        entryReturnData = ret;
    }

    receive() external payable { }
}
