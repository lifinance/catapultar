// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import { Test } from "forge-std/src/Test.sol";

import { MockERC20 } from "solady/test/utils/mocks/MockERC20.sol";

import { IntentExecutor } from "../../../src/libs/IntentExecutor.sol";
import { IntentExecutorTron } from "../../../src/libs/IntentExecutor.tron.sol";

import { MockTronUSDT } from "../../mocks/MockTronUSDT.sol";

contract IntentExecutorTronTest is Test {
    IntentExecutorTron executor;
    MockTronUSDT tronUsdt;
    MockERC20 standardToken;
    address recipient;
    /// @dev Return data of the executor call entry() made, read back by run().
    bytes internal entryReturnData;

    function setUp() external {
        address[] memory solvers = new address[](1);
        solvers[0] = address(this);
        executor = new IntentExecutorTron(makeAddr("owner"), solvers);
        tronUsdt = new MockTronUSDT();
        standardToken = new MockERC20("Standard", "STD", 18);
        recipient = makeAddr("recipient");
    }

    // -- executeAndSweep with Tron USDT --

    function test_executeAndSweep_tronUsdt_sweepsFullBalance() external {
        uint256 amount = 1000e6;
        tronUsdt.mint(address(executor), amount);

        IntentExecutor.Approval[] memory approvals = new IntentExecutor.Approval[](0);
        IntentExecutor.Call3[] memory calls = new IntentExecutor.Call3[](0);
        IntentExecutor.SweepTarget[] memory sweeps = new IntentExecutor.SweepTarget[](1);
        sweeps[0] = IntentExecutor.SweepTarget({ token: address(tronUsdt), recipient: recipient });

        vm.expectEmit(true, true, false, true);
        emit IntentExecutor.Swept(address(tronUsdt), recipient, amount);

        run(abi.encodeCall(IntentExecutor.executeAndSweep, (approvals, calls, sweeps)));

        assertEq(tronUsdt.balanceOf(recipient), amount);
        assertEq(tronUsdt.balanceOf(address(executor)), 0);
    }

    function test_executeAndSweep_tronUsdt_multiSweep() external {
        uint256 usdtAmount = 1000e6;
        uint256 stdAmount = 2 ether;
        tronUsdt.mint(address(executor), usdtAmount);
        standardToken.mint(address(executor), stdAmount);

        IntentExecutor.Approval[] memory approvals = new IntentExecutor.Approval[](0);
        IntentExecutor.Call3[] memory calls = new IntentExecutor.Call3[](0);
        IntentExecutor.SweepTarget[] memory sweeps = new IntentExecutor.SweepTarget[](2);
        sweeps[0] = IntentExecutor.SweepTarget({ token: address(tronUsdt), recipient: recipient });
        sweeps[1] = IntentExecutor.SweepTarget({ token: address(standardToken), recipient: recipient });

        run(abi.encodeCall(IntentExecutor.executeAndSweep, (approvals, calls, sweeps)));

        assertEq(tronUsdt.balanceOf(recipient), usdtAmount);
        assertEq(standardToken.balanceOf(recipient), stdAmount);
        assertEq(tronUsdt.balanceOf(address(executor)), 0);
        assertEq(standardToken.balanceOf(address(executor)), 0);
    }

    function test_fuzz_executeAndSweep_tronUsdt(
        uint256 amount
    ) external {
        vm.assume(amount > 0);
        tronUsdt.mint(address(executor), amount);

        IntentExecutor.Approval[] memory approvals = new IntentExecutor.Approval[](0);
        IntentExecutor.Call3[] memory calls = new IntentExecutor.Call3[](0);
        IntentExecutor.SweepTarget[] memory sweeps = new IntentExecutor.SweepTarget[](1);
        sweeps[0] = IntentExecutor.SweepTarget({ token: address(tronUsdt), recipient: recipient });

        run(abi.encodeCall(IntentExecutor.executeAndSweep, (approvals, calls, sweeps)));

        assertEq(tronUsdt.balanceOf(recipient), amount);
        assertEq(tronUsdt.balanceOf(address(executor)), 0);
    }

    // -- executeAndSweepNative with Tron USDT --

    function test_executeAndSweepNative_tronUsdt_sweepsBothTokenAndNative() external {
        uint256 nativeAmount = 1 ether;
        uint256 tokenAmount = 1000e6;
        vm.deal(address(executor), nativeAmount);
        tronUsdt.mint(address(executor), tokenAmount);

        IntentExecutor.Approval[] memory approvals = new IntentExecutor.Approval[](0);
        IntentExecutor.Call3Value[] memory calls = new IntentExecutor.Call3Value[](0);
        IntentExecutor.SweepTarget[] memory sweeps = new IntentExecutor.SweepTarget[](1);
        sweeps[0] = IntentExecutor.SweepTarget({ token: address(tronUsdt), recipient: recipient });

        run(abi.encodeCall(IntentExecutor.executeAndSweepNative, (approvals, calls, sweeps, payable(recipient))));

        assertEq(tronUsdt.balanceOf(recipient), tokenAmount);
        assertEq(recipient.balance, nativeAmount);
        assertEq(tronUsdt.balanceOf(address(executor)), 0);
        assertEq(address(executor).balance, 0);
    }

    // -- Approvals still work --

    function test_approval_setsMaxAllowance() external {
        IntentExecutor.Approval[] memory approvals = new IntentExecutor.Approval[](1);
        approvals[0] = IntentExecutor.Approval({ token: address(tronUsdt), spender: address(this) });

        IntentExecutor.Call3[] memory calls = new IntentExecutor.Call3[](0);
        IntentExecutor.SweepTarget[] memory sweeps = new IntentExecutor.SweepTarget[](0);

        run(abi.encodeCall(IntentExecutor.executeAndSweep, (approvals, calls, sweeps)));

        assertEq(tronUsdt.allowance(address(executor), address(this)), type(uint256).max);
    }

    // -- End-to-end: approve, call, sweep with Tron USDT --

    function test_endToEnd_tronUsdt_approveCallSweep() external {
        uint256 inputAmount = 10_000e6;
        uint256 feeAmount = inputAmount / 100;
        tronUsdt.mint(address(executor), inputAmount);

        IntentExecutor.Approval[] memory approvals = new IntentExecutor.Approval[](1);
        approvals[0] = IntentExecutor.Approval({ token: address(tronUsdt), spender: address(this) });

        address feeCollector = makeAddr("feeCollector");
        IntentExecutor.Call3[] memory calls = new IntentExecutor.Call3[](1);
        calls[0] = IntentExecutor.Call3({
            target: address(tronUsdt),
            allowFailure: false,
            callData: abi.encodeCall(MockERC20.transfer, (feeCollector, feeAmount))
        });

        IntentExecutor.SweepTarget[] memory sweeps = new IntentExecutor.SweepTarget[](1);
        sweeps[0] = IntentExecutor.SweepTarget({ token: address(tronUsdt), recipient: recipient });

        run(abi.encodeCall(IntentExecutor.executeAndSweep, (approvals, calls, sweeps)));

        assertEq(tronUsdt.balanceOf(feeCollector), feeAmount);
        assertEq(tronUsdt.balanceOf(recipient), inputAmount - feeAmount);
        assertEq(tronUsdt.balanceOf(address(executor)), 0);
    }

    // -- Sweep guards --

    function testRevert_sweepToZeroAddress() external {
        tronUsdt.mint(address(executor), 1000e6);

        IntentExecutor.Approval[] memory approvals = new IntentExecutor.Approval[](0);
        IntentExecutor.Call3[] memory calls = new IntentExecutor.Call3[](0);
        IntentExecutor.SweepTarget[] memory sweeps = new IntentExecutor.SweepTarget[](1);
        sweeps[0] = IntentExecutor.SweepTarget({ token: address(tronUsdt), recipient: address(0) });

        vm.expectRevert(abi.encodeWithSelector(IntentExecutor.ZeroRecipient.selector));
        run(abi.encodeCall(IntentExecutor.executeAndSweep, (approvals, calls, sweeps)));
    }

    // -- Solver gate --

    function testRevert_executeWithoutAuthorization() external {
        tronUsdt.mint(address(executor), 1000e6);

        IntentExecutor.SweepTarget[] memory sweeps = new IntentExecutor.SweepTarget[](1);
        sweeps[0] = IntentExecutor.SweepTarget({ token: address(tronUsdt), recipient: recipient });

        vm.expectRevert(IntentExecutor.CallNotAuthorized.selector);
        executor.executeAndSweep(new IntentExecutor.Approval[](0), new IntentExecutor.Call3[](0), sweeps);
        assertEq(tronUsdt.balanceOf(address(executor)), 1000e6);
    }

    // -- Standard token still works --

    function test_executeAndSweep_standardToken_stillWorks() external {
        uint256 amount = 1 ether;
        standardToken.mint(address(executor), amount);

        IntentExecutor.Approval[] memory approvals = new IntentExecutor.Approval[](0);
        IntentExecutor.Call3[] memory calls = new IntentExecutor.Call3[](0);
        IntentExecutor.SweepTarget[] memory sweeps = new IntentExecutor.SweepTarget[](1);
        sweeps[0] = IntentExecutor.SweepTarget({ token: address(standardToken), recipient: recipient });

        run(abi.encodeCall(IntentExecutor.executeAndSweep, (approvals, calls, sweeps)));

        assertEq(standardToken.balanceOf(recipient), amount);
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

    /// @dev Stands in for a CAT validator's `entry`: calls `execTarget` with `execPayload`
    /// and bubbles a revert verbatim.
    function entry(
        address execTarget,
        bytes calldata execPayload
    ) external {
        require(msg.sender == address(executor), "entry: not executor");
        (bool success, bytes memory ret) = execTarget.call(execPayload);
        if (!success) {
            assembly ("memory-safe") {
                revert(add(ret, 0x20), mload(ret))
            }
        }
        entryReturnData = ret;
    }

    receive() external payable { }
}
