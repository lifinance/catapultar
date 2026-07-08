// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { Test } from "forge-std/src/Test.sol";

import { MockERC20 } from "solady/test/utils/mocks/MockERC20.sol";

import { SafeTransferLibTron } from "../../src/libs/SafeTransferLib.tron.sol";

import { CATValidator } from "../../src/CATValidator.sol";
import { CATValidatorTron } from "../../src/CATValidator.tron.sol";
import { AllowanceSpend, Outcome } from "../../src/libs/LibExecutionConstraint.sol";

import { MockTronUSDT } from "../mocks/MockTronUSDT.sol";

contract CATValidatorTronMock is CATValidatorTron {
    function validatePayment(
        address signer,
        Outcome[] calldata outcomes
    ) external {
        return _validatePayment(signer, outcomes);
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
}

/// @dev Simulates a solver that delivers tokens to the validator during execution.
contract MockTokenSenderTron {
    function sendTo(
        address token,
        uint256 amount,
        address recipient
    ) external {
        SafeTransferLibTron.safeTransfer(token, recipient, amount);
    }
}

contract CATValidatorTronTest is Test {
    CATValidatorTronMock validator;
    MockTronUSDT tronUsdt;
    address recipient;

    function setUp() external {
        validator = new CATValidatorTronMock();
        tronUsdt = new MockTronUSDT();
        recipient = makeAddr("recipient");
    }

    // -----------------------------------------------------------------------
    // _validatePayment with Tron USDT
    // -----------------------------------------------------------------------

    function test_validatePayment_tronUsdt_succeeds() external {
        address dest = makeAddr("dest");
        uint256 amount = 1000e6;

        tronUsdt.mint(address(validator), amount);

        Outcome[] memory outcomes = new Outcome[](1);
        outcomes[0] = Outcome({ token: address(tronUsdt), amount: amount, destination: dest });

        validator.validatePayment(address(this), outcomes);

        assertEq(tronUsdt.balanceOf(dest), amount);
        assertEq(tronUsdt.balanceOf(address(validator)), 0);
    }

    function test_validatePayment_tronUsdt_excessForwarded() external {
        address dest = makeAddr("dest");
        uint256 required = 1000e6;
        uint256 deposited = 2000e6;

        tronUsdt.mint(address(validator), deposited);

        Outcome[] memory outcomes = new Outcome[](1);
        outcomes[0] = Outcome({ token: address(tronUsdt), amount: required, destination: dest });

        validator.validatePayment(address(this), outcomes);

        assertEq(tronUsdt.balanceOf(dest), deposited);
        assertEq(tronUsdt.balanceOf(address(validator)), 0);
    }

    function test_validatePayment_tronUsdt_mixedOutcomes() external {
        address destA = makeAddr("destA");
        address destB = makeAddr("destB");
        uint256 usdtAmount = 1000e6;
        uint256 stdAmount = 2 ether;

        tronUsdt.mint(address(validator), usdtAmount);
        MockERC20 stdToken = new MockERC20("Standard", "STD", 18);
        stdToken.mint(address(validator), stdAmount);

        Outcome[] memory outcomes = new Outcome[](2);
        outcomes[0] = Outcome({ token: address(tronUsdt), amount: usdtAmount, destination: destA });
        outcomes[1] = Outcome({ token: address(stdToken), amount: stdAmount, destination: destB });

        validator.validatePayment(address(this), outcomes);

        assertEq(tronUsdt.balanceOf(destA), usdtAmount);
        assertEq(stdToken.balanceOf(destB), stdAmount);
        assertEq(tronUsdt.balanceOf(address(validator)), 0);
        assertEq(stdToken.balanceOf(address(validator)), 0);
    }

    function test_validatePayment_tronUsdt_revertsOnInsufficientBalance() external {
        address dest = makeAddr("dest");
        uint256 required = 1000e6;

        tronUsdt.mint(address(validator), required - 1);

        Outcome[] memory outcomes = new Outcome[](1);
        outcomes[0] = Outcome({ token: address(tronUsdt), amount: required, destination: dest });

        vm.expectRevert(abi.encodeWithSelector(CATValidator.InvalidTokenAmount.selector, required, required - 1));
        validator.validatePayment(address(this), outcomes);
    }

    function test_validatePayment_tronUsdt_zeroDestinationUsesSigner() external {
        address signer = makeAddr("signer");
        uint256 amount = 500e6;

        tronUsdt.mint(address(validator), amount);

        Outcome[] memory outcomes = new Outcome[](1);
        outcomes[0] = Outcome({ token: address(tronUsdt), amount: amount, destination: address(0) });

        validator.validatePayment(signer, outcomes);

        assertEq(tronUsdt.balanceOf(signer), amount);
    }

    // -----------------------------------------------------------------------
    // _validatePayment with native ETH (unaffected, sanity check)
    // -----------------------------------------------------------------------

    function test_validatePayment_nativeETH_stillWorks() external {
        address dest = makeAddr("dest");
        uint256 amount = 1 ether;

        vm.deal(address(validator), amount);

        Outcome[] memory outcomes = new Outcome[](1);
        outcomes[0] = Outcome({ token: address(0), amount: amount, destination: dest });

        validator.validatePayment(address(this), outcomes);

        assertEq(dest.balance, amount);
    }

    // -----------------------------------------------------------------------
    // _handleAllowances with Tron USDT (uses safeTransferFrom, should work)
    // -----------------------------------------------------------------------

    function test_handleAllowances_tronUsdt_succeeds() external {
        address destination = makeAddr("destination");
        address account = makeAddr("account");
        uint256 amount = 1000e6;

        tronUsdt.mint(account, amount);
        vm.prank(account);
        tronUsdt.approve(address(validator), amount);

        AllowanceSpend[] memory allowances = new AllowanceSpend[](1);
        allowances[0] = AllowanceSpend({ token: address(tronUsdt), allocated: amount, spend: amount });

        validator.handleAllowances(destination, account, allowances);

        assertEq(tronUsdt.balanceOf(destination), amount);
        assertEq(tronUsdt.balanceOf(account), 0);
    }

    // -----------------------------------------------------------------------
    // Standard ERC20 (no regression)
    // -----------------------------------------------------------------------

    function test_validatePayment_standardToken_stillWorks() external {
        address dest = makeAddr("dest");
        uint256 amount = 1 ether;

        MockERC20 token = new MockERC20("Standard", "STD", 18);
        token.mint(address(validator), amount);

        Outcome[] memory outcomes = new Outcome[](1);
        outcomes[0] = Outcome({ token: address(token), amount: amount, destination: dest });

        validator.validatePayment(address(this), outcomes);

        assertEq(token.balanceOf(dest), amount);
        assertEq(token.balanceOf(address(validator)), 0);
    }

    // -----------------------------------------------------------------------
    // End-to-end: full entry flow with Tron USDT
    // -----------------------------------------------------------------------

    function test_entry_tronUsdt_endToEnd() external {
        (address account, uint256 key) = makeAddrAndKey("account");
        address executor = makeAddr("executor");
        address dest = makeAddr("dest");
        uint256 inAmount = 1000e6;
        uint256 outAmount = 900e6;

        address inToken;
        {
            MockERC20 token = new MockERC20("In", "IN", 18);
            inToken = address(token);
            token.mint(account, inAmount);
            vm.prank(account);
            token.approve(address(validator), inAmount);
        }

        MockTokenSenderTron sender = new MockTokenSenderTron();
        tronUsdt.mint(address(sender), outAmount);

        AllowanceSpend[] memory allowances = new AllowanceSpend[](1);
        allowances[0] = AllowanceSpend({ token: inToken, allocated: inAmount, spend: inAmount });

        Outcome[] memory outcomes = new Outcome[](1);
        outcomes[0] = Outcome({ token: address(tronUsdt), amount: outAmount, destination: dest });

        bytes memory sig;
        {
            bytes32 digest = keccak256(
                abi.encodePacked("\x19\x01", validator.DOMAIN_SEPARATOR(), _typehash(allowances, outcomes, executor, 1))
            );
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
            sig = abi.encodePacked(r, s, v);
        }

        bytes memory execPayload =
            abi.encodeCall(MockTokenSenderTron.sendTo, (address(tronUsdt), outAmount, address(validator)));

        vm.prank(executor);
        validator.entry(address(sender), execPayload, account, 1, allowances, outcomes, sig);

        assertEq(tronUsdt.balanceOf(dest), outAmount);
        assertEq(tronUsdt.balanceOf(address(validator)), 0);
        assertEq(MockERC20(inToken).balanceOf(address(executor)), 0);
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    function _typehash(
        AllowanceSpend[] memory allowances,
        Outcome[] memory outcomes,
        address executor,
        uint256 nonce
    ) internal pure returns (bytes32) {
        bytes32[] memory allowanceHashes = new bytes32[](allowances.length);
        for (uint256 i; i < allowances.length; ++i) {
            allowanceHashes[i] = keccak256(
                abi.encode(
                    keccak256(bytes("Allowance(address token,uint256 amount)")),
                    allowances[i].token,
                    allowances[i].allocated
                )
            );
        }

        bytes32[] memory outcomeHashes = new bytes32[](outcomes.length);
        for (uint256 i; i < outcomes.length; ++i) {
            outcomeHashes[i] = keccak256(
                abi.encode(
                    keccak256(bytes("Outcome(address token,uint256 amount,address destination)")),
                    outcomes[i].token,
                    outcomes[i].amount,
                    outcomes[i].destination
                )
            );
        }

        return keccak256(
            abi.encode(
                keccak256(
                    bytes(
                        "ExecutionConstraint(Allowance[] allowances,Outcome[] outcomes,address executor,uint256 nonce)Allowance(address token,uint256 amount)Outcome(address token,uint256 amount,address destination)"
                    )
                ),
                keccak256(abi.encodePacked(allowanceHashes)),
                keccak256(abi.encodePacked(outcomeHashes)),
                executor,
                nonce
            )
        );
    }
}
