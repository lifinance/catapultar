// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { IERC20 } from "forge-std/src/interfaces/IERC20.sol";
import { SafeTransferLib } from "solady/src/utils/SafeTransferLib.sol";

import { CATValidatorV2 } from "../../src/CATValidatorV2.sol";
import { AllowanceSpend, Outcome } from "../../src/libs/LibExecutionConstraint.sol";
import { ExecutionBinding } from "../../src/libs/LibExecutionConstraintV2.sol";
import { LibValidationVM, VMCommand, VMState } from "../../src/libs/LibValidationVM.sol";
import { VcTestBase } from "./VcTestBase.sol";

/// @dev Stands in for the LI.FI swap: the validator sends it the allowance, it pays the outcome.
contract FixtureFill {
    function fill(
        address outToken,
        address to,
        uint256 outAmount
    ) external {
        SafeTransferLib.safeTransfer(outToken, to, outAmount);
    }
}

/**
 * @title Derived-program entry harness (triggers C1/C2)
 * @notice Settles the PRD §2 Stop Loss fixture in wallet mode through the deployed
 * `CATValidatorV2.entry` on a Base fork: the demo EOA signs the V2 constraint,
 * `account` = the EOA, allowance 1 WETH, outcome 1 980 USDC to the EOA.
 * The program and params are inputs, so C2 swaps the placeholder for the
 * `validation_program` / `validation_params` WS-A commits.
 */
abstract contract DerivedProgramHarness is VcTestBase {
    /// @dev Anvil account 1 = the demo EOA 0x70997970C51812dc3A010C7d01b50e0d17dc79C8.
    uint256 internal constant USER_KEY = 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d;
    uint256 internal constant ALLOCATED_WETH = 1 ether;
    uint256 internal constant FLOOR_USDC = 1980e6;
    uint256 internal constant STRIKE = 2000e8;
    uint256 internal constant EXPIRES_AT = 1796428800; // 2026-12-05
    bytes4 internal constant SEL_LATEST_ANSWER = 0x50d25bcd;
    bytes4 internal constant LTE_FAILED = 0xb5c6fd70; // InvariantChecker.AssertLteFailed(uint256,uint256)
    /// @dev The ETH/USD proxy the slice C compiler run baked into compiled-callspec.json.
    address internal constant MAINNET_FEED_ETH_USD = 0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419;
    /// @dev The 10-argument V2 `entry`.
    bytes4 internal constant ENTRY_V2_SELECTOR = bytes4(
        keccak256(
            "entry(address,bytes,address,uint256,(address,uint256,uint256)[],(address,uint256,address)[],(address,bytes32),(uint8,bytes32)[],bytes32[],bytes)"
        )
    );

    CATValidatorV2 internal validator;
    FixtureFill internal fillTarget;
    address internal user;
    address internal executor;

    struct EntryCall {
        bytes calldata_;
        bytes32 digest;
        AllowanceSpend[] allowances;
        Outcome[] outcomes;
    }

    function setUpHarness() internal {
        forkBaseIfConfigured();
        if (!hasBaseFork()) return;
        validator = CATValidatorV2(BASE_VALIDATOR_V2);
        fillTarget = new FixtureFill();
        executor = makeAddr("executor");
        // The pass case asserts exact USDC deltas; drop any live stray balance on the validator.
        deal(BASE_USDC, address(validator), 0);
        user = vm.addr(USER_KEY);
        // On Base the public anvil key carries an EIP-7702 delegation; SignatureCheckerLib would
        // then ask the delegate (ERC-1271) instead of ecrecover. Clear it, as the demo fork must.
        vm.etch(user, "");
    }

    /* ─────────────────────────── program inputs
    ─────────────────────────── */

    /// @notice The slice C compiler output (8 commands: now <= expiry, ETH/USD latestAnswer() <= strike),
    /// retargeted from the mainnet feed to the Base feed, with the fixture params
    /// `[destination, expiresAt, strike]`. Placeholder until WS-A's program lands.
    function placeholderProgram() internal view returns (bytes memory program, bytes32[] memory params) {
        string memory j = readFixture("compiled-callspec.json");
        bytes memory cd = vm.parseJsonBytes(j, ".calldata");
        bytes memory args = new bytes(cd.length - 4);
        for (uint256 i; i < args.length; ++i) {
            args[i] = cd[i + 4];
        }
        (VMCommand[] memory cmds,) = abi.decode(args, (VMCommand[], VMState));
        for (uint256 i; i < cmds.length; ++i) {
            // CALL word: [calltype:1][target:20][dest][src]...
            if (cmds[i].op == 0 && address(bytes20(cmds[i].data << 8)) == MAINNET_FEED_ETH_USD) {
                bytes32 mask = bytes32(uint256(type(uint160).max)) << 88;
                cmds[i].data = (cmds[i].data & ~mask) | (bytes32(uint256(uint160(BASE_FEED_ETH_USD))) << 88);
            }
        }
        program = abi.encode(cmds);
        params = new bytes32[](3);
        params[0] = bytes32(uint256(uint160(user)));
        params[1] = bytes32(EXPIRES_AT);
        params[2] = bytes32(STRIKE);
    }

    /// @notice WS-A's committed program for the fixture, read from the Intent Factory row
    /// (`fixtures/handoff-a-program.json`). Asserts the harness hashes it exactly as the row does.
    function derivedProgram() internal view returns (bytes memory program, bytes32[] memory params) {
        string memory j = readFixture("handoff-a-program.json");
        program = vm.parseJsonBytes(j, ".validationProgram");
        params = vm.parseJsonBytes32Array(j, ".validationParams");
        assertEq(
            hashProgram(abi.decode(program, (VMCommand[]))),
            vm.parseJsonBytes32(j, ".validationProgramHash"),
            "validationProgramHash parity"
        );
        assertEq(hashParams(params), vm.parseJsonBytes32(j, ".paramsHash"), "paramsHash parity");
    }

    /* ─────────────────────────── entry building
    ─────────────────────────── */

    /// @notice Builds the signed wallet-mode `entry` calldata for `(program, params)`.
    /// `program` is `abi.encode(VMCommand[])`.
    function buildEntry(
        bytes memory program,
        bytes32[] memory params,
        uint256 nonce
    ) internal view returns (EntryCall memory c) {
        VMCommand[] memory cmds = abi.decode(program, (VMCommand[]));
        c.allowances = new AllowanceSpend[](1);
        c.allowances[0] = AllowanceSpend({ token: BASE_WETH, allocated: ALLOCATED_WETH, spend: ALLOCATED_WETH });
        c.outcomes = new Outcome[](1);
        c.outcomes[0] = Outcome({ token: BASE_USDC, amount: FLOOR_USDC, destination: user });
        c.digest = constraintDigest(
            validator.DOMAIN_SEPARATOR(),
            c.allowances,
            c.outcomes,
            executor,
            nonce,
            hashProgram(cmds),
            hashParams(params)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(USER_KEY, c.digest);
        c.calldata_ = abi.encodeWithSelector(
            ENTRY_V2_SELECTOR,
            address(fillTarget),
            abi.encodeCall(FixtureFill.fill, (BASE_USDC, address(validator), FLOOR_USDC)),
            user,
            nonce,
            c.allowances,
            c.outcomes,
            ExecutionBinding({ executionTarget: address(0), payloadHash: bytes32(0) }),
            cmds,
            params,
            abi.encodePacked(r, s, v)
        );
    }

    /// @notice Funds the EOA (1 WETH, approved to the validator) and the fill target (1 980 USDC).
    function fundFixture() internal {
        deal(BASE_WETH, user, ALLOCATED_WETH);
        vm.prank(user);
        IERC20(BASE_WETH).approve(address(validator), ALLOCATED_WETH);
        deal(BASE_USDC, address(fillTarget), FLOOR_USDC);
    }

    /// @notice C2 entry point: settles `(program, params)` through the deployed `entry`.
    /// Empty `expectedErr` expects success; otherwise `ValidationFailed(expectedErr)`.
    /// Returns the gas of the whole `entry` call and of the `runVM` call alone.
    function settleThroughEntry(
        bytes memory program,
        bytes32[] memory params,
        uint256 nonce,
        bytes memory expectedErr
    ) internal returns (uint256 entryGas, uint256 vmGas) {
        fundFixture();
        EntryCall memory c = buildEntry(program, params, nonce);
        vmGas = runVMGas(program, params);

        uint256 usdcBefore = IERC20(BASE_USDC).balanceOf(user);
        vm.prank(executor);
        uint256 g = gasleft();
        (bool ok, bytes memory ret) = address(validator).call(c.calldata_);
        entryGas = g - gasleft();

        if (expectedErr.length == 0) {
            assertTrue(ok, string.concat("entry reverted: ", vm.toString(ret)));
            assertEq(IERC20(BASE_USDC).balanceOf(user) - usdcBefore, FLOOR_USDC, "outcome not delivered");
            assertEq(IERC20(BASE_WETH).balanceOf(user), 0, "allowance not spent");
        } else {
            assertFalse(ok, "entry should revert");
            assertEq(ret, abi.encodeWithSelector(CATValidatorV2.ValidationFailed.selector, expectedErr), "revert data");
        }
        assertEq(validator.spentNonces(user, nonce), expectedErr.length == 0, "nonce state");
    }

    /// @notice Gas of `runVM` alone, with the registers `entry` builds after a full fill
    /// (spent = allocation, paid = floor).
    function runVMGas(
        bytes memory program,
        bytes32[] memory params
    ) internal view returns (uint256 gasUsed) {
        uint256[] memory spent = new uint256[](1);
        spent[0] = ALLOCATED_WETH;
        uint256[] memory paid = new uint256[](1);
        paid[0] = FLOOR_USDC;
        bytes memory cd = abi.encodeWithSelector(
            LibValidationVM.RUN_VM_SELECTOR,
            abi.decode(program, (VMCommand[])),
            VMState(this.registersFor(params, user, spent, paid))
        );
        uint256 g = gasleft();
        VM_ADDR.staticcall(cd);
        gasUsed = g - gasleft();
    }

    function registersFor(
        bytes32[] calldata params,
        address account,
        uint256[] calldata spent,
        uint256[] calldata paid
    ) external pure returns (bytes[] memory) {
        return LibValidationVM.buildRegisters(params, account, spent, paid);
    }

    function mockAnswer(
        uint256 answer
    ) internal {
        vm.mockCall(BASE_FEED_ETH_USD, abi.encodeWithSelector(SEL_LATEST_ANSWER), abi.encode(int256(answer)));
    }
}
