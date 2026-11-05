// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { LibValidationVM, VMCommand, VMState } from "../../src/libs/LibValidationVM.sol";
import { DerivedProgramHarness } from "./DerivedProgramHarness.sol";

interface IAgg {
    function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80);
}

/// The compose compiler's own output (derive.ts -> ir1_web_compiler validation profile) for two
/// `call` AssertionSpecs: Multicall3.getCurrentBlockTimestamp() lte expiry, and ETH/USD
/// latestAnswer() lte strike. Run on the deployed VM on Base exactly as
/// CATValidatorV2._runValidation does (LibValidationVM.buildRegisters + runVM).
contract CompiledCallSpecTest is DerivedProgramHarness {
    function setUp() external {
        setUpHarness();
    }

    function _run(
        VMCommand[] memory program,
        uint256 expiry,
        uint256 strike
    ) internal view returns (bool ok, bytes memory ret) {
        bytes32[] memory params = new bytes32[](3);
        params[0] = bytes32(uint256(uint160(user)));
        params[1] = bytes32(expiry);
        params[2] = bytes32(strike);
        (ok, ret) = VM_ADDR.staticcall(
            abi.encodeWithSelector(
                LibValidationVM.RUN_VM_SELECTOR,
                program,
                VMState(this.registersFor(params, user, new uint256[](1), new uint256[](1)))
            )
        );
    }

    function test_compiled_expiryAndStrike() external onlyBaseFork {
        (bytes memory encoded,) = placeholderProgram();
        VMCommand[] memory program = abi.decode(encoded, (VMCommand[]));
        (, int256 a,,,) = IAgg(BASE_FEED_ETH_USD).latestRoundData();
        uint256 answer = uint256(a);
        (bool ok, bytes memory ret) = _run(program, block.timestamp, answer);
        assertTrue(ok, vm.toString(ret));
        (ok, ret) = _run(program, block.timestamp - 1, answer);
        assertEq(ret, abi.encodeWithSelector(LTE_FAILED, block.timestamp, block.timestamp - 1), "expiry");
        (ok, ret) = _run(program, block.timestamp, answer - 1);
        assertEq(ret, abi.encodeWithSelector(LTE_FAILED, answer, answer - 1), "strike");
        emit log_named_uint("commands", program.length);
    }
}
