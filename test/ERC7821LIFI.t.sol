// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import {Test, Vm} from "forge-std/Test.sol";

import {ERC7821} from "solady/src/accounts/ERC7821.sol";
import {MockERC7821LIFI} from "./MockERC7821LIFI.sol";

contract ERC7821LIFITest is Test {
    error CustomError(bytes);

    event CallReverted(bytes32 extraData, bytes revertData);

    MockERC7821LIFI mbe;

    bytes32 internal constant _SUPPORTED_MODE = bytes10(0x01000000000078210001);

    bytes[] internal _bytes;

    function setUp() public {
        mbe = new MockERC7821LIFI();
    }

    function revertsWithCustomError(bytes calldata m) external payable {
        revert CustomError(m);
    }

    function returnsBytes(
        bytes memory b
    ) external payable returns (bytes memory) {
        return b;
    }

    function returnsHash(bytes memory b) external payable returns (bytes32) {
        return keccak256(b);
    }

    function testERC7821LIFI_executionModeRevert(bytes32 mode) external view {
        bytes32 result = mbe.executionModeRevert(mode);
        bytes32 toSelect = mode &
            bytes32(
                0x00ff000000000000000000000000000000000000000000000000000000000000
            );
        if (uint256(toSelect) > 0) vm.assertEq(toSelect << 8, result);
        else
            vm.assertEq(
                result,
                bytes32(
                    0x0000000000000000000000000000000000000000000000000000000000000000
                )
            );
    }

    struct RandomBytes {
        bytes payload;
        bool fail;
    }

    function testERC7821LIFI_nonces(
        uint256 nonce,
        RandomBytes[] calldata randomBytes
    ) public {

        ERC7821.Call[] memory calls = new ERC7821.Call[](randomBytes.length);
        for (uint256 i; i < randomBytes.length; ++i) {
            calls[i] = ERC7821.Call({
                to: address(this),
                data: abi.encodeWithSignature(
                    randomBytes[i].fail
                        ? "revertsWithCustomError(bytes)"
                        : "returnsBytes(bytes)",
                    randomBytes[i].payload
                ),
                value: 0
            });
        }

        // vm.recordLogs();
        uint256 extraDataU = uint256(bytes32(bytes1(0x01))) +
            uint256(uint240(nonce) << 80);
        for (uint256 i; i < randomBytes.length; ++i) {
            if (randomBytes[i].fail) {
                // TODO: figure out what the issue is.
                // vm.expectEmit(true, true, true, true);
                emit CallReverted(
                    bytes32(extraDataU + i),
                    abi.encodeWithSelector(CustomError.selector, (randomBytes[i].payload))
                );
            }
        }

        bytes memory executionData = abi.encode(calls, abi.encode(nonce));

        vm.prank(address(mbe));
        mbe.execute(bytes10(0x01010000000078210001), executionData);

        // Vm.Log[] memory logs = vm.getRecordedLogs();

        // for (uint256 i; i < logs.length; ++i) {
        //     console.logBytes32(logs[i].topics[0]);
        //     console.logBytes(logs[i].data);
        // }
    }

    function _totalValue(
        ERC7821.Call[] memory calls
    ) internal pure returns (uint256 result) {
        unchecked {
            for (uint256 i; i < calls.length; ++i) {
                result += calls[i].value;
            }
        }
    }
}