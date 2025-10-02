// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { Test } from "forge-std/Test.sol";

import { ERC7821 } from "solady/src/accounts/ERC7821.sol";
import { LibZip } from "solady/src/utils/LibZip.sol";

import { Catapultar } from "../src/Catapultar.sol";
import { CatapultarFactory } from "../src/CatapultarFactory.sol";
import { LibCalls } from "../src/libs/LibCalls.sol";

interface EIP712 {
    function DOMAIN_SEPARATOR() external view returns (bytes32);
}

contract DummyContract {
    error CustomError();
    error CustomErrorPayload(bytes);

    mapping(uint256 => uint256) public store;

    function revertsWithCustomError() external payable {
        revert CustomError();
    }

    function revertsWithCustomErrorPayload(
        bytes calldata payload
    ) external payable {
        revert CustomErrorPayload(payload);
    }

    function setStore(
        uint256 i
    ) external payable {
        store[i] = store[i] + 1;
    }
}

/**
 * @notice The intention of this test is to showcase the entire usecase-flow of using the Catapultar system.
 */
contract IntegrationTest is Test {
    bytes32 constant NO_REVERT_MODE = bytes32(bytes10(0x01000000000078210001));
    bytes32 constant REVERT_MODE = bytes32(bytes10(0x01010000000078210001));

    event CallReverted(bytes32 extraData, bytes revertData);

    CatapultarFactory factory;
    address dummy;

    function setUp() external {
        factory = new CatapultarFactory();
        dummy = address(new DummyContract());
    }

    function test_integration() external {
        (address owner, uint256 key) = makeAddrAndKey("owner");
        bytes32 salt = bytes32(bytes20(uint160(owner)));

        // Lets get a proxy.
        address proxy = factory.deploy(owner, salt);

        // Create the calls. We wanna make a batch of 6 calls:
        // 1. 2 normal calls. (revert flag 0x00)
        // 2. 2 normal calls. (revert flag 0x01)
        // 3. 1 normal call + 1 revert (revert flag 0x00)
        // 4. 1 normal call + 1 revert (revert flag 0x01)
        // 5. 2 revert (revert flag 0x00)
        // 6. 2 revert (revert flag 0x01)
        //
        // We then wanna wrap it inside a non-reverting call.
        ERC7821.Call[] memory globalCall = new ERC7821.Call[](6);

        // Lets create the normal calls.
        ERC7821.Call[] memory calls = new ERC7821.Call[](2);
        calls[0] = ERC7821.Call({ to: dummy, value: 0, data: abi.encodeCall(DummyContract.setStore, (0)) });
        calls[1] = ERC7821.Call({ to: dummy, value: 0, data: abi.encodeCall(DummyContract.setStore, (1)) });

        // Encode inside global call.
        globalCall[0] = ERC7821.Call({
            to: address(0),
            value: 0,
            data: abi.encodeCall(ERC7821.execute, (NO_REVERT_MODE, abi.encode(calls, abi.encode(0))))
        });
        globalCall[1] = ERC7821.Call({
            to: address(proxy),
            value: 0,
            data: abi.encodeCall(ERC7821.execute, (REVERT_MODE, abi.encode(calls, abi.encode(1))))
        });

        // Lets modify calls to have the first transaction fail.
        calls[0] = ERC7821.Call({
            to: dummy,
            value: 0,
            data: abi.encodeCall(
                DummyContract.revertsWithCustomErrorPayload,
                (bytes("Once upon a time, there was a little smart contract called Catapultar"))
            )
        });

        // Encode inside global call.
        globalCall[2] = ERC7821.Call({
            to: address(proxy),
            value: 0,
            data: abi.encodeCall(ERC7821.execute, (NO_REVERT_MODE, abi.encode(calls, abi.encode(2))))
        });
        globalCall[3] = ERC7821.Call({
            to: address(0),
            value: 0,
            data: abi.encodeCall(ERC7821.execute, (REVERT_MODE, abi.encode(calls, abi.encode(3))))
        });

        // Lets modify calls to have the last transaction fail.
        calls[1] = ERC7821.Call({ to: dummy, value: 0, data: abi.encodeCall(DummyContract.revertsWithCustomError, ()) });

        // Encode inside global call.
        globalCall[4] = ERC7821.Call({
            to: address(proxy),
            value: 0,
            data: abi.encodeCall(ERC7821.execute, (NO_REVERT_MODE, abi.encode(calls, abi.encode(4))))
        });
        globalCall[5] = ERC7821.Call({
            to: address(0),
            value: 0,
            data: abi.encodeCall(ERC7821.execute, (REVERT_MODE, abi.encode(calls, abi.encode(5))))
        });

        // Sign the batch.
        uint256 nonce = 100;
        bytes32 th = this.typehash(nonce, REVERT_MODE, globalCall);
        bytes32 domainSeparator = EIP712(proxy).DOMAIN_SEPARATOR();
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, th));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes memory callPayload =
            abi.encodeCall(ERC7821.execute, (REVERT_MODE, abi.encode(globalCall, abi.encodePacked(nonce, signature))));

        // Zip the calldata for efficiency.
        bytes memory compressedCallPayload = LibZip.cdCompress(callPayload);

        // Generate a list of the expected call tree.
        // Call 1
        vm.expectCall(dummy, abi.encodeCall(DummyContract.setStore, (0)));
        vm.expectCall(dummy, abi.encodeCall(DummyContract.setStore, (1)));

        // Call 2
        vm.expectCall(dummy, abi.encodeCall(DummyContract.setStore, (0)));
        vm.expectCall(dummy, abi.encodeCall(DummyContract.setStore, (1)));

        // Call 3
        vm.expectCall(
            dummy,
            abi.encodeCall(
                DummyContract.revertsWithCustomErrorPayload,
                (bytes("Once upon a time, there was a little smart contract called Catapultar"))
            )
        );

        // Call 4
        vm.expectCall(
            dummy,
            abi.encodeCall(
                DummyContract.revertsWithCustomErrorPayload,
                (bytes("Once upon a time, there was a little smart contract called Catapultar"))
            )
        );
        vm.expectCall(dummy, abi.encodeCall(DummyContract.setStore, (1)));

        // Call 5
        vm.expectCall(
            dummy,
            abi.encodeCall(
                DummyContract.revertsWithCustomErrorPayload,
                (bytes("Once upon a time, there was a little smart contract called Catapultar"))
            )
        );

        // Call 6
        vm.expectCall(
            dummy,
            abi.encodeCall(
                DummyContract.revertsWithCustomErrorPayload,
                (bytes("Once upon a time, there was a little smart contract called Catapultar"))
            )
        );
        vm.expectCall(dummy, abi.encodeCall(DummyContract.revertsWithCustomError, ()));

        // Call 3
        vm.expectEmit();
        emit CallReverted(
            assembleExtraData(0x00, 2, 0),
            abi.encodeWithSelector(
                DummyContract.CustomErrorPayload.selector,
                (bytes("Once upon a time, there was a little smart contract called Catapultar"))
            )
        );
        vm.expectEmit();
        emit CallReverted(
            assembleExtraData(0x01, 100, 2),
            abi.encodeWithSelector(
                DummyContract.CustomErrorPayload.selector,
                (bytes("Once upon a time, there was a little smart contract called Catapultar"))
            )
        );
        // Call 4
        vm.expectEmit();
        emit CallReverted(
            assembleExtraData(0x01, 3, 0),
            abi.encodeWithSelector(
                DummyContract.CustomErrorPayload.selector,
                (bytes("Once upon a time, there was a little smart contract called Catapultar"))
            )
        );
        // Call 5
        vm.expectEmit();
        emit CallReverted(
            assembleExtraData(0x00, 4, 0),
            abi.encodeWithSelector(
                DummyContract.CustomErrorPayload.selector,
                (bytes("Once upon a time, there was a little smart contract called Catapultar"))
            )
        );
        vm.expectEmit();
        emit CallReverted(
            assembleExtraData(0x01, 100, 4),
            abi.encodeWithSelector(
                DummyContract.CustomErrorPayload.selector,
                (bytes("Once upon a time, there was a little smart contract called Catapultar"))
            )
        );
        // Call 6
        vm.expectEmit();
        emit CallReverted(
            assembleExtraData(0x01, 5, 0),
            abi.encodeWithSelector(
                DummyContract.CustomErrorPayload.selector,
                (bytes("Once upon a time, there was a little smart contract called Catapultar"))
            )
        );
        vm.expectEmit();
        emit CallReverted(assembleExtraData(0x01, 5, 1), abi.encodeWithSelector(DummyContract.CustomError.selector));

        payable(proxy).call(compressedCallPayload);

        assertEq(DummyContract(dummy).store(0), 2, "Should have been called two times");
        assertEq(DummyContract(dummy).store(1), 3, "Should have been called three times");
    }

    function typehash(uint256 nonce, bytes32 mode, ERC7821.Call[] calldata calls) external pure returns (bytes32) {
        return LibCalls.typehash(nonce, mode, calls);
    }

    function assembleExtraData(bytes1 revertMode, uint256 nonce, uint256 index) internal pure returns (bytes32) {
        uint256 extraData = uint256(bytes32(bytes1(revertMode)));
        extraData = extraData + ((nonce << (9 * 8)) >> 8);
        extraData = extraData + uint256(uint64(index));
        return bytes32(extraData);
    }
}
