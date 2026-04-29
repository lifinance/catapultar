// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

// forge-lint: disable-start(unsafe-typecast)
// forge-lint: disable-start(unchecked-call)

import { ERC7821 } from "solady/src/accounts/ERC7821.sol";
import { LibZip } from "solady/src/utils/LibZip.sol";
import { MockERC20 } from "solady/test/utils/mocks/MockERC20.sol";

import { LibExecutionConstraintTest } from "./libs/LibExecutionConstraint.t.sol";

import { CATValidator } from "../src/CATValidator.sol";
import { Allowance, AllowanceSpend, ExecutionConstraint, Outcome } from "../src/libs/LibExecutionConstraint.sol";

import { Catapultar } from "../src/Catapultar.sol";
import { CatapultarFactory } from "../src/CatapultarFactory.sol";

import { KeyedOwnable } from "../src/libs/KeyedOwnable.sol";
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
contract IntegrationTest is LibExecutionConstraintTest {
    bytes32 constant NO_REVERT_MODE = bytes32(bytes10(0x01000000000078210001));
    bytes32 constant REVERT_MODE = bytes32(bytes10(0x01010000000078210001));

    event CallReverted(bytes32 extraData, bytes revertData);

    CatapultarFactory factory;
    address dummy;

    CATValidator validator;

    MockERC20 validatorToken;
    address validatorAddress;
    uint256 balanceOfSwap = 0;

    function setUp() external {
        factory = new CatapultarFactory();
        dummy = address(new DummyContract());
        validator = new CATValidator();
    }

    function test_integration() external {
        (address owner, uint256 key) = makeAddrAndKey("owner");
        bytes32 salt = bytes32(bytes20(uint160(owner)));

        bytes32[] memory keys = new bytes32[](1);
        keys[0] = bytes32(uint256(uint160(owner)));
        // Lets get a proxy.
        address proxy = factory.deploy(KeyedOwnable.PublicKeyType.ECDSAOrSmartContract, keys, salt);

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
            data: abi.encodeCall(ERC7821.execute, (NO_REVERT_MODE, abi.encode(calls, abi.encode(1))))
        });
        globalCall[1] = ERC7821.Call({
            to: address(proxy),
            value: 0,
            data: abi.encodeCall(ERC7821.execute, (REVERT_MODE, abi.encode(calls, abi.encode(2))))
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
            data: abi.encodeCall(ERC7821.execute, (NO_REVERT_MODE, abi.encode(calls, abi.encode(3))))
        });
        globalCall[3] = ERC7821.Call({
            to: address(0),
            value: 0,
            data: abi.encodeCall(ERC7821.execute, (REVERT_MODE, abi.encode(calls, abi.encode(4))))
        });

        // Lets modify calls to have the last transaction fail.
        calls[1] = ERC7821.Call({ to: dummy, value: 0, data: abi.encodeCall(DummyContract.revertsWithCustomError, ()) });

        // Encode inside global call.
        globalCall[4] = ERC7821.Call({
            to: address(proxy),
            value: 0,
            data: abi.encodeCall(ERC7821.execute, (NO_REVERT_MODE, abi.encode(calls, abi.encode(5))))
        });
        globalCall[5] = ERC7821.Call({
            to: address(0),
            value: 0,
            data: abi.encodeCall(ERC7821.execute, (REVERT_MODE, abi.encode(calls, abi.encode(6))))
        });

        // Sign the batch.
        uint256 nonce = 100;
        bytes32 th = this.typehash(nonce, REVERT_MODE, globalCall);
        bytes32 domainSeparator = EIP712(proxy).DOMAIN_SEPARATOR();
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, th));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        bytes memory callPayload = abi.encodeCall(
            ERC7821.execute, (REVERT_MODE, abi.encode(globalCall, abi.encodePacked(nonce, signature)))
        );

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
            assembleExtraData(0x00, 3, 0),
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
            assembleExtraData(0x01, 4, 0),
            abi.encodeWithSelector(
                DummyContract.CustomErrorPayload.selector,
                (bytes("Once upon a time, there was a little smart contract called Catapultar"))
            )
        );
        // Call 5
        vm.expectEmit();
        emit CallReverted(
            assembleExtraData(0x00, 5, 0),
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
            assembleExtraData(0x01, 6, 0),
            abi.encodeWithSelector(
                DummyContract.CustomErrorPayload.selector,
                (bytes("Once upon a time, there was a little smart contract called Catapultar"))
            )
        );
        vm.expectEmit();
        emit CallReverted(assembleExtraData(0x01, 6, 1), abi.encodeWithSelector(DummyContract.CustomError.selector));

        (bool success,) = payable(proxy).call(compressedCallPayload);
        assertEq(success, true);

        assertEq(DummyContract(dummy).store(0), 2, "Should have been called two times");
        assertEq(DummyContract(dummy).store(1), 3, "Should have been called three times");
    }

    function test_validator() external {
        validatorToken = new MockERC20("Outcome Token", "OutTok", 18);
        validatorAddress = address(validator);

        (address user,) = makeAddrAndKey("user");

        // Create ExecutionConstraint:
        Allowance[] memory allowances = new Allowance[](1);
        allowances[0] = Allowance({ amount: 10 ** 18, token: address(new MockERC20("Allowance Token", "IT", 18)) });
        Outcome[] memory outcomes = new Outcome[](1);
        outcomes[0] = Outcome({ token: address(validatorToken), amount: 10 ** 18, destination: user });

        ExecutionConstraint memory constraint = ExecutionConstraint({
            allowances: allowances, outcomes: outcomes, executor: makeAddr("executor"), nonce: 0
        });

        // Get digest.
        bytes32 th =
            typehashReference(constraint.allowances, constraint.outcomes, constraint.executor, constraint.nonce);
        bytes32 domainSeparator = EIP712(address(validator)).DOMAIN_SEPARATOR();
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, th));

        address payable proxy;
        {
            // Turn the digest into a call of approve and then setSignature.
            ERC7821.Call[] memory calls = new ERC7821.Call[](2);
            calls[0] = ERC7821.Call({
                to: allowances[0].token,
                data: abi.encodeWithSignature("approve(address,uint256)", address(validator), allowances[0].amount),
                value: 0
            });
            calls[1] = ERC7821.Call({
                to: address(0), // self
                data: abi.encodeCall(Catapultar.setSignature, (digest, Catapultar.DigestApproval.Signature)),
                value: 0
            });

            bytes32 callsTypeHash = this.typehash(1, REVERT_MODE, calls);

            // Deploy an account with the digest embedded.

            bytes32[] memory keys = new bytes32[](1);
            keys[0] = bytes32(uint256(uint160(user)));
            // Lets get a proxy.
            proxy = factory.deployWithDigest(
                KeyedOwnable.PublicKeyType.ECDSAOrSmartContract,
                keys,
                bytes32(bytes20(uint160(user))),
                callsTypeHash,
                false
            );

            // Execute calls on account.
            Catapultar(proxy).execute(REVERT_MODE, abi.encode(calls, abi.encodePacked(uint256(1))));

            // Fund the account with the allowance token.
            MockERC20(allowances[0].token).mint(proxy, allowances[0].amount);
        }

        // We can now execute our generate calldata on the validator. Lets generate our calldata.
        // First, we wanna forward the allowances to this contract. (since the swap function here expected us to send
        // tokens ahead of time).
        AllowanceSpend[] memory inputTargets = new AllowanceSpend[](1);
        inputTargets[0] = AllowanceSpend({
            token: allowances[0].token, allocated: allowances[0].amount, spend: allowances[0].amount
        });
        // Pass the CATValidator address so swap() delivers output tokens there,
        // not to the final destination (which would leave CATValidator with nothing).
        bytes memory externalCall =
            abi.encodeCall(this.swap, (allowances[0].amount, allowances[0].token, address(validator)));

        vm.prank(makeAddr("WrongCaller"));
        vm.expectRevert(abi.encodeWithSelector(CATValidator.BadSignature.selector));
        validator.entry(address(this), externalCall, proxy, constraint.nonce, inputTargets, outcomes, hex"");

        vm.prank(constraint.executor);
        validator.entry(address(this), externalCall, proxy, constraint.nonce, inputTargets, outcomes, hex"");

        assertEq(validatorToken.balanceOf(outcomes[0].destination), outcomes[0].amount);
    }

    // -----------------------------------------------------------------------
    // Audit 6.1.1 integration tests — full multicall path
    // -----------------------------------------------------------------------

    /// Shared setup: deploy a Catapultar account that has pre-approved `validator`
    /// to spend its allowance token and pre-registered the execution constraint digest
    /// via setSignature. Returns the account proxy and the prepared calldata pieces.
    ///
    /// The execution constraint uses nonce 0 (long-lived) so the CATValidator
    /// accepts `hex""` as signature via the account's EIP-1271 isValidSignature path.
    function _deployConstrainedProxy(
        address executor,
        address user
    ) internal returns (address payable proxy, AllowanceSpend[] memory inputTargets, Outcome[] memory outcomes) {
        uint256 amount = 10 ** 18;
        address allowanceToken = address(new MockERC20("Allowance Token", "IT", 18));

        Allowance[] memory allowances = new Allowance[](1);
        allowances[0] = Allowance({ amount: amount, token: allowanceToken });
        outcomes = new Outcome[](1);
        outcomes[0] = Outcome({ token: address(validatorToken), amount: amount, destination: user });

        // Build the EIP-712 digest for the constraint so the account can store it.
        bytes32 th = typehashReference(allowances, outcomes, executor, 0);
        bytes32 domainSeparator = EIP712(address(validator)).DOMAIN_SEPARATOR();
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, th));

        // Batch: approve validator + call setSignature on the account itself.
        ERC7821.Call[] memory calls = new ERC7821.Call[](2);
        calls[0] = ERC7821.Call({
            to: allowanceToken,
            data: abi.encodeWithSignature("approve(address,uint256)", address(validator), amount),
            value: 0
        });
        calls[1] = ERC7821.Call({
            to: address(0), // self
            data: abi.encodeCall(Catapultar.setSignature, (digest, Catapultar.DigestApproval.Signature)),
            value: 0
        });

        bytes32[] memory keys = new bytes32[](1);
        keys[0] = bytes32(uint256(uint160(user)));
        proxy = factory.deployWithDigest(
            KeyedOwnable.PublicKeyType.ECDSAOrSmartContract,
            keys,
            bytes32(bytes20(uint160(user))),
            this.typehash(1, REVERT_MODE, calls),
            false
        );

        // Execute the approve + setSignature batch on the freshly deployed account.
        Catapultar(proxy).execute(REVERT_MODE, abi.encode(calls, abi.encodePacked(uint256(1))));

        // Fund the account with the allowance token.
        MockERC20(allowanceToken).mint(proxy, amount);

        inputTargets = new AllowanceSpend[](1);
        inputTargets[0] = AllowanceSpend({ token: allowanceToken, allocated: amount, spend: amount });
    }

    /// Audit 6.1.1: executor calls swap(), which mints output tokens directly to the
    /// outcome destination during execution. CATValidator receives nothing.
    /// The outcome check must fail even though `dest` was paid via the external call.
    function test_audit_611_swap_mints_to_dest_rejected() external {
        validatorToken = new MockERC20("Outcome Token", "OutTok", 18);

        address user = makeAddr("user");
        address executor = makeAddr("executor");

        (address payable proxy, AllowanceSpend[] memory inputTargets, Outcome[] memory outcomes) =
            _deployConstrainedProxy(executor, user);

        // swap() mints validatorToken to `user` — not to CATValidator.
        bytes memory externalCall = abi.encodeCall(this.swap, (inputTargets[0].spend, inputTargets[0].token, user));

        vm.prank(executor);
        vm.expectRevert(abi.encodeWithSelector(CATValidator.InvalidTokenAmount.selector, outcomes[0].amount, 0));
        validator.entry(address(this), externalCall, proxy, 0, inputTargets, outcomes, hex"");
    }

    /// Audit 6.1.1 correct path: executor calls swap(), which mints output tokens to
    /// CATValidator during execution. Outcome check passes and tokens are forwarded to dest.
    function test_audit_611_swap_mints_to_validator_accepted() external {
        validatorToken = new MockERC20("Outcome Token", "OutTok", 18);

        address user = makeAddr("user");
        address executor = makeAddr("executor");

        (address payable proxy, AllowanceSpend[] memory inputTargets, Outcome[] memory outcomes) =
            _deployConstrainedProxy(executor, user);

        // swap() mints validatorToken to CATValidator — correct delivery path.
        bytes memory externalCall =
            abi.encodeCall(this.swap, (inputTargets[0].spend, inputTargets[0].token, address(validator)));

        vm.prank(executor);
        validator.entry(address(this), externalCall, proxy, 0, inputTargets, outcomes, hex"");

        assertEq(validatorToken.balanceOf(user), outcomes[0].amount);
        assertEq(validatorToken.balanceOf(address(validator)), 0);
    }

    // Mock functions for exchanging 1 token for another.
    // `deliverTo` must be the CATValidator address so _validatePayment can read
    // its own balance and then forward tokens to the final outcome destination.
    function swap(
        uint256 amount,
        address inToken,
        address deliverTo
    ) external {
        // Check for balance increase.
        uint256 diff = MockERC20(inToken).balanceOf(address(this)) - balanceOfSwap;
        balanceOfSwap += diff;

        validatorToken.mint(deliverTo, amount);
    }

    function typehash(
        uint256 nonce,
        bytes32 mode,
        ERC7821.Call[] calldata calls
    ) external pure returns (bytes32) {
        return LibCalls.typehash(nonce, mode, calls);
    }

    function assembleExtraData(
        bytes1 revertMode,
        uint256 nonce,
        uint256 index
    ) internal pure returns (bytes32) {
        uint256 extraData = uint256(bytes32(bytes1(revertMode)));
        extraData = extraData + ((nonce << (9 * 8)) >> 8);
        extraData = extraData + uint256(uint64(index));
        return bytes32(extraData);
    }
}
