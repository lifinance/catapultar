// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { Test, stdError } from "forge-std/src/Test.sol";
import { ERC7821 } from "solady/src/accounts/ERC7821.sol";
import { ReentrancyGuard } from "solady/src/utils/ReentrancyGuard.sol";
import { SafeTransferLib } from "solady/src/utils/SafeTransferLib.sol";
import { MockERC20 } from "solady/test/utils/mocks/MockERC20.sol";

import { CATValidator } from "../src/CATValidator.sol";
import { CATValidatorV1_1 } from "../src/CATValidatorV1_1.sol";
import { Catapultar } from "../src/Catapultar.sol";
import { CatapultarFactory } from "../src/CatapultarFactory.sol";
import { ICATValidatorV1_1 } from "../src/interfaces/ICATValidatorV1_1.sol";
import { KeyedOwnable } from "../src/libs/KeyedOwnable.sol";
import { LibCalls } from "../src/libs/LibCalls.sol";
import { Allowance, AllowanceSpend, LibExecutionConstraint, Outcome } from "../src/libs/LibExecutionConstraint.sol";
import { LibExecutionConstraintV1_1 } from "../src/libs/LibExecutionConstraintV1_1.sol";
import { CATValidatorV1_1Standalone } from "./reference/CATValidatorV1_1Standalone.sol";

interface IPulled {
    function pulled(
        address token
    ) external view returns (uint256);
}

contract TypehashHelper {
    function v11(
        AllowanceSpend[] calldata allowances,
        Outcome[] calldata outcomes,
        address executor,
        uint256 nonce,
        address executionTarget,
        bytes32 payloadHash
    ) external pure returns (bytes32) {
        return LibExecutionConstraintV1_1.typehash(allowances, outcomes, executor, nonce, executionTarget, payloadHash);
    }

    function v1(
        AllowanceSpend[] calldata allowances,
        Outcome[] calldata outcomes,
        address executor,
        uint256 nonce
    ) external pure returns (bytes32) {
        return LibExecutionConstraint.typehash(allowances, outcomes, executor, nonce);
    }

    function batch(
        uint256 nonce,
        bytes32 mode,
        ERC7821.Call[] calldata calls
    ) external pure returns (bytes32) {
        return LibCalls.typehash(nonce, mode, calls);
    }
}

contract RecordingProbe {
    uint256[] public seen;

    function probe(
        address validator,
        address token
    ) external {
        seen.push(IPulled(validator).pulled(token));
    }

    function probeTokens(
        address validator,
        address[] calldata tokens
    ) external {
        for (uint256 i; i < tokens.length; ++i) {
            seen.push(IPulled(validator).pulled(tokens[i]));
        }
    }

    function count() external view returns (uint256) {
        return seen.length;
    }

    function seenAt(
        uint256 i
    ) external view returns (uint256) {
        return seen[i];
    }
}

/// @dev ERC-1271 account that approves every digest.
contract AnyAccount {
    function isValidSignature(
        bytes32,
        bytes calldata
    ) external pure returns (bytes4) {
        return bytes4(0x1626ba7e);
    }

    function approveToken(
        address token,
        address spender
    ) external {
        SafeTransferLib.safeApprove(token, spender, type(uint256).max);
    }
}

/// @dev Reads `pulled` from a token-transfer hook, a window in which `pulled` must read zero.
contract ReceiptProbe {
    address public validator;
    address public token;
    uint256[] public seen;

    function config(
        address v,
        address t
    ) external {
        validator = v;
        token = t;
    }

    function onTokenReceived(
        address,
        address,
        uint256
    ) external {
        seen.push(IPulled(validator).pulled(token));
    }

    function count() external view returns (uint256) {
        return seen.length;
    }

    function seenAt(
        uint256 i
    ) external view returns (uint256) {
        return seen[i];
    }
}

/// @dev ERC-20 that calls a hook inside `transferFrom`.
contract CallbackERC20 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    address public hook;

    function setHook(
        address h
    ) external {
        hook = h;
    }

    function mint(
        address to,
        uint256 a
    ) external {
        balanceOf[to] += a;
    }

    function approve(
        address s,
        uint256 a
    ) external returns (bool) {
        allowance[msg.sender][s] = a;
        return true;
    }

    function transferFrom(
        address from,
        address to,
        uint256 a
    ) external returns (bool) {
        uint256 al = allowance[from][msg.sender];
        if (al != type(uint256).max) allowance[from][msg.sender] = al - a;
        balanceOf[from] -= a;
        balanceOf[to] += a;
        if (hook != address(0)) ReceiptProbe(hook).onTokenReceived(address(this), to, a);
        return true;
    }
}

/// @dev Any `transferFrom` reverts, so any other revert reason fired before the first transfer.
contract TransferTrapERC20 {
    function balanceOf(
        address
    ) external pure returns (uint256) {
        return 1e18;
    }

    function transferFrom(
        address,
        address,
        uint256
    ) external pure returns (bool) {
        revert();
    }
}

contract ZeroRejectingERC20 is MockERC20 {
    constructor() MockERC20("ZERO", "ZERO", 6) { }

    function transfer(
        address to,
        uint256 amount
    ) public override returns (bool) {
        require(amount != 0, "zero transfer");
        return super.transfer(to, amount);
    }

    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) public override returns (bool) {
        require(amount != 0, "zero transfer");
        return super.transferFrom(from, to, amount);
    }
}

/// @dev Burns 1% of every `transferFrom` from the recipient.
contract FeeOnTransferERC20 is MockERC20 {
    constructor() MockERC20("FOT", "FOT", 6) { }

    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) public override returns (bool) {
        super.transferFrom(from, to, amount);
        _burn(to, amount / 100);
        return true;
    }
}

/// @dev USDC-style blacklist: a transfer from, to or by a blacklisted account reverts.
contract BlacklistERC20 is MockERC20 {
    mapping(address => bool) public isBlacklisted;

    constructor() MockERC20("USDC", "USDC", 6) { }

    function blacklist(
        address account
    ) external {
        isBlacklisted[account] = true;
    }

    function transfer(
        address to,
        uint256 amount
    ) public override returns (bool) {
        _notBlacklisted(msg.sender);
        _notBlacklisted(to);
        return super.transfer(to, amount);
    }

    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) public override returns (bool) {
        _notBlacklisted(msg.sender);
        _notBlacklisted(from);
        _notBlacklisted(to);
        return super.transferFrom(from, to, amount);
    }

    function _notBlacklisted(
        address account
    ) internal view {
        require(!isBlacklisted[account], "Blacklistable: account is blacklisted");
    }
}

/// @dev Execution target that re-enters the validator and records the outcome.
contract ReentryProbe {
    bytes public reason;
    uint256 public pulledAfterAttempt;

    function reenter(
        address validator,
        address token,
        bytes calldata call
    ) external {
        (bool ok, bytes memory ret) = validator.call(call);
        require(!ok, "nested entry succeeded");
        reason = ret;
        pulledAfterAttempt = IPulled(validator).pulled(token);
    }
}

/// @dev The `IntentExecutor.executeAndSweep` shape: non-payable, no `receive` or `fallback`.
contract NonPayableExecutor {
    function executeAndSweep(
        address token,
        address recipient
    ) external {
        SafeTransferLib.safeTransferAll(token, recipient);
    }
}

/// @dev Runs entries and reads `pulled` inside one external call, so transient storage behaves as on-chain.
contract SameTxHarness {
    uint256 public pulledBetween;
    uint256 public pulledAfter;
    bytes public revertData;

    function runTwo(
        address validator,
        address token,
        bytes calldata call1,
        bytes calldata call2
    ) external {
        (bool ok1,) = validator.call(call1);
        require(ok1, "e1");
        pulledBetween = IPulled(validator).pulled(token);
        (bool ok2,) = validator.call(call2);
        require(ok2, "e2");
        pulledAfter = IPulled(validator).pulled(token);
    }

    function runRevertingThenOne(
        address validator,
        address token,
        bytes calldata reverting,
        bytes calldata call
    ) external {
        (bool ok1, bytes memory ret) = validator.call(reverting);
        require(!ok1, "e1 succeeded");
        revertData = ret;
        pulledBetween = IPulled(validator).pulled(token);
        (bool ok2,) = validator.call(call);
        require(ok2, "e2");
        pulledAfter = IPulled(validator).pulled(token);
    }

    function runAll(
        address validator,
        bytes[] calldata calls
    ) external returns (bool[] memory ok, bytes[] memory ret) {
        ok = new bool[](calls.length);
        ret = new bytes[](calls.length);
        for (uint256 i; i < calls.length; ++i) {
            (ok[i], ret[i]) = validator.call(calls[i]);
        }
    }
}

/// @dev Frame gas of one call, independent of `--isolate`.
contract GasMeter {
    function measure(
        address target,
        bytes calldata data
    ) external returns (uint256 used) {
        assembly ("memory-safe") {
            let m := mload(0x40)
            calldatacopy(m, data.offset, data.length)
            let g := gas()
            let ok := call(gas(), target, 0, m, data.length, codesize(), 0x00)
            used := sub(g, gas())
            if iszero(ok) {
                returndatacopy(m, 0x00, returndatasize())
                revert(m, returndatasize())
            }
        }
    }
}

contract CATValidatorV1_1Mock is CATValidatorV1_1 {
    function validateApproval(
        address account,
        uint256 nonce,
        AllowanceSpend[] calldata allowances,
        Outcome[] calldata outcomes,
        address executionTarget,
        bytes32 payloadHash,
        bytes calldata signature
    ) external view {
        _validateApproval(account, nonce, allowances, outcomes, executionTarget, payloadHash, signature);
    }
}

/// @dev Reports the validator's `pulled(token)` as its balance, so an outcome check observes `pulled`.
contract PulledReaderToken {
    address public validator;
    address public token;

    constructor(
        address v,
        address t
    ) {
        validator = v;
        token = t;
    }

    function balanceOf(
        address
    ) external view returns (uint256) {
        return IPulled(validator).pulled(token);
    }
}

/// @dev Records the validator's `entryId()` and the call-time `pulled(token)` from inside an entry.
contract EntryIdProbe {
    uint256[] public ids;

    function record(
        address validator
    ) external {
        ids.push(CATValidatorV1_1(payable(validator)).entryId());
    }

    function count() external view returns (uint256) {
        return ids.length;
    }
}

/// @dev Execution target that delivers `amount` of `token` to `to`: the outcome delivery the validator holds.
contract Deliverer {
    function deliver(
        address token,
        address to,
        uint256 amount
    ) external {
        SafeTransferLib.safeTransfer(token, to, amount);
    }

    function deliverMany(
        address[] calldata tokens,
        address to,
        uint256[] calldata amounts
    ) external {
        for (uint256 i; i < tokens.length; ++i) {
            SafeTransferLib.safeTransfer(tokens[i], to, amounts[i]);
        }
    }
}

/// @dev Reverts with 196 bytes, longer than the 64-byte scratch space.
contract LongReverter {
    error LongRevert(uint256[6] words);

    function boom(
        uint256[6] calldata words
    ) external pure {
        revert LongRevert(words);
    }
}

contract CATValidatorV1_1Test is Test {
    CATValidator base;
    CATValidatorV1_1 v11;
    CATValidatorV1_1Standalone v11Standalone;
    MockERC20 token;
    RecordingProbe probe;
    CatapultarFactory factory;
    TypehashHelper thh;
    CATValidatorV1_1Mock mock;

    address executor = makeAddr("executor");
    uint256 constant DEPOSIT = 1_000e6;
    uint256 constant SPEND_MAGIC = 1 << 255;

    function setUp() external {
        base = new CATValidator();
        v11 = new CATValidatorV1_1();
        v11Standalone = new CATValidatorV1_1Standalone();
        token = new MockERC20("USDC", "USDC", 6);
        probe = new RecordingProbe();
        factory = new CatapultarFactory();
        thh = new TypehashHelper();
        mock = new CATValidatorV1_1Mock();
    }

    function isValidSignature(
        bytes32,
        bytes calldata
    ) public pure returns (bytes4) {
        return bytes4(0x1626ba7e);
    }

    function _fund(
        address validator
    ) internal {
        token.mint(address(this), DEPOSIT);
        token.approve(validator, type(uint256).max);
    }

    function _spend(
        address t,
        uint256 allocated,
        uint256 spend
    ) internal pure returns (AllowanceSpend[] memory a) {
        a = new AllowanceSpend[](1);
        a[0] = AllowanceSpend({ token: t, allocated: allocated, spend: spend });
    }

    function _spendTwo(
        address t,
        uint256 s0,
        uint256 s1
    ) internal pure returns (AllowanceSpend[] memory a) {
        a = new AllowanceSpend[](2);
        a[0] = AllowanceSpend({ token: t, allocated: s0, spend: s0 });
        a[1] = AllowanceSpend({ token: t, allocated: s1, spend: s1 });
    }

    function _noOut() internal pure returns (Outcome[] memory o) {
        o = new Outcome[](0);
    }

    function _refundOut(
        address t,
        address dest
    ) internal pure returns (Outcome[] memory o) {
        o = new Outcome[](1);
        o[0] = Outcome({ token: t, amount: 0, destination: dest });
    }

    function _probePayload(
        address validator,
        address t
    ) internal pure returns (bytes memory) {
        return abi.encodeCall(RecordingProbe.probe, (validator, t));
    }

    function _domainSep(
        string memory version,
        address verifying
    ) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("CAT Validator")),
                keccak256(bytes(version)),
                block.chainid,
                verifying
            )
        );
    }

    function _digest(
        bytes32 domainSep,
        bytes32 structHash
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(hex"1901", domainSep, structHash));
    }

    function _v11Digest(
        AllowanceSpend[] memory a,
        Outcome[] memory o,
        uint256 nonce,
        address executionTarget,
        bytes32 payloadHash
    ) internal view returns (bytes32) {
        return _digest(_domainSep("1.1", address(v11)), thh.v11(a, o, executor, nonce, executionTarget, payloadHash));
    }

    function _entryCall(
        address execTarget,
        bytes memory payload,
        address account,
        uint256 nonce,
        AllowanceSpend[] memory a
    ) internal pure returns (bytes memory) {
        return abi.encodeCall(
            ICATValidatorV1_1.entry, (execTarget, payload, account, nonce, a, _noOut(), address(0), bytes32(0), "")
        );
    }

    function _toAllowances(
        AllowanceSpend[] memory allowanceSpends
    ) internal pure returns (Allowance[] memory allowances) {
        allowances = new Allowance[](allowanceSpends.length);
        for (uint256 i; i < allowanceSpends.length; ++i) {
            allowances[i] = Allowance({ token: allowanceSpends[i].token, amount: allowanceSpends[i].allocated });
        }
    }

    function _typehashReference(
        Allowance[] memory allowances,
        Outcome[] memory outcomes,
        address exec,
        uint256 nonce,
        address executionTarget,
        bytes32 payloadHash
    ) internal pure returns (bytes32) {
        bytes32[] memory allowanceHashes = new bytes32[](allowances.length);
        for (uint256 i; i < allowances.length; ++i) {
            allowanceHashes[i] = keccak256(
                abi.encode(
                    keccak256(bytes("Allowance(address token,uint256 amount)")),
                    allowances[i].token,
                    allowances[i].amount
                )
            );
        }

        bytes32[] memory outputHashes = new bytes32[](outcomes.length);
        for (uint256 i; i < outcomes.length; ++i) {
            outputHashes[i] = keccak256(
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
                        "ExecutionConstraint(Allowance[] allowances,Outcome[] outcomes,address executor,uint256 nonce,address executionTarget,bytes32 payloadHash)Allowance(address token,uint256 amount)Outcome(address token,uint256 amount,address destination)"
                    )
                ),
                keccak256(abi.encodePacked(allowanceHashes)),
                keccak256(abi.encodePacked(outputHashes)),
                exec,
                nonce,
                executionTarget,
                payloadHash
            )
        );
    }

    function _calldataGas(
        bytes memory data
    ) internal pure returns (uint256 g) {
        for (uint256 i; i < data.length; ++i) {
            g += data[i] == 0 ? 4 : 16;
        }
    }

    function _deployAccount(
        address ownerAddr,
        bytes32 digest
    ) internal returns (address payable account) {
        bytes32[] memory ownerArr = new bytes32[](1);
        ownerArr[0] = bytes32(uint256(uint160(ownerAddr)));
        bytes32 salt = bytes32(uint256(uint160(ownerAddr)) << 96);
        address predicted = factory.predictDeployWithDigest(
            KeyedOwnable.PublicKeyType.ECDSAOrSmartContract, ownerArr, salt, digest, true
        );
        account =
            factory.deployWithDigest(KeyedOwnable.PublicKeyType.ECDSAOrSmartContract, ownerArr, salt, digest, true);
        assertEq(account, predicted, "predicted == deployed account");
    }

    // ---- identity ----

    function test_reference_is_pinned() external pure {
        assertEq(
            keccak256(type(CATValidatorV1_1Standalone).creationCode),
            0xb0b6e910d65139d80e793c8313cfc292670f5763b95a04e7d0a73df1c877ba1d
        );
    }

    function test_selectors_pinned() external pure {
        assertEq(CATValidatorV1_1.pulled.selector, bytes4(0x6ea6f87f));
        assertEq(CATValidatorV1_1.pulled.selector, bytes4(keccak256("pulled(address)")));
        assertEq(ICATValidatorV1_1.pulled.selector, bytes4(0x6ea6f87f));
        assertEq(ICATValidatorV1_1.entry.selector, bytes4(0x6e84b055));
        assertEq(CATValidator.entry.selector, bytes4(0xe5ce4787));
        assertEq(CATValidatorV1_1.entryId.selector, bytes4(0xd323e74d));
        assertEq(ICATValidatorV1_1.entryId.selector, bytes4(0xd323e74d));
    }

    /// @dev The inherited 7-argument entry follows the base's flow: it pulls like the base, bumps no id, and its
    ///      v1 digest cannot pass a v1.1 account's commitment.
    function test_entry_v1_overload_keeps_base_flow() external {
        _fund(address(v11));
        EntryIdProbe idProbe = new EntryIdProbe();
        vm.prank(executor);
        v11.entry(
            address(idProbe),
            abi.encodeCall(EntryIdProbe.record, (address(v11))),
            address(this),
            1,
            _spend(address(token), DEPOSIT, DEPOSIT),
            _noOut(),
            ""
        );
        assertEq(token.balanceOf(address(idProbe)), DEPOSIT, "pulled like the base");
        assertEq(idProbe.ids(0), 0, "no entry id inside it");
        assertEq(v11.entryId(), 0, "bumped no entry id");
        assertTrue(v11.spentNonces(address(this), 1), "spent the nonce");

        (address ownerAddr,) = makeAddrAndKey("v1OverloadDepositor");
        AllowanceSpend[] memory a = _spend(address(token), DEPOSIT, DEPOSIT);
        address payable account = _deployAccount(ownerAddr, _v11Digest(a, _noOut(), 1, address(0), 0));
        token.mint(account, DEPOSIT);
        vm.prank(account);
        token.approve(address(v11), type(uint256).max);
        vm.prank(executor);
        vm.expectRevert(CATValidator.BadSignature.selector);
        v11.entry(address(probe), "", account, 1, a, _noOut(), "");
    }

    function test_domain_name_and_version() external view {
        (, string memory name, string memory version,, address verifying,,) = v11.eip712Domain();
        assertEq(name, "CAT Validator");
        assertEq(version, "1.1");
        assertEq(verifying, address(v11));
        assertEq(v11.DOMAIN_SEPARATOR(), _domainSep("1.1", address(v11)));
    }

    function test_type_string_commits_target_and_payload() external view {
        AllowanceSpend[] memory a = _spend(address(token), DEPOSIT, DEPOSIT);
        Outcome[] memory o = _noOut();
        bytes32 expected = keccak256(
            abi.encode(
                keccak256(
                    "ExecutionConstraint(Allowance[] allowances,Outcome[] outcomes,address executor,uint256 nonce,address executionTarget,bytes32 payloadHash)Allowance(address token,uint256 amount)Outcome(address token,uint256 amount,address destination)"
                ),
                keccak256(
                    abi.encode(
                        keccak256(abi.encode(keccak256("Allowance(address token,uint256 amount)"), token, DEPOSIT))
                    )
                ),
                keccak256(""),
                executor,
                uint256(7),
                address(0xBEEF),
                bytes32(uint256(0xCAFE))
            )
        );
        assertEq(thh.v11(a, o, executor, 7, address(0xBEEF), bytes32(uint256(0xCAFE))), expected);
        assertTrue(thh.v11(a, o, executor, 7, address(0), 0) != thh.v11(a, o, executor, 7, address(0xBEEF), 0));
        assertTrue(thh.v11(a, o, executor, 7, address(0), 0) != thh.v11(a, o, executor, 7, address(0), bytes32("x")));
    }

    function test_fuzz_typehash_matches_reference(
        AllowanceSpend[] calldata allowances,
        Outcome[] calldata outcomes,
        address exec,
        uint256 nonce,
        address executionTarget,
        bytes32 payloadHash
    ) external pure {
        assertEq(
            LibExecutionConstraintV1_1.typehash(allowances, outcomes, exec, nonce, executionTarget, payloadHash),
            _typehashReference(_toAllowances(allowances), outcomes, exec, nonce, executionTarget, payloadHash)
        );
    }

    function test_fuzz_validateApproval_ecdsa(
        AllowanceSpend[] memory allowances,
        Outcome[] memory outcomes,
        address exec,
        uint256 nonce,
        address executionTarget,
        bytes32 payloadHash
    ) external {
        (address signer, uint256 key) = makeAddrAndKey("signer");
        assertEq(mock.DOMAIN_SEPARATOR(), _domainSep("1.1", address(mock)));
        bytes32 digest = _digest(
            mock.DOMAIN_SEPARATOR(),
            _typehashReference(_toAllowances(allowances), outcomes, exec, nonce, executionTarget, payloadHash)
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);

        vm.startPrank(exec);
        mock.validateApproval(
            signer, nonce, allowances, outcomes, executionTarget, payloadHash, abi.encodePacked(r, s, v)
        );

        vm.expectRevert(abi.encodeWithSelector(CATValidator.BadSignature.selector));
        mock.validateApproval(
            signer,
            nonce,
            allowances,
            outcomes,
            executionTarget,
            payloadHash,
            abi.encodePacked(r ^ bytes32(uint256(1)), s, v)
        );

        vm.expectRevert(abi.encodeWithSelector(CATValidator.BadSignature.selector));
        mock.validateApproval(
            signer,
            nonce,
            allowances,
            outcomes,
            address(uint160(executionTarget) ^ 1),
            payloadHash,
            abi.encodePacked(r, s, v)
        );

        vm.expectRevert(abi.encodeWithSelector(CATValidator.BadSignature.selector));
        mock.validateApproval(
            signer,
            nonce,
            allowances,
            outcomes,
            executionTarget,
            payloadHash ^ bytes32(uint256(1)),
            abi.encodePacked(r, s, v)
        );

        vm.expectRevert(abi.encodeWithSelector(CATValidator.BadSignature.selector));
        mock.validateApproval(signer, nonce, allowances, outcomes, executionTarget, payloadHash, hex"");
        vm.stopPrank();
    }

    // ---- constructor TSTORE probe ----

    function test_constructor_probe_clears_its_slot() external {
        CATValidatorV1_1 fresh = new CATValidatorV1_1();
        assertEq(fresh.pulled(address(0)), 0);
    }

    function test_revert_constructor_without_tstore() external {
        vm.setEvmVersion("shanghai");
        assertGt(address(new CATValidator()).code.length, 0, "the base deploys on shanghai");
        vm.expectRevert();
        new CATValidatorV1_1();
    }

    // ---- pulled ----

    function test_pulled_zero_outside_entry() external view {
        assertEq(v11.pulled(address(token)), 0);
    }

    function test_fuzz_pulled_equals_spend(
        uint128 spend
    ) external {
        token.mint(address(this), spend);
        token.approve(address(v11), type(uint256).max);
        vm.prank(executor);
        v11.entry(
            address(probe),
            _probePayload(address(v11), address(token)),
            address(this),
            1,
            _spend(address(token), spend, spend),
            _noOut(),
            address(0),
            0,
            ""
        );
        assertEq(probe.seenAt(0), spend, "pulled during entry");
        assertEq(v11.pulled(address(token)), 0, "pulled after entry");
        assertEq(token.balanceOf(address(probe)), spend);
    }

    function test_fuzz_pulled_tracks_balance_sweep_magic(
        uint128 balance
    ) external {
        token.mint(address(this), balance);
        token.approve(address(v11), type(uint256).max);
        vm.prank(executor);
        v11.entry(
            address(probe),
            _probePayload(address(v11), address(token)),
            address(this),
            1,
            _spend(address(token), type(uint256).max, SPEND_MAGIC),
            _noOut(),
            address(0),
            0,
            ""
        );
        assertEq(probe.seenAt(0), balance);
        assertEq(v11.pulled(address(token)), 0);
    }

    function test_entry_spend_zero_pulls_nothing() external {
        _fund(address(v11));
        vm.prank(executor);
        v11.entry(
            address(probe),
            _probePayload(address(v11), address(token)),
            address(this),
            1,
            _spend(address(token), type(uint256).max, 0),
            _noOut(),
            address(0),
            0,
            ""
        );
        assertEq(probe.seenAt(0), 0, "pulled during entry");
        assertEq(token.balanceOf(address(this)), DEPOSIT, "signer balance unchanged");
        assertEq(token.balanceOf(address(probe)), 0);
    }

    /// @dev `pulled` is cleared before the payout, so a token read from inside it sees zero.
    function test_fuzz_pulled_zero_during_payout(
        uint128 s0,
        uint128 s1
    ) external {
        uint256 total = uint256(s0) + s1;
        token.mint(address(this), total);
        token.approve(address(v11), type(uint256).max);
        Outcome[] memory o = new Outcome[](1);
        o[0] = Outcome({
            token: address(new PulledReaderToken(address(v11), address(token))),
            amount: 1,
            destination: makeAddr("dest")
        });
        AllowanceSpend[] memory a = _spendTwo(address(token), s0, s1);

        vm.prank(executor);
        vm.expectRevert(abi.encodeWithSelector(CATValidator.InvalidTokenAmount.selector, 1, 0));
        v11.entry(address(probe), "", address(this), 1, a, o, address(0), 0, "");
        assertEq(v11.pulled(address(token)), 0, "pulled after entry");
    }

    function test_fuzz_pulled_other_token_zero_during_call(
        uint128 sA,
        uint128 sB
    ) external {
        MockERC20 tokenB = new MockERC20("B", "B", 6);
        address other = address(new MockERC20("C", "C", 6));
        token.mint(address(this), sA);
        token.approve(address(v11), type(uint256).max);
        tokenB.mint(address(this), sB);
        tokenB.approve(address(v11), type(uint256).max);

        AllowanceSpend[] memory a = new AllowanceSpend[](2);
        a[0] = AllowanceSpend({ token: address(token), allocated: sA, spend: sA });
        a[1] = AllowanceSpend({ token: address(tokenB), allocated: sB, spend: sB });
        address[] memory read = new address[](3);
        read[0] = address(token);
        read[1] = address(tokenB);
        read[2] = other;

        vm.prank(executor);
        v11.entry(
            address(probe),
            abi.encodeCall(RecordingProbe.probeTokens, (address(v11), read)),
            address(this),
            1,
            a,
            _noOut(),
            address(0),
            0,
            ""
        );
        assertEq(probe.seenAt(0), sA);
        assertEq(probe.seenAt(1), sB);
        assertEq(probe.seenAt(2), 0, "token outside the allowances");
        assertEq(v11.pulled(address(token)), 0);
        assertEq(v11.pulled(address(tokenB)), 0);
    }

    function test_fuzz_pulled_reports_spend_not_received_for_fee_on_transfer(
        uint128 spend
    ) external {
        FeeOnTransferERC20 fot = new FeeOnTransferERC20();
        fot.mint(address(this), spend);
        fot.approve(address(v11), type(uint256).max);

        vm.prank(executor);
        v11.entry(
            address(probe),
            _probePayload(address(v11), address(fot)),
            address(this),
            1,
            _spend(address(fot), spend, spend),
            _noOut(),
            address(0),
            0,
            ""
        );
        assertEq(probe.seenAt(0), spend, "pulled is the spend");
        assertEq(fot.balanceOf(address(probe)), uint256(spend) - spend / 100, "target received less");
        assertEq(v11.pulled(address(fot)), 0);
    }

    function test_fuzz_reverted_entry_leaves_pulled_zero_same_tx(
        uint128 s1,
        uint128 s2
    ) external {
        AnyAccount acct = new AnyAccount();
        SameTxHarness harness = new SameTxHarness();
        RecordingProbe pa = new RecordingProbe();
        RecordingProbe pb = new RecordingProbe();
        token.mint(address(acct), uint256(s1) + s2);
        acct.approveToken(address(token), address(v11));

        bytes memory payload = _probePayload(address(v11), address(token));
        Outcome[] memory unpaid = new Outcome[](1);
        unpaid[0] = Outcome({ token: address(token), amount: 1, destination: makeAddr("unpaid") });
        bytes memory reverting = abi.encodeCall(
            ICATValidatorV1_1.entry,
            (address(pa), payload, address(acct), 1, _spend(address(token), s1, s1), unpaid, address(0), bytes32(0), "")
        );

        harness.runRevertingThenOne(
            address(v11),
            address(token),
            reverting,
            _entryCall(address(pb), payload, address(acct), 2, _spend(address(token), s2, s2))
        );
        assertEq(harness.revertData(), abi.encodeWithSelector(CATValidator.InvalidTokenAmount.selector, 1, 0));
        assertEq(harness.pulledBetween(), 0, "reverted entry leaves nothing");
        assertEq(pa.count(), 0, "reverted probe record rolled back");
        assertEq(pb.seenAt(0), s2, "next entry sees only its own pull");
        assertEq(harness.pulledAfter(), 0);
        assertFalse(v11.spentNonces(address(acct), 1));
    }

    function test_revert_nested_entry_reentrancy() external {
        _fund(address(v11));
        ReentryProbe rp = new ReentryProbe();
        address sink = makeAddr("sink");
        uint256 outer = DEPOSIT / 2;
        bytes memory nested = _entryCall(sink, "", address(this), 2, _spend(address(token), 1, 1));

        vm.prank(executor);
        v11.entry(
            address(rp),
            abi.encodeCall(ReentryProbe.reenter, (address(v11), address(token), nested)),
            address(this),
            1,
            _spend(address(token), outer, outer),
            _noOut(),
            address(0),
            0,
            ""
        );
        assertEq(rp.reason(), abi.encodeWithSelector(ReentrancyGuard.Reentrancy.selector));
        assertEq(rp.pulledAfterAttempt(), outer, "nested attempt leaves the outer pull");
        assertEq(v11.pulled(address(token)), 0);
        assertEq(token.balanceOf(sink), 0);
        assertFalse(v11.spentNonces(address(this), 2));
    }

    function test_fuzz_sequential_entries_same_tx_isolated_both_orders(
        uint128 s1,
        uint128 s2
    ) external {
        _sequential(s1, s2);
        _sequential(s2, s1);
    }

    function _sequential(
        uint256 s1,
        uint256 s2
    ) internal {
        AnyAccount acct = new AnyAccount();
        SameTxHarness harness = new SameTxHarness();
        RecordingProbe pa = new RecordingProbe();
        RecordingProbe pb = new RecordingProbe();
        token.mint(address(acct), s1 + s2);
        acct.approveToken(address(token), address(v11));

        bytes memory payload = _probePayload(address(v11), address(token));
        vm.prank(executor);
        harness.runTwo(
            address(v11),
            address(token),
            _entryCall(address(pa), payload, address(acct), 1, _spend(address(token), s1, s1)),
            _entryCall(address(pb), payload, address(acct), 2, _spend(address(token), s2, s2))
        );
        assertEq(pa.seenAt(0), s1, "entry 1 sees its own pull");
        assertEq(pb.seenAt(0), s2, "entry 2 sees its own pull");
        assertEq(harness.pulledBetween(), 0, "cleared between entries");
        assertEq(harness.pulledAfter(), 0, "cleared after last entry");
    }

    function test_fuzz_callback_reads_zero_pulled_duplicate_allowances(
        uint128 s0,
        uint128 s1
    ) external {
        AnyAccount acct = new AnyAccount();
        CallbackERC20 cb = new CallbackERC20();
        ReceiptProbe hook = new ReceiptProbe();
        hook.config(address(v11), address(cb));
        cb.setHook(address(hook));

        cb.mint(address(acct), uint256(s0) + s1);
        acct.approveToken(address(cb), address(v11));

        vm.prank(executor);
        v11.entry(
            address(probe),
            _probePayload(address(v11), address(cb)),
            address(acct),
            1,
            _spendTwo(address(cb), s0, s1),
            _noOut(),
            address(0),
            0,
            ""
        );
        assertEq(hook.count(), 2, "hook fired once per transfer");
        assertEq(hook.seenAt(0), 0);
        assertEq(hook.seenAt(1), 0);
        assertEq(probe.seenAt(0), uint256(s0) + s1, "payload sees the aggregated total");
        assertEq(cb.balanceOf(address(probe)), uint256(s0) + s1);
        assertEq(v11.pulled(address(cb)), 0, "cleared after entry");
    }

    function test_fuzz_callback_reads_zero_pulled_single_allowance(
        uint128 spend
    ) external {
        AnyAccount acct = new AnyAccount();
        CallbackERC20 cb = new CallbackERC20();
        ReceiptProbe hook = new ReceiptProbe();
        hook.config(address(v11), address(cb));
        cb.setHook(address(hook));
        cb.mint(address(acct), spend);
        acct.approveToken(address(cb), address(v11));

        vm.prank(executor);
        v11.entry(
            address(probe),
            _probePayload(address(v11), address(cb)),
            address(acct),
            1,
            _spend(address(cb), spend, spend),
            _noOut(),
            address(0),
            0,
            ""
        );
        assertEq(hook.count(), 1);
        assertEq(hook.seenAt(0), 0);
        assertEq(probe.seenAt(0), spend);
        assertEq(v11.pulled(address(cb)), 0);
    }

    // ---- refund commitment ----

    function test_refund_commitment_rejects_before_any_transfer() external {
        AnyAccount acct = new AnyAccount();
        TransferTrapERC20 trap = new TransferTrapERC20();
        address refund = makeAddr("refund");
        AllowanceSpend[] memory a = _spend(address(trap), type(uint256).max, SPEND_MAGIC);
        Outcome[] memory o = _refundOut(address(trap), refund);
        bytes32 emptyHash = keccak256("");

        vm.startPrank(executor);
        vm.expectRevert(CATValidatorV1_1.TargetNotCommitted.selector);
        v11.entry(makeAddr("attacker"), "", address(acct), 0, a, o, refund, emptyHash, "");

        vm.expectRevert(CATValidatorV1_1.PayloadNotCommitted.selector);
        v11.entry(refund, hex"01", address(acct), 0, a, o, refund, emptyHash, "");

        vm.expectRevert(SafeTransferLib.TransferFromFailed.selector);
        v11.entry(refund, "", address(acct), 0, a, o, refund, emptyHash, "");
        vm.stopPrank();
    }

    function test_refund_commitment_binds_target_and_payload() external {
        _fund(address(v11));
        address refund = makeAddr("refund");
        AllowanceSpend[] memory a = _spend(address(token), type(uint256).max, SPEND_MAGIC);
        Outcome[] memory o = _refundOut(address(token), refund);
        bytes32 emptyHash = keccak256("");

        vm.startPrank(executor);
        vm.expectRevert(CATValidatorV1_1.TargetNotCommitted.selector);
        v11.entry(makeAddr("attacker"), "", address(this), 0, a, o, refund, emptyHash, "");
        vm.expectRevert(CATValidatorV1_1.PayloadNotCommitted.selector);
        v11.entry(refund, hex"01", address(this), 0, a, o, refund, emptyHash, "");
        assertEq(token.balanceOf(address(this)), DEPOSIT, "signer untouched");

        v11.entry(refund, "", address(this), 0, a, o, refund, emptyHash, "");
        vm.stopPrank();
        assertEq(token.balanceOf(refund), DEPOSIT);
    }

    function test_fuzz_revert_refund_target_mismatch(
        address execTarget
    ) external {
        address refund = makeAddr("refund");
        vm.assume(execTarget != refund);
        TransferTrapERC20 trap = new TransferTrapERC20();
        AnyAccount acct = new AnyAccount();

        vm.prank(executor);
        vm.expectRevert(CATValidatorV1_1.TargetNotCommitted.selector);
        v11.entry(
            execTarget,
            "",
            address(acct),
            0,
            _spend(address(trap), type(uint256).max, SPEND_MAGIC),
            _refundOut(address(trap), refund),
            refund,
            keccak256(""),
            ""
        );
    }

    function test_fuzz_revert_refund_payload_mismatch(
        bytes calldata payload
    ) external {
        vm.assume(payload.length != 0);
        address refund = makeAddr("refund");
        TransferTrapERC20 trap = new TransferTrapERC20();
        AnyAccount acct = new AnyAccount();

        vm.prank(executor);
        vm.expectRevert(CATValidatorV1_1.PayloadNotCommitted.selector);
        v11.entry(
            refund,
            payload,
            address(acct),
            0,
            _spend(address(trap), type(uint256).max, SPEND_MAGIC),
            _refundOut(address(trap), refund),
            refund,
            keccak256(""),
            ""
        );
    }

    function test_fuzz_committed_target_and_payload_on_execute_digest(
        address target,
        bytes calldata payload
    ) external {
        assumeUnusedAddress(target);
        (address signer, uint256 key) = makeAddrAndKey("committer");
        vm.assume(target != signer);
        token.mint(signer, DEPOSIT);
        vm.prank(signer);
        token.approve(address(v11), type(uint256).max);

        AllowanceSpend[] memory a = _spend(address(token), DEPOSIT, DEPOSIT);
        Outcome[] memory o = _noOut();
        bytes32 h = keccak256(payload);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, _v11Digest(a, o, 1, target, h));
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.startPrank(executor);
        vm.expectRevert(CATValidatorV1_1.TargetNotCommitted.selector);
        v11.entry(address(uint160(target) ^ 1), payload, signer, 1, a, o, target, h, sig);

        vm.expectRevert(CATValidatorV1_1.PayloadNotCommitted.selector);
        v11.entry(target, bytes.concat(payload, hex"00"), signer, 1, a, o, target, h, sig);

        vm.expectRevert(CATValidator.BadSignature.selector);
        v11.entry(target, payload, signer, 1, a, o, address(0), bytes32(0), sig);

        vm.expectRevert(CATValidator.BadSignature.selector);
        v11.entry(target, payload, signer, 1, a, o, target, bytes32(0), sig);

        vm.expectRevert(CATValidator.BadSignature.selector);
        v11.entry(target, payload, signer, 1, a, o, address(0), h, sig);

        v11.entry(target, payload, signer, 1, a, o, target, h, sig);
        vm.stopPrank();
        assertEq(token.balanceOf(target), DEPOSIT);
        assertEq(token.balanceOf(signer), 0);
    }

    // ---- inherited v1 mechanics ----

    function test_fuzz_revert_allocation_too_small(
        uint256 allocated,
        uint256 spend
    ) external {
        allocated = bound(allocated, 0, type(uint256).max - 1);
        spend = bound(spend, allocated + 1, type(uint256).max);
        vm.assume(spend != SPEND_MAGIC);

        vm.prank(executor);
        vm.expectRevert(abi.encodeWithSelector(CATValidator.AllocationTooSmall.selector, allocated, spend));
        v11.entry(
            address(probe), "", address(this), 1, _spend(address(token), allocated, spend), _noOut(), address(0), 0, ""
        );
    }

    function test_fuzz_revert_allocation_too_small_balance_sweep(
        uint256 allocated,
        uint256 balance
    ) external {
        balance = bound(balance, 1, type(uint128).max);
        allocated = bound(allocated, 0, balance - 1);
        token.mint(address(this), balance);
        token.approve(address(v11), type(uint256).max);

        vm.prank(executor);
        vm.expectRevert(abi.encodeWithSelector(CATValidator.AllocationTooSmall.selector, allocated, balance));
        v11.entry(
            address(probe),
            "",
            address(this),
            1,
            _spend(address(token), allocated, SPEND_MAGIC),
            _noOut(),
            address(0),
            0,
            ""
        );
    }

    function test_fuzz_revert_outcome_below_floor(
        uint256 delivered,
        uint256 floor
    ) external {
        floor = bound(floor, 1, type(uint128).max);
        delivered = bound(delivered, 0, floor - 1);
        Deliverer deliverer = new Deliverer();
        token.mint(address(deliverer), floor);
        address dest = makeAddr("dest");
        Outcome[] memory o = new Outcome[](1);
        o[0] = Outcome({ token: address(token), amount: floor, destination: dest });
        AllowanceSpend[] memory none = new AllowanceSpend[](0);

        vm.startPrank(executor);
        vm.expectRevert(abi.encodeWithSelector(CATValidator.InvalidTokenAmount.selector, floor, delivered));
        v11.entry(
            address(deliverer),
            abi.encodeCall(Deliverer.deliver, (address(token), address(v11), delivered)),
            address(this),
            1,
            none,
            o,
            address(0),
            0,
            ""
        );

        v11.entry(
            address(deliverer),
            abi.encodeCall(Deliverer.deliver, (address(token), address(v11), floor)),
            address(this),
            1,
            none,
            o,
            address(0),
            0,
            ""
        );
        vm.stopPrank();
        assertEq(token.balanceOf(dest), floor);
    }

    // ---- real account derivation ----

    function test_real_account_derivation_and_entry() external {
        (address ownerAddr,) = makeAddrAndKey("depositor");
        AllowanceSpend[] memory a = _spend(address(token), DEPOSIT, DEPOSIT);
        Outcome[] memory o = _noOut();
        address payable account = _deployAccount(ownerAddr, _v11Digest(a, o, 1, address(0), 0));

        token.mint(account, DEPOSIT);
        vm.prank(account);
        token.approve(address(v11), type(uint256).max);

        address sink = makeAddr("sink");
        vm.prank(executor);
        v11.entry(sink, "", account, 1, a, o, address(0), 0, "");
        assertEq(token.balanceOf(sink), DEPOSIT);
        assertEq(token.balanceOf(account), 0);
    }

    function test_revert_entry_on_account_of_another_digest() external {
        (address ownerAddr,) = makeAddrAndKey("depositor2");
        AllowanceSpend[] memory a = _spend(address(token), DEPOSIT, DEPOSIT);
        Outcome[] memory o = _noOut();
        bytes32 committed = _digest(
            _domainSep("1.1", address(v11)), thh.v11(a, o, makeAddr("otherExecutor"), 1, address(0), bytes32(0))
        );
        address payable account = _deployAccount(ownerAddr, committed);
        token.mint(account, DEPOSIT);
        vm.prank(account);
        token.approve(address(v11), type(uint256).max);

        vm.prank(executor);
        vm.expectRevert(CATValidator.BadSignature.selector);
        v11.entry(makeAddr("sink"), "", account, 1, a, o, address(0), 0, "");
    }

    function test_account_address_differs_from_base_for_identical_terms() external {
        (address ownerAddr,) = makeAddrAndKey("commitProbe");
        bytes32[] memory ownerArr = new bytes32[](1);
        ownerArr[0] = bytes32(uint256(uint160(ownerAddr)));
        bytes32 salt = bytes32(uint256(uint160(ownerAddr)) << 96);
        AllowanceSpend[] memory a = _spend(address(token), DEPOSIT, DEPOSIT);
        Outcome[] memory o = _noOut();

        bytes32 structV11 = thh.v11(a, o, executor, 1, address(0), 0);
        bytes32 structV1 = thh.v1(a, o, executor, 1);
        assertTrue(structV11 != structV1, "type string changes struct hash");
        assertEq(_domainSep("1", address(base)), base.DOMAIN_SEPARATOR());

        bytes32 digestV1 = _digest(_domainSep("1", address(base)), structV1);
        bytes32 digestV11 = _digest(_domainSep("1.1", address(v11)), structV11);
        address accountV1 = factory.predictDeployWithDigest(
            KeyedOwnable.PublicKeyType.ECDSAOrSmartContract, ownerArr, salt, digestV1, true
        );
        address accountV11 = factory.predictDeployWithDigest(
            KeyedOwnable.PublicKeyType.ECDSAOrSmartContract, ownerArr, salt, digestV11, true
        );
        assertTrue(accountV1 != accountV11);
    }

    // ---- nonce-0 refund sweep ----

    function test_refund_nonce0_sweeps_residue_and_late_deposits_after_execute() external {
        (address ownerAddr,) = makeAddrAndKey("refundDepositor");
        address refund = makeAddr("refundAddress");
        bytes32 emptyHash = keccak256("");
        uint256 residue = 5e6;

        AllowanceSpend[] memory execA = _spend(address(token), DEPOSIT, DEPOSIT);
        Outcome[] memory execO = _noOut();
        AllowanceSpend[] memory refA = _spend(address(token), type(uint256).max, SPEND_MAGIC);
        Outcome[] memory refO = _refundOut(address(token), refund);

        address payable account = _deployAccount(ownerAddr, _v11Digest(execA, execO, 1, address(0), 0));
        bytes32 refundDigest = _v11Digest(refA, refO, 0, refund, emptyHash);
        vm.prank(ownerAddr);
        Catapultar(account).setSignature(refundDigest, Catapultar.DigestApproval.Signature);
        vm.prank(account);
        token.approve(address(v11), type(uint256).max);

        token.mint(account, DEPOSIT + residue);
        address sink = makeAddr("execSink");
        vm.startPrank(executor);
        v11.entry(sink, "", account, 1, execA, execO, address(0), 0, "");
        assertEq(token.balanceOf(sink), DEPOSIT);
        assertTrue(v11.spentNonces(account, 1));

        vm.expectRevert(CATValidator.NonceAlreadySpent.selector);
        v11.entry(sink, "", account, 1, execA, execO, address(0), 0, "");

        vm.expectRevert(CATValidatorV1_1.TargetNotCommitted.selector);
        v11.entry(makeAddr("attacker"), "", account, 0, refA, refO, refund, emptyHash, "");

        v11.entry(refund, "", account, 0, refA, refO, refund, emptyHash, "");
        assertEq(token.balanceOf(refund), residue, "residue swept after execute");

        token.mint(account, 123e6);
        v11.entry(refund, "", account, 0, refA, refO, refund, emptyHash, "");
        assertEq(token.balanceOf(refund), residue + 123e6, "late deposit 1");

        token.mint(account, 77e6);
        v11.entry(refund, "", account, 0, refA, refO, refund, emptyHash, "");
        assertEq(token.balanceOf(refund), residue + 200e6, "late deposit 2");

        v11.entry(refund, "", account, 0, refA, refO, refund, emptyHash, "");
        vm.stopPrank();
        assertEq(token.balanceOf(refund), residue + 200e6, "empty-account sweep is a no-op");
        assertEq(token.balanceOf(account), 0);
        assertFalse(v11.spentNonces(account, 0));
    }

    function test_revert_refund_nonce0_empty_sweep_on_zero_rejecting_token() external {
        ZeroRejectingERC20 zt = new ZeroRejectingERC20();
        AnyAccount acct = new AnyAccount();
        acct.approveToken(address(zt), address(v11));
        address refund = makeAddr("refund");
        AllowanceSpend[] memory a = _spend(address(zt), type(uint256).max, SPEND_MAGIC);
        Outcome[] memory o = _refundOut(address(zt), refund);
        bytes32 emptyHash = keccak256("");

        zt.mint(address(acct), DEPOSIT);
        vm.startPrank(executor);
        v11.entry(refund, "", address(acct), 0, a, o, refund, emptyHash, "");
        assertEq(zt.balanceOf(refund), DEPOSIT);

        vm.expectRevert(SafeTransferLib.TransferFromFailed.selector);
        v11.entry(refund, "", address(acct), 0, a, o, refund, emptyHash, "");
        vm.stopPrank();
    }

    /// @dev When the refund wallet also owns the account, its key recovers what the sweep cannot pay.
    function test_refund_nonce0_blacklisted_refund_wallet_sweep_reverts_owner_recovers() external {
        BlacklistERC20 usdc = new BlacklistERC20();
        (address refund, uint256 refundKey) = makeAddrAndKey("blacklistedRefund");
        address recovery = makeAddr("recovery");
        bytes32 emptyHash = keccak256("");

        AllowanceSpend[] memory execA = _spend(address(usdc), DEPOSIT, DEPOSIT);
        AllowanceSpend[] memory refA = _spend(address(usdc), type(uint256).max, SPEND_MAGIC);
        Outcome[] memory refO = _refundOut(address(usdc), refund);
        address payable account = _deployAccount(refund, _v11Digest(execA, _noOut(), 1, address(0), 0));
        bytes32 refundDigest = _v11Digest(refA, refO, 0, refund, emptyHash);
        vm.prank(refund);
        Catapultar(account).setSignature(refundDigest, Catapultar.DigestApproval.Signature);
        vm.prank(account);
        usdc.approve(address(v11), type(uint256).max);
        usdc.mint(account, DEPOSIT);
        usdc.blacklist(refund);

        vm.prank(executor);
        vm.expectRevert(SafeTransferLib.TransferFromFailed.selector);
        v11.entry(refund, "", account, 0, refA, refO, refund, emptyHash, "");
        assertEq(usdc.balanceOf(account), DEPOSIT, "failed sweep moved funds");
        assertEq(usdc.balanceOf(refund), 0);

        ERC7821.Call[] memory calls = new ERC7821.Call[](1);
        calls[0] = ERC7821.Call({
            to: address(usdc), value: 0, data: abi.encodeCall(MockERC20.transfer, (recovery, DEPOSIT))
        });
        bytes32 mode = bytes10(0x01000000000078210001);
        uint256 nonce = 1;
        bytes32 digest = _digest(Catapultar(account).DOMAIN_SEPARATOR(), thh.batch(nonce, mode, calls));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(refundKey, digest);
        Catapultar(account).execute(mode, abi.encode(calls, abi.encodePacked(nonce, r, s, v)));

        assertEq(usdc.balanceOf(account), 0, "account emptied");
        assertEq(usdc.balanceOf(recovery), DEPOSIT, "owner recovered the deposit");
    }

    function _zeroRefundAccount()
        internal
        returns (address payable account, AllowanceSpend[] memory refA, Outcome[] memory refO)
    {
        (address ownerAddr,) = makeAddrAndKey("zeroRefundDepositor");
        refA = _spend(address(token), type(uint256).max, SPEND_MAGIC);
        refO = _refundOut(address(token), address(0));
        account =
            _deployAccount(ownerAddr, _v11Digest(_spend(address(token), DEPOSIT, DEPOSIT), _noOut(), 1, address(0), 0));
        bytes32 refundDigest = _v11Digest(refA, refO, 0, address(0), keccak256(""));
        vm.prank(ownerAddr);
        Catapultar(account).setSignature(refundDigest, Catapultar.DigestApproval.Signature);
        vm.prank(account);
        token.approve(address(v11), type(uint256).max);
    }

    /// @dev A reusable nonce-0 refund digest committing no execution target (a zero refund address) would let the
    /// executor sweep to any target, again for every later deposit; the entry refuses it.
    function test_zero_refund_address_fails_closed() external {
        (address payable account, AllowanceSpend[] memory refA, Outcome[] memory refO) = _zeroRefundAccount();
        address attacker = makeAddr("attacker");
        token.mint(account, DEPOSIT);
        vm.prank(executor);
        vm.expectRevert(CATValidatorV1_1.ZeroDestination.selector);
        v11.entry(attacker, "", account, 0, refA, refO, address(0), keccak256(""), "");
        assertEq(token.balanceOf(attacker), 0);
        assertEq(token.balanceOf(account), DEPOSIT);
        assertFalse(v11.spentNonces(account, 0));
    }

    function test_fuzz_zero_refund_address_fails_closed_for_any_target(
        address target,
        uint128 balance
    ) external {
        (address payable account, AllowanceSpend[] memory refA, Outcome[] memory refO) = _zeroRefundAccount();
        token.mint(account, balance);
        vm.prank(executor);
        vm.expectRevert(CATValidatorV1_1.ZeroDestination.selector);
        v11.entry(target, "", account, 0, refA, refO, address(0), keccak256(""), "");
    }

    // ---- revert bubbling ----

    function test_entry_bubbles_long_revert_data_verbatim() external {
        LongReverter target = new LongReverter();
        uint256[6] memory words;
        for (uint256 i; i < words.length; ++i) {
            words[i] = uint256(keccak256(abi.encode(i)));
        }
        bytes memory expected = abi.encodeWithSelector(LongReverter.LongRevert.selector, words);
        assertEq(expected.length, 196);

        _fund(address(v11));
        vm.prank(executor);
        vm.expectRevert(expected);
        v11.entry(
            address(target),
            abi.encodeCall(LongReverter.boom, (words)),
            address(this),
            1,
            _spend(address(token), DEPOSIT, DEPOSIT),
            _noOut(),
            address(0),
            0,
            ""
        );
    }

    // ---- value forwarding ----

    function _forceFedSettle(
        uint256 fed
    ) internal {
        NonPayableExecutor exec = new NonPayableExecutor();
        address recipient = makeAddr("bridgeSink");
        _fund(address(v11));
        vm.deal(address(v11), fed);

        vm.prank(executor);
        v11.entry(
            address(exec),
            abi.encodeCall(NonPayableExecutor.executeAndSweep, (address(token), recipient)),
            address(this),
            1,
            _spend(address(token), DEPOSIT, DEPOSIT),
            _noOut(),
            address(0),
            0,
            ""
        );
        assertEq(token.balanceOf(recipient), DEPOSIT, "settled");
        assertEq(address(v11).balance, fed, "validator balance unchanged");
        assertEq(address(exec).balance, 0);
    }

    function test_force_fed_one_wei_does_not_brick_non_payable_executor() external {
        _forceFedSettle(1);
    }

    function test_force_fed_large_amount_does_not_brick_non_payable_executor() external {
        _forceFedSettle(1_000 ether);
    }

    function test_base_force_fed_wei_bricks_non_payable_executor() external {
        NonPayableExecutor exec = new NonPayableExecutor();
        _fund(address(base));
        vm.deal(address(base), 1);
        vm.prank(executor);
        vm.expectRevert(bytes(""));
        base.entry(
            address(exec),
            abi.encodeCall(NonPayableExecutor.executeAndSweep, (address(token), makeAddr("bridgeSink"))),
            address(this),
            1,
            _spend(address(token), DEPOSIT, DEPOSIT),
            _noOut(),
            ""
        );
    }

    // ---- entry id ----

    function test_entryId_zero_outside_and_monotonic_inside() external {
        assertEq(v11.entryId(), 0, "before");
        EntryIdProbe idProbe = new EntryIdProbe();
        bytes memory record = abi.encodeCall(EntryIdProbe.record, (address(v11)));
        AllowanceSpend[] memory none = new AllowanceSpend[](0);
        bytes[] memory calls = new bytes[](4);
        calls[0] = _entryCall(address(idProbe), record, address(this), 1, none);
        calls[1] = abi.encodeCall(CATValidatorV1_1.entryId, ());
        calls[2] = _entryCall(address(idProbe), record, address(this), 2, none);
        calls[3] = _entryCall(address(idProbe), record, address(this), 3, none);

        (bool[] memory ok, bytes[] memory ret) = new SameTxHarness().runAll(address(v11), calls);
        for (uint256 i; i < ok.length; ++i) {
            assertTrue(ok[i]);
        }
        assertEq(abi.decode(ret[1], (uint256)), 0, "between");
        assertEq(idProbe.ids(0), 1);
        assertEq(idProbe.ids(1), 2);
        assertEq(idProbe.ids(2), 3);
        assertEq(v11.entryId(), 0, "after");
    }

    function test_entryId_rolls_back_with_a_reverted_entry() external {
        EntryIdProbe idProbe = new EntryIdProbe();
        bytes memory record = abi.encodeCall(EntryIdProbe.record, (address(v11)));
        AllowanceSpend[] memory none = new AllowanceSpend[](0);
        Outcome[] memory unmet = new Outcome[](1);
        unmet[0] = Outcome({ token: address(token), amount: 1, destination: makeAddr("x") });

        bytes[] memory calls = new bytes[](3);
        calls[0] = _entryCall(address(idProbe), record, address(this), 1, none);
        calls[1] = abi.encodeCall(
            ICATValidatorV1_1.entry,
            (address(idProbe), record, address(this), 2, none, unmet, address(0), bytes32(0), "")
        );
        calls[2] = _entryCall(address(idProbe), record, address(this), 3, none);

        (bool[] memory ok,) = new SameTxHarness().runAll(address(v11), calls);
        assertTrue(ok[0]);
        assertFalse(ok[1], "the unmet outcome reverts the entry");
        assertTrue(ok[2]);
        assertEq(idProbe.count(), 2, "the reverted entry's record rolled back");
        assertEq(idProbe.ids(0), 1);
        assertEq(idProbe.ids(1), 2, "its id was never taken");
    }

    // ---- held outcomes ----

    function test_outcomes_are_held_then_forwarded_in_full() external {
        Deliverer deliverer = new Deliverer();
        MockERC20 out = new MockERC20("OUT", "OUT", 6);
        out.mint(address(deliverer), 150e6);
        address dest = makeAddr("dest");
        Outcome[] memory o = new Outcome[](1);
        o[0] = Outcome({ token: address(out), amount: 100e6, destination: dest });
        bytes memory deliver = abi.encodeCall(Deliverer.deliver, (address(out), address(v11), 150e6));

        vm.startPrank(executor);
        v11.entry(address(deliverer), deliver, address(this), 1, new AllowanceSpend[](0), o, address(0), 0, "");
        vm.stopPrank();
        assertEq(out.balanceOf(dest), 150e6, "the whole held balance, surplus included");
        assertEq(out.balanceOf(address(v11)), 0, "nothing stays held");
    }

    function test_revert_outcome_under_delivery() external {
        Deliverer deliverer = new Deliverer();
        MockERC20 out = new MockERC20("OUT", "OUT", 6);
        out.mint(address(deliverer), 99e6);
        Outcome[] memory o = new Outcome[](1);
        o[0] = Outcome({ token: address(out), amount: 100e6, destination: makeAddr("dest") });
        bytes memory deliver = abi.encodeCall(Deliverer.deliver, (address(out), address(v11), 99e6));

        vm.prank(executor);
        vm.expectRevert(abi.encodeWithSelector(CATValidator.InvalidTokenAmount.selector, 100e6, 99e6));
        v11.entry(address(deliverer), deliver, address(this), 1, new AllowanceSpend[](0), o, address(0), 0, "");
    }

    /// @dev A zero outcome on a token that rejects zero transfers settles: the zero payout is skipped.
    function test_zero_payout_is_skipped_on_a_zero_rejecting_token() external {
        ZeroRejectingERC20 zt = new ZeroRejectingERC20();
        address refund = makeAddr("refund");
        vm.prank(executor);
        v11.entry(
            address(probe),
            "",
            address(this),
            1,
            new AllowanceSpend[](0),
            _refundOut(address(zt), refund),
            address(0),
            0,
            ""
        );
        assertEq(zt.balanceOf(refund), 0);
    }

    // ---- domain ----

    function test_revert_signature_under_domain_1() external {
        (address signer, uint256 key) = makeAddrAndKey("domainSigner");
        AllowanceSpend[] memory a = _spend(address(token), DEPOSIT, DEPOSIT);
        token.mint(signer, DEPOSIT);
        vm.prank(signer);
        token.approve(address(v11), type(uint256).max);
        bytes32 structHash = thh.v11(a, _noOut(), executor, 1, address(0), 0);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, _digest(_domainSep("1", address(v11)), structHash));
        vm.prank(executor);
        vm.expectRevert(CATValidator.BadSignature.selector);
        v11.entry(address(probe), "", signer, 1, a, _noOut(), address(0), 0, abi.encodePacked(r, s, v));

        (v, r, s) = vm.sign(key, _digest(_domainSep("1.1", address(v11)), structHash));
        vm.prank(executor);
        v11.entry(address(probe), "", signer, 1, a, _noOut(), address(0), 0, abi.encodePacked(r, s, v));
        assertEq(token.balanceOf(address(probe)), DEPOSIT);
    }

    function test_domain_separator_recomputes_on_a_fork() external {
        bytes32 before = v11.DOMAIN_SEPARATOR();
        vm.chainId(999);
        assertEq(v11.DOMAIN_SEPARATOR(), _domainSep("1.1", address(v11)));
        assertTrue(v11.DOMAIN_SEPARATOR() != before);
        (,,, uint256 chainId,,,) = v11.eip712Domain();
        assertEq(chainId, 999);

        (address signer, uint256 key) = makeAddrAndKey("forkSigner");
        AllowanceSpend[] memory a = _spend(address(token), DEPOSIT, DEPOSIT);
        token.mint(signer, DEPOSIT);
        vm.prank(signer);
        token.approve(address(v11), type(uint256).max);
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(key, _digest(_domainSep("1.1", address(v11)), thh.v11(a, _noOut(), executor, 1, address(0), 0)));
        vm.prank(executor);
        v11.entry(address(probe), "", signer, 1, a, _noOut(), address(0), 0, abi.encodePacked(r, s, v));
    }

    // ---- gas ----

    uint256 constant BASE_GAS_DELTA = 2005;

    function test_gas_entry_delta_base_to_v1_1() external {
        MockERC20 tBase = new MockERC20("H", "H", 6);
        MockERC20 t11 = new MockERC20("B", "B", 6);
        tBase.mint(address(this), DEPOSIT);
        tBase.approve(address(base), type(uint256).max);
        t11.mint(address(this), DEPOSIT);
        t11.approve(address(v11), type(uint256).max);
        AllowanceSpend[] memory aBase = _spend(address(tBase), DEPOSIT, DEPOSIT);
        AllowanceSpend[] memory a11 = _spend(address(t11), DEPOSIT, DEPOSIT);
        Outcome[] memory o = _noOut();
        GasMeter meter = new GasMeter();

        uint256 gasBase = meter.measure(
            address(base), abi.encodeCall(CATValidator.entry, (address(probe), "", address(this), 1, aBase, o, ""))
        );
        bytes memory cdV11 = abi.encodeCall(
            ICATValidatorV1_1.entry, (address(probe), "", address(this), 1, a11, o, address(0), bytes32(0), "")
        );
        uint256 gasV11 = meter.measure(address(v11), cdV11);

        emit log_named_uint("base entry gas", gasBase);
        emit log_named_uint("v1.1 entry gas", gasV11);
        emit log_named_uint("v1.1 - base delta", gasV11 - gasBase);
        assertLe(
            gasV11 - gasBase, BASE_GAS_DELTA * 110 / 100, "delta within 10% of the measured v1.1 - base frame delta"
        );
        assertLt(gasV11, 100_000, "loose absolute ceiling");

        bytes memory cdBase = abi.encodeCall(CATValidator.entry, (address(probe), "", address(this), 1, a11, o, ""));
        emit log_named_uint("base calldata bytes", cdBase.length);
        emit log_named_uint("v1.1 calldata bytes", cdV11.length);
        emit log_named_uint("v1.1 - base calldata gas", _calldataGas(cdV11) - _calldataGas(cdBase));
        assertEq(cdBase.length, 452);
        assertEq(cdV11.length, 516);
        assertEq(_calldataGas(cdV11) - _calldataGas(cdBase), 280);
    }

    uint256 constant SUBCLASS_GAS_MARGIN = 500;

    function test_gas_entry_delta_standalone_to_subclass() external {
        MockERC20 tStandalone = new MockERC20("A", "A", 6);
        MockERC20 tSubclass = new MockERC20("B", "B", 6);
        tStandalone.mint(address(this), DEPOSIT);
        tStandalone.approve(address(v11Standalone), type(uint256).max);
        tSubclass.mint(address(this), DEPOSIT);
        tSubclass.approve(address(v11), type(uint256).max);
        GasMeter meter = new GasMeter();

        uint256 gasStandalone = meter.measure(
            address(v11Standalone),
            _entryCall(address(probe), "", address(this), 1, _spend(address(tStandalone), DEPOSIT, DEPOSIT))
        );
        uint256 gasSubclass = meter.measure(
            address(v11), _entryCall(address(probe), "", address(this), 1, _spend(address(tSubclass), DEPOSIT, DEPOSIT))
        );

        emit log_named_uint("standalone v1.1 entry gas", gasStandalone);
        emit log_named_uint("subclass v1.1 entry gas", gasSubclass);
        assertLe(gasSubclass, gasStandalone + SUBCLASS_GAS_MARGIN, "subclass within margin of the standalone");
    }

    /// forge-config: default.isolate = true
    function test_gas_snapshot_entry_one_allowance_standalone() external {
        _fund(address(v11Standalone));
        vm.prank(executor);
        v11Standalone.entry(
            address(probe), "", address(this), 1, _spend(address(token), DEPOSIT, DEPOSIT), _noOut(), address(0), 0, ""
        );
        vm.snapshotGasLastCall("entryOneAllowanceStandalone");
    }

    /// forge-config: default.isolate = true
    function test_gas_snapshot_refund_sweep_standalone() external {
        _fund(address(v11Standalone));
        address refund = makeAddr("refund");
        vm.prank(executor);
        v11Standalone.entry(
            refund,
            "",
            address(this),
            0,
            _spend(address(token), type(uint256).max, SPEND_MAGIC),
            _refundOut(address(token), refund),
            refund,
            keccak256(""),
            ""
        );
        vm.snapshotGasLastCall("entryRefundSweepStandalone");
    }

    /// forge-config: default.isolate = true
    function test_gas_snapshot_entry_one_allowance() external {
        _fund(address(v11));
        vm.prank(executor);
        v11.entry(
            address(probe), "", address(this), 1, _spend(address(token), DEPOSIT, DEPOSIT), _noOut(), address(0), 0, ""
        );
        vm.snapshotGasLastCall("entryOneAllowance");
    }

    /// forge-config: default.isolate = true
    function test_gas_snapshot_refund_sweep() external {
        _fund(address(v11));
        address refund = makeAddr("refund");
        vm.prank(executor);
        v11.entry(
            refund,
            "",
            address(this),
            0,
            _spend(address(token), type(uint256).max, SPEND_MAGIC),
            _refundOut(address(token), refund),
            refund,
            keccak256(""),
            ""
        );
        vm.snapshotGasLastCall("entryRefundSweep");
    }
}
