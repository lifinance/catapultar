// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { Test } from "forge-std/src/Test.sol";
import { EfficientHashLib } from "solady/src/utils/EfficientHashLib.sol";
import { LibClone } from "solady/src/utils/LibClone.sol";
import { SafeTransferLib } from "solady/src/utils/SafeTransferLib.sol";
import { MockERC20 } from "solady/test/utils/mocks/MockERC20.sol";

import { CATValidator } from "../../src/CATValidator.sol";
import { CATValidatorV1_1 } from "../../src/CATValidatorV1_1.sol";
import { Catapultar } from "../../src/Catapultar.sol";
import { CatapultarFactory } from "../../src/CatapultarFactory.sol";
import { KeyedOwnable } from "../../src/libs/KeyedOwnable.sol";
import { AllowanceSpend, Outcome } from "../../src/libs/LibExecutionConstraint.sol";
import { LibExecutionConstraintV1_1 } from "../../src/libs/LibExecutionConstraintV1_1.sol";
import { Deliverer, ZeroRejectingERC20 } from "../CATValidatorV1_1.t.sol";

/**
 * @notice C2 sca-parity for CATValidatorV1_1 (NCBF PRD §4.2), schema `c2-sca-parity-v1_1/v1`.
 *
 * `sca-parity.v1_1.vectors.json` pins pure-math vectors with every address input explicit (EIP-712 domain fields,
 * factory, executor implementation, all synthetic), so the TS mirrors (the catapultar SDK and catapultar-utils)
 * reproduce constraint → execute and refund digests → saltWithDigest → escrow address with no environment
 * dependency. The regeneration mode (`VC_REGEN_SCA_FIXTURE=true`) writes the fixture from the code under test; the
 * default mode reads the committed fixture and proves the pinned numbers are reproducible.
 *
 * Live-instance tests prove the pinned formulas match a deployed CATValidatorV1_1 domain separator and the
 * factory's predictDeployWithDigest, and replay the nonce-0 refund sweep on escrows derived from the fixture.
 */
contract ScaParityTest is Test {
    /// @dev Synthetic pinned inputs, mirrored in the fixture. Clearly
    /// non-production values: the C2 vectors are pure math, valid for any
    /// deployment environment that supplies its own real addresses.
    address internal constant PIN_EXECUTOR_IMPL = address(uint160(0xCA7A0001));
    address internal constant PIN_EXECUTOR = address(uint160(0xCA7A0003));
    address internal constant PIN_OWNER = address(uint160(0xCA7A00AA));
    address internal constant PIN_FACTORY = address(uint160(0xFAC70127));
    uint256 internal constant PIN_CHAIN_ID = 1;
    /// @dev Owner in the first 20 bytes; `_factorySalt` takes the owner key from there.
    bytes32 internal constant PIN_SALT = bytes32((uint256(uint160(PIN_OWNER)) << 96) | 1);

    address internal constant DELIVERY = 0x1111111111111111111111111111111111111111;

    string internal constant SCA_PARITY_V1_1_VECTORS = "test/vc/fixtures/sca-parity/sca-parity.v1_1.vectors.json";
    address internal constant PIN_VERIFYING_CONTRACT_V1_1 = address(uint160(0xCA7A0011));
    address internal constant PIN_REFUND = address(uint160(0xCA7A00BB));
    address internal constant PIN_LEDGER = address(uint160(0xCA7A0004));
    address internal constant PIN_COMMIT = address(uint160(uint256(keccak256("vc/sca-parity/v1_1/commit"))));
    uint256 internal constant PIN_RANDOM_NONCE = uint256(keccak256("vc/sca-parity/v1_1/nonce"));
    uint256 internal constant SPEND_BALANCE_OF_MAGIC = 1 << 255;

    /// @dev Ethereum mainnet tokens the fixture constraints carry (pure data; nothing is deployed).
    address internal constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address internal constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;

    bytes32 internal constant EIP712_DOMAIN_TYPE_HASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    /// @dev The signed fields of a v1.1 `ExecutionConstraint` except `executor`, which the fixture shares.
    struct ConstraintV1_1 {
        uint256 nonce;
        address executionTarget;
        bytes32 payloadHash;
        AllowanceSpend[] allowances;
        Outcome[] outcomes;
    }

    struct FixtureEscrow {
        CATValidatorV1_1 validator;
        address payable escrow;
        address executor;
        ConstraintV1_1 execute;
        ConstraintV1_1 refund;
    }

    /* ─────────────────────────── fixture parity
    ─────────────────────────── */

    function test_fixtureParityV1_1() external {
        if (vm.envOr("VC_REGEN_SCA_FIXTURE", false)) _regenerateFixtureV1_1();

        string memory json = vm.readFile(SCA_PARITY_V1_1_VECTORS);
        assertEq(vm.parseJsonString(json, ".schema"), "c2-sca-parity-v1_1/v1", "schema mismatch");
        assertEq(vm.parseJsonString(json, ".domain.version"), "1.1", "domain version");
        assertNotEq(
            vm.parseJsonAddress(json, ".refundAddress"),
            address(0),
            "zero refund address collides with the execute sentinel"
        );

        uint256 count = jsonArrayLength(json, ".vectors");
        assertGt(count, 0, "fixture has no vectors");
        address[] memory escrows = new address[](count);
        for (uint256 i; i < count; ++i) {
            escrows[i] = _assertVectorV1_1(json, string.concat(".vectors[", vm.toString(i), "]"));
        }
        for (uint256 i; i < count; ++i) {
            for (uint256 j = i + 1; j < count; ++j) {
                assertNotEq(escrows[i], escrows[j], "distinct shapes must pin distinct escrows");
            }
        }
    }

    /// @dev `CatapultarFactory._salt` for the fixture's single ECDSA owner, the address in the first 20 bytes of
    /// `salt`.
    function _factorySalt(
        bytes32 salt
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                salt,
                uint8(KeyedOwnable.PublicKeyType.ECDSAOrSmartContract),
                uint8(1),
                bytes32(uint256(uint160(bytes20(salt))))
            )
        );
    }

    /// @dev Recomputes one v1.1 vector from its inputs and checks the §4.2 execute and refund fields.
    function _assertVectorV1_1(
        string memory json,
        string memory p
    ) internal view returns (address escrow) {
        string memory name = vm.parseJsonString(json, string.concat(p, ".name"));
        address executor = vm.parseJsonAddress(json, ".executor");
        ConstraintV1_1 memory execute = _parseConstraintV1_1(json, string.concat(p, ".execute"));
        ConstraintV1_1 memory refund = _parseConstraintV1_1(json, string.concat(p, ".refund"));

        assertNotEq(execute.nonce, 0, string.concat(name, ": execute nonce must be spendable"));
        assertEq(execute.executionTarget, address(0), string.concat(name, ": execute target sentinel"));
        assertEq(execute.payloadHash, bytes32(0), string.concat(name, ": execute payload sentinel"));
        assertEq(
            abi.encode(refund),
            abi.encode(_refundConstraint(execute.allowances, vm.parseJsonAddress(json, ".refundAddress"))),
            string.concat(name, ": refund constraint")
        );

        bytes32 domainSeparator = _domainSeparator(
            vm.parseJsonString(json, ".domain.name"),
            vm.parseJsonString(json, ".domain.version"),
            vm.parseJsonUint(json, ".domain.chainId"),
            vm.parseJsonAddress(json, ".domain.verifyingContract")
        );
        string memory e = string.concat(p, ".expected");
        bytes32 structHash = _structHashV1_1(execute, executor);
        bytes32 executeDigest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        assertEq(
            structHash,
            vm.parseJsonBytes32(json, string.concat(e, ".executeStructHash")),
            string.concat(name, ": executeStructHash")
        );
        assertEq(
            executeDigest,
            vm.parseJsonBytes32(json, string.concat(e, ".executeDigest")),
            string.concat(name, ": executeDigest")
        );

        structHash = _structHashV1_1(refund, executor);
        bytes32 refundDigest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        assertEq(
            structHash,
            vm.parseJsonBytes32(json, string.concat(e, ".refundStructHash")),
            string.concat(name, ": refundStructHash")
        );
        assertEq(
            refundDigest,
            vm.parseJsonBytes32(json, string.concat(e, ".refundDigest")),
            string.concat(name, ": refundDigest")
        );
        assertNotEq(executeDigest, refundDigest, string.concat(name, ": execute and refund digests collide"));

        bytes32 saltWithDigest = EfficientHashLib.hash(
            _factorySalt(vm.parseJsonBytes32(json, string.concat(p, ".salt"))),
            executeDigest,
            bytes32(_parseFlavorNonce(json, p))
        );
        assertEq(
            saltWithDigest,
            vm.parseJsonBytes32(json, string.concat(e, ".saltWithDigest")),
            string.concat(name, ": saltWithDigest")
        );
        escrow = LibClone.predictDeterministicAddress_PUSH0(
            vm.parseJsonAddress(json, ".clone.executorImpl"),
            saltWithDigest,
            vm.parseJsonAddress(json, ".clone.factory")
        );
        assertEq(escrow, vm.parseJsonAddress(json, string.concat(e, ".escrow")), string.concat(name, ": escrow"));
    }

    /* ─────────────────────────── live instances
    ─────────────────────────── */

    /// @dev The v1.1 fixture's domain name and version, through the pinned formula, on any chain.
    function test_fuzz_liveDomainSeparatorV1_1MatchesPinnedFormula(
        uint256 chainId
    ) external {
        chainId = bound(chainId, 1, type(uint64).max);
        string memory json = vm.readFile(SCA_PARITY_V1_1_VECTORS);
        CATValidatorV1_1 validator = new CATValidatorV1_1();
        vm.chainId(chainId);
        assertEq(
            validator.DOMAIN_SEPARATOR(),
            _domainSeparator(
                vm.parseJsonString(json, ".domain.name"),
                vm.parseJsonString(json, ".domain.version"),
                chainId,
                address(validator)
            )
        );
    }

    /// @dev The fixture's saltWithDigest + PUSH0-clone prediction formula
    /// matches what the factory actually deploys, for both digest flavors.
    function test_livePredictDeployWithDigestMatchesDeployment() external {
        CatapultarFactory factory = new CatapultarFactory();
        address owner = makeAddr("owner");
        bytes32[] memory keys = new bytes32[](1);
        keys[0] = bytes32(uint256(uint160(owner)));
        bytes32 salt = bytes32(bytes20(uint160(owner)));
        bytes32 digest = keccak256("vc/sca-parity/live-digest");

        KeyedOwnable.PublicKeyType ktp = KeyedOwnable.PublicKeyType.ECDSAOrSmartContract;
        address predictedCall = factory.predictDeployWithDigest(ktp, keys, salt, digest, false);
        address deployedCall = factory.deployWithDigest(ktp, keys, salt, digest, false);
        assertEq(predictedCall, deployedCall, "call flavor: prediction != deployment");

        address predictedSig = factory.predictDeployWithDigest(ktp, keys, salt, digest, true);
        address deployedSig = factory.deployWithDigest(ktp, keys, salt, digest, true);
        assertEq(predictedSig, deployedSig, "signature flavor: prediction != deployment");

        assertNotEq(deployedCall, deployedSig, "flavor must be part of the address commitment");
    }

    /* ─────────────────────────── v1.1 refund sweep replay
    ─────────────────────────── */

    /// @dev I13: after execute, nonce 0 sweeps residue and each late deposit to the committed refund address, never
    /// elsewhere, and an empty sweep moves nothing.
    function test_fuzz_refundSweepReplaysToCommittedAddressOnly(
        uint256 residue0,
        uint256 residue1,
        uint256 late0,
        uint256 late1,
        address attacker
    ) external {
        uint256[2] memory residue = [bound(residue0, 0, type(uint128).max), bound(residue1, 0, type(uint128).max)];
        uint256[2] memory late = [bound(late0, 1, type(uint128).max), bound(late1, 0, type(uint128).max)];
        address[] memory tokens = new address[](2);
        tokens[0] = address(new MockERC20("A", "A", 18));
        tokens[1] = address(new MockERC20("B", "B", 6));
        FixtureEscrow memory f = _deployFixtureEscrow("two-allowances", tokens);
        address refund = f.refund.executionTarget;
        address sink = f.execute.outcomes[0].destination;
        vm.assume(attacker != refund);

        for (uint256 i; i < 2; ++i) {
            MockERC20(tokens[i]).mint(f.escrow, f.execute.allowances[i].allocated + residue[i]);
        }
        _executeDelivering(f, tokens);
        assertTrue(f.validator.spentNonces(f.escrow, f.execute.nonce));

        vm.expectRevert(CATValidatorV1_1.TargetNotCommitted.selector);
        _sweepTo(f, attacker);

        _sweep(f);
        _assertOnlyRefundHolds(f, tokens, sink, residue);

        for (uint256 i; i < 2; ++i) {
            MockERC20(tokens[i]).mint(f.escrow, late[i]);
            residue[i] += late[i];
        }
        _sweep(f);
        _assertOnlyRefundHolds(f, tokens, sink, residue);

        _sweep(f);
        _assertOnlyRefundHolds(f, tokens, sink, residue);
        assertFalse(f.validator.spentNonces(f.escrow, 0));
    }

    /// @dev The attested shape refunded before any fill, then a late deposit: the replay on an empty escrow reverts
    /// on a token that rejects zero-value transfers, because the sweep transfers even a zero balance.
    function test_fuzz_emptyRefundSweepRevertsOnZeroRejectingToken(
        uint256 deposit,
        uint256 late
    ) external {
        deposit = bound(deposit, 1, type(uint128).max);
        late = bound(late, 1, type(uint128).max);
        ZeroRejectingERC20 token = new ZeroRejectingERC20();
        address[] memory tokens = new address[](1);
        tokens[0] = address(token);
        FixtureEscrow memory f = _deployFixtureEscrow("ledger-outcome", tokens);
        address refund = f.refund.executionTarget;

        token.mint(f.escrow, deposit);
        _sweep(f);
        assertEq(token.balanceOf(refund), deposit);

        token.mint(f.escrow, late);
        _sweep(f);
        assertEq(token.balanceOf(refund), deposit + late);
        assertEq(token.balanceOf(f.escrow), 0);
        assertFalse(f.validator.spentNonces(f.escrow, f.execute.nonce));

        vm.expectRevert(SafeTransferLib.TransferFromFailed.selector);
        _sweep(f);
    }

    /// @dev Before any transfer, the refund signature covers neither the sentinels, a payload nor another caller.
    function test_fuzz_refundSweepRejectsSubstitutionsBeforeAnyTransfer(
        uint256 deposit0,
        uint256 deposit1,
        address attacker,
        bytes calldata payload
    ) external {
        vm.assume(payload.length != 0);
        uint256[2] memory deposit = [bound(deposit0, 1, type(uint128).max), bound(deposit1, 1, type(uint128).max)];
        address[] memory tokens = new address[](2);
        tokens[0] = address(new MockERC20("A", "A", 18));
        tokens[1] = address(new MockERC20("B", "B", 6));
        FixtureEscrow memory f = _deployFixtureEscrow("two-allowances", tokens);
        address refund = f.refund.executionTarget;
        vm.assume(attacker != f.executor);
        for (uint256 i; i < 2; ++i) {
            MockERC20(tokens[i]).mint(f.escrow, deposit[i]);
        }

        vm.expectRevert(CATValidatorV1_1.ZeroDestination.selector);
        _refundEntry(f, f.executor, attacker, payload, address(0), 0);
        _assertEscrowHoldsAll(f, tokens, deposit);

        vm.expectRevert(CATValidatorV1_1.PayloadNotCommitted.selector);
        _refundEntry(f, f.executor, refund, payload, refund, f.refund.payloadHash);
        _assertEscrowHoldsAll(f, tokens, deposit);

        vm.expectRevert(CATValidator.BadSignature.selector);
        _refundEntry(f, attacker, refund, "", refund, f.refund.payloadHash);
        _assertEscrowHoldsAll(f, tokens, deposit);
    }

    /// forge-config: default.isolate = true
    function test_gas_snapshot_escrow_refund_sweep() external {
        address[] memory tokens = new address[](2);
        tokens[0] = address(new MockERC20("A", "A", 18));
        tokens[1] = address(new MockERC20("B", "B", 6));
        FixtureEscrow memory f = _deployFixtureEscrow("two-allowances", tokens);
        for (uint256 i; i < 2; ++i) {
            MockERC20(tokens[i]).mint(f.escrow, f.execute.allowances[i].allocated);
        }
        _sweep(f);
        vm.snapshotGasLastCall("escrowRefundSweep");
        for (uint256 i; i < 2; ++i) {
            assertEq(MockERC20(tokens[i]).balanceOf(f.refund.executionTarget), f.execute.allowances[i].allocated);
        }
    }

    /// @dev Deploys CATValidatorV1_1 and the escrow of fixture vector `name` with its allowance tokens replaced, in
    /// order, by `tokens`. Digests and address come from the pinned formulas; the escrow approves the validator and
    /// holds both digests as a minted bundle does.
    function _deployFixtureEscrow(
        string memory name,
        address[] memory tokens
    ) internal returns (FixtureEscrow memory f) {
        string memory json = vm.readFile(SCA_PARITY_V1_1_VECTORS);
        string memory p = _vectorPath(json, name);
        f.executor = vm.parseJsonAddress(json, ".executor");
        f.execute = _parseConstraintV1_1(json, string.concat(p, ".execute"));
        f.refund = _parseConstraintV1_1(json, string.concat(p, ".refund"));
        assertEq(f.execute.allowances.length, tokens.length, "one token per allowance");
        for (uint256 i; i < tokens.length; ++i) {
            address from = f.execute.allowances[i].token;
            _replaceToken(f.execute, from, tokens[i]);
            _replaceToken(f.refund, from, tokens[i]);
        }

        f.validator = new CATValidatorV1_1();
        CatapultarFactory factory = new CatapultarFactory();
        bytes32 domainSeparator = _domainSeparator(
            vm.parseJsonString(json, ".domain.name"),
            vm.parseJsonString(json, ".domain.version"),
            block.chainid,
            address(f.validator)
        );
        bytes32 executeDigest =
            keccak256(abi.encodePacked("\x19\x01", domainSeparator, _structHashV1_1(f.execute, f.executor)));
        bytes32 refundDigest =
            keccak256(abi.encodePacked("\x19\x01", domainSeparator, _structHashV1_1(f.refund, f.executor)));

        bytes32 salt = vm.parseJsonBytes32(json, string.concat(p, ".salt"));
        uint256 flavorNonce = _parseFlavorNonce(json, p);
        // forge-lint: disable-next-line(unsafe-typecast)
        address owner = address(bytes20(salt));
        bytes32[] memory keys = new bytes32[](1);
        keys[0] = bytes32(uint256(uint160(owner)));
        f.escrow = factory.deployWithDigest(
            KeyedOwnable.PublicKeyType.ECDSAOrSmartContract, keys, salt, executeDigest, flavorNonce == 2
        );
        assertEq(
            f.escrow,
            LibClone.predictDeterministicAddress_PUSH0(
                factory.EXECUTOR(),
                EfficientHashLib.hash(_factorySalt(salt), executeDigest, bytes32(flavorNonce)),
                address(factory)
            ),
            "pinned escrow formula != deployment"
        );

        vm.prank(owner);
        Catapultar(f.escrow).setSignature(refundDigest, Catapultar.DigestApproval.Signature);
        for (uint256 i; i < tokens.length; ++i) {
            vm.prank(f.escrow);
            MockERC20(tokens[i]).approve(address(f.validator), type(uint256).max);
            f.execute.allowances[i].spend = f.execute.allowances[i].allocated;
            f.refund.allowances[i].spend = SPEND_BALANCE_OF_MAGIC;
        }
    }

    /// @dev The execute entry with a target that delivers every pulled token to the validator, which forwards it to the
    /// outcome destination.
    function _executeDelivering(
        FixtureEscrow memory f,
        address[] memory tokens
    ) internal {
        uint256[] memory amounts = new uint256[](tokens.length);
        for (uint256 i; i < tokens.length; ++i) {
            amounts[i] = f.execute.allowances[i].allocated;
        }
        Deliverer deliverer = new Deliverer();
        bytes memory deliver = abi.encodeCall(Deliverer.deliverMany, (tokens, address(f.validator), amounts));
        vm.prank(f.executor);
        f.validator
            .entry(
                address(deliverer),
                deliver,
                f.escrow,
                f.execute.nonce,
                f.execute.allowances,
                f.execute.outcomes,
                address(0),
                0,
                ""
            );
    }

    function _sweep(
        FixtureEscrow memory f
    ) internal {
        _sweepTo(f, f.refund.executionTarget);
    }

    function _sweepTo(
        FixtureEscrow memory f,
        address execTarget
    ) internal {
        _refundEntry(f, f.executor, execTarget, "", f.refund.executionTarget, f.refund.payloadHash);
    }

    function _refundEntry(
        FixtureEscrow memory f,
        address caller,
        address execTarget,
        bytes memory execPayload,
        address executionTarget,
        bytes32 payloadHash
    ) internal {
        vm.prank(caller);
        f.validator
            .entry(
                execTarget,
                execPayload,
                f.escrow,
                f.refund.nonce,
                f.refund.allowances,
                f.refund.outcomes,
                executionTarget,
                payloadHash,
                ""
            );
    }

    function _assertEscrowHoldsAll(
        FixtureEscrow memory f,
        address[] memory tokens,
        uint256[2] memory deposit
    ) internal view {
        assertEq(tokens.length, 2, "two-token helper");
        for (uint256 i; i < tokens.length; ++i) {
            assertEq(MockERC20(tokens[i]).balanceOf(f.escrow), deposit[i], "escrow");
            assertEq(MockERC20(tokens[i]).totalSupply(), deposit[i], "held elsewhere");
        }
    }

    /// @dev `sink` keeps what execute delivered; the refund address holds everything else ever minted.
    function _assertOnlyRefundHolds(
        FixtureEscrow memory f,
        address[] memory tokens,
        address sink,
        uint256[2] memory refunded
    ) internal view {
        assertEq(tokens.length, 2, "two-token helper");
        for (uint256 i; i < tokens.length; ++i) {
            MockERC20 token = MockERC20(tokens[i]);
            assertEq(token.balanceOf(f.refund.executionTarget), refunded[i], "refund address");
            assertEq(token.balanceOf(sink), f.execute.allowances[i].allocated, "execute delivery");
            assertEq(token.totalSupply(), refunded[i] + f.execute.allowances[i].allocated, "held elsewhere");
        }
    }

    function _regenerateFixtureV1_1() internal {
        bytes32 domainSeparator = _domainSeparator("CAT Validator", "1.1", PIN_CHAIN_ID, PIN_VERIFYING_CONTRACT_V1_1);

        AllowanceSpend[] memory usdc = new AllowanceSpend[](1);
        usdc[0] = AllowanceSpend({ token: USDC, allocated: 1000e6, spend: 0 });
        AllowanceSpend[] memory two = new AllowanceSpend[](2);
        two[0] = AllowanceSpend({ token: WETH, allocated: 2 ether, spend: 0 });
        two[1] = AllowanceSpend({ token: USDC, allocated: 1000e6, spend: 0 });
        Outcome[] memory ledger = new Outcome[](1);
        ledger[0] = Outcome({ token: PIN_LEDGER, amount: 1, destination: PIN_COMMIT });
        (, Outcome[] memory uc1) = _sharedConstraintParts();

        string[3] memory names = ["empty-outcomes", "ledger-outcome", "two-allowances"];
        ConstraintV1_1[3] memory executes = [
            ConstraintV1_1(1, address(0), 0, usdc, new Outcome[](0)),
            ConstraintV1_1(PIN_RANDOM_NONCE, address(0), 0, usdc, ledger),
            ConstraintV1_1(1, address(0), 0, two, uc1)
        ];
        uint256[3] memory flavorNonces = [uint256(1), 2, 2];

        string memory vectorsJson = "";
        for (uint256 i; i < names.length; ++i) {
            ConstraintV1_1 memory refund = _refundConstraint(executes[i].allowances, PIN_REFUND);
            bytes32 executeStructHash = _structHashV1_1(executes[i], PIN_EXECUTOR);
            bytes32 executeDigest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, executeStructHash));
            bytes32 refundStructHash = _structHashV1_1(refund, PIN_EXECUTOR);
            bytes32 saltWithDigest =
                EfficientHashLib.hash(_factorySalt(PIN_SALT), executeDigest, bytes32(flavorNonces[i]));

            vectorsJson = string.concat(
                vectorsJson,
                i == 0 ? "" : ",",
                "\n    {\n      \"name\": \"",
                names[i],
                "\",\n      \"saltFlavor\": \"",
                flavorNonces[i] == 2 ? "signature" : "call",
                "\",\n      \"flavorNonce\": ",
                vm.toString(flavorNonces[i]),
                ",\n      \"salt\": \"",
                vm.toString(PIN_SALT),
                "\",\n      \"execute\": ",
                _constraintJson(executes[i]),
                ",\n      \"refund\": ",
                _constraintJson(refund),
                ",\n      \"expected\": {\n        \"executeStructHash\": \"",
                vm.toString(executeStructHash),
                "\",\n        \"executeDigest\": \"",
                vm.toString(executeDigest)
            );
            vectorsJson = string.concat(
                vectorsJson,
                "\",\n        \"refundStructHash\": \"",
                vm.toString(refundStructHash),
                "\",\n        \"refundDigest\": \"",
                vm.toString(keccak256(abi.encodePacked("\x19\x01", domainSeparator, refundStructHash))),
                "\",\n        \"saltWithDigest\": \"",
                vm.toString(saltWithDigest),
                "\",\n        \"escrow\": \"",
                vm.toString(LibClone.predictDeterministicAddress_PUSH0(PIN_EXECUTOR_IMPL, saltWithDigest, PIN_FACTORY)),
                "\"\n      }\n    }"
            );
        }

        string memory json = string.concat(
            "{\n  \"schema\": \"c2-sca-parity-v1_1/v1\",",
            "\n  \"domain\": {\n    \"name\": \"CAT Validator\",\n    \"version\": \"1.1\",\n    \"chainId\": ",
            vm.toString(PIN_CHAIN_ID),
            ",\n    \"verifyingContract\": \"",
            vm.toString(PIN_VERIFYING_CONTRACT_V1_1),
            "\"\n  },\n  \"clone\": {\n    \"factory\": \"",
            vm.toString(PIN_FACTORY),
            "\",\n    \"executorImpl\": \"",
            vm.toString(PIN_EXECUTOR_IMPL),
            "\"\n  },\n  \"executor\": \"",
            vm.toString(PIN_EXECUTOR),
            "\",\n  \"refundAddress\": \"",
            vm.toString(PIN_REFUND),
            "\",\n  \"vectors\": [",
            vectorsJson,
            "\n  ]\n}\n"
        );

        vm.writeFile(SCA_PARITY_V1_1_VECTORS, json);
    }

    function _constraintJson(
        ConstraintV1_1 memory c
    ) internal pure returns (string memory json) {
        json = string.concat(
            "{\n        \"nonce\": \"",
            vm.toString(c.nonce),
            "\",\n        \"executionTarget\": \"",
            vm.toString(c.executionTarget),
            "\",\n        \"payloadHash\": \"",
            vm.toString(c.payloadHash),
            "\",\n        \"allowances\": ["
        );
        for (uint256 i; i < c.allowances.length; ++i) {
            json = string.concat(
                json,
                i == 0 ? "" : ",",
                "\n          { \"token\": \"",
                vm.toString(c.allowances[i].token),
                "\", \"amount\": \"",
                vm.toString(c.allowances[i].allocated),
                "\" }"
            );
        }
        json = string.concat(json, "\n        ],\n        \"outcomes\": [");
        for (uint256 i; i < c.outcomes.length; ++i) {
            json = string.concat(
                json,
                i == 0 ? "" : ",",
                "\n          { \"token\": \"",
                vm.toString(c.outcomes[i].token),
                "\", \"amount\": \"",
                vm.toString(c.outcomes[i].amount),
                "\", \"destination\": \"",
                vm.toString(c.outcomes[i].destination),
                "\" }"
            );
        }
        json = string.concat(json, c.outcomes.length == 0 ? "]" : "\n        ]", "\n      }");
    }

    /* ─────────────────────────── shared pieces
    ──────────────────────────── */

    /// @dev The uc1-shaped constraint parts the `two-allowances` vector reuses: one WETH allowance, WETH + USDC
    /// minimum deliveries to the delivery address.
    function _sharedConstraintParts()
        internal
        pure
        returns (AllowanceSpend[] memory allowances, Outcome[] memory outcomes)
    {
        allowances = new AllowanceSpend[](1);
        // `spend` is settlement-time input, not part of the EIP-712 hash.
        allowances[0] = AllowanceSpend({ token: WETH, allocated: 2 ether, spend: 0 });
        outcomes = new Outcome[](2);
        outcomes[0] = Outcome({ token: WETH, amount: 1 ether, destination: DELIVERY });
        outcomes[1] = Outcome({ token: USDC, amount: 1000e6, destination: DELIVERY });
    }

    function _parseAllowances(
        string memory json,
        string memory path
    ) internal view returns (AllowanceSpend[] memory allowances) {
        allowances = new AllowanceSpend[](jsonArrayLength(json, path));
        for (uint256 i; i < allowances.length; ++i) {
            string memory p = string.concat(path, "[", vm.toString(i), "]");
            allowances[i] = AllowanceSpend({
                token: vm.parseJsonAddress(json, string.concat(p, ".token")),
                allocated: vm.parseJsonUint(json, string.concat(p, ".amount")),
                spend: 0
            });
        }
    }

    function _parseOutcomes(
        string memory json,
        string memory path
    ) internal view returns (Outcome[] memory outcomes) {
        outcomes = new Outcome[](jsonArrayLength(json, path));
        for (uint256 i; i < outcomes.length; ++i) {
            string memory p = string.concat(path, "[", vm.toString(i), "]");
            outcomes[i] = Outcome({
                token: vm.parseJsonAddress(json, string.concat(p, ".token")),
                amount: vm.parseJsonUint(json, string.concat(p, ".amount")),
                destination: vm.parseJsonAddress(json, string.concat(p, ".destination"))
            });
        }
    }

    function _parseConstraintV1_1(
        string memory json,
        string memory path
    ) internal view returns (ConstraintV1_1 memory c) {
        c.nonce = vm.parseJsonUint(json, string.concat(path, ".nonce"));
        c.executionTarget = vm.parseJsonAddress(json, string.concat(path, ".executionTarget"));
        c.payloadHash = vm.parseJsonBytes32(json, string.concat(path, ".payloadHash"));
        c.allowances = _parseAllowances(json, string.concat(path, ".allowances"));
        c.outcomes = _parseOutcomes(json, string.concat(path, ".outcomes"));
    }

    /// @dev Reads `flavorNonce` and checks it against `saltFlavor` (1 = call, 2 = signature).
    function _parseFlavorNonce(
        string memory json,
        string memory vectorPath
    ) internal view returns (uint256 flavorNonce) {
        flavorNonce = vm.parseJsonUint(json, string.concat(vectorPath, ".flavorNonce"));
        string memory flavor = vm.parseJsonString(json, string.concat(vectorPath, ".saltFlavor"));
        assertEq(
            flavorNonce,
            keccak256(bytes(flavor)) == keccak256("signature") ? 2 : 1,
            string.concat(
                vm.parseJsonString(json, string.concat(vectorPath, ".name")), ": flavorNonce/saltFlavor mismatch"
            )
        );
    }

    function _vectorPath(
        string memory json,
        string memory name
    ) internal view returns (string memory p) {
        uint256 count = jsonArrayLength(json, ".vectors");
        for (uint256 i; i < count; ++i) {
            p = string.concat(".vectors[", vm.toString(i), "]");
            if (keccak256(bytes(vm.parseJsonString(json, string.concat(p, ".name")))) == keccak256(bytes(name))) {
                return p;
            }
        }
        revert(string.concat("no fixture vector ", name));
    }

    function _replaceToken(
        ConstraintV1_1 memory c,
        address from,
        address to
    ) internal pure {
        for (uint256 i; i < c.allowances.length; ++i) {
            if (c.allowances[i].token == from) c.allowances[i].token = to;
        }
        for (uint256 i; i < c.outcomes.length; ++i) {
            if (c.outcomes[i].token == from) c.outcomes[i].token = to;
        }
    }

    /// @dev PRD §4.2 refund digest: nonce 0, `executionTarget = refund`, `payloadHash = keccak256("")`, and per
    /// allowance token a `type(uint256).max` allowance with a zero-floor outcome to `refund`.
    function _refundConstraint(
        AllowanceSpend[] memory allowances,
        address refund
    ) internal pure returns (ConstraintV1_1 memory c) {
        c.executionTarget = refund;
        c.payloadHash = keccak256("");
        c.allowances = new AllowanceSpend[](allowances.length);
        c.outcomes = new Outcome[](allowances.length);
        for (uint256 i; i < allowances.length; ++i) {
            c.allowances[i] = AllowanceSpend({ token: allowances[i].token, allocated: type(uint256).max, spend: 0 });
            c.outcomes[i] = Outcome({ token: allowances[i].token, amount: 0, destination: refund });
        }
    }

    function _structHashV1_1(
        ConstraintV1_1 memory c,
        address executor
    ) internal view returns (bytes32) {
        return this.exposedTypehashV1_1(c.allowances, c.outcomes, executor, c.nonce, c.executionTarget, c.payloadHash);
    }

    /// @dev Calldata trampoline for the library's calldata-typed arguments.
    function exposedTypehashV1_1(
        AllowanceSpend[] calldata allowances,
        Outcome[] calldata outcomes,
        address executor,
        uint256 nonce,
        address executionTarget,
        bytes32 payloadHash
    ) external pure returns (bytes32) {
        return LibExecutionConstraintV1_1.typehash(allowances, outcomes, executor, nonce, executionTarget, payloadHash);
    }

    /// @notice Length of a JSON array at `arrayPath` (stdJson has no direct array-length read for arrays of objects).
    function jsonArrayLength(
        string memory json,
        string memory arrayPath
    ) internal view returns (uint256 count) {
        while (vm.keyExistsJson(json, string.concat(arrayPath, "[", vm.toString(count), "]"))) ++count;
    }

    /// @dev The exact EIP-712 domain-hash formula the fixture pins (solady
    /// EIP712 default field set: name, version, chainId, verifyingContract).
    function _domainSeparator(
        string memory name,
        string memory version,
        uint256 chainId,
        address verifyingContract
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPE_HASH, keccak256(bytes(name)), keccak256(bytes(version)), chainId, verifyingContract
            )
        );
    }
}
