// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { Test } from "forge-std/src/Test.sol";

import { AllowanceSpend, Outcome } from "../../src/libs/LibExecutionConstraint.sol";
import { LibExecutionConstraintV2 } from "../../src/libs/LibExecutionConstraintV2.sol";

/**
 * @title Verified-continuations test base
 * @notice Shared plumbing for the CATValidatorV2 test suites (test/vc/*):
 * canonical platform addresses, access to the fixtures in test/vc/fixtures/,
 * and the Ethereum-mainnet fork helper.
 *
 * Fixtures are the source of truth: if a test and a fixture disagree, the
 * fixture wins.
 */
abstract contract VcTestBase is Test {
    /// @dev Canonical deterministic deployments, identical on all supported chains
    /// (see `DEPLOYMENTS.md` in the VirtualMachine sources).
    address internal constant VM_ADDR = 0xb57Ce43Be47DF611C98EB0943e5D36EBDb36cc6D;
    address internal constant INVARIANT_CHECKER = 0xe17006F4DfE8Aa2bf80589E497ad98D470f66fef;
    address internal constant ARITHMETIC_PROCESSOR = 0x25407266A1229c83d03ececfff8eD7d92754b285;

    /// @dev Ethereum mainnet tokens baked into the uc1 hash-parity fixture programs.
    address internal constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address internal constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;

    /// @dev runVM((uint8,bytes32)[],(bytes[])) — pinned; asserted against the
    /// fixture calldata prefix in HashParity.t.sol.
    bytes4 internal constant RUN_VM_SELECTOR = 0x00a32e6c;

    string internal constant HASH_PARITY_VECTORS = "hash-parity/vectors.json";

    /// @notice Root of the fixtures, relative to the Foundry project root.
    function fixturesDir() internal pure returns (string memory) {
        return "test/vc/fixtures/";
    }

    function readFixture(
        string memory relPath
    ) internal view returns (string memory json) {
        return vm.readFile(string.concat(fixturesDir(), relPath));
    }

    /// @notice Length of a JSON array at `arrayPath` (stdJson has no direct
    /// array-length read for arrays of objects).
    function jsonArrayLength(
        string memory json,
        string memory arrayPath
    ) internal view returns (uint256 count) {
        while (vm.keyExistsJson(json, string.concat(arrayPath, "[", vm.toString(count), "]"))) ++count;
    }

    /// @notice True when a mainnet RPC is configured; fork tests skip otherwise.
    function hasForkRpc() internal view returns (bool) {
        return bytes(vm.envOr("VC_MAINNET_RPC_URL", string(""))).length != 0;
    }

    /// @notice Fork Ethereum mainnet and sanity-check the canonical VM exists there,
    /// so a wrong RPC fails loudly instead of producing confusing empty-code reverts.
    function forkMainnet() internal {
        vm.createSelectFork("mainnet");
        require(VM_ADDR.code.length != 0, "VcTestBase: no VirtualMachine code at canonical address on fork");
    }

    /// @dev Calldata trampoline for the library's calldata-typed arguments.
    function exposedTypehash(
        AllowanceSpend[] calldata allowances,
        Outcome[] calldata outcomes,
        address executor,
        uint256 nonce,
        bytes32 validationProgramHash,
        bytes32 paramsHash
    ) external pure returns (bytes32) {
        return
            LibExecutionConstraintV2.typehash(allowances, outcomes, executor, nonce, validationProgramHash, paramsHash);
    }
}
