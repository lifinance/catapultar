// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { Test } from "forge-std/src/Test.sol";

import { AllowanceSpend, Outcome } from "../../src/libs/LibExecutionConstraint.sol";

/**
 * @title Validation-program test base
 * @notice Shared plumbing for the CATValidatorV2 suites under `test/vc/`: the
 * canonical platform addresses, access to the fixtures in `test/vc/fixtures/`,
 * the Ethereum mainnet fork gate, and an EIP-712 encoding of the V2 constraint
 * written independently of `LibExecutionConstraintV2`.
 *
 * Fixtures are the source of truth: if a test and a fixture disagree, the
 * fixture wins.
 */
abstract contract VcTestBase is Test {
    /// @dev Canonical deterministic deployments, identical on every supported chain
    /// (`DEPLOYMENTS.md` in the VirtualMachine sources).
    address internal constant VM_ADDR = 0xb57Ce43Be47DF611C98EB0943e5D36EBDb36cc6D;
    address internal constant INVARIANT_CHECKER = 0xe17006F4DfE8Aa2bf80589E497ad98D470f66fef;
    address internal constant ARITHMETIC_PROCESSOR = 0x25407266A1229c83d03ececfff8eD7d92754b285;

    /// @dev Ethereum mainnet tokens; the uc1 fixture program bakes both into its body.
    address internal constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address internal constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;

    string internal constant HASH_PARITY_VECTORS = "hash-parity/vectors.json";

    string internal constant FORK_RPC_ENV = "VC_MAINNET_RPC_URL";

    /// @notice Root of the fixtures, relative to the Foundry project root.
    function fixturesDir() internal pure returns (string memory) {
        return "test/vc/fixtures/";
    }

    function readFixture(
        string memory relPath
    ) internal view returns (string memory json) {
        return vm.readFile(string.concat(fixturesDir(), relPath));
    }

    /// @notice Length of the JSON array at `arrayPath` (stdJson has no direct
    /// length read for arrays of objects).
    function jsonArrayLength(
        string memory json,
        string memory arrayPath
    ) internal view returns (uint256 count) {
        while (vm.keyExistsJson(json, string.concat(arrayPath, "[", vm.toString(count), "]"))) ++count;
    }

    /* ─────────────────────────── mainnet fork
    ─────────────────────────── */

    function forkRpcUrl() internal view returns (string memory) {
        return vm.envOr(FORK_RPC_ENV, string(""));
    }

    function hasForkRpc() internal view returns (bool) {
        return bytes(forkRpcUrl()).length != 0;
    }

    /// @notice Forks Ethereum mainnet at the latest block when `VC_MAINNET_RPC_URL`
    /// is set, and checks that the canonical VM is deployed there, so a wrong RPC
    /// fails loudly instead of producing empty-code reverts. A no-op otherwise.
    function forkMainnetIfConfigured() internal {
        if (!hasForkRpc()) return;
        vm.createSelectFork(forkRpcUrl());
        require(block.chainid == 1, "VcTestBase: VC_MAINNET_RPC_URL is not an Ethereum mainnet RPC");
        require(VM_ADDR.code.length != 0, "VcTestBase: no VirtualMachine code at the canonical address");
    }

    /// @notice Skips the test, so CI without the RPC secret stays green.
    modifier onlyFork() {
        if (!hasForkRpc()) {
            vm.skip(true, "VC_MAINNET_RPC_URL unset");
            return;
        }
        _;
    }

    /* ─────────────────────────── V2 constraint digest
    ─────────────────────────── */

    /// @notice The V2 constraint digest under `validator`'s domain, encoded without
    /// `LibExecutionConstraintV2`, so a drift in the library fails the settlement.
    function constraintDigest(
        bytes32 domainSeparator,
        AllowanceSpend[] memory allowances,
        Outcome[] memory outcomes,
        address executor,
        uint256 nonce,
        bytes32 validationProgramHash,
        bytes32 paramsHash
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
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256(
                    bytes(
                        "ExecutionConstraint(Allowance[] allowances,Outcome[] outcomes,address executor,uint256 nonce,bytes32 validationProgramHash,bytes32 paramsHash)Allowance(address token,uint256 amount)Outcome(address token,uint256 amount,address destination)"
                    )
                ),
                keccak256(abi.encodePacked(allowanceHashes)),
                keccak256(abi.encodePacked(outcomeHashes)),
                executor,
                nonce,
                validationProgramHash,
                paramsHash
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }

    /// @notice `keccak256` of the concatenated words, `bytes32(0)` when empty.
    function hashParams(
        bytes32[] memory params
    ) internal pure returns (bytes32) {
        if (params.length == 0) return bytes32(0);
        bytes memory buffer;
        for (uint256 i; i < params.length; ++i) {
            buffer = abi.encodePacked(buffer, params[i]);
        }
        return keccak256(buffer);
    }
}
