// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { EfficientHashLib } from "solady/src/utils/EfficientHashLib.sol";

import { Catapultar } from "./Catapultar.sol";
import { KeyedOwnable } from "./libs/KeyedOwnable.sol";
import { LibCloneTron } from "./libs/LibClone.tron.sol";

/**
 * @title Catapultar Factory Tron
 * @author Alexander @ LIFI (https://li.fi)
 * @custom:version 0.2.0
 * @notice Facilitates the deployment of clones of Catapultar.
 *
 * Two cloning strategies are supported:
 * - Non-upgradeable minimal PUSH_0 clone for a low cost batch execution account.
 * - Upgradeable ERC1967 proxy for a durable long term account.
 *
 * After the proxy has been deployed, init is called to set the owner.
 *
 * Each proxy is deployed deterministically using create2 with no overlap in addresses between the types:
 * - Each proxy has specific init data.
 * - The owner of each proxy is embedded in the salt.
 * The caller of deploy is not validated against owner deployments. Someone can deploy a contract for your owner or
 * front-run call deployment.
 * For the same reason, it may not be safe using a 0 address in the salt.
 *
 * If deploy is called twice with the same parameters (owner, salt), the second transaction will fail. In those cases,
 * the predictDeploy* functions can be used to re-discover the deployed contract.
 * The owner of a deployed proxy may not be the same as the owner it was deployed with.
 */
contract CatapultarFactoryTron {
    error TooManyOwners();
    address payable public immutable EXECUTOR;

    constructor() {
        EXECUTOR = payable(new Catapultar());
    }

    function VERSION() external view returns (string memory) {
        (,, string memory version,,,,) = Catapultar(EXECUTOR).eip712Domain();
        return version;
    }

    function deploy(
        KeyedOwnable.PublicKeyType ktp,
        bytes32[] calldata owner,
        bytes32 salt
    ) external payable returns (address payable proxy) {
        proxy = payable(LibCloneTron.cloneDeterministic_PUSH0(EXECUTOR, _salt(salt, ktp, owner)));

        Catapultar(payable(proxy)).init{ value: msg.value }(ktp, owner);
    }

    /// @dev Do not trust that the owner of the returned proxy is equal to the provided owner. Ownership may have been
    /// handed over.
    function predictDeploy(
        KeyedOwnable.PublicKeyType ktp,
        bytes32[] calldata owner,
        bytes32 salt
    ) external view returns (address proxy) {
        return LibCloneTron.predictDeterministicAddress_PUSH0(EXECUTOR, _salt(salt, ktp, owner), address(this));
    }

    function deployWithDigest(
        KeyedOwnable.PublicKeyType ktp,
        bytes32[] calldata owner,
        bytes32 salt,
        bytes32 digest,
        bool isSignature
    ) external payable returns (address payable proxy) {
        uint256 nonce;
        assembly ("memory-safe") {
            // Catapultar.DigestApproval.Call == 1
            // Catapultar.DigestApproval.Signature == 2
            // isSignature + 1 == 2 if isSignature === true otherwise 1.
            nonce := add(isSignature, 1)
        }
        bytes32 saltWithDigest = EfficientHashLib.hash(_salt(salt, ktp, owner), digest, bytes32(nonce));
        proxy = payable(LibCloneTron.cloneDeterministic_PUSH0(EXECUTOR, saltWithDigest));

        // forge-lint: disable-next-line(unsafe-typecast)
        // wake-disable-next-line reentrancy
        Catapultar(payable(proxy)).setSignature(digest, Catapultar.DigestApproval(uint8(nonce)));
        Catapultar(payable(proxy)).init{ value: msg.value }(ktp, owner);
    }

    /// @dev Do not trust that the owner of the returned proxy is equal to the provided owner. Ownership may have been
    /// handed over.
    function predictDeployWithDigest(
        KeyedOwnable.PublicKeyType ktp,
        bytes32[] calldata owner,
        bytes32 salt,
        bytes32 digest,
        bool isSignature
    ) external view returns (address proxy) {
        uint256 nonce;
        assembly ("memory-safe") {
            // Catapultar.DigestApproval.Call == 1
            // Catapultar.DigestApproval.Signature == 2
            // isSignature + 1 == 2 if isSignature === true otherwise 1.
            nonce := add(isSignature, 1)
        }
        bytes32 saltWithDigest = EfficientHashLib.hash(_salt(salt, ktp, owner), digest, bytes32(nonce));
        return LibCloneTron.predictDeterministicAddress_PUSH0(EXECUTOR, saltWithDigest, address(this));
    }

    function deployUpgradeable(
        KeyedOwnable.PublicKeyType ktp,
        bytes32[] calldata owner,
        bytes32 salt
    ) external payable returns (address payable proxy) {
        proxy = payable(LibCloneTron.deployDeterministicERC1967(EXECUTOR, _salt(salt, ktp, owner)));

        Catapultar(payable(proxy)).init{ value: msg.value }(ktp, owner);
    }

    /// @dev Do not trust that the owner of the returned proxy is equal to the provided owner. Ownership may have been
    /// handed over.
    /// Do not trust that the implementation of the returned proxy matches the expected version of Catapultar or
    /// Catapultar in general. The contract implementation is upgradeable.
    function predictDeployUpgradeable(
        KeyedOwnable.PublicKeyType ktp,
        bytes32[] calldata owner,
        bytes32 salt
    ) external view returns (address proxy) {
        return LibCloneTron.predictDeterministicAddressERC1967(EXECUTOR, _salt(salt, ktp, owner), address(this));
    }

    // --- Helpers --- //

    /**
     * @notice Computes a new salt based on the provided creation parameters
     * @param preSalt A bytes32 value intended to pseudo-randomize the deployed address.
     * @param ktp The keytype for the account
     * @param owner A desired callable parameter for a proxy address
     */
    function _salt(
        bytes32 preSalt,
        KeyedOwnable.PublicKeyType ktp,
        bytes32[] calldata owner
    ) internal pure returns (bytes32 salt) {
        uint256 numOwners = owner.length;
        if (numOwners > type(uint8).max) revert TooManyOwners();
        assembly ("memory-safe") {
            let m := mload(0x40)

            // In memory, store:
            // [m .. m+31]:         preSalt
            // [m+32]:              ktp
            // [m+33]:              numOwners
            // [m+34 .. m+33+N*32]: owners
            mstore(m, preSalt)
            mstore8(add(m, 32), ktp)
            mstore8(add(m, 33), numOwners)
            calldatacopy(add(m, 34), owner.offset, mul(numOwners, 32))

            salt := keccak256(m, add(34, mul(numOwners, 32)))
        }
    }
}
