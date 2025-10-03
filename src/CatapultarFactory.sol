// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.30;

import { EfficientHashLib } from "solady/src/utils/EfficientHashLib.sol";
import { LibClone } from "solady/src/utils/LibClone.sol";

import { Catapultar } from "./Catapultar.sol";
import { KeyedOwnable } from "./libs/KeyedOwnable.sol";

/**
 * @title Catapultar Factory
 * @author Alexander @ LIFI (https://li.fi)
 * @custom:version 0.0.1
 * @notice Facilitates the deployment of clones of Catapultar.
 *
 * Three cloning strategies are supported:
 * - Non-upgradeable minimal PUSH_0 clone for a low cost batch execution account.
 * - Non-upgradeable embedded args clone for a short lived account with a pre-configured allowed call.
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
 * If deploy is called twice with the same parameters (owner, salt), the second transaction will fall. In those cases,
 * the predictDeploy* functions can be used to re-discover the deployed contract.
 * The owner of a deployed proxy may not be the same as the owner it was deployed with. Catapultar uses Solady Ownable
 * which allows ownership transfers.
 *
 */
contract CatapultarFactory {
    address public immutable EXECUTOR_NO_EMBEDDED_CALLS;
    address public immutable EXECUTOR_EMBEDDED_CALLS;

    constructor() {
        // Whether or not a contract supports immutable calls is set in the constructor. Since this contracts supports
        // both types, we need to deploy 2 versions of the contract: one with embedded calls enabled and one without.
        EXECUTOR_NO_EMBEDDED_CALLS = address(new Catapultar(false));
        EXECUTOR_EMBEDDED_CALLS = address(new Catapultar(true));
    }

    /// @param salt The first 20 bytes of salt has to be the owner or 0.
    function deploy(
        KeyedOwnable.KeyType ktp,
        bytes32[] calldata owner,
        bytes32 salt
    ) external ownerInSalt(salt, ktp, owner) returns (address proxy) {
        proxy = LibClone.cloneDeterministic_PUSH0(address(EXECUTOR_NO_EMBEDDED_CALLS), salt);

        Catapultar(payable(proxy)).init(ktp, owner);
    }

    function deploy(
        address owner,
        bytes32 salt
    ) external returns (address proxy) {
        proxy = LibClone.cloneDeterministic_PUSH0(address(EXECUTOR_NO_EMBEDDED_CALLS), salt);

        bytes32[] memory keys = new bytes32[](1);
        keys[0] = bytes32(uint256(uint160(owner)));
        Catapultar(payable(proxy)).init(KeyedOwnable.KeyType.ECDSAThenSmartContract, keys);
    }

    /// @dev Do not trust that the owner of the returned proxy is equal to the provided owner. Ownership may have been
    /// handed over.
    /// @param salt The first 20 bytes of salt has to be the owner or 0.
    function predictDeploy(
        KeyedOwnable.KeyType ktp,
        bytes32[] calldata owner,
        bytes32 salt
    ) external view ownerInSalt(salt, ktp, owner) returns (address proxy) {
        return LibClone.predictDeterministicAddress_PUSH0(address(EXECUTOR_NO_EMBEDDED_CALLS), salt, address(this));
    }

    /// @param salt The first 20 bytes of salt has to be the owner or 0.
    function deployWithEmbedCall(
        KeyedOwnable.KeyType ktp,
        bytes32[] calldata owner,
        bytes32 salt,
        bytes32 callsTypeHash
    ) external ownerInSalt(salt, ktp, owner) returns (address proxy) {
        proxy = LibClone.cloneDeterministic(address(EXECUTOR_EMBEDDED_CALLS), abi.encodePacked(callsTypeHash), salt);

        Catapultar(payable(proxy)).init(ktp, owner);
    }

    /// @dev Do not trust that the owner of the returned proxy is equal to the provided owner. Ownership may have been
    /// handed over.
    /// @param salt The first 20 bytes of salt has to be the owner or 0.
    function predictDeployWithEmbedCall(
        KeyedOwnable.KeyType ktp,
        bytes32[] calldata owner,
        bytes32 salt,
        bytes32 callsTypeHash
    ) external view ownerInSalt(salt, ktp, owner) returns (address proxy) {
        return LibClone.predictDeterministicAddress(
            address(EXECUTOR_EMBEDDED_CALLS), abi.encodePacked(callsTypeHash), salt, address(this)
        );
    }

    /// @param salt The first 20 bytes of salt has to be the owner or 0.
    function deployUpgradeable(
        KeyedOwnable.KeyType ktp,
        bytes32[] calldata owner,
        bytes32 salt
    ) external ownerInSalt(salt, ktp, owner) returns (address proxy) {
        proxy = LibClone.deployDeterministicERC1967(address(EXECUTOR_NO_EMBEDDED_CALLS), salt);

        Catapultar(payable(proxy)).init(ktp, owner);
    }

    /// @dev Do not trust that the owner of the returned proxy is equal to the provided owner. Ownership may have been
    /// handed over.
    /// Do not trust that the implementation of the returned proxy matches the expected version of Catapultar or
    /// Catapultar in general. The contract implementation is upgradeable.
    /// @param salt The first 20 bytes of salt has to be the owner or 0.
    function predictDeployUpgradeable(
        KeyedOwnable.KeyType ktp,
        bytes32[] calldata owner,
        bytes32 salt
    ) external view ownerInSalt(salt, ktp, owner) returns (address proxy) {
        return LibClone.predictDeterministicAddressERC1967(address(EXECUTOR_NO_EMBEDDED_CALLS), salt, address(this));
    }

    // --- Helpers --- //

    /**
     * @notice Requires that the salt contains the owner as the first 20 bytes or they are 0.
     * @dev When deploying proxies, it may not be safe to set the first 20 bytes to 0. If this is desired, the risk is
     * entirely up to the user.
     * @param salt A bytes32 value intended to pseudo-randomize the deployed address.
     * @param owner A desired callable parameter for a proxy address
     */
    modifier ownerInSalt(bytes32 salt, KeyedOwnable.KeyType ktp, bytes32[] calldata owner) {
        if (KeyedOwnable.KeyType.ECDSAThenSmartContract == ktp && owner.length == 1) {
            LibClone.checkStartsWith(salt, address(uint160(uint256(owner[0]))));
        } else {
            // TODO: this is cheating but it _technically is valid
            bytes20 ownerHash = bytes20(EfficientHashLib.hash(bytes32(uint256(uint8(ktp))), owner[0], owner[1]));
            LibClone.checkStartsWith(salt, address(ownerHash));
        }
        _;
    }
}
