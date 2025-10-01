## Catapultar

Catapultar is an optimised smart account primarily intended to be used as a batch account executor. It consists of a base template — [`Catapultar.sol`](./src/Catapultar.sol) — with a proxy factory — [`CatapultarFactory.sol`](./src/CatapultarFactory.sol) — to easily deploy minimal proxies in front.

It is based on Solady's [`ERC7821.sol`](https://github.com/vectorized/solady/blob/main/src/accounts/ERC7821.sol) for efficient portable batch execution.


### Key Features

- **Batch Execution Modes:**
	- Conditional batch: All transactions succeed or all fail. Nonce is only spent on success.
	- Individual batch: Each transaction in the batch is executed independently; failures do not block others. Nonce is always spent.
	- Nested batches: Mix conditional and individual batches for complex workflows.
- **Signature Validation:**
	- Supports ECDSA and ERC1271 signatures.
	- Implements replay protection: signatures are valid only for a specific account instance.
- **Proxy Deployment Strategies:**
	- Minimal proxy (low cost, non-upgradeable).
	- Proxy with embedded calldata (pre-configured calls, non-upgradeable).
	- Upgradeable ERC1967 proxy (ownership handover, upgradable logic).

### Account Deployment

Use the `CatapultarFactory` contract to deploy Catapultar proxies:

- **Minimal Proxy:**
	```solidity
	factory.deploy(owner, salt);
	```
	Deploys a minimal proxy for batch execution.

- **Proxy with Embedded Call:**
	```solidity
	factory.deployWithEmbedCall(owner, salt, callsTypeHash);
	```
	Deploys a proxy with a pre-configured allowed call.

- **Upgradeable Proxy:**
	```solidity
	factory.deployUpgradeable(owner, salt);
	```
	Deploys an ERC1967 upgradeable proxy. Ownership can be transferred and logic upgraded.

For all deployments, the first 20 bytes of `salt` should be the owner address or zero. Use the `predictDeploy*` functions to precompute addresses before deployment.

| Feature               | Minimal Proxy | Embedded Call Proxy | Upgradeable Proxy |
| --------------------- | :-----------: | :-----------------: | :---------------: |
| Upgradable            |      No       |         No          |        Yes        |
| Embedded Call Support |      No       |         Yes         |        No         |
| Ownership Transfer    |      Yes      |         Yes         |        Yes        |
| Gas Cost              |    Lowest     |         Low         |      Higher       |

### Events Reference

Catapultar emits the following events:

- `UnorderedNonceInvalidation(uint256 wordPos, uint256 mask)` — Nonce invalidation.
- `CallReverted(bytes32 extraData, bytes revertData)` — Transaction failure in batch execution.

`extraData` packs execution mode, nonce, and index for identifying failed calls into: `bytes1(executionMode) | bytes23(nonce) | bytes8(index)`.

In particular, if an event is observed then its batch can be identified with the nonce as `extraData[1:24]` and the transaction's index in the batch can be identified using `extraData[24:32]`.

### Account Signature Validation (ERC1271)

To validate signatures against the account, the message hash needs to be further hash for replay protection. 

- Hash your payload as usual (e.g., EIP-712).
- Compute the replay-protected hash:
	```solidity
	bytes32 replayHash = keccak256(abi.encode(
      keccak256(bytes("Replay(address account,bytes32 payload)")),
      address(account),
      payloadHash
  ));
	```
- Sign and verify using `::isValidSignature`.

### Nonce Management

Catapultar uses unordered nonces for replay protection. Nonces are stored in 256 bit index using a 24 byte word: `bytes24(word) | bytes8(index)`. For efficient nonce mangement, nonces should be spent for entire masks at a time.

Multiple nonces can be invalidated at a time using index masks: `::invalidateUnorderedNonces(word, mask)`.

### Embedded Calls

It is possible to deploy accounts with a pre-approved call — an embedded call — that can be called by anyone at any time.

Noteworthy about accounts with embedded calls:
- Accounts with embedded calls cannot be upgradeable.
- The embedded call can be executed by anyone.
- The embedded call is a *regular call* and has a mode and nonce. That means it can be allowed to revert (and still consume the nonce) or only consume the nonce on success.
- Embedded calls can have their nonce invalidated.
- The embedded call is the typehash of a batch, the call itself is not stored on-chain. As a result, if the payload is lost, it may not be possible to recovered the embedded call.

Having an embedded call with a mode allowing the call to revert, may make the call suceptible to a DoS attack.

The embedded call can be read through `::embeddedCall()`

### Integration Example

Batch execution uses a `Call` struct defined as:

```solidity
struct Call {
	address to;
	uint256 value;
	bytes data;
}
```

Each batch is an array of `Call` objects. The mode and nonce are provided as part of the calldata.

```solidity
// Deploy
address proxy = factory.deploy(owner, salt);

// Prepare batch
Call[] memory calls = new Call[](2);
calls[0] = Call({to: addr1, value: 0, data: data1});
calls[1] = Call({to: addr2, value: 0, data: data2});

// Prepare opData (nonce + signature)
bytes memory opData = abi.encodePacked(nonce, signature);

// Execute (from proxy)
proxy.execute(mode, calls, opData);
```

On chains where calldata is expensive, Catapultar supports Solady's `LibZip::cdFallback()` to compress calldata.

## Usage

### Build

```shell
$ forge build
```

### Test

```shell
$ forge test
```

### Coverage

```shell
$ forge coverage
```

### Format

```shell
$ forge fmt
```

### Deploy

```shell
$ forge script script/Counter.s.sol:CounterScript --rpc-url <your_rpc_url> --private-key <your_private_key>
```

## License Notice

This project is licensed under the **[GNU Lesser General Public License v3.0 only (LGPL-3.0-only)](/LICENSE)**.

It also uses the following third-party libraries:

- **[Solady](https://github.com/Vectorized/solady)** – Licensed under the [MIT License](https://opensource.org/licenses/MIT)
- **[Permit2](https://github.com/Uniswap/permit2)** – Licensed under the [MIT License](https://opensource.org/licenses/MIT)

Each library is included under the terms of its respective license. Copies of the license texts can be found in their source files or original repositories.

When distributing this project, please ensure that all relevant license notices are preserved in accordance with their terms.