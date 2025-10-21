## Catapultar

Catapultar is an optimised smart account primarily intended to be used as a batch executor. It consists of a base template — [`Catapultar.sol`](./src/Catapultar.sol) — and a proxy factory — [`CatapultarFactory.sol`](./src/CatapultarFactory.sol) — to aid with the deployment of various versions of proxies.

It is based on Solady's [`ERC7821.sol`](https://github.com/vectorized/solady/blob/main/src/accounts/ERC7821.sol) for efficient portable batch execution.

### Design Goal

A smart contract account that can be used to scale a transaction dispatch environment without relying on nonce spamming while still working as a minimal SCA for an end user. It should provide durable double spend protection ensuring dispatched transactions are not nefariously nor accidentally executed twice.

To scale a transaction dispatch environment, execution mode `0x01010000000078210001` can be used. It is a once callable, revert ignoring batch call. It allows a set of transactions to be executed in single call with no call blocking others.

To provide durable double spend protections, execution mode `0x01000000000078210001` can be used. It is a once executable, revert raising batch call. It allows a set of transaction to be executed conditionally.

Both execution modes can be combined with an outer signed `0x01010000000078210001` calling itself allowing for a one time callable batch with inner unsigned `0x01000000000078210001` allowing for safe re-tryable transactions. A transaction dispatch service can maintain a list of `0x01000000000078210001`s. Once the transaction executor is available, all outstanding `0x01000000000078210001`s can be executed through a single `0x01010000000078210001`.

#### Catapultar Usage Note

- To simulate dual mode transaction, mode `0x01000000000078210001` transactions can be submitted to the relevant proxy using the context of `msg.sender === proxy`.
- Catapultar contains no gas controls. If dual mode transactions are used, gas controls should be handled off-chain. Gas-spending untrusted contracts should be executed individually.
- Catapultar contains no calldata manipulation. Injection of `erc20::balanceOf()` or similar manipulations should be on external contracts.
- Catapultar does not support external delegate calls. Delegate calls are dangourus, particularly for upgradeable contracts. They can change the owner of Catapultar but also the implementation of a proxy (ERC-1967).

#### Key Features

- **Batch Execution Modes:**
	- Conditional batch: All transactions succeed or all fail. Nonce is only spent on success.
	- Individual batch: Each transaction in the batch is executed independently; failures do not block others. Nonce is always spent.
	- Nested batches: Mix conditional and individual batches for complex workflows.
- **Signature Validation:**
	- Supports ECDSA and ERC-1271 signatures.
	- Implements replay protection: signatures are valid only for a specific account instance.
- **Proxy Deployment Strategies:**
	- Minimal proxy (low cost, non-upgradeable).
	- Proxy with embedded calldata (pre-configured calls, non-upgradeable).
	- Upgradeable ERC-1967 proxy (ownership handover, upgradable logic).

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

### Execution Modes (ERC-7821)

Catapultar is not `ERC-7821` compatible but it follows `ERC-7821` specification. It supports the following execution modes:

| Execution Mode          | 0x0100....78210001 | 0x0101....78210001 | 0x0100....78210002 |
| ----------------------- | :----------------: | :----------------: | :----------------: |
| Raise Revert            |         Yes        |         No         |         Yes        |
| Consume Nonce on Revert |         No         |         Yes        |         No         |
| Batch of Batches        |         No         |         No         |         Yes        |
| OpData Required         |         Yes        |         Yes        |         No         |


#### opData

To execute a transaction batch `opData` is required for execution. As a result, mode `0x01000000000000000000` is not supported. `opData` is expected to be formatted in one of two ways:
1. `abi.encodePacked(bytes32(nonce), bytes(signature))` whenever the account is called externally.
2. `abi.encodePacked(bytes32(nonce))` if the account calls itself.

Since `0x01000000000078210002` does not execute a transaction batch but a batch of batches, it does not require `opData`.

#### Execution Models

- **0x01000000000078210001**: Executing a set of conditional trasactions.
  
	If 1 transaction in a set fails, the entire set should fail. This can allow for retrying the transaction at a later time since the nonce is not spent.
 
- **0x01010000000078210001**: Executing a set of individual transactions.
  
	If 1 or more transactions in a set fails, the remaining transactions in the set should be executed. The nonce is always spent.
 
- **0x01000000000078210001 inside 0x01010000000078210001**: Executing a large set of individual transactions containing conditional transactions.
  
	Each 0x01000000000078210001 batch can be retried in the future if it fails with each 0x01010000000078210001 only being executable once. This allows a batch executor to schedule a set of transaction to be executed. The entire set should be executed individually (0x01010000000078210001) but each sub-batch or transaction needs to be executed conditionally (0x01000000000078210001).


### Account Signature Validation (ERC-1271)

To validate ERC-1271 signatures against the account, the message hash needs to be rehashed for replay protection. 

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

Catapultar uses unordered nonces for replay protection. Nonces are stored in a 256 bit index using a 24 byte word: `bytes24(word) | bytes8(index)`. For efficient nonce management, nonces should be spent in each word in its entirety.

Multiple nonces can be invalidated at one time using index masks: `::invalidateUnorderedNonces(word, mask)`.

### Embedded Calls

It is possible to deploy accounts with a pre-approved call — an embedded call — that can be called by anyone at any time.

Noteworthy about accounts with embedded calls:
- Accounts with embedded calls cannot be upgradeable.
- The embedded call can be executed by anyone.
- The embedded call is a *regular call* and has a mode and nonce. That means it can be allowed to revert (and still consume the nonce) or only consume the nonce on success.
- Embedded calls can have their nonce invalidated.
- The embedded call is the typehash of a batch, the call itself is not stored on-chain. As a result, if the payload is lost, it may not be possible to recovered the embedded call.

If the mode of a embedded call uses a revertable mode it may make the call suceptible to a DoS attack.

A embedded call can be read through `::embeddedCall()`.

### Events Reference

Catapultar emits the following events:

- `UnorderedNonceInvalidation(uint256 wordPos, uint256 mask)` — Nonce invalidation.
- `CallReverted(bytes32 extraData, bytes revertData)` — Transaction failure in batch execution.

`extraData` packs execution mode, nonce, and index for identifying failed calls into: `bytes1(executionMode) | bytes23(nonce) | bytes8(index)`.

In particular, if an event is observed then its batch can be identified with the nonce as `extraData[1:24]` and the transaction's index in the batch can be identified using `extraData[24:32]`.

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
proxy.execute(mode, abi.encode(calls, opData));
```

On chains where calldata is expensive, Catapultar supports Solady's `LibZip::cdFallback()` to compress calldata.

### Stowaway

This proxy implements **[Reednaa's Stowaway](https://github.com/reednaa/stowaway)** to catch stray fallback functions. To make use of Stowaway encode a `ERC7821::execute` call into a bytes field which will be delievered to the account. You can optionally LibZip the call.

### Usage Warnings

When the smart account calls itself, it can bypass security checks on important functions. This feature is used to allow other accounts to execute all functions for a signer. The following have authorization that can be bypassed if called from itself:

- The `exeute` endpoint does not require a signature IFF the caller is the SCA. 
- The SCA can authorize an upgrade of the underlying SCA if the contract is upgradable.
- The SCA can upgrade the contract owner.

The only way to have the SCA call itself is through the batch endpoint. The batch endpoint requires a structured signed message but the encoded messages themselves are not structured. It is very important to parse and validate that **ALL** signed batches are legit and safe. Take the following batch:

- Call self, transferOwnership to A.
- Call A
- Call self, transferOwnership to original owner.

If A implement ERC-1271, it can execute **ANY** call it desires on the SCA. Using the above batch, it is possible to:

1. Call A with batch + custom calldata.
2. Store custom calldata in transient storage and set custom calldata as signed	(by A).
3. Execute Batch On SCA -> SCA calls A.
4. A calls SCA with custom calldata.
5. SCA will validate the batch by staticcall A, A returns true.
6. Custom calldata will be executed in context of SCA.

Additionally, remember that token allowances are long lived. If a token allowance is set on a contract, no signature or approval is needed to withdraw tokens.

## Development

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
$ forge coverage --no-match-coverage "(script|test)" [--report lcov]
```

### Deploy

To deploy the script, provide RPC urls in `.env` in the format of: `RPC_URL_<name>`. The name does not matter but when used in the below script, the name is accessed through the `string[]` array.

```shell
$ forge script deploy --sig "run(string[])" "[<chains>]" --multi --verify --broadcast
```

## License Notice

This project is licensed under the **[GNU Lesser General Public License v3.0 only (LGPL-3.0-only)](/LICENSE)**.

It also uses the following third-party libraries:

- **[Solady](https://github.com/Vectorized/solady)** – Licensed under the [MIT License](https://opensource.org/licenses/MIT)
- **[Permit2](https://github.com/Uniswap/permit2)** – Licensed under the [MIT License](https://opensource.org/licenses/MIT)
- **[Stowaway](https://github.com/reednaa/stowaway)**

Each library is included under the terms of its respective license. Copies of the license texts can be found in their source files or original repositories.

When distributing this project, please ensure that all relevant license notices are preserved in accordance with their terms.