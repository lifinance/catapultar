/**
 * Deploy Catapultar Tron-variant contracts to Tron.
 *
 * Only `.tron.sol` artifacts are deployed. Mirrors the Forge deploy.s.sol but
 * uses TronWeb instead of CREATE2.
 * Deploy order: CatapultarFactoryTron -> CATValidatorTron -> IntentExecutorTron
 *
 * Prerequisites:
 *   1. `cd catapultar/solidity && forge build`
 *   2. Set environment variables:
 *      - PRIVATE_KEY (deployer private key) - can be also passed as --private-key <key>
 *      - RPC_URL_TRON (optional, defaults to https://api.trongrid.io)
 *      - TRONGRID_API_KEY (optional)
 *      - INTENT_EXECUTOR_OWNER (required to deploy IntentExecutorTron): owner of the
 *        solver set (a multisig), base58 (T...) or hex
 *      - INTENT_EXECUTOR_SOLVERS (required to deploy IntentExecutorTron): comma-separated
 *        accounts that call the executor's `fill`, base58 or hex
 *      - INTENT_EXECUTOR_FORWARDERS (optional): comma-separated permissionless forwarders,
 *        base58 or hex, that must not be solvers: the CALL_PROXY of every deployed
 *        validator not covered below
 *
 * A forwarder that runs any caller's call would, as a solver, let anyone call fill()
 * with any payload. Deploying IntentExecutorTron throws when a solver is in
 * INTENT_EXECUTOR_FORWARDERS, is one of TRON_MAINNET_FORWARDERS on mainnet, or is the
 * CALL_PROXY of a CATValidatorTron deployed in the same run.
 *
 * IntentExecutorTron keeps solver authorizations in transient storage, so it needs
 * TVM Cancun (TLOAD/TSTORE, chain parameter getAllowTvmCancun = 1).
 *
 * Usage (run from catapultar/typescript):
 *   bun run scripts/tron/deploy-catapultar.ts [--dry-run] [--testnet|--network tronshasta] [--private-key 0x...] [--rpc-url <url>] [--trongrid-api-key <key>]
 *
 * Deploy only selected contracts (canonical order is always preserved):
 *   --step CatapultarFactoryTron
 *   --step CATValidatorTron
 *   --step IntentExecutorTron
 *   --step McopyTestTron   (not deployed by default)
 *   --step 1   (same as CatapultarFactoryTron; 2 = CATValidatorTron, 3 = IntentExecutorTron, 4 = McopyTestTron)
 *   Repeat --step to deploy a subset, e.g. --step 1 --step 3
 */

import { readFile } from 'fs/promises'
import { resolve } from 'path'

import type { TronWeb } from 'tronweb'
import { consola } from 'consola'

import {
  TronContractDeployer,
  tronScanTransactionUrl,
  getPrivateKey,
  getTronRpcUrl,
  getTronGridAPIKey,
  TRON_PRO_API_KEY_HEADER,
  promptEnergyRentalReminder,
  type IForgeArtifact,
  type ITronDeploymentConfig,
  type ITronDeploymentResult,
  type TronTvmNetworkName,
  getTronWebCodecOnlyForNetwork,
  tronAddressToHex,
} from '@lifi/tron-devkit'

// ── Configuration ──────────────────────────────────────────────────────────────

const ARTIFACTS_DIR = resolve(import.meta.dir, '../../../solidity/out')
const DEPLOYMENTS_FILE = resolve(
  import.meta.dir,
  '../../../solidity/deployments/tron.json'
)

/** Production contracts — deployed when no --step flags are provided. */
const DEFAULT_CONTRACTS = [
  'CatapultarFactoryTron',
  'CATValidatorTron',
  'IntentExecutorTron',
] as const

/** Opt-in contracts — only deployed when explicitly requested via --step. */
const OPTIONAL_CONTRACTS = ['McopyTestTron'] as const

/** Every contract selectable via --step. Must end in "Tron"; the source file is the name minus that suffix + ".tron.sol". */
const ALL_CONTRACTS = [...DEFAULT_CONTRACTS, ...OPTIONAL_CONTRACTS] as const

type DeployStepName = (typeof ALL_CONTRACTS)[number]

/**
 * Permissionless forwarders on Tron mainnet, keyed by 0x hex body. Tron's CREATE2
 * uses a 0x41 prefix and no deterministic deployer, so deploy.s.sol's EVM addresses
 * (Multicall3, the legacy IntentExecutor, the validators' CALL_PROXY) exist on none of
 * them. Tron has no Multicall3.
 */
const TRON_MAINNET_FORWARDERS: Readonly<Record<string, string>> = {
  // TH5ysvD4VbUzKRQoFPXbMZpcetGcdHo2Q9: its executeAndSweep runs any caller's calls.
  '0x4e10d66c72f3184b83fe9d611f96e7eca1d8fc85': 'legacy IntentExecutorTron',
  // TT8Y3hwAx15zW1viwmskwno3WwgtrknPPT, read from CALL_PROXY() on
  // CATValidatorTron TYjEq9DdArEAtsdRY9S65Y2GbqmM4myuzw.
  '0xbc3dc7cdf6c90a2e6c484ace018c7c2ce19720f6':
    'CALL_PROXY of CATValidatorTron',
}

/** Constructor arguments per contract; contracts without arguments return []. */
function constructorParams(
  contractName: DeployStepName,
  network: TronTvmNetworkName
): unknown[] {
  if (contractName !== 'IntentExecutorTron') return []
  const owner = process.env.INTENT_EXECUTOR_OWNER
  const solvers = process.env.INTENT_EXECUTOR_SOLVERS
  if (!owner || !solvers)
    throw new Error(
      'IntentExecutorTron needs INTENT_EXECUTOR_OWNER and INTENT_EXECUTOR_SOLVERS'
    )
  const tronWeb = getTronWebCodecOnlyForNetwork(network)
  const ownerHex = parseTronAccount(tronWeb, 'INTENT_EXECUTOR_OWNER', owner)
  const solverHexes = parseTronAccountList(
    tronWeb,
    'INTENT_EXECUTOR_SOLVERS',
    solvers
  )
  if (solverHexes.length === 0)
    throw new Error('INTENT_EXECUTOR_SOLVERS: lists no solver address')
  const forwarders = new Map<string, string>(
    network === 'tron' ? Object.entries(TRON_MAINNET_FORWARDERS) : []
  )
  for (const forwarder of parseTronAccountList(
    tronWeb,
    'INTENT_EXECUTOR_FORWARDERS',
    process.env.INTENT_EXECUTOR_FORWARDERS ?? ''
  ))
    forwarders.set(forwarder, 'listed in INTENT_EXECUTOR_FORWARDERS')
  requireNoForwarderSolver(tronWeb, solverHexes, forwarders)
  consola.info('IntentExecutorTron constructor:', {
    owner: `${tronWeb.address.fromHex(ownerHex)} (${ownerHex})`,
    solvers: solverHexes.map(
      (solver) => `${tronWeb.address.fromHex(solver)} (${solver})`
    ),
  })
  return [ownerHex, solverHexes]
}

/** Parses a comma-separated list with {@link parseTronAccount}, lowercased. */
function parseTronAccountList(
  tronWeb: TronWeb,
  variable: string,
  raw: string
): string[] {
  return raw
    .split(',')
    .filter((account) => account.trim() !== '')
    .map((account) =>
      parseTronAccount(tronWeb, variable, account).toLowerCase()
    )
}

/**
 * Throws when a solver is one of `forwarders` (lowercase 0x hex body → description).
 */
function requireNoForwarderSolver(
  tronWeb: TronWeb,
  solverHexes: string[],
  forwarders: ReadonlyMap<string, string>
): void {
  for (const solver of solverHexes) {
    const forwarder = forwarders.get(solver.toLowerCase())
    if (forwarder)
      throw new Error(
        `SolverIsForwarder: ${tronWeb.address.fromHex(solver)} (${solver}) is a forwarder: ${forwarder}`
      )
  }
}

/**
 * Parses one account as base58 (T...) or 20-byte hex with a 0x or 41 prefix, and
 * returns its 0x hex form. Anything else, including the zero address, throws: a
 * mistyped owner would freeze the solver set for good.
 */
function parseTronAccount(
  tronWeb: TronWeb,
  variable: string,
  raw: string
): string {
  const value = raw.trim()
  const wellFormed =
    /^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(value) ||
    /^(0x|41)[0-9a-fA-F]{40}$/.test(value)
  if (!wellFormed || (value.startsWith('T') && !tronWeb.isAddress(value)))
    throw new Error(`${variable}: not a Tron or 0x address: ${value}`)
  const hex = tronAddressToHex(tronWeb, value)
  if (!/^0x[0-9a-fA-F]{40}$/.test(hex) || BigInt(hex) === 0n)
    throw new Error(`${variable}: resolves to an invalid or zero address: ${value}`)
  return hex
}

async function loadTronArtifact(
  contractName: DeployStepName
): Promise<IForgeArtifact> {
  const sourceFile = `${contractName.replace(/Tron$/, '')}.tron`
  const artifactPath = resolve(
    ARTIFACTS_DIR,
    `${sourceFile}.sol/${contractName}.json`
  )
  const artifact = JSON.parse(await readFile(artifactPath, 'utf-8'))
  if (!artifact.abi || !artifact.bytecode?.object)
    throw new Error(
      `Invalid artifact for ${contractName}: missing ABI or bytecode`
    )
  consola.info(`Loaded ${contractName} from: ${artifactPath}`)
  return artifact
}

function resolveStepArg(raw: string): DeployStepName {
  if (/^\d+$/.test(raw)) {
    const n = Number.parseInt(raw, 10)
    if (n < 1 || n > ALL_CONTRACTS.length) {
      consola.error(
        `--step index must be between 1 and ${ALL_CONTRACTS.length} (${ALL_CONTRACTS.join(' → ')})`
      )
      process.exit(1)
    }
    return ALL_CONTRACTS[n - 1]!
  }
  const match = ALL_CONTRACTS.find(
    (c) => c.toLowerCase() === raw.toLowerCase()
  )
  if (!match) {
    consola.error(
      `Unknown --step "${raw}". Use: ${ALL_CONTRACTS.join(', ')}, or 1–${ALL_CONTRACTS.length}`
    )
    process.exit(1)
  }
  return match
}

/** If set, only these contracts are deployed, in canonical order. */
function parseStepFlags(args: string[]): DeployStepName[] | undefined {
  const steps: DeployStepName[] = []
  for (let i = 0; i < args.length; i++) {
    if (args[i] !== '--step') continue
    const raw = args[i + 1]
    if (!raw || raw.startsWith('--')) {
      consola.error(`--step requires a contract name or index (1–${ALL_CONTRACTS.length})`)
      process.exit(1)
    }
    steps.push(resolveStepArg(raw))
    i++
  }
  if (steps.length === 0) return undefined
  const selected = new Set(steps)
  return ALL_CONTRACTS.filter((c) => selected.has(c))
}

// ── CLI argument parsing ───────────────────────────────────────────────────────

function parseArgs(): {
  dryRun: boolean
  network: TronTvmNetworkName
  privateKey?: string
  rpcUrl?: string
  trongridApiKey?: string
  steps?: DeployStepName[]
} {
  const args = process.argv.slice(2)
  const dryRun = args.includes('--dry-run')
  const testnet = args.includes('--testnet')
  const networkIdx = args.indexOf('--network')
  const networkArg = networkIdx >= 0 ? args[networkIdx + 1] : undefined
  const network: TronTvmNetworkName =
    testnet || networkArg === 'tronshasta' ? 'tronshasta' : 'tron'
  const pkIdx = args.indexOf('--private-key')
  const privateKey = pkIdx >= 0 ? args[pkIdx + 1] : undefined
  const rpcIdx = args.indexOf('--rpc-url')
  const rpcUrl = rpcIdx >= 0 ? args[rpcIdx + 1] : undefined
  const apiKeyIdx = args.indexOf('--trongrid-api-key')
  const trongridApiKey = apiKeyIdx >= 0 ? args[apiKeyIdx + 1] : undefined
  const steps = parseStepFlags(args)
  return { dryRun, network, privateKey, rpcUrl, trongridApiKey, steps }
}

// ── Deployment persistence ─────────────────────────────────────────────────────

async function loadDeployments(): Promise<Record<string, string>> {
  try {
    return await Bun.file(DEPLOYMENTS_FILE).json()
  } catch {
    return {}
  }
}

async function saveDeployments(
  deployments: Record<string, string>
): Promise<void> {
  await Bun.write(DEPLOYMENTS_FILE, JSON.stringify(deployments, null, 2) + '\n')
  consola.info(`Deployments saved to: ${DEPLOYMENTS_FILE}`)
}

// ── Main ───────────────────────────────────────────────────────────────────────

/**
 * IntentExecutorTron keeps solver authorizations in transient storage and has no
 * storage fallback. Refuse to deploy it unless the chain has TLOAD/TSTORE enabled.
 */
async function requireTvmCancun(
  rpcUrl: string,
  headers: Record<string, string>
): Promise<void> {
  const response = await fetch(`${rpcUrl}/wallet/getchainparameters`, {
    headers,
  })
  if (!response.ok)
    throw new Error(`getchainparameters failed: HTTP ${response.status}`)
  const { chainParameter } = (await response.json()) as {
    chainParameter: Array<{ key: string; value?: number }>
  }
  const allowCancun = chainParameter.find(
    (parameter) => parameter.key === 'getAllowTvmCancun'
  )?.value
  if (allowCancun !== 1)
    throw new Error(
      'IntentExecutorTron needs TVM Cancun (getAllowTvmCancun = 1); this chain lacks it'
    )
  consola.info('TVM Cancun enabled (getAllowTvmCancun = 1)')
}

/** Reads CALL_PROXY() of a deployed CATValidatorTron, as a lowercase 0x hex body. */
async function readCallProxy(
  rpcUrl: string,
  headers: Record<string, string>,
  validator: string
): Promise<string> {
  const response = await fetch(`${rpcUrl}/wallet/triggerconstantcontract`, {
    method: 'POST',
    headers: { ...headers, 'content-type': 'application/json' },
    body: JSON.stringify({
      owner_address: validator,
      contract_address: validator,
      function_selector: 'CALL_PROXY()',
      visible: true,
    }),
  })
  if (!response.ok)
    throw new Error(
      `CALL_PROXY() on ${validator} failed: HTTP ${response.status}`
    )
  const { constant_result: constantResult, result } =
    (await response.json()) as {
      constant_result?: string[]
      result?: { result?: boolean }
    }
  const word = constantResult?.[0]
  if (!result?.result || !word || !/^0{24}[0-9a-fA-F]{40}$/.test(word))
    throw new Error(`CALL_PROXY() on ${validator} returned no address`)
  return `0x${word.slice(24).toLowerCase()}`
}

async function main() {
  const {
    dryRun,
    network,
    privateKey: pkFlag,
    rpcUrl: rpcUrlFlag,
    trongridApiKey: apiKeyFlag,
    steps,
  } = parseArgs()

  const contractsToRun = steps ?? [...DEFAULT_CONTRACTS]

  consola.info(`Deploying Catapultar contracts to ${network}...`)
  if (steps) {
    consola.info(`Steps: ${contractsToRun.join(' → ')}`)
  }
  if (dryRun) consola.warn('DRY RUN mode - no transactions will be broadcast')

  if (!dryRun) await promptEnergyRentalReminder()

  const privateKey = getPrivateKey(pkFlag)
  const rpcUrl = getTronRpcUrl(network, rpcUrlFlag)
  const trongridApiKey = getTronGridAPIKey(apiKeyFlag)

  const headers: Record<string, string> = {}
  if (trongridApiKey) headers[TRON_PRO_API_KEY_HEADER] = trongridApiKey

  const config: ITronDeploymentConfig = {
    fullHost: rpcUrl,
    tvmNetworkKey: network,
    privateKey,
    dryRun,
    verbose: process.argv.includes('--verbose'),
    ...(Object.keys(headers).length > 0 && { headers }),
  }

  const deployer = new TronContractDeployer(config)

  const info = await deployer.getNetworkInfo()
  consola.info('Network info:', {
    network: info.network,
    block: info.block,
    address: info.address,
    balance: `${info.balance} TRX`,
  })

  if (contractsToRun.includes('IntentExecutorTron'))
    await requireTvmCancun(rpcUrl, headers)
  // Resolve every constructor argument up front: a bad INTENT_EXECUTOR_* value must
  // fail before the run deploys anything.
  const params = new Map(
    contractsToRun.map((name) => [name, constructorParams(name, network)])
  )

  const deployments = await loadDeployments()
  const results: Array<{
    contract: string
    result: ITronDeploymentResult
  }> = []

  for (const contractName of contractsToRun) {
    consola.info(`\n--- Deploying ${contractName} ---`)

    try {
      const artifact = await loadTronArtifact(contractName)
      const result = await deployer.deployContract(
        artifact,
        params.get(contractName)
      )

      results.push({ contract: contractName, result })
      // The pre-3.0.0 executor is ungated and stays callable forever: keep its address
      // on record for the migration instead of overwriting it.
      const previous = deployments[contractName]
      if (
        contractName === 'IntentExecutorTron' &&
        previous &&
        previous !== result.contractAddress &&
        !deployments.IntentExecutorTronUngated
      )
        deployments.IntentExecutorTronUngated = previous
      deployments[contractName] = result.contractAddress

      consola.success(`${contractName} deployed:`)
      consola.info(`  Address: ${result.contractAddress}`)
      consola.info(`  TX: ${tronScanTransactionUrl(network, result.transactionId)}`)
      consola.info(`  Cost: ${result.actualCost.trxCost} TRX`)

      // No one can know a new validator's CALL_PROXY before it exists, so the run's
      // IntentExecutorTron solvers are checked against it here, before the executor step.
      const executorParams = params.get('IntentExecutorTron')
      if (contractName === 'CATValidatorTron' && executorParams) {
        if (dryRun) {
          consola.warn(
            'DRY RUN: the new CATValidatorTron CALL_PROXY is not checked against INTENT_EXECUTOR_SOLVERS'
          )
        } else {
          try {
            const callProxy = await readCallProxy(
              rpcUrl,
              headers,
              result.contractAddress
            )
            requireNoForwarderSolver(
              getTronWebCodecOnlyForNetwork(network),
              executorParams[1] as string[],
              new Map([
                [callProxy, 'CALL_PROXY of the CATValidatorTron just deployed'],
              ])
            )
          } catch (error: any) {
            // The validator is live: record it before refusing the executor.
            await saveDeployments(deployments)
            consola.error(
              `Refusing to deploy IntentExecutorTron: ${error.message}`
            )
            process.exit(1)
          }
        }
      }
    } catch (error: any) {
      if (dryRun && /insufficient balance/i.test(error.message)) {
        consola.warn(`${contractName}: ${error.message}`)
        continue
      }
      consola.error(`Failed to deploy ${contractName}: ${error.message}`)
      process.exit(1)
    }
  }

  if (!dryRun) {
    await saveDeployments(deployments)
  }

  consola.info('\n=== Deployment Summary ===')
  for (const { contract, result } of results) {
    consola.info(`  ${contract}: ${result.contractAddress}`)
  }
  consola.success(
    steps
      ? 'Selected contract(s) deployed successfully!'
      : 'All Catapultar contracts deployed successfully!'
  )
}

main().catch((error) => {
  consola.error('Deployment failed:', error)
  process.exit(1)
})
