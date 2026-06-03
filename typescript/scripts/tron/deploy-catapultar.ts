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

  const deployments = await loadDeployments()
  const results: Array<{
    contract: string
    result: ITronDeploymentResult
  }> = []

  for (const contractName of contractsToRun) {
    consola.info(`\n--- Deploying ${contractName} ---`)

    try {
      const artifact = await loadTronArtifact(contractName)
      const result = await deployer.deployContract(artifact)

      results.push({ contract: contractName, result })
      deployments[contractName] = result.contractAddress

      consola.success(`${contractName} deployed:`)
      consola.info(`  Address: ${result.contractAddress}`)
      consola.info(`  TX: ${tronScanTransactionUrl(network, result.transactionId)}`)
      consola.info(`  Cost: ${result.actualCost.trxCost} TRX`)
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
