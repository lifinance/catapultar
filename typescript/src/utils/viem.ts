import { type Chain, defineChain } from "viem";
import { mainnet, arbitrum, optimism, base, polygon, anvil } from "viem/chains";
import { extractChain } from "viem/utils";

const chains = [mainnet, arbitrum, optimism, base, polygon, anvil] as const;
type ChainIds = (typeof chains)[number]["id"];

/**
 * Resolve a viem {@link Chain} for a given chainId.
 *
 * An explicitly supplied `chain` always wins. Otherwise a well-known chain is
 * looked up. Otherwise a minimal chain is synthesized so any network works —
 * the transport (RPC URL) supplies connectivity, the `Chain` only carries the
 * id and metadata. This never returns `undefined`, so callers never silently
 * build a chain-less client.
 */
export function resolveChain(options: {
  chainId: number;
  chain?: Chain;
}): Chain {
  if (options.chain) return options.chain;
  const known = extractChain({ chains, id: options.chainId as ChainIds });
  if (known) return known;
  return defineChain({
    id: options.chainId,
    name: `chain-${options.chainId}`,
    nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
    rpcUrls: { default: { http: [] } },
  });
}
