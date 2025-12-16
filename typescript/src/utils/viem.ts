import {mainnet, arbitrum, optimism } from "viem/chains";
import { extractChain } from "viem/utils";

const chains = [mainnet, arbitrum, optimism];
type ChainIds = (typeof chains)[number]["id"];

export function getViemChainId(chainId: number) {
  return extractChain({
    chains,
    id: chainId as ChainIds,
  });
}
