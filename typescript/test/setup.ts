import { Instance, Server } from "prool";

const TEST_ANVIL_PORT = 18545;
const TEST_RPC_URL = `http://127.0.0.1:${TEST_ANVIL_PORT}/1`;

export const anvil = Server.create({
  instance: Instance.anvil({ loadState: "anvil.state" }),
  port: TEST_ANVIL_PORT,
});

export const rpcUrl = () => {
  return TEST_RPC_URL;
};

beforeAll(async () => {
  try {
    await anvil.start();
  } catch (error) {
    throw new Error(
      `Failed to start test anvil server on port ${TEST_ANVIL_PORT}: ${(error as Error).message}`,
    );
  }
});
afterAll(async () => await anvil.stop());
