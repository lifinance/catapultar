import { Instance, Server } from "prool";

export const anvil = Server.create({
  instance: Instance.anvil({ loadState: "anvil.state" }),
});

export const rpcUrl = () => {
  const ad = anvil.address();
  if (ad === null || ad === undefined) {
    throw new Error("Could not start anvil for testing");
  }
  return `http://localhost:${ad.port}/1`;
};

beforeAll(async () => {
  await anvil.start();
});
afterAll(async () => await anvil.stop());
