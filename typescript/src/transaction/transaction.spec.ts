import { ExecutionMode, type Call } from "../types/types";
import { random } from "../utils/helpers";
import { BaseTransaction } from "./transaction";

describe("Base Transaction", () => {
  it.concurrent("should set nonce", () => {
    const tx = new BaseTransaction();
    expect(tx.nonce).toBeUndefined();
    tx.setNonce(124n);
    expect(tx.nonce).toBe(124n);
    tx.setNonce(1300n);
    expect(tx.nonce).toBe(1300n);
    tx.setNonce(2n ** 256n - 1n);
    expect(tx.nonce).toBe(2n ** 256n - 1n);
  });

  it.concurrent("should set a random nonce", () => {
    const tx = new BaseTransaction();
    const firstNonce = tx.nonce;
    tx.setRandomNonce();
    expect(tx.nonce).not.toBe(firstNonce);
    const secondNonce = tx.nonce;
    tx.setRandomNonce();
    expect(tx.nonce).not.toBe(firstNonce);
    expect(tx.nonce).not.toBe(secondNonce);
  });

  it.concurrent("should set mode", () => {
    const tx = new BaseTransaction();
    expect(tx.mode).toBeUndefined();
    tx.setMode(ExecutionMode.RaiseRevert);
    expect(tx.mode).toBe(ExecutionMode.RaiseRevert);
    tx.setMode(ExecutionMode.RaiseRevertMultiChain);
    expect(tx.mode).toBe(ExecutionMode.RaiseRevertMultiChain);
    tx.setMode(ExecutionMode.SkipRevert);
    expect(tx.mode).toBe(ExecutionMode.SkipRevert);
    tx.setMode(ExecutionMode.SkipRevertMultiChain);
    expect(tx.mode).toBe(ExecutionMode.SkipRevertMultiChain);
  });

  it.concurrent("has valid mode", () => {
    const tx = new BaseTransaction();
    tx.setMode(ExecutionMode.RaiseRevert);
    expect(tx.hasValidMode()).toBe(true);
    tx.setMode(ExecutionMode.RaiseRevertMultiChain);
    expect(tx.hasValidMode()).toBe(true);
    tx.setMode(ExecutionMode.SkipRevert);
    expect(tx.hasValidMode()).toBe(true);
    tx.setMode(ExecutionMode.SkipRevertMultiChain);
    expect(tx.hasValidMode()).toBe(true);
    tx.setMode(
      "0x0200000000007821000100000000000000000000000000000000000000000000" as ExecutionMode,
    );
    expect(tx.hasValidMode()).toBe(false);
  });

  it.concurrent("has multichain mode", () => {
    const tx = new BaseTransaction();
    tx.setMode(ExecutionMode.RaiseRevert);
    expect(tx.hasMultichainMode()).toBe(false);
    tx.setMode(ExecutionMode.RaiseRevertMultiChain);
    expect(tx.hasMultichainMode()).toBe(true);
    tx.setMode(ExecutionMode.SkipRevert);
    expect(tx.hasMultichainMode()).toBe(false);
    tx.setMode(ExecutionMode.SkipRevertMultiChain);
    expect(tx.hasMultichainMode()).toBe(true);
  });

  it.concurrent("should add call", () => {
    const tx = new BaseTransaction();
    expect(tx.calls.length).toBe(0);
    expect(tx.calls).toEqual([]);

    const callA: Call = { to: random(20), data: "0x", value: 0n };
    tx.addCall(callA);

    expect(tx.calls).toEqual([callA]);
    tx.addCall(callA);
    expect(tx.calls).toEqual([callA, callA]);

    const callB: Call = {
      to: random(20),
      data: "0xdeadbeef",
      value: 251251251n,
    };
    tx.addCall(callB);
    expect(tx.calls).toEqual([callA, callA, callB]);
    tx.calls = [];
    expect(tx.calls).toEqual([]);
  });

  it.concurrent("should get total value of calls", () => {
    const tx = new BaseTransaction();
    expect(tx.getTotalValue()).toBe(0n);

    const callA: Call = { to: random(20), data: "0x", value: 1524n };
    tx.addCall(callA);

    expect(tx.getTotalValue()).toEqual(1524n);
    tx.addCall(callA);
    expect(tx.getTotalValue()).toEqual(1524n * 2n);

    const callB: Call = {
      to: random(20),
      data: "0xdeadbeef",
      value: 251251251n,
    };
    tx.addCall(callB);
    expect(tx.getTotalValue()).toEqual(1524n * 2n + 251251251n);
    tx.calls = [];
    expect(tx.getTotalValue()).toEqual(0n);
  });

  //-- Errors --//

  it.concurrent("should disallow nonce 0", () => {
    const tx = new BaseTransaction();
    const nonce0Error = `Nonce 0 is not allowed. It cannot be differentiated from an invalid nonce.`;
    expect(() => tx.setNonce(0n)).toThrow(nonce0Error);
    expect(tx.nonce).toBeUndefined();
    tx.nonce = 0n;
    expect(() => tx.getOpData()).toThrow(nonce0Error);
  });
});
