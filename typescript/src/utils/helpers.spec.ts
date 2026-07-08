import { padEven, asHex } from "./helpers";

describe("Catapultar Helpers", () => {
  it("should pad evenly (padEven)", () => {
    expect(padEven("")).toBe("00");
    expect(padEven("", 0)).toBe("");
    expect(padEven("0", 0)).toBe("00");
    expect(padEven("0", 2)).toBe("00");
    expect(padEven("0", 20)).toBe("00000000000000000000");
    expect(padEven("01", 20)).toBe("00000000000000000001");

    expect(padEven("1234567fa11")).toBe("01234567fa11");

    expect(padEven("1234567fa11", 2, "æ")).toBe("æ1234567fa11");
  });

  it("should convert to hex (asHex)", () => {
    expect(asHex(32) as string).toBe("20");
    expect(asHex(32, 32) as string).toBe(
      "0000000000000000000000000000000000000000000000000000000000000020",
    );
    expect(asHex(10000000) as string).toBe("989680");
    expect(asHex(10000000) as string).toBe("989680");
    expect(asHex(200000000) as string).toBe("0bebc200");
    expect(asHex(200000000, 16) as string).toBe(
      "0000000000000000000000000bebc200",
    );
  });
});
