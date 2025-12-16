import { padEven, random, saltContainsAddress, toHex } from "./helpers";

describe('Catapultar Helpers', () => {
  it('should pad evenly (padEven)', () => {
    expect(padEven('')).toBe('00');
    expect(padEven('', 0)).toBe('');
    expect(padEven('0', 0)).toBe('00');
    expect(padEven('0', 2)).toBe('00');
    expect(padEven('0', 20)).toBe('00000000000000000000');
    expect(padEven('01', 20)).toBe('00000000000000000001');

    expect(padEven('1234567fa11')).toBe('01234567fa11');

    expect(padEven('1234567fa11', 2, 'æ')).toBe('æ1234567fa11');
  });

  it('should convert to hex (toHex)', () => {
    expect(toHex(32) as string).toBe('20');
    expect(toHex(32, 32) as string).toBe(
      '0000000000000000000000000000000000000000000000000000000000000020',
    );
    expect(toHex(10000000) as string).toBe('989680');
    expect(toHex(10000000) as string).toBe('989680');
    expect(toHex(200000000) as string).toBe('0bebc200');
    expect(toHex(200000000, 16) as string).toBe('0000000000000000000000000bebc200');
  });

  it('should check if address contains salt (saltContainsAddress)', () => {
    const address = random(20);
    expect(
      saltContainsAddress(address, address.padEnd(66, '0') as `0x${string}`),
    ).toBe(true);

    expect(
      saltContainsAddress(
        address,
        '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470',
      ),
    ).toBe(false);

    expect(
      saltContainsAddress(
        '0xc5d2460186f7233c927e7db2dcc703c0e500b653',
        '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470',
      ),
    ).toBe(true);
  });
});