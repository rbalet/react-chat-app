import { describe, expect, it } from 'vitest';
import {
  base64ToBytes,
  bytesToBase64,
  bytesToU32,
  bytesToUtf8,
  u32ToBytes,
  utf8ToBytes,
} from '../core/utils';

describe('base64 codec', () => {
  // RFC 4648 §10 test vectors.
  const vectors: [string, string][] = [
    ['', ''],
    ['f', 'Zg=='],
    ['fo', 'Zm8='],
    ['foo', 'Zm9v'],
    ['foob', 'Zm9vYg=='],
    ['fooba', 'Zm9vYmE='],
    ['foobar', 'Zm9vYmFy'],
  ];

  it('matches RFC 4648 vectors', () => {
    for (const [input, expected] of vectors) {
      expect(bytesToBase64(utf8ToBytes(input))).toBe(expected);
      expect(bytesToUtf8(base64ToBytes(expected))).toBe(input);
    }
  });

  it('round-trips random binary data of every length mod 3', () => {
    for (let length = 0; length < 66; length++) {
      const bytes = new Uint8Array(length).map((_, i) => (i * 37 + length) & 0xff);
      expect(base64ToBytes(bytesToBase64(bytes))).toEqual(bytes);
    }
  });

  it('rejects invalid input', () => {
    expect(() => base64ToBytes('a$b=')).toThrow();
  });
});

describe('u32 codec', () => {
  it('round-trips boundary values big-endian', () => {
    for (const n of [0, 1, 255, 256, 0x3fff, 0xffffffff]) {
      expect(bytesToU32(u32ToBytes(n))).toBe(n);
    }
    expect([...u32ToBytes(1)]).toEqual([0, 0, 0, 1]);
  });

  it('rejects out-of-range values', () => {
    expect(() => u32ToBytes(-1)).toThrow();
    expect(() => u32ToBytes(0x100000000)).toThrow();
    expect(() => u32ToBytes(1.5)).toThrow();
  });
});
