/**
 * Byte/string utilities. Dependency-free except @noble/ciphers utils
 * (re-exported so the rest of the module has a single import point).
 */

import { bytesToUtf8, concatBytes, equalBytes, utf8ToBytes } from '@noble/ciphers/utils.js';

export { bytesToUtf8, concatBytes, equalBytes, utf8ToBytes };

const BASE64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

const BASE64_LOOKUP: Record<string, number> = (() => {
  const lookup: Record<string, number> = {};
  for (let i = 0; i < BASE64_ALPHABET.length; i++) lookup[BASE64_ALPHABET[i] as string] = i;
  return lookup;
})();

/**
 * Manual base64 codec: works identically in browsers, WebViews, Node and
 * workers, with no reliance on btoa/atob (binary-string pitfalls) or Buffer.
 */
export function bytesToBase64(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i]!;
    const b1 = bytes[i + 1];
    const b2 = bytes[i + 2];
    out += BASE64_ALPHABET[b0 >> 2];
    out += BASE64_ALPHABET[((b0 & 0x03) << 4) | ((b1 ?? 0) >> 4)];
    out += b1 === undefined ? '=' : BASE64_ALPHABET[((b1 & 0x0f) << 2) | ((b2 ?? 0) >> 6)];
    out += b2 === undefined ? '=' : BASE64_ALPHABET[b2 & 0x3f];
  }
  return out;
}

export function base64ToBytes(b64: string): Uint8Array {
  const clean = b64.replace(/=+$/, '');
  const out = new Uint8Array(Math.floor((clean.length * 3) / 4));
  let o = 0;
  for (let i = 0; i < clean.length; i += 4) {
    const n0 = BASE64_LOOKUP[clean[i] as string];
    const n1 = BASE64_LOOKUP[clean[i + 1] as string];
    const n2 = clean[i + 2] === undefined ? undefined : BASE64_LOOKUP[clean[i + 2] as string];
    const n3 = clean[i + 3] === undefined ? undefined : BASE64_LOOKUP[clean[i + 3] as string];
    if (n0 === undefined || n1 === undefined) throw new Error('Invalid base64 input');
    out[o++] = (n0 << 2) | (n1 >> 4);
    if (n2 !== undefined) out[o++] = ((n1 & 0x0f) << 4) | (n2 >> 2);
    if (n3 !== undefined) out[o++] = ((n2! & 0x03) << 6) | n3;
  }
  return out;
}

/** Big-endian u32 serialization for counters and ids. */
export function u32ToBytes(n: number): Uint8Array {
  if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) {
    throw new Error(`Value out of u32 range: ${n}`);
  }
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n, false);
  return out;
}

export function bytesToU32(bytes: Uint8Array, offset = 0): number {
  if (bytes.length < offset + 4) throw new Error('Buffer too short for u32');
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(offset, false);
}
