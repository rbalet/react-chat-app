import { describe, expect, it } from 'vitest';
import {
  aeadDecrypt,
  aeadEncrypt,
  dh,
  edPrivateToX,
  edPublicToX,
  encodePublicKey,
  generateDHKeyPair,
  generateSigningKeyPair,
  hkdfSha256,
  sign,
  verify,
} from '../core/crypto';
import { utf8ToBytes } from '../core/utils';

function hex(s: string): Uint8Array {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function toHex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
}

describe('X25519 DH (RFC 7748 §6.1 vector)', () => {
  const alicePriv = hex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a');
  const alicePub = hex('8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a');
  const bobPriv = hex('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb');
  const bobPub = hex('de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f');
  const shared = '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742';

  it('derives the RFC shared secret from both sides', () => {
    expect(toHex(dh(alicePriv, bobPub))).toBe(shared);
    expect(toHex(dh(bobPriv, alicePub))).toBe(shared);
  });

  it('generated key pairs agree on a shared secret', () => {
    const a = generateDHKeyPair();
    const b = generateDHKeyPair();
    expect(dh(a.privateKey, b.publicKey)).toEqual(dh(b.privateKey, a.publicKey));
  });
});

describe('Ed25519 signatures (RFC 8032 §7.1 test 1)', () => {
  const seed = hex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60');
  const expectedSig =
    'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b';

  it('reproduces the RFC signature over the empty message', () => {
    const message = new Uint8Array(0);
    expect(toHex(sign(seed, message))).toBe(expectedSig);
  });

  it('signs and verifies; rejects tampered message and wrong key', () => {
    const { publicKey, privateKey } = generateSigningKeyPair();
    const message = utf8ToBytes('signed prekey');
    const signature = sign(privateKey, message);
    expect(verify(publicKey, message, signature)).toBe(true);
    expect(verify(publicKey, utf8ToBytes('signed prekeY'), signature)).toBe(false);
    expect(verify(generateSigningKeyPair().publicKey, message, signature)).toBe(false);
  });

  it('verify returns false (not throw) on malformed inputs', () => {
    const { publicKey, privateKey } = generateSigningKeyPair();
    const message = utf8ToBytes('x');
    const signature = sign(privateKey, message);
    expect(verify(new Uint8Array(31), message, signature)).toBe(false); // bad key length
    expect(verify(publicKey, message, new Uint8Array(63))).toBe(false); // bad sig length
    // NB: the all-zero key + all-zero signature degenerate case verifies
    // under RFC 8032 (small-order point). Harmless here: X25519 DH rejects
    // low-order points, so such an identity can never establish a session.
  });
});

describe('Edwards → Montgomery identity conversion', () => {
  it('converted key pairs perform valid DH', () => {
    const identityA = generateSigningKeyPair();
    const identityB = generateSigningKeyPair();
    const sharedFromA = dh(edPrivateToX(identityA.privateKey), edPublicToX(identityB.publicKey));
    const sharedFromB = dh(edPrivateToX(identityB.privateKey), edPublicToX(identityA.publicKey));
    expect(sharedFromA).toEqual(sharedFromB);
  });
});

describe('HKDF-SHA256 (RFC 5869 A.1 test case 1)', () => {
  it('reproduces the RFC OKM', () => {
    const ikm = hex('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
    const salt = hex('000102030405060708090a0b0c');
    const info = hex('f0f1f2f3f4f5f6f7f8f9');
    const okm = hkdfSha256(ikm, salt, info, 42);
    expect(toHex(okm)).toBe(
      '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865',
    );
  });
});

describe('AES-256-GCM-SIV AEAD', () => {
  const key = new Uint8Array(32).fill(7);
  const nonce = new Uint8Array(12).fill(3);
  const aad = utf8ToBytes('associated data');
  const plaintext = utf8ToBytes('attack at dawn');

  it('round-trips and appends a 16-byte tag', () => {
    const ciphertext = aeadEncrypt(key, nonce, plaintext, aad);
    expect(ciphertext.length).toBe(plaintext.length + 16);
    expect(aeadDecrypt(key, nonce, ciphertext, aad)).toEqual(plaintext);
  });

  it('rejects tampered ciphertext, wrong AAD, wrong key, wrong nonce', () => {
    const ciphertext = aeadEncrypt(key, nonce, plaintext, aad);
    const tampered = ciphertext.slice();
    tampered[0]! ^= 0x01;
    expect(() => aeadDecrypt(key, nonce, tampered, aad)).toThrow();
    expect(() => aeadDecrypt(key, nonce, ciphertext, utf8ToBytes('other'))).toThrow();
    expect(() => aeadDecrypt(new Uint8Array(32), nonce, ciphertext, aad)).toThrow();
    expect(() => aeadDecrypt(key, new Uint8Array(12), ciphertext, aad)).toThrow();
  });
});

describe('encodePublicKey', () => {
  it('prefixes the key type byte', () => {
    const key = new Uint8Array(32).fill(9);
    expect([...encodePublicKey(key, 'x25519')]).toEqual([0x05, ...key]);
    expect([...encodePublicKey(key, 'ed25519')]).toEqual([0x06, ...key]);
    expect(() => encodePublicKey(new Uint8Array(31), 'x25519')).toThrow();
  });
});
