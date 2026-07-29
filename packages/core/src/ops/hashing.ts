/**
 * Hashing operations.
 *
 * SHA-1 and SHA-2 come from WebCrypto, which is present in Node 20+ and every
 * target browser. MD5, CRC-32, Adler-32 and Keccak are implemented here
 * because WebCrypto does not offer them, and each is checked against its
 * published test vectors in `test/vectors.test.ts`.
 */

import { getKeyBytes, getOption } from '../args.js';
import { base64Encode, concat, hexEncode, utf8Encode } from '../bytes.js';
import { OperationError, type Bytes, type Operation } from '../types.js';

function subtle(): SubtleCrypto {
  const c = globalThis.crypto;
  if (!c?.subtle) {
    throw new OperationError('WebCrypto is unavailable. Zest needs Node 20+ or a browser with a secure context.');
  }
  return c.subtle;
}

// --- MD5 --------------------------------------------------------------------

const MD5_SHIFTS = [
  7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
  5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

const MD5_K = (() => {
  const k = new Int32Array(64);
  for (let i = 0; i < 64; i++) k[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 0x100000000) | 0;
  return k;
})();

export function md5(message: Bytes): Bytes {
  const bitLength = message.length * 8;
  const padLength = (56 - ((message.length + 1) % 64) + 64) % 64;
  const total = message.length + 1 + padLength + 8;

  const buffer = new Uint8Array(total);
  buffer.set(message);
  buffer[message.length] = 0x80;
  const view = new DataView(buffer.buffer);
  view.setUint32(total - 8, bitLength >>> 0, true);
  view.setUint32(total - 4, Math.floor(bitLength / 0x100000000), true);

  let a0 = 0x67452301 | 0;
  let b0 = 0xefcdab89 | 0;
  let c0 = 0x98badcfe | 0;
  let d0 = 0x10325476 | 0;

  const block = new Int32Array(16);
  for (let offset = 0; offset < total; offset += 64) {
    for (let i = 0; i < 16; i++) block[i] = view.getInt32(offset + i * 4, true);

    let a = a0;
    let b = b0;
    let c = c0;
    let d = d0;

    for (let i = 0; i < 64; i++) {
      let f: number;
      let g: number;
      if (i < 16) {
        f = (b & c) | (~b & d);
        g = i;
      } else if (i < 32) {
        f = (d & b) | (~d & c);
        g = (5 * i + 1) % 16;
      } else if (i < 48) {
        f = b ^ c ^ d;
        g = (3 * i + 5) % 16;
      } else {
        f = c ^ (b | ~d);
        g = (7 * i) % 16;
      }
      const sum = (f + a + MD5_K[i] + block[g]) | 0;
      const shift = MD5_SHIFTS[i];
      a = d;
      d = c;
      c = b;
      b = (b + ((sum << shift) | (sum >>> (32 - shift)))) | 0;
    }

    a0 = (a0 + a) | 0;
    b0 = (b0 + b) | 0;
    c0 = (c0 + c) | 0;
    d0 = (d0 + d) | 0;
  }

  const out = new Uint8Array(16);
  const outView = new DataView(out.buffer);
  outView.setInt32(0, a0, true);
  outView.setInt32(4, b0, true);
  outView.setInt32(8, c0, true);
  outView.setInt32(12, d0, true);
  return out;
}

// --- Checksums --------------------------------------------------------------

const CRC32_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[i] = c >>> 0;
  }
  return table;
})();

export function crc32(bytes: Bytes): number {
  let crc = 0xffffffff;
  for (let i = 0; i < bytes.length; i++) crc = CRC32_TABLE[(crc ^ bytes[i]) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

export function adler32(bytes: Bytes): number {
  let a = 1;
  let b = 0;
  for (let i = 0; i < bytes.length; i++) {
    a = (a + bytes[i]) % 65521;
    b = (b + a) % 65521;
  }
  return ((b << 16) | a) >>> 0;
}

// --- Keccak / SHA-3 ---------------------------------------------------------

const MASK64 = (1n << 64n) - 1n;

const KECCAK_RC = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];

// Rotation offsets indexed as x + 5y.
const KECCAK_RHO = [
  0, 1, 62, 28, 27,
  36, 44, 6, 55, 20,
  3, 10, 43, 25, 39,
  41, 45, 15, 21, 8,
  18, 2, 61, 56, 14,
];

function rotl64(value: bigint, count: number): bigint {
  if (count === 0) return value;
  return ((value << BigInt(count)) | (value >> BigInt(64 - count))) & MASK64;
}

function keccakF(state: bigint[]): void {
  for (let round = 0; round < 24; round++) {
    const c = new Array<bigint>(5);
    for (let x = 0; x < 5; x++) c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];

    const d = new Array<bigint>(5);
    for (let x = 0; x < 5; x++) d[x] = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1);

    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) state[x + 5 * y] ^= d[x];
    }

    const b = new Array<bigint>(25).fill(0n);
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl64(state[x + 5 * y], KECCAK_RHO[x + 5 * y]);
      }
    }

    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        state[x + 5 * y] = b[x + 5 * y] ^ (~b[((x + 1) % 5) + 5 * y] & MASK64 & b[((x + 2) % 5) + 5 * y]);
      }
    }

    state[0] ^= KECCAK_RC[round];
  }
}

export function keccak(message: Bytes, outputBits: number, suffix: number): Bytes {
  const outputBytes = outputBits / 8;
  const rate = 200 - 2 * outputBytes;

  const padLength = rate - (message.length % rate);
  const padded = new Uint8Array(message.length + padLength);
  padded.set(message);
  padded[message.length] = suffix;
  padded[padded.length - 1] |= 0x80;

  const state = new Array<bigint>(25).fill(0n);
  for (let offset = 0; offset < padded.length; offset += rate) {
    for (let i = 0; i < rate / 8; i++) {
      let lane = 0n;
      for (let b = 7; b >= 0; b--) lane = (lane << 8n) | BigInt(padded[offset + i * 8 + b]);
      state[i] ^= lane;
    }
    keccakF(state);
  }

  const out = new Uint8Array(outputBytes);
  let written = 0;
  while (written < outputBytes) {
    for (let i = 0; i < rate / 8 && written < outputBytes; i++) {
      let lane = state[i];
      for (let b = 0; b < 8 && written < outputBytes; b++) {
        out[written++] = Number(lane & 0xffn);
        lane >>= 8n;
      }
    }
    if (written < outputBytes) keccakF(state);
  }
  return out;
}

// --- HMAC over a synchronous hash -------------------------------------------

function hmacSync(hash: (b: Bytes) => Bytes, blockSize: number, key: Bytes, message: Bytes): Bytes {
  const normalised = key.length > blockSize ? hash(key) : key;
  const padded = new Uint8Array(blockSize);
  padded.set(normalised);

  const inner = new Uint8Array(blockSize);
  const outer = new Uint8Array(blockSize);
  for (let i = 0; i < blockSize; i++) {
    inner[i] = padded[i] ^ 0x36;
    outer[i] = padded[i] ^ 0x5c;
  }
  return hash(concat(outer, hash(concat(inner, message))));
}

// --- Output shaping ---------------------------------------------------------

const DIGEST_FORMATS = ['Hex', 'Base64', 'Raw bytes'] as const;

function formatDigest(digest: Bytes, format: (typeof DIGEST_FORMATS)[number]): Bytes {
  if (format === 'Raw bytes') return digest;
  if (format === 'Base64') return utf8Encode(base64Encode(digest));
  return utf8Encode(hexEncode(digest));
}

const formatArg = { name: 'format', type: 'select', options: DIGEST_FORMATS, default: 'Hex' } as const;

function digestOp(config: {
  id: string;
  name: string;
  description: string;
  keywords?: string[];
  compute: (input: Bytes) => Bytes | Promise<Bytes>;
  examples?: Operation['examples'];
}): Operation {
  return {
    id: config.id,
    name: config.name,
    category: 'Hashing',
    description: config.description,
    keywords: config.keywords,
    args: [formatArg],
    examples: config.examples,
    async run(input, args) {
      return formatDigest(await config.compute(input), getOption(args, 'format', DIGEST_FORMATS, 'Hex'));
    },
  };
}

const SHA2_SIZES = ['SHA-256', 'SHA-384', 'SHA-512'] as const;
const SHA3_SIZES = ['224', '256', '384', '512'] as const;
const HMAC_ALGORITHMS = ['SHA-256', 'SHA-384', 'SHA-512', 'SHA-1', 'MD5'] as const;

export const hashingOps: Operation[] = [
  digestOp({
    id: 'md5',
    name: 'MD5',
    description: 'MD5 digest. Broken for signatures since 2004 — treat a match as an integrity check, never as proof of authenticity.',
    keywords: ['digest', 'checksum'],
    compute: md5,
    examples: [{ input: 'hello', output: '5d41402abc4b2a76b9719d911017c592' }],
  }),
  digestOp({
    id: 'sha1',
    name: 'SHA-1',
    description: 'SHA-1 digest. Collisions are practical (SHAttered, 2017); still seen in Git object IDs and legacy TLS.',
    keywords: ['digest', 'git'],
    compute: async (input) => new Uint8Array(await subtle().digest('SHA-1', input)),
    examples: [{ input: 'hello', output: 'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d' }],
  }),
  {
    id: 'sha2',
    name: 'SHA-2',
    category: 'Hashing',
    description: 'SHA-2 digest at the size you choose. The default for anything that needs to stay trustworthy.',
    keywords: ['sha256', 'sha512', 'sha384', 'digest'],
    args: [{ name: 'size', type: 'select', options: SHA2_SIZES, default: 'SHA-256' }, formatArg],
    examples: [
      { input: 'hello', output: '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824' },
      { name: 'SHA-512', input: 'hello', args: { size: 'SHA-512' }, output: '9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043' },
    ],
    async run(input, args) {
      const size = getOption(args, 'size', SHA2_SIZES, 'SHA-256');
      const digest = new Uint8Array(await subtle().digest(size, input));
      return formatDigest(digest, getOption(args, 'format', DIGEST_FORMATS, 'Hex'));
    },
  },
  {
    id: 'sha3',
    name: 'SHA-3',
    category: 'Hashing',
    description: 'SHA-3 digest (FIPS 202). A sponge construction, so it is immune to the length-extension attacks SHA-2 allows.',
    keywords: ['keccak', 'fips202', 'digest'],
    args: [{ name: 'size', type: 'select', options: SHA3_SIZES, default: '256' }, formatArg],
    examples: [{ input: '', output: 'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a' }],
    run(input, args) {
      const size = Number(getOption(args, 'size', SHA3_SIZES, '256'));
      return formatDigest(keccak(input, size, 0x06), getOption(args, 'format', DIGEST_FORMATS, 'Hex'));
    },
  },
  {
    id: 'keccak',
    name: 'Keccak',
    category: 'Hashing',
    description: 'Original Keccak digest, with the pre-standard 0x01 padding. This is what Ethereum means by "sha3".',
    keywords: ['ethereum', 'evm', 'solidity', 'sha3'],
    args: [{ name: 'size', type: 'select', options: SHA3_SIZES, default: '256' }, formatArg],
    examples: [{ input: '', output: 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470' }],
    run(input, args) {
      const size = Number(getOption(args, 'size', SHA3_SIZES, '256'));
      return formatDigest(keccak(input, size, 0x01), getOption(args, 'format', DIGEST_FORMATS, 'Hex'));
    },
  },
  {
    id: 'hmac',
    name: 'HMAC',
    category: 'Hashing',
    description: 'Keyed hash for message authentication. Unlike a bare hash, an attacker cannot recompute it without the key.',
    keywords: ['mac', 'signature', 'authentication'],
    args: [
      { name: 'key', type: 'key', default: '', defaultEncoding: 'utf8' },
      { name: 'algorithm', type: 'select', options: HMAC_ALGORITHMS, default: 'SHA-256' },
      formatArg,
    ],
    examples: [
      {
        name: 'RFC 4231 test case 1',
        input: 'Hi There',
        args: { key: 'hex:0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b', algorithm: 'SHA-256' },
        output: 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7',
      },
    ],
    async run(input, args) {
      const key = getKeyBytes(args, 'key');
      const algorithm = getOption(args, 'algorithm', HMAC_ALGORITHMS, 'SHA-256');
      const format = getOption(args, 'format', DIGEST_FORMATS, 'Hex');

      if (algorithm === 'MD5') {
        return formatDigest(hmacSync(md5, 64, key, input), format);
      }
      const cryptoKey = await subtle().importKey('raw', key, { name: 'HMAC', hash: algorithm }, false, ['sign']);
      const signature = new Uint8Array(await subtle().sign('HMAC', cryptoKey, input));
      return formatDigest(signature, format);
    },
  },
  {
    id: 'crc32',
    name: 'CRC-32',
    category: 'Hashing',
    description: 'CRC-32 checksum (IEEE 802.3, the ZIP and PNG polynomial). Detects accidental corruption; trivially forged on purpose.',
    keywords: ['checksum', 'zip', 'png'],
    examples: [{ input: 'hello', output: '3610a686' }],
    run(input) {
      return utf8Encode(crc32(input).toString(16).padStart(8, '0'));
    },
  },
  {
    id: 'adler32',
    name: 'Adler-32',
    category: 'Hashing',
    description: 'Adler-32 checksum. Faster than CRC-32 and used by zlib, but weak on short inputs.',
    keywords: ['checksum', 'zlib'],
    examples: [{ input: 'hello', output: '062c0215' }],
    run(input) {
      return utf8Encode(adler32(input).toString(16).padStart(8, '0'));
    },
  },
  {
    id: 'pbkdf2',
    name: 'PBKDF2',
    category: 'Hashing',
    description: 'Derives a key from a password by iterating a hash. Raise the iteration count until derivation takes ~100ms on your slowest client.',
    keywords: ['kdf', 'password', 'derive', 'rfc2898'],
    args: [
      { name: 'salt', type: 'key', default: '', defaultEncoding: 'utf8' },
      { name: 'iterations', type: 'number', default: 100000, min: 1 },
      { name: 'keyLength', label: 'Key length (bits)', type: 'number', default: 256, min: 8, step: 8 },
      { name: 'hash', type: 'select', options: ['SHA-256', 'SHA-384', 'SHA-512', 'SHA-1'], default: 'SHA-256' },
      formatArg,
    ],
    examples: [
      {
        name: 'RFC 6070 test case 1 (SHA-1)',
        input: 'password',
        args: { salt: 'salt', iterations: 1, keyLength: 160, hash: 'SHA-1' },
        output: '0c60c80f961f0e71f3a9b524af6012062fe037a6',
      },
    ],
    async run(input, args) {
      const iterations = getNumberStrict(args, 'iterations', 100000);
      const keyLength = getNumberStrict(args, 'keyLength', 256);
      if (keyLength % 8 !== 0) throw new OperationError(`Key length must be a whole number of bytes; ${keyLength} bits is not.`);
      const hash = getOption(args, 'hash', ['SHA-256', 'SHA-384', 'SHA-512', 'SHA-1'] as const, 'SHA-256');

      const baseKey = await subtle().importKey('raw', input, 'PBKDF2', false, ['deriveBits']);
      const bits = await subtle().deriveBits(
        { name: 'PBKDF2', salt: getKeyBytes(args, 'salt'), iterations, hash },
        baseKey,
        keyLength,
      );
      return formatDigest(new Uint8Array(bits), getOption(args, 'format', DIGEST_FORMATS, 'Hex'));
    },
  },
];

function getNumberStrict(args: Record<string, unknown>, name: string, fallback: number): number {
  const value = args[name];
  if (value === undefined || value === null || value === '') return fallback;
  const num = Number(value);
  if (!Number.isFinite(num) || num <= 0) {
    throw new OperationError(`Argument ${JSON.stringify(name)} must be a positive number, got ${JSON.stringify(value)}.`);
  }
  return num;
}
