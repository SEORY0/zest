/**
 * Encryption operations.
 *
 * AES goes through WebCrypto rather than a hand-rolled implementation — the
 * browser and Node both ship a constant-time one, and reimplementing a block
 * cipher is exactly the kind of thing this tool should not do.
 *
 * The classical ciphers (ROT, Vigenère, RC4, XOR) are here because they turn
 * up constantly in CTFs, malware config blobs and legacy formats. They are not
 * secure and each says so.
 */

import { getBoolean, getKeyBytes, getNumber, getOption, getString } from '../args.js';
import { base64Encode, concat, hexEncode, utf8Decode, utf8Encode } from '../bytes.js';
import { OperationError, type Bytes, type Operation } from '../types.js';

function subtle(): SubtleCrypto {
  const c = globalThis.crypto;
  if (!c?.subtle) {
    throw new OperationError('WebCrypto is unavailable. Zest needs Node 20+ or a browser with a secure context.');
  }
  return c.subtle;
}

const AES_MODES = ['GCM', 'CBC', 'CTR'] as const;
type AesMode = (typeof AES_MODES)[number];

const OUTPUT_FORMATS = ['Hex', 'Base64', 'Raw bytes'] as const;
const INPUT_FORMATS = ['Hex', 'Base64', 'Raw bytes'] as const;

function shapeOutput(bytes: Bytes, format: (typeof OUTPUT_FORMATS)[number]): Bytes {
  if (format === 'Raw bytes') return bytes;
  if (format === 'Base64') return utf8Encode(base64Encode(bytes));
  return utf8Encode(hexEncode(bytes));
}

function parseInput(bytes: Bytes, format: (typeof INPUT_FORMATS)[number]): Bytes {
  if (format === 'Raw bytes') return bytes;
  const text = utf8Decode(bytes).trim();
  if (format === 'Base64') {
    // Reuse the tolerant decoder so pasted ciphertext with newlines still works.
    return decodeBase64Loose(text);
  }
  const clean = text.replace(/[^0-9a-fA-F]/g, '');
  if (clean.length % 2 !== 0) throw new OperationError('Hex ciphertext has an odd number of digits.');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
  return out;
}

function decodeBase64Loose(text: string): Bytes {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  const lookup = new Int16Array(128).fill(-1);
  for (let i = 0; i < 64; i++) lookup[alphabet.charCodeAt(i)] = i;
  lookup['-'.charCodeAt(0)] = 62;
  lookup['_'.charCodeAt(0)] = 63;

  const symbols: number[] = [];
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    const value = code < 128 ? lookup[code] : -1;
    if (value >= 0) symbols.push(value);
  }
  const out = new Uint8Array(Math.floor((symbols.length * 3) / 4));
  let o = 0;
  for (let i = 0; i < symbols.length; i += 4) {
    const remaining = symbols.length - i;
    const quad = (symbols[i] << 18) | (symbols[i + 1] << 12) | ((remaining > 2 ? symbols[i + 2] : 0) << 6) | (remaining > 3 ? symbols[i + 3] : 0);
    out[o++] = (quad >> 16) & 0xff;
    if (remaining > 2) out[o++] = (quad >> 8) & 0xff;
    if (remaining > 3) out[o++] = quad & 0xff;
  }
  return out.subarray(0, o);
}

function checkKeyLength(key: Bytes): void {
  if (![16, 24, 32].includes(key.length)) {
    throw new OperationError(
      `AES needs a 16, 24 or 32-byte key; got ${key.length} bytes. If the key is hex, set the key encoding to hex.`,
    );
  }
}

function aesParams(mode: AesMode, iv: Bytes, tagLength: number): AesCbcParams | AesCtrParams | AesGcmParams {
  switch (mode) {
    case 'CBC':
      if (iv.length !== 16) throw new OperationError(`AES-CBC needs a 16-byte IV; got ${iv.length} bytes.`);
      return { name: 'AES-CBC', iv };
    case 'CTR':
      if (iv.length !== 16) throw new OperationError(`AES-CTR needs a 16-byte counter block; got ${iv.length} bytes.`);
      return { name: 'AES-CTR', counter: iv, length: 64 };
    case 'GCM':
      if (iv.length === 0) throw new OperationError('AES-GCM needs a nonce. 12 bytes is the standard size.');
      return { name: 'AES-GCM', iv, tagLength };
  }
}

const ALGORITHM_NAME: Record<AesMode, string> = { GCM: 'AES-GCM', CBC: 'AES-CBC', CTR: 'AES-CTR' };

// --- Stream and classical ciphers -------------------------------------------

function xorBytes(input: Bytes, key: Bytes): Bytes {
  if (key.length === 0) throw new OperationError('XOR needs a key of at least one byte.');
  const out = new Uint8Array(input.length);
  for (let i = 0; i < input.length; i++) out[i] = input[i] ^ key[i % key.length];
  return out;
}

function rc4(input: Bytes, key: Bytes): Bytes {
  if (key.length === 0) throw new OperationError('RC4 needs a key of at least one byte.');
  const s = new Uint8Array(256);
  for (let i = 0; i < 256; i++) s[i] = i;

  let j = 0;
  for (let i = 0; i < 256; i++) {
    j = (j + s[i] + key[i % key.length]) & 0xff;
    [s[i], s[j]] = [s[j], s[i]];
  }

  const out = new Uint8Array(input.length);
  let i = 0;
  j = 0;
  for (let k = 0; k < input.length; k++) {
    i = (i + 1) & 0xff;
    j = (j + s[i]) & 0xff;
    [s[i], s[j]] = [s[j], s[i]];
    out[k] = input[k] ^ s[(s[i] + s[j]) & 0xff];
  }
  return out;
}

function rotateAlphabet(text: string, amount: number): string {
  const shift = ((amount % 26) + 26) % 26;
  return text.replace(/[a-zA-Z]/g, (ch) => {
    const base = ch <= 'Z' ? 65 : 97;
    return String.fromCharCode(((ch.charCodeAt(0) - base + shift) % 26) + base);
  });
}

function vigenere(text: string, key: string, decode: boolean): string {
  const cleanKey = key.replace(/[^a-zA-Z]/g, '').toLowerCase();
  if (cleanKey.length === 0) throw new OperationError('Vigenère needs a key containing at least one letter.');

  let keyIndex = 0;
  return text.replace(/[a-zA-Z]/g, (ch) => {
    const base = ch <= 'Z' ? 65 : 97;
    const shift = cleanKey.charCodeAt(keyIndex % cleanKey.length) - 97;
    keyIndex++;
    const offset = decode ? 26 - shift : shift;
    return String.fromCharCode(((ch.charCodeAt(0) - base + offset) % 26) + base);
  });
}

export const encryptionOps: Operation[] = [
  {
    id: 'aes-encrypt',
    name: 'AES encrypt',
    category: 'Encryption',
    description: 'Encrypts with AES. GCM also authenticates the ciphertext and appends a tag — prefer it unless a format forces CBC or CTR on you.',
    keywords: ['rijndael', 'gcm', 'cbc', 'ctr', 'symmetric'],
    args: [
      { name: 'key', type: 'key', default: '', defaultEncoding: 'hex' },
      { name: 'iv', label: 'IV / nonce', type: 'key', default: '', defaultEncoding: 'hex', hint: '16 bytes for CBC and CTR, 12 for GCM' },
      { name: 'mode', type: 'select', options: AES_MODES, default: 'GCM' },
      { name: 'aad', label: 'Additional data (GCM)', type: 'key', default: '', defaultEncoding: 'utf8' },
      { name: 'tagLength', label: 'GCM tag length (bits)', type: 'number', default: 128 },
      { name: 'output', type: 'select', options: OUTPUT_FORMATS, default: 'Hex' },
    ],
    examples: [
      {
        name: 'AES-128-CBC',
        input: 'Attack at dawn!!',
        args: { key: 'hex:000102030405060708090a0b0c0d0e0f', iv: 'hex:000102030405060708090a0b0c0d0e0f', mode: 'CBC' },
        output: '90a38387d67662f6663d529f748e0b5a191169e48f69ddebbe4412196196bc98',
      },
    ],
    async run(input, args) {
      const key = getKeyBytes(args, 'key', 'hex');
      checkKeyLength(key);
      const mode = getOption(args, 'mode', AES_MODES, 'GCM');
      const iv = getKeyBytes(args, 'iv', 'hex');
      const tagLength = getNumber(args, 'tagLength', 128);

      const cryptoKey = await subtle().importKey('raw', key, ALGORITHM_NAME[mode], false, ['encrypt']);
      const params = aesParams(mode, iv, tagLength);
      if (mode === 'GCM') {
        const aad = getKeyBytes(args, 'aad');
        if (aad.length > 0) (params as AesGcmParams).additionalData = aad;
      }

      const ciphertext = new Uint8Array(await subtle().encrypt(params, cryptoKey, input));
      return shapeOutput(ciphertext, getOption(args, 'output', OUTPUT_FORMATS, 'Hex'));
    },
  },
  {
    id: 'aes-decrypt',
    name: 'AES decrypt',
    category: 'Encryption',
    description: 'Decrypts AES ciphertext. For GCM the authentication tag must be the last 16 bytes of the input; a wrong key and a tampered message both fail the same way.',
    keywords: ['rijndael', 'gcm', 'cbc', 'ctr', 'symmetric'],
    args: [
      { name: 'key', type: 'key', default: '', defaultEncoding: 'hex' },
      { name: 'iv', label: 'IV / nonce', type: 'key', default: '', defaultEncoding: 'hex' },
      { name: 'mode', type: 'select', options: AES_MODES, default: 'GCM' },
      { name: 'aad', label: 'Additional data (GCM)', type: 'key', default: '', defaultEncoding: 'utf8' },
      { name: 'tagLength', label: 'GCM tag length (bits)', type: 'number', default: 128 },
      { name: 'input', label: 'Ciphertext format', type: 'select', options: INPUT_FORMATS, default: 'Hex' },
    ],
    async run(input, args) {
      const key = getKeyBytes(args, 'key', 'hex');
      checkKeyLength(key);
      const mode = getOption(args, 'mode', AES_MODES, 'GCM');
      const iv = getKeyBytes(args, 'iv', 'hex');
      const tagLength = getNumber(args, 'tagLength', 128);
      const ciphertext = parseInput(input, getOption(args, 'input', INPUT_FORMATS, 'Hex'));

      const cryptoKey = await subtle().importKey('raw', key, ALGORITHM_NAME[mode], false, ['decrypt']);
      const params = aesParams(mode, iv, tagLength);
      if (mode === 'GCM') {
        const aad = getKeyBytes(args, 'aad');
        if (aad.length > 0) (params as AesGcmParams).additionalData = aad;
      }

      try {
        return new Uint8Array(await subtle().decrypt(params, cryptoKey, ciphertext));
      } catch {
        throw new OperationError(
          mode === 'GCM'
            ? 'AES-GCM decryption failed. The key, nonce, additional data or tag does not match — GCM cannot tell you which.'
            : 'AES decryption failed. Check the key, IV and that the ciphertext length is a multiple of 16 bytes.',
        );
      }
    },
  },
  {
    id: 'xor',
    name: 'XOR',
    category: 'Encryption',
    description: 'XORs the input against a repeating key. Symmetric — running it twice with the same key returns the original.',
    keywords: ['obfuscation', 'malware', 'ctf'],
    args: [
      { name: 'key', type: 'key', default: '', defaultEncoding: 'hex' },
      { name: 'output', type: 'select', options: OUTPUT_FORMATS, default: 'Raw bytes' },
    ],
    examples: [
      { name: 'Single-byte key', input: 'Hello', args: { key: 'hex:41', output: 'Hex' }, output: '09242d2d2e' },
    ],
    run(input, args) {
      const result = xorBytes(input, getKeyBytes(args, 'key', 'hex'));
      return shapeOutput(result, getOption(args, 'output', OUTPUT_FORMATS, 'Raw bytes'));
    },
  },
  {
    id: 'xor-brute-force',
    name: 'XOR brute force',
    category: 'Encryption',
    description: 'Tries every single-byte XOR key and reports the ones that produce printable text. The starting point for most obfuscated blobs.',
    keywords: ['crack', 'ctf', 'malware', 'bruteforce'],
    args: [
      { name: 'crib', label: 'Known plaintext', type: 'string', default: '', hint: 'Only show keys whose output contains this text' },
      { name: 'printableOnly', type: 'boolean', default: true },
      { name: 'sampleLength', type: 'number', default: 80, min: 8 },
    ],
    examples: [
      { name: 'Recovers key 0x41', input: '09242d2d2e', args: { crib: 'Hello' }, output: 'key=0x41  Hello' },
    ],
    run(input, args) {
      // Accept hex-looking input directly so this composes after a capture.
      const text = utf8Decode(input).trim();
      const data = /^[0-9a-fA-F\s]+$/.test(text) && text.replace(/\s/g, '').length % 2 === 0 && text.length > 1
        ? parseInput(input, 'Hex')
        : input;

      const crib = getString(args, 'crib');
      const printableOnly = getBoolean(args, 'printableOnly', true);
      const sampleLength = getNumber(args, 'sampleLength', 80);

      const lines: string[] = [];
      for (let key = 0; key < 256; key++) {
        const decoded = new Uint8Array(data.length);
        for (let i = 0; i < data.length; i++) decoded[i] = data[i] ^ key;

        const sample = utf8Decode(decoded.subarray(0, sampleLength));
        if (crib && !sample.includes(crib)) continue;
        if (printableOnly && !/^[\x09\x0a\x0d\x20-\x7e]*$/.test(sample)) continue;

        lines.push(`key=0x${key.toString(16).padStart(2, '0')}  ${sample.replace(/\n/g, '\\n')}`);
      }
      return utf8Encode(lines.length ? lines.join('\n') : 'No single-byte key produced matching output.');
    },
  },
  {
    id: 'rot',
    name: 'ROT',
    category: 'Encryption',
    description: 'Rotates letters through the alphabet. ROT13 is its own inverse. A puzzle, not a cipher.',
    keywords: ['rot13', 'caesar', 'shift'],
    args: [{ name: 'amount', type: 'number', default: 13, min: -25, max: 25 }],
    examples: [
      { input: 'Hello, World!', output: 'Uryyb, Jbeyq!' },
      { name: 'Caesar shift of 3', input: 'attack', args: { amount: 3 }, output: 'dwwdfn' },
    ],
    run(input, args) {
      return utf8Encode(rotateAlphabet(utf8Decode(input), getNumber(args, 'amount', 13)));
    },
  },
  {
    id: 'rot47',
    name: 'ROT47',
    category: 'Encryption',
    description: 'Rotates every printable ASCII character, not just letters, so digits and punctuation change too. Self-inverse at the default of 47.',
    keywords: ['rot', 'shift', 'ctf'],
    args: [{ name: 'amount', type: 'number', default: 47, min: -94, max: 94 }],
    examples: [{ input: 'Hello, World!', output: 'w6==@[ (@C=5P' }],
    run(input, args) {
      const amount = ((getNumber(args, 'amount', 47) % 94) + 94) % 94;
      return utf8Encode(
        utf8Decode(input).replace(/[!-~]/g, (ch) => String.fromCharCode(((ch.charCodeAt(0) - 33 + amount) % 94) + 33)),
      );
    },
  },
  {
    id: 'vigenere-encode',
    name: 'Vigenère encode',
    category: 'Encryption',
    description: 'Polyalphabetic substitution using a repeating keyword. Broken by frequency analysis once you know the key length.',
    keywords: ['classical', 'ctf', 'polyalphabetic'],
    args: [{ name: 'key', type: 'string', default: '' }],
    examples: [{ input: 'attackatdawn', args: { key: 'lemon' }, output: 'lxfopvefrnhr' }],
    run(input, args) {
      return utf8Encode(vigenere(utf8Decode(input), getString(args, 'key'), false));
    },
  },
  {
    id: 'vigenere-decode',
    name: 'Vigenère decode',
    category: 'Encryption',
    description: 'Reverses a Vigenère encoding with a known keyword.',
    keywords: ['classical', 'ctf', 'polyalphabetic'],
    args: [{ name: 'key', type: 'string', default: '' }],
    examples: [{ input: 'lxfopvefrnhr', args: { key: 'lemon' }, output: 'attackatdawn' }],
    run(input, args) {
      return utf8Encode(vigenere(utf8Decode(input), getString(args, 'key'), true));
    },
  },
  {
    id: 'rc4',
    name: 'RC4',
    category: 'Encryption',
    description: 'RC4 stream cipher. Symmetric, and prohibited in TLS since RFC 7465 — you will meet it in malware and old protocols, not in anything you should build.',
    keywords: ['arcfour', 'stream', 'malware'],
    args: [
      { name: 'key', type: 'key', default: '', defaultEncoding: 'utf8' },
      { name: 'output', type: 'select', options: OUTPUT_FORMATS, default: 'Raw bytes' },
    ],
    examples: [
      { name: 'RFC 6229 40-bit key', input: 'Plaintext', args: { key: 'Key', output: 'Hex' }, output: 'bbf316e8d940af0ad3' },
    ],
    run(input, args) {
      const result = rc4(input, getKeyBytes(args, 'key'));
      return shapeOutput(result, getOption(args, 'output', OUTPUT_FORMATS, 'Raw bytes'));
    },
  },
  {
    id: 'bitwise-not',
    name: 'Bitwise NOT',
    category: 'Encryption',
    description: 'Inverts every bit. A common one-step obfuscation in packed binaries.',
    keywords: ['invert', 'complement', 'malware'],
    run(input) {
      const out = new Uint8Array(input.length);
      for (let i = 0; i < input.length; i++) out[i] = ~input[i] & 0xff;
      return out;
    },
  },
  {
    id: 'bit-rotate',
    name: 'Bit rotate',
    category: 'Encryption',
    description: 'Rotates the bits of each byte left or right. Pairs with XOR in simple packers.',
    keywords: ['rol', 'ror', 'shift', 'malware'],
    args: [
      { name: 'direction', type: 'select', options: ['Left', 'Right'], default: 'Left' },
      { name: 'amount', type: 'number', default: 1, min: 0, max: 7 },
    ],
    examples: [{ input: 'A', args: { amount: 1 }, output: '', outputEncoding: 'latin1' }],
    run(input, args) {
      const amount = getNumber(args, 'amount', 1) & 7;
      const left = getOption(args, 'direction', ['Left', 'Right'] as const, 'Left') === 'Left';
      const shift = left ? amount : 8 - amount;
      const out = new Uint8Array(input.length);
      for (let i = 0; i < input.length; i++) out[i] = ((input[i] << shift) | (input[i] >>> (8 - shift))) & 0xff;
      return out;
    },
  },
  {
    id: 'derive-aes-key',
    name: 'Derive AES key from password',
    category: 'Encryption',
    description: 'Turns a password into an AES key with PBKDF2. Use this rather than hashing a password once — the iteration count is what makes brute force expensive.',
    keywords: ['pbkdf2', 'kdf', 'password'],
    args: [
      { name: 'salt', type: 'key', default: '', defaultEncoding: 'utf8' },
      { name: 'iterations', type: 'number', default: 600000, min: 1 },
      { name: 'keySize', label: 'Key size (bits)', type: 'select', options: ['128', '192', '256'], default: '256' },
      { name: 'hash', type: 'select', options: ['SHA-256', 'SHA-512'], default: 'SHA-256' },
      { name: 'output', type: 'select', options: OUTPUT_FORMATS, default: 'Hex' },
    ],
    async run(input, args) {
      const iterations = getNumber(args, 'iterations', 600000);
      if (iterations < 1) throw new OperationError('Iteration count must be at least 1.');
      const keySize = Number(getOption(args, 'keySize', ['128', '192', '256'] as const, '256'));
      const hash = getOption(args, 'hash', ['SHA-256', 'SHA-512'] as const, 'SHA-256');

      const baseKey = await subtle().importKey('raw', input, 'PBKDF2', false, ['deriveBits']);
      const bits = await subtle().deriveBits(
        { name: 'PBKDF2', salt: getKeyBytes(args, 'salt'), iterations, hash },
        baseKey,
        keySize,
      );
      return shapeOutput(new Uint8Array(bits), getOption(args, 'output', OUTPUT_FORMATS, 'Hex'));
    },
  },
  {
    id: 'random-key',
    name: 'Generate AES key and IV',
    category: 'Encryption',
    description: 'Emits a fresh key and nonce from the system CSPRNG, ready to paste into AES encrypt.',
    keywords: ['keygen', 'csprng', 'nonce'],
    args: [
      { name: 'keySize', label: 'Key size (bits)', type: 'select', options: ['128', '192', '256'], default: '256' },
      { name: 'ivLength', label: 'IV length (bytes)', type: 'number', default: 12, min: 1, max: 32 },
    ],
    run(_input, args) {
      const keyBytes = Number(getOption(args, 'keySize', ['128', '192', '256'] as const, '256')) / 8;
      const ivLength = getNumber(args, 'ivLength', 12);
      const key = globalThis.crypto.getRandomValues(new Uint8Array(keyBytes));
      const iv = globalThis.crypto.getRandomValues(new Uint8Array(ivLength));
      return utf8Encode(`key = ${hexEncode(key)}\niv  = ${hexEncode(iv)}`);
    },
  },
];

/** Exported for the Magic engine, which speculatively XORs candidate blobs. */
export { xorBytes, rc4, rotateAlphabet, concat };
