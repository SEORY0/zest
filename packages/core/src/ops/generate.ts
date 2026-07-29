/**
 * Generators.
 *
 * Everything random here comes from `crypto.getRandomValues`, never
 * `Math.random`, because values produced by a security tool get used as
 * secrets whether or not that was the intent.
 */

import { getBoolean, getNumber, getOption, getString, unescapeLiteral } from '../args.js';
import { base64Encode, hexEncode, utf8Encode } from '../bytes.js';
import { OperationError, type Bytes, type Operation } from '../types.js';

function randomBytes(length: number): Bytes {
  const out = new Uint8Array(length);
  // getRandomValues caps at 65536 bytes per call.
  for (let offset = 0; offset < length; offset += 65536) {
    globalThis.crypto.getRandomValues(out.subarray(offset, Math.min(offset + 65536, length)));
  }
  return out;
}

/** Uniform index in [0, range) with rejection sampling, so no value is favoured. */
function uniformIndex(range: number): number {
  if (range <= 0) throw new OperationError('Cannot pick from an empty character set.');
  const limit = Math.floor(0x100000000 / range) * range;
  const buffer = new Uint32Array(1);
  let value: number;
  do {
    globalThis.crypto.getRandomValues(buffer);
    value = buffer[0];
  } while (value >= limit);
  return value % range;
}

const CHARSETS = {
  lowercase: 'abcdefghijklmnopqrstuvwxyz',
  uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  digits: '0123456789',
  symbols: '!#$%&*+-=?@^_~',
  // Excludes 0/O and 1/l/I, which are the characters people mistype when reading aloud.
  unambiguous: 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789',
};

const OUTPUT_FORMATS = ['Hex', 'Base64', 'Raw bytes'] as const;

export const generateOps: Operation[] = [
  {
    id: 'generate-uuid',
    name: 'Generate UUID',
    category: 'Generate',
    description: 'Emits random version 4 UUIDs. Ignores its input.',
    keywords: ['guid', 'uuid4', 'random', 'identifier'],
    args: [
      { name: 'count', type: 'number', default: 1, min: 1, max: 10000 },
      { name: 'uppercase', type: 'boolean', default: false },
      { name: 'braces', type: 'boolean', default: false },
    ],
    run(_input, args) {
      const count = getNumber(args, 'count', 1);
      const uppercase = getBoolean(args, 'uppercase', false);
      const braces = getBoolean(args, 'braces', false);

      const list: string[] = [];
      for (let i = 0; i < count; i++) {
        const uuid = globalThis.crypto.randomUUID();
        const shaped = uppercase ? uuid.toUpperCase() : uuid;
        list.push(braces ? `{${shaped}}` : shaped);
      }
      return utf8Encode(list.join('\n'));
    },
  },
  {
    id: 'generate-random',
    name: 'Generate random bytes',
    category: 'Generate',
    description: 'Emits cryptographically secure random bytes. Ignores its input.',
    keywords: ['entropy', 'nonce', 'iv', 'salt', 'csprng'],
    args: [
      { name: 'length', label: 'Length (bytes)', type: 'number', default: 32, min: 1, max: 1048576 },
      { name: 'format', type: 'select', options: OUTPUT_FORMATS, default: 'Hex' },
    ],
    run(_input, args) {
      const bytes = randomBytes(getNumber(args, 'length', 32));
      const format = getOption(args, 'format', OUTPUT_FORMATS, 'Hex');
      if (format === 'Raw bytes') return bytes;
      return utf8Encode(format === 'Base64' ? base64Encode(bytes) : hexEncode(bytes));
    },
  },
  {
    id: 'generate-password',
    name: 'Generate password',
    category: 'Generate',
    description: 'Builds passwords from a character set you choose, and reports how much entropy each one actually carries. Ignores its input.',
    keywords: ['passphrase', 'secret', 'credential', 'entropy'],
    args: [
      { name: 'length', type: 'number', default: 20, min: 4, max: 256 },
      { name: 'count', type: 'number', default: 5, min: 1, max: 1000 },
      { name: 'lowercase', type: 'boolean', default: true },
      { name: 'uppercase', type: 'boolean', default: true },
      { name: 'digits', type: 'boolean', default: true },
      { name: 'symbols', type: 'boolean', default: true },
      { name: 'unambiguous', label: 'Avoid look-alike characters', type: 'boolean', default: false },
    ],
    run(_input, args) {
      let alphabet = '';
      if (getBoolean(args, 'unambiguous', false)) {
        alphabet = CHARSETS.unambiguous;
        if (getBoolean(args, 'symbols', true)) alphabet += CHARSETS.symbols;
      } else {
        if (getBoolean(args, 'lowercase', true)) alphabet += CHARSETS.lowercase;
        if (getBoolean(args, 'uppercase', true)) alphabet += CHARSETS.uppercase;
        if (getBoolean(args, 'digits', true)) alphabet += CHARSETS.digits;
        if (getBoolean(args, 'symbols', true)) alphabet += CHARSETS.symbols;
      }
      if (!alphabet) throw new OperationError('Enable at least one character set.');

      const length = getNumber(args, 'length', 20);
      const count = getNumber(args, 'count', 5);

      const passwords: string[] = [];
      for (let i = 0; i < count; i++) {
        let password = '';
        for (let j = 0; j < length; j++) password += alphabet[uniformIndex(alphabet.length)];
        passwords.push(password);
      }

      const entropy = length * Math.log2(alphabet.length);
      return utf8Encode(
        `${passwords.join('\n')}\n\n${alphabet.length} character alphabet, ${length} characters — ${entropy.toFixed(1)} bits of entropy each.`,
      );
    },
  },
  {
    id: 'generate-totp',
    name: 'Generate TOTP',
    category: 'Generate',
    description: 'Derives the current time-based one-time password from a Base32 secret (RFC 6238). The input is the secret.',
    keywords: ['2fa', 'mfa', 'otp', 'authenticator', 'rfc6238'],
    args: [
      { name: 'digits', type: 'number', default: 6, min: 6, max: 10 },
      { name: 'period', label: 'Period (seconds)', type: 'number', default: 30, min: 1 },
      { name: 'algorithm', type: 'select', options: ['SHA-1', 'SHA-256', 'SHA-512'], default: 'SHA-1' },
      { name: 'at', label: 'Unix time to use', type: 'number', default: 0, hint: '0 uses the current time' },
    ],
    examples: [
      {
        name: 'RFC 6238 vector at t=59',
        input: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
        args: { at: 59, digits: 8 },
        output: '94287082',
      },
    ],
    async run(input, args) {
      const secret = new TextDecoder().decode(input).trim().replace(/[=\s]/g, '').toUpperCase();
      const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

      const key: number[] = [];
      let bits = 0;
      let value = 0;
      for (const ch of secret) {
        const index = alphabet.indexOf(ch);
        if (index < 0) throw new OperationError(`${JSON.stringify(ch)} is not a Base32 character. TOTP secrets are Base32.`);
        value = (value << 5) | index;
        bits += 5;
        if (bits >= 8) {
          key.push((value >>> (bits - 8)) & 0xff);
          bits -= 8;
        }
      }

      const period = getNumber(args, 'period', 30);
      const at = getNumber(args, 'at', 0) || Math.floor(Date.now() / 1000);
      const counter = Math.floor(at / period);

      const message = new Uint8Array(8);
      new DataView(message.buffer).setBigUint64(0, BigInt(counter));

      const algorithm = getOption(args, 'algorithm', ['SHA-1', 'SHA-256', 'SHA-512'] as const, 'SHA-1');
      const cryptoKey = await globalThis.crypto.subtle.importKey('raw', Uint8Array.from(key), { name: 'HMAC', hash: algorithm }, false, ['sign']);
      const mac = new Uint8Array(await globalThis.crypto.subtle.sign('HMAC', cryptoKey, message));

      const offset = mac[mac.length - 1] & 0x0f;
      const truncated =
        ((mac[offset] & 0x7f) << 24) | ((mac[offset + 1] & 0xff) << 16) | ((mac[offset + 2] & 0xff) << 8) | (mac[offset + 3] & 0xff);

      const digits = getNumber(args, 'digits', 6);
      return utf8Encode(String(truncated % 10 ** digits).padStart(digits, '0'));
    },
  },
  {
    id: 'repeat',
    name: 'Repeat',
    category: 'Generate',
    description: 'Repeats the input a number of times. Useful for building buffer-overflow padding and load-test payloads.',
    keywords: ['pad', 'fill', 'buffer', 'fuzz'],
    args: [
      { name: 'count', type: 'number', default: 2, min: 0, max: 1000000 },
      { name: 'separator', type: 'string', default: '' },
    ],
    examples: [{ input: 'ab', args: { count: 3 }, output: 'ababab' }],
    run(input, args) {
      const count = getNumber(args, 'count', 2);
      const gap = utf8Encode(unescapeLiteral(getString(args, 'separator', '')));

      const total = count * input.length + Math.max(0, count - 1) * gap.length;
      if (total > 50_000_000) throw new OperationError(`That would produce ${total} bytes. Reduce the count.`);

      const out = new Uint8Array(total);
      let offset = 0;
      for (let i = 0; i < count; i++) {
        if (i > 0 && gap.length) {
          out.set(gap, offset);
          offset += gap.length;
        }
        out.set(input, offset);
        offset += input.length;
      }
      return out;
    },
  },
];
