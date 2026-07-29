/**
 * Encoding operations — reversible representation changes.
 *
 * Every `to-*` has a matching `from-*` so recipes read symmetrically, and the
 * decoders are deliberately lenient about whitespace and stray punctuation
 * because real-world captures are rarely clean.
 */

import { getBoolean, getOption, getString, unescapeLiteral } from '../args.js';
import {
  B64_STANDARD,
  B64_URLSAFE,
  base64Decode,
  base64Encode,
  hexDecode,
  hexEncode,
  latin1Decode,
  utf8Decode,
  utf8Encode,
} from '../bytes.js';
import { OperationError, type Bytes, type Operation } from '../types.js';

const SEPARATORS = ['Space', 'None', 'Comma', 'Semi-colon', 'Colon', 'Line feed', 'CRLF'] as const;
type Separator = (typeof SEPARATORS)[number];

const SEPARATOR_TEXT: Record<Separator, string> = {
  Space: ' ',
  None: '',
  Comma: ',',
  'Semi-colon': ';',
  Colon: ':',
  'Line feed': '\n',
  CRLF: '\r\n',
};

const BASE64_ALPHABETS = ['Standard', 'URL-safe', 'Custom'] as const;

function base64Alphabet(name: string, custom: string): string {
  if (name === 'URL-safe') return B64_URLSAFE;
  if (name === 'Custom') {
    if (custom.length < 64) {
      throw new OperationError(`Custom Base64 alphabet needs 64 characters, got ${custom.length}.`);
    }
    return custom;
  }
  return B64_STANDARD;
}

// --- Base32 -----------------------------------------------------------------

const B32_RFC4648 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const B32_HEX = '0123456789ABCDEFGHIJKLMNOPQRSTUV';

function base32Encode(bytes: Bytes, alphabet: string, pad: boolean): string {
  let out = '';
  let bits = 0;
  let value = 0;
  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i];
    bits += 8;
    while (bits >= 5) {
      out += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += alphabet[(value << (5 - bits)) & 31];
  if (pad) while (out.length % 8 !== 0) out += '=';
  return out;
}

function base32Decode(text: string, alphabet: string): Bytes {
  const clean = text.toUpperCase().replace(/[=\s]/g, '');
  const out: number[] = [];
  let bits = 0;
  let value = 0;
  for (const ch of clean) {
    const index = alphabet.indexOf(ch);
    if (index < 0) throw new OperationError(`Character ${JSON.stringify(ch)} is not in the Base32 alphabet.`);
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Uint8Array.from(out);
}

// --- Base58 -----------------------------------------------------------------

const B58_BITCOIN = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const B58_RIPPLE = 'rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz';

function base58Encode(bytes: Bytes, alphabet: string): string {
  if (bytes.length === 0) return '';
  const digits: number[] = [];
  for (let i = 0; i < bytes.length; i++) {
    let carry = bytes[i];
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  let out = '';
  for (let i = 0; i < bytes.length && bytes[i] === 0; i++) out += alphabet[0];
  for (let i = digits.length - 1; i >= 0; i--) out += alphabet[digits[i]];
  return out;
}

function base58Decode(text: string, alphabet: string): Bytes {
  const clean = text.replace(/\s/g, '');
  const bytes: number[] = [];
  for (const ch of clean) {
    let carry = alphabet.indexOf(ch);
    if (carry < 0) throw new OperationError(`Character ${JSON.stringify(ch)} is not in the Base58 alphabet.`);
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j] * 58;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  for (let i = 0; i < clean.length && clean[i] === alphabet[0]; i++) bytes.push(0);
  return Uint8Array.from(bytes.reverse());
}

// --- Ascii85 ----------------------------------------------------------------

function ascii85Encode(bytes: Bytes, useMarkers: boolean): string {
  let out = useMarkers ? '<~' : '';
  for (let i = 0; i < bytes.length; i += 4) {
    const chunk = bytes.subarray(i, i + 4);
    let value = 0;
    for (let j = 0; j < 4; j++) value = value * 256 + (chunk[j] ?? 0);

    if (chunk.length === 4 && value === 0) {
      out += 'z';
      continue;
    }
    const group = new Array(5);
    for (let j = 4; j >= 0; j--) {
      group[j] = String.fromCharCode(33 + (value % 85));
      value = Math.floor(value / 85);
    }
    out += group.slice(0, chunk.length + 1).join('');
  }
  return out + (useMarkers ? '~>' : '');
}

function ascii85Decode(text: string): Bytes {
  const clean = text.replace(/^<~/, '').replace(/~>$/, '').replace(/\s/g, '');
  const out: number[] = [];
  let group: number[] = [];

  const flush = (): void => {
    if (group.length === 0) return;
    const size = group.length;
    while (group.length < 5) group.push(84); // pad with 'u'
    let value = 0;
    for (const digit of group) value = value * 85 + digit;
    const quad = [(value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff];
    out.push(...quad.slice(0, size - 1));
    group = [];
  };

  for (const ch of clean) {
    if (ch === 'z' && group.length === 0) {
      out.push(0, 0, 0, 0);
      continue;
    }
    const code = ch.charCodeAt(0);
    if (code < 33 || code > 117) {
      throw new OperationError(`Character ${JSON.stringify(ch)} is not valid Ascii85.`);
    }
    group.push(code - 33);
    if (group.length === 5) {
      let value = 0;
      for (const digit of group) value = value * 85 + digit;
      out.push((value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff);
      group = [];
    }
  }
  if (group.length === 1) throw new OperationError('Ascii85 input is truncated — a final group has only 1 character.');
  flush();
  return Uint8Array.from(out);
}

// --- HTML entities ----------------------------------------------------------

const NAMED_ENTITIES: Record<string, string> = {
  amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', copy: '©', reg: '®',
  trade: '™', hellip: '…', mdash: '—', ndash: '–', lsquo: '‘', rsquo: '’',
  ldquo: '“', rdquo: '”', bull: '•', dagger: '†', permil: '‰', euro: '€',
  pound: '£', yen: '¥', cent: '¢', sect: '§', para: '¶', deg: '°',
  plusmn: '±', times: '×', divide: '÷', frac12: '½', frac14: '¼',
  micro: 'µ', middot: '·', laquo: '«', raquo: '»', larr: '←', uarr: '↑',
  rarr: '→', darr: '↓', harr: '↔', spades: '♠', clubs: '♣', hearts: '♥',
  diams: '♦', alpha: 'α', beta: 'β', gamma: 'γ', delta: 'δ', pi: 'π',
  sigma: 'σ', omega: 'ω', infin: '∞', ne: '≠', le: '≤', ge: '≥',
  radic: '√', sum: '∑', prod: '∏', int: '∫', asymp: '≈', equiv: '≡',
};

const ENTITY_BY_CHAR = new Map(Object.entries(NAMED_ENTITIES).map(([name, ch]) => [ch, name]));

// --- Morse ------------------------------------------------------------------

const MORSE: Record<string, string> = {
  A: '.-', B: '-...', C: '-.-.', D: '-..', E: '.', F: '..-.', G: '--.', H: '....', I: '..', J: '.---',
  K: '-.-', L: '.-..', M: '--', N: '-.', O: '---', P: '.--.', Q: '--.-', R: '.-.', S: '...', T: '-',
  U: '..-', V: '...-', W: '.--', X: '-..-', Y: '-.--', Z: '--..',
  '0': '-----', '1': '.----', '2': '..---', '3': '...--', '4': '....-',
  '5': '.....', '6': '-....', '7': '--...', '8': '---..', '9': '----.',
  '.': '.-.-.-', ',': '--..--', '?': '..--..', "'": '.----.', '!': '-.-.--', '/': '-..-.',
  '(': '-.--.', ')': '-.--.-', '&': '.-...', ':': '---...', ';': '-.-.-.', '=': '-...-',
  '+': '.-.-.', '-': '-....-', '_': '..--.-', '"': '.-..-.', '$': '...-..-', '@': '.--.-.',
};

const MORSE_REVERSE = new Map(Object.entries(MORSE).map(([ch, code]) => [code, ch]));

// --- Character codes --------------------------------------------------------

const NUMBER_BASES = ['Binary', 'Octal', 'Decimal', 'Hexadecimal'] as const;
const BASE_RADIX: Record<(typeof NUMBER_BASES)[number], number> = {
  Binary: 2, Octal: 8, Decimal: 10, Hexadecimal: 16,
};
const BASE_WIDTH: Record<(typeof NUMBER_BASES)[number], number> = {
  Binary: 8, Octal: 3, Decimal: 0, Hexadecimal: 2,
};

function toCharcode(bytes: Bytes, base: (typeof NUMBER_BASES)[number], separator: string): string {
  const radix = BASE_RADIX[base];
  const width = BASE_WIDTH[base];
  const parts: string[] = [];
  for (let i = 0; i < bytes.length; i++) {
    parts.push(bytes[i].toString(radix).padStart(width, '0'));
  }
  return parts.join(separator);
}

function fromCharcode(text: string, base: (typeof NUMBER_BASES)[number]): Bytes {
  const radix = BASE_RADIX[base];
  const tokens = text.trim().split(/[^0-9a-fA-F]+/).filter(Boolean);
  const out = new Uint8Array(tokens.length);
  for (let i = 0; i < tokens.length; i++) {
    const value = parseInt(tokens[i], radix);
    if (Number.isNaN(value)) {
      throw new OperationError(`${JSON.stringify(tokens[i])} is not a valid base-${radix} number.`);
    }
    if (value > 255) {
      throw new OperationError(`Value ${value} does not fit in a byte. Was the input really base-${radix}?`);
    }
    out[i] = value;
  }
  return out;
}

// --- Operations -------------------------------------------------------------

export const encodingOps: Operation[] = [
  {
    id: 'to-base64',
    name: 'To Base64',
    category: 'Encoding',
    description: 'Encodes bytes as Base64 text. Use the URL-safe alphabet for values that travel in query strings or JWTs.',
    keywords: ['b64', 'rfc4648'],
    args: [
      { name: 'alphabet', type: 'select', options: BASE64_ALPHABETS, default: 'Standard' },
      { name: 'custom', label: 'Custom alphabet', type: 'string', default: '', hint: '64 characters, used when alphabet is Custom' },
      { name: 'padding', type: 'boolean', default: true, hint: 'Append = so the output length is a multiple of 4' },
    ],
    examples: [
      { input: 'Hello, world!', output: 'SGVsbG8sIHdvcmxkIQ==' },
      { name: 'URL-safe, unpadded', input: 'ÿï¾', args: { alphabet: 'URL-safe', padding: false }, output: 'w7_Dr8K-' },
    ],
    run(input, args) {
      const alphabet = base64Alphabet(getOption(args, 'alphabet', BASE64_ALPHABETS, 'Standard'), getString(args, 'custom'));
      return utf8Encode(base64Encode(input, alphabet, getBoolean(args, 'padding', true)));
    },
  },
  {
    id: 'from-base64',
    name: 'From Base64',
    category: 'Encoding',
    description: 'Decodes Base64 text back to bytes. Whitespace and missing padding are tolerated; set strict to reject anything outside the alphabet.',
    keywords: ['b64', 'decode', 'rfc4648'],
    args: [
      { name: 'alphabet', type: 'select', options: BASE64_ALPHABETS, default: 'Standard' },
      { name: 'custom', label: 'Custom alphabet', type: 'string', default: '' },
      { name: 'strict', type: 'boolean', default: false, hint: 'Fail on characters outside the alphabet instead of skipping them' },
    ],
    examples: [
      { input: 'SGVsbG8sIHdvcmxkIQ==', output: 'Hello, world!' },
      { name: 'Tolerates newlines', input: 'SGVs\nbG8=', output: 'Hello' },
    ],
    run(input, args) {
      const alphabet = base64Alphabet(getOption(args, 'alphabet', BASE64_ALPHABETS, 'Standard'), getString(args, 'custom'));
      return base64Decode(utf8Decode(input), alphabet, getBoolean(args, 'strict', false));
    },
  },
  {
    id: 'to-base32',
    name: 'To Base32',
    category: 'Encoding',
    description: 'Encodes bytes as Base32 (RFC 4648). Common in TOTP seeds and case-insensitive identifiers.',
    keywords: ['totp', 'otp', 'rfc4648'],
    args: [
      { name: 'alphabet', type: 'select', options: ['RFC 4648', 'base32hex'], default: 'RFC 4648' },
      { name: 'padding', type: 'boolean', default: true },
    ],
    examples: [{ input: 'Hello', output: 'JBSWY3DP' }],
    run(input, args) {
      const alphabet = getOption(args, 'alphabet', ['RFC 4648', 'base32hex'] as const, 'RFC 4648') === 'base32hex' ? B32_HEX : B32_RFC4648;
      return utf8Encode(base32Encode(input, alphabet, getBoolean(args, 'padding', true)));
    },
  },
  {
    id: 'from-base32',
    name: 'From Base32',
    category: 'Encoding',
    description: 'Decodes Base32 text back to bytes.',
    keywords: ['totp', 'otp'],
    args: [{ name: 'alphabet', type: 'select', options: ['RFC 4648', 'base32hex'], default: 'RFC 4648' }],
    examples: [{ input: 'JBSWY3DP', output: 'Hello' }],
    run(input, args) {
      const alphabet = getOption(args, 'alphabet', ['RFC 4648', 'base32hex'] as const, 'RFC 4648') === 'base32hex' ? B32_HEX : B32_RFC4648;
      return base32Decode(utf8Decode(input), alphabet);
    },
  },
  {
    id: 'to-base58',
    name: 'To Base58',
    category: 'Encoding',
    description: 'Encodes bytes as Base58. The Bitcoin alphabet omits 0, O, I and l so encoded values survive being read aloud or retyped.',
    keywords: ['bitcoin', 'btc', 'ipfs', 'wallet'],
    args: [{ name: 'alphabet', type: 'select', options: ['Bitcoin', 'Ripple'], default: 'Bitcoin' }],
    examples: [{ input: 'Hello World!', output: '2NEpo7TZRRrLZSi2U' }],
    run(input, args) {
      const alphabet = getOption(args, 'alphabet', ['Bitcoin', 'Ripple'] as const, 'Bitcoin') === 'Ripple' ? B58_RIPPLE : B58_BITCOIN;
      return utf8Encode(base58Encode(input, alphabet));
    },
  },
  {
    id: 'from-base58',
    name: 'From Base58',
    category: 'Encoding',
    description: 'Decodes Base58 text back to bytes.',
    keywords: ['bitcoin', 'btc', 'ipfs', 'wallet'],
    args: [{ name: 'alphabet', type: 'select', options: ['Bitcoin', 'Ripple'], default: 'Bitcoin' }],
    examples: [{ input: '2NEpo7TZRRrLZSi2U', output: 'Hello World!' }],
    run(input, args) {
      const alphabet = getOption(args, 'alphabet', ['Bitcoin', 'Ripple'] as const, 'Bitcoin') === 'Ripple' ? B58_RIPPLE : B58_BITCOIN;
      return base58Decode(utf8Decode(input), alphabet);
    },
  },
  {
    id: 'to-base85',
    name: 'To Base85',
    category: 'Encoding',
    description: 'Encodes bytes as Ascii85. Denser than Base64 — four bytes become five characters. Used by PDF and PostScript.',
    keywords: ['ascii85', 'a85', 'pdf', 'postscript'],
    args: [{ name: 'markers', label: 'Include <~ ~> markers', type: 'boolean', default: false }],
    examples: [{ input: 'Hello, world!', output: '87cURD_*#TDfTZ)+T' }],
    run(input, args) {
      return utf8Encode(ascii85Encode(input, getBoolean(args, 'markers', false)));
    },
  },
  {
    id: 'from-base85',
    name: 'From Base85',
    category: 'Encoding',
    description: 'Decodes Ascii85 text back to bytes.',
    keywords: ['ascii85', 'a85', 'pdf'],
    examples: [{ input: '87cURD_*#TDfTZ)+T', output: 'Hello, world!' }],
    run(input) {
      return ascii85Decode(utf8Decode(input));
    },
  },
  {
    id: 'to-hex',
    name: 'To Hex',
    category: 'Encoding',
    description: 'Renders each byte as two hexadecimal digits.',
    keywords: ['hexadecimal', 'base16'],
    args: [
      { name: 'separator', type: 'select', options: SEPARATORS, default: 'Space' },
      { name: 'prefix', type: 'select', options: ['None', '0x', '\\x'], default: 'None' },
      { name: 'uppercase', type: 'boolean', default: false },
    ],
    examples: [
      { input: 'Hello', output: '48 65 6c 6c 6f' },
      { name: 'C-style literal', input: 'Hi', args: { separator: 'None', prefix: '\\x' }, output: '\\x48\\x69' },
    ],
    run(input, args) {
      const separator = SEPARATOR_TEXT[getOption(args, 'separator', SEPARATORS, 'Space')];
      const prefix = getOption(args, 'prefix', ['None', '0x', '\\x'] as const, 'None');
      const uppercase = getBoolean(args, 'uppercase', false);
      const parts: string[] = [];
      for (let i = 0; i < input.length; i++) {
        const pair = hexEncode(input.subarray(i, i + 1));
        parts.push((prefix === 'None' ? '' : prefix) + (uppercase ? pair.toUpperCase() : pair));
      }
      return utf8Encode(parts.join(separator));
    },
  },
  {
    id: 'from-hex',
    name: 'From Hex',
    category: 'Encoding',
    description: 'Parses hexadecimal digits back to bytes, ignoring whitespace, 0x prefixes and any punctuation used as a separator.',
    keywords: ['hexadecimal', 'base16', 'unhex'],
    examples: [
      { input: '48 65 6c 6c 6f', output: 'Hello' },
      { name: 'Mixed separators', input: '0x48,0x69', output: 'Hi' },
    ],
    run(input) {
      return hexDecode(utf8Decode(input));
    },
  },
  {
    id: 'url-encode',
    name: 'URL encode',
    category: 'Encoding',
    description: 'Percent-encodes text for use in a URL. Encode all characters when the value goes in a query string that may be parsed twice.',
    keywords: ['percent', 'uri', 'urlencode'],
    args: [{ name: 'encodeAll', label: 'Encode all special characters', type: 'boolean', default: false }],
    examples: [
      { input: 'a b&c=d', output: 'a%20b%26c%3Dd' },
      { name: 'Leave reserved characters alone', input: 'https://a.test/x y', args: { encodeAll: false }, output: 'https://a.test/x%20y' },
    ],
    run(input, args) {
      const text = utf8Decode(input);
      if (getBoolean(args, 'encodeAll', false)) {
        return utf8Encode(
          Array.from(utf8Encode(text))
            .map((b) => `%${b.toString(16).toUpperCase().padStart(2, '0')}`)
            .join(''),
        );
      }
      return utf8Encode(encodeURI(text).replace(/[&=?#+]/g, (ch) => `%${ch.charCodeAt(0).toString(16).toUpperCase().padStart(2, '0')}`));
    },
  },
  {
    id: 'url-decode',
    name: 'URL decode',
    category: 'Encoding',
    description: 'Decodes percent-encoded text. Decodes + as a space when the input came from a form body.',
    keywords: ['percent', 'uri', 'urldecode'],
    args: [{ name: 'plusIsSpace', label: 'Treat + as space', type: 'boolean', default: false }],
    examples: [
      { input: 'a%20b%26c%3Dd', output: 'a b&c=d' },
      { name: 'Form encoding', input: 'a+b', args: { plusIsSpace: true }, output: 'a b' },
    ],
    run(input, args) {
      let text = utf8Decode(input);
      if (getBoolean(args, 'plusIsSpace', false)) text = text.replace(/\+/g, ' ');
      // Decode manually so a stray % does not abort the whole string.
      const out: number[] = [];
      for (let i = 0; i < text.length; i++) {
        const match = /^%([0-9a-fA-F]{2})/.exec(text.slice(i, i + 3));
        if (match) {
          out.push(parseInt(match[1], 16));
          i += 2;
        } else {
          out.push(...utf8Encode(text[i]));
        }
      }
      return Uint8Array.from(out);
    },
  },
  {
    id: 'to-html-entity',
    name: 'To HTML entity',
    category: 'Encoding',
    description: 'Escapes characters that would otherwise be read as markup. Encode everything when injecting into an attribute of unknown quoting.',
    keywords: ['escape', 'xss', 'htmlencode'],
    args: [
      { name: 'scope', type: 'select', options: ['Special characters', 'Everything non-ASCII', 'Everything'], default: 'Special characters' },
      { name: 'format', type: 'select', options: ['Named where possible', 'Decimal', 'Hex'], default: 'Named where possible' },
    ],
    examples: [
      { input: '<script>alert(1)</script>', output: '&lt;script&gt;alert(1)&lt;/script&gt;' },
      { name: 'Hex numeric', input: '<a>', args: { format: 'Hex' }, output: '&#x3c;a&#x3e;' },
    ],
    run(input, args) {
      const scope = getOption(args, 'scope', ['Special characters', 'Everything non-ASCII', 'Everything'] as const, 'Special characters');
      const format = getOption(args, 'format', ['Named where possible', 'Decimal', 'Hex'] as const, 'Named where possible');
      let out = '';
      for (const ch of utf8Decode(input)) {
        const code = ch.codePointAt(0)!;
        const special = '&<>"\''.includes(ch);
        const shouldEncode = scope === 'Everything' || (scope === 'Everything non-ASCII' && (code > 126 || special)) || (scope === 'Special characters' && special);
        if (!shouldEncode) {
          out += ch;
          continue;
        }
        const named = ENTITY_BY_CHAR.get(ch);
        if (format === 'Named where possible' && named) out += `&${named};`;
        else if (format === 'Hex') out += `&#x${code.toString(16)};`;
        else out += `&#${code};`;
      }
      return utf8Encode(out);
    },
  },
  {
    id: 'from-html-entity',
    name: 'From HTML entity',
    category: 'Encoding',
    description: 'Resolves named and numeric HTML entities back to characters.',
    keywords: ['unescape', 'htmldecode'],
    examples: [{ input: '&lt;b&gt;hi&lt;/b&gt; &amp; &#x263A;', output: '<b>hi</b> & ☺' }],
    run(input) {
      const text = utf8Decode(input).replace(/&(#x[0-9a-fA-F]+|#[0-9]+|[a-zA-Z][a-zA-Z0-9]*);/g, (whole, body: string) => {
        if (body[0] === '#') {
          const code = body[1] === 'x' || body[1] === 'X' ? parseInt(body.slice(2), 16) : parseInt(body.slice(1), 10);
          return Number.isFinite(code) && code >= 0 && code <= 0x10ffff ? String.fromCodePoint(code) : whole;
        }
        return NAMED_ENTITIES[body] ?? NAMED_ENTITIES[body.toLowerCase()] ?? whole;
      });
      return utf8Encode(text);
    },
  },
  {
    id: 'to-charcode',
    name: 'To character code',
    category: 'Encoding',
    description: 'Writes each byte as a number in the base you choose.',
    keywords: ['ord', 'ascii', 'octal'],
    args: [
      { name: 'base', type: 'select', options: NUMBER_BASES, default: 'Hexadecimal' },
      { name: 'separator', type: 'select', options: SEPARATORS, default: 'Space' },
    ],
    examples: [{ input: 'Hi', args: { base: 'Decimal' }, output: '72 105' }],
    run(input, args) {
      const base = getOption(args, 'base', NUMBER_BASES, 'Hexadecimal');
      const separator = SEPARATOR_TEXT[getOption(args, 'separator', SEPARATORS, 'Space')];
      return utf8Encode(toCharcode(input, base, separator));
    },
  },
  {
    id: 'from-charcode',
    name: 'From character code',
    category: 'Encoding',
    description: 'Parses a list of numbers back to bytes. Any non-digit run counts as a separator.',
    keywords: ['chr', 'ascii', 'octal'],
    args: [{ name: 'base', type: 'select', options: NUMBER_BASES, default: 'Hexadecimal' }],
    examples: [{ input: '72 105', args: { base: 'Decimal' }, output: 'Hi' }],
    run(input, args) {
      return fromCharcode(utf8Decode(input), getOption(args, 'base', NUMBER_BASES, 'Hexadecimal'));
    },
  },
  {
    id: 'to-binary',
    name: 'To binary',
    category: 'Encoding',
    description: 'Writes each byte as eight bits.',
    keywords: ['bits', 'base2'],
    args: [{ name: 'separator', type: 'select', options: SEPARATORS, default: 'Space' }],
    examples: [{ input: 'Hi', output: '01001000 01101001' }],
    run(input, args) {
      return utf8Encode(toCharcode(input, 'Binary', SEPARATOR_TEXT[getOption(args, 'separator', SEPARATORS, 'Space')]));
    },
  },
  {
    id: 'from-binary',
    name: 'From binary',
    category: 'Encoding',
    description: 'Parses a run of bits back to bytes.',
    keywords: ['bits', 'base2'],
    examples: [{ input: '01001000 01101001', output: 'Hi' }],
    run(input) {
      const text = utf8Decode(input).replace(/[^01]/g, '');
      if (text.length % 8 !== 0) {
        throw new OperationError(`Binary input has ${text.length} bits, which is not a whole number of bytes.`);
      }
      const out = new Uint8Array(text.length / 8);
      for (let i = 0; i < out.length; i++) out[i] = parseInt(text.substr(i * 8, 8), 2);
      return out;
    },
  },
  {
    id: 'to-decimal',
    name: 'To decimal',
    category: 'Encoding',
    description: 'Writes each byte as a decimal number.',
    keywords: ['base10', 'ord'],
    args: [{ name: 'separator', type: 'select', options: SEPARATORS, default: 'Space' }],
    examples: [{ input: 'Hi', output: '72 105' }],
    run(input, args) {
      return utf8Encode(toCharcode(input, 'Decimal', SEPARATOR_TEXT[getOption(args, 'separator', SEPARATORS, 'Space')]));
    },
  },
  {
    id: 'from-decimal',
    name: 'From decimal',
    category: 'Encoding',
    description: 'Parses decimal numbers back to bytes.',
    keywords: ['base10', 'chr'],
    examples: [{ input: '72 105', output: 'Hi' }],
    run(input) {
      return fromCharcode(utf8Decode(input), 'Decimal');
    },
  },
  {
    id: 'to-quoted-printable',
    name: 'To quoted-printable',
    category: 'Encoding',
    description: 'Encodes bytes for an email body: printable ASCII stays as-is, everything else becomes =XX, and lines wrap at 76 characters.',
    keywords: ['email', 'mime', 'qp'],
    examples: [{ input: 'café', output: 'caf=C3=A9' }],
    run(input) {
      let line = '';
      const lines: string[] = [];
      const pushSoft = (): void => {
        lines.push(`${line}=`);
        line = '';
      };
      for (let i = 0; i < input.length; i++) {
        const b = input[i];
        if (b === 0x0a) {
          lines.push(line);
          line = '';
          continue;
        }
        const literal = (b >= 33 && b <= 60) || (b >= 62 && b <= 126) || b === 32 || b === 9;
        const atLineEnd = i === input.length - 1 || input[i + 1] === 0x0a;
        const token = literal && !((b === 32 || b === 9) && atLineEnd) ? String.fromCharCode(b) : `=${b.toString(16).toUpperCase().padStart(2, '0')}`;
        if (line.length + token.length > 75) pushSoft();
        line += token;
      }
      lines.push(line);
      return utf8Encode(lines.join('\r\n'));
    },
  },
  {
    id: 'from-quoted-printable',
    name: 'From quoted-printable',
    category: 'Encoding',
    description: 'Decodes a quoted-printable email body, joining soft line breaks.',
    keywords: ['email', 'mime', 'qp'],
    examples: [{ input: 'caf=C3=A9', output: 'café' }],
    run(input) {
      const text = utf8Decode(input).replace(/=(?:\r\n|\n|\r)/g, '');
      const out: number[] = [];
      for (let i = 0; i < text.length; i++) {
        const match = /^=([0-9a-fA-F]{2})/.exec(text.slice(i, i + 3));
        if (match) {
          out.push(parseInt(match[1], 16));
          i += 2;
        } else {
          out.push(...utf8Encode(text[i]));
        }
      }
      return Uint8Array.from(out);
    },
  },
  {
    id: 'to-morse',
    name: 'To Morse code',
    category: 'Encoding',
    description: 'Converts letters, digits and common punctuation to Morse.',
    keywords: ['cw', 'telegraph'],
    args: [
      { name: 'letterSeparator', type: 'string', default: ' ' },
      { name: 'wordSeparator', type: 'string', default: '/' },
    ],
    examples: [{ input: 'SOS', output: '... --- ...' }],
    run(input, args) {
      const letterSeparator = unescapeLiteral(getString(args, 'letterSeparator', ' '));
      const wordSeparator = unescapeLiteral(getString(args, 'wordSeparator', '/'));
      return utf8Encode(
        utf8Decode(input)
          .toUpperCase()
          .split(/\s+/)
          .filter(Boolean)
          .map((word) =>
            Array.from(word)
              .map((ch) => MORSE[ch] ?? '')
              .filter(Boolean)
              .join(letterSeparator),
          )
          .join(`${letterSeparator}${wordSeparator}${letterSeparator}`),
      );
    },
  },
  {
    id: 'from-morse',
    name: 'From Morse code',
    category: 'Encoding',
    description: 'Decodes Morse back to text. Accepts dots and dashes in any spacing, with / between words.',
    keywords: ['cw', 'telegraph'],
    examples: [{ input: '... --- ...', output: 'SOS' }],
    run(input) {
      const text = utf8Decode(input).replace(/[_–—]/g, '-').replace(/[·•]/g, '.');
      return utf8Encode(
        text
          .split(/\s*\/\s*|\s{3,}/)
          .map((word) =>
            word
              .trim()
              .split(/\s+/)
              .filter(Boolean)
              .map((code) => MORSE_REVERSE.get(code) ?? '')
              .join(''),
          )
          .filter(Boolean)
          .join(' '),
      );
    },
  },
  {
    id: 'to-latin1',
    name: 'Reinterpret as Latin-1',
    category: 'Encoding',
    description: 'Reads each byte as one Latin-1 character and re-encodes the result as UTF-8. Repairs text that was decoded with the wrong charset (mojibake).',
    keywords: ['mojibake', 'iso-8859-1', 'charset', 'encoding'],
    examples: [{ input: 'cafÃ©', output: 'cafÃÂ©' }],
    run(input) {
      return utf8Encode(latin1Decode(input));
    },
  },
];
