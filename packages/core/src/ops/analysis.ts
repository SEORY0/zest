/**
 * Analysis operations — read-only views that tell you what you are holding.
 */

import { getBoolean, getNumber, getOption } from '../args.js';
import { hexEncode, latin1Decode, shannonEntropy, utf8Decode, utf8Encode } from '../bytes.js';
import { detectFileType } from '../filetypes.js';
import { OperationError, type Bytes, type Operation } from '../types.js';

function hexdump(data: Bytes, width: number, offsetBase: number): string {
  const lines: string[] = [];
  for (let offset = 0; offset < data.length; offset += width) {
    const slice = data.subarray(offset, offset + width);

    const hexParts: string[] = [];
    for (let i = 0; i < width; i++) {
      hexParts.push(i < slice.length ? hexEncode(slice.subarray(i, i + 1)) : '  ');
      // A gap at the halfway point makes column counting possible by eye.
      if (i === width / 2 - 1) hexParts.push('');
    }

    let ascii = '';
    for (let i = 0; i < slice.length; i++) {
      ascii += slice[i] >= 0x20 && slice[i] < 0x7f ? String.fromCharCode(slice[i]) : '.';
    }

    lines.push(`${(offsetBase + offset).toString(16).padStart(8, '0')}  ${hexParts.join(' ')}  |${ascii}|`);
  }
  return lines.join('\n');
}

const HASH_SHAPES: { length: number; names: string[] }[] = [
  { length: 32, names: ['MD5', 'MD4', 'NTLM', 'LM (half)'] },
  { length: 40, names: ['SHA-1', 'RIPEMD-160', 'MySQL 4.1+ (without *)'] },
  { length: 56, names: ['SHA-224', 'SHA3-224'] },
  { length: 64, names: ['SHA-256', 'SHA3-256', 'Keccak-256', 'BLAKE2s-256'] },
  { length: 96, names: ['SHA-384', 'SHA3-384'] },
  { length: 128, names: ['SHA-512', 'SHA3-512', 'BLAKE2b-512', 'Whirlpool'] },
];

const HASH_PREFIXES: [RegExp, string][] = [
  [/^\$2[aby]?\$\d{2}\$/, 'bcrypt'],
  [/^\$argon2(id|i|d)\$/, 'Argon2'],
  [/^\$6\$/, 'sha512crypt (Unix)'],
  [/^\$5\$/, 'sha256crypt (Unix)'],
  [/^\$1\$/, 'md5crypt (Unix)'],
  [/^\$y\$/, 'yescrypt (Unix)'],
  [/^\$scrypt\$/, 'scrypt'],
  [/^\{SSHA\}/, 'Salted SHA-1 (LDAP)'],
  [/^\{SHA\}/, 'SHA-1 (LDAP)'],
  [/^pbkdf2_/, 'PBKDF2 (Django)'],
  [/^\*[A-F0-9]{40}$/i, 'MySQL 4.1+'],
  [/^[a-f0-9]{32}:[a-f0-9]{32}$/i, 'NTLM:LM pair'],
];

export const analysisOps: Operation[] = [
  {
    id: 'hexdump',
    name: 'Hex dump',
    category: 'Analysis',
    description: 'Renders bytes as a classic offset / hex / ASCII dump.',
    keywords: ['xxd', 'hd', 'dump', 'binary', 'view'],
    args: [
      { name: 'width', label: 'Bytes per line', type: 'number', default: 16, min: 4, max: 64 },
      { name: 'offset', label: 'Starting offset', type: 'number', default: 0 },
    ],
    examples: [
      {
        input: 'Hello, hex dump!',
        output: '00000000  48 65 6c 6c 6f 2c 20 68  65 78 20 64 75 6d 70 21  |Hello, hex dump!|',
      },
    ],
    run(input, args) {
      const width = Math.max(4, getNumber(args, 'width', 16));
      return utf8Encode(hexdump(input, width, getNumber(args, 'offset', 0)));
    },
  },
  {
    id: 'from-hexdump',
    name: 'From hex dump',
    category: 'Analysis',
    description: 'Recovers the bytes from a hex dump, discarding the offset column and the ASCII gutter.',
    keywords: ['xxd', 'undump', 'parse'],
    examples: [{ input: '00000000  48 65 6c 6c 6f  |Hello|', output: 'Hello' }],
    run(input) {
      const out: number[] = [];
      for (const line of utf8Decode(input).split('\n')) {
        // Drop the ASCII gutter, then the leading offset column.
        const body = line.replace(/\s*\|.*\|?\s*$/, '').replace(/^\s*[0-9a-fA-F]{4,}:?\s+/, '');
        for (const token of body.split(/\s+/)) {
          if (/^[0-9a-fA-F]{2}$/.test(token)) out.push(parseInt(token, 16));
        }
      }
      return Uint8Array.from(out);
    },
  },
  {
    id: 'entropy',
    name: 'Entropy',
    category: 'Analysis',
    description: 'Shannon entropy in bits per byte. Above ~7.5 means encrypted or compressed; English prose sits near 4.',
    keywords: ['randomness', 'packed', 'encrypted', 'malware'],
    args: [{ name: 'blockSize', label: 'Also chart blocks of', type: 'number', default: 0, min: 0, hint: '0 reports the whole input only' }],
    examples: [{ input: 'aaaaaaaa', output: 'entropy   0.000 bits per byte\nverdict   single repeated byte' }],
    run(input, args) {
      const entropy = shannonEntropy(input);
      const verdict =
        input.length === 0
          ? 'empty input'
          : entropy === 0
            ? 'single repeated byte'
            : entropy > 7.5
              ? 'encrypted, compressed or otherwise random'
              : entropy > 6
                ? 'dense — encoded or binary'
                : entropy > 3.5
                  ? 'natural language or structured text'
                  : 'very repetitive';

      const lines = [`entropy   ${entropy.toFixed(3)} bits per byte`, `verdict   ${verdict}`];

      const blockSize = getNumber(args, 'blockSize', 0);
      if (blockSize > 0) {
        lines.push('', `blocks of ${blockSize} bytes`);
        for (let offset = 0; offset < input.length; offset += blockSize) {
          const block = shannonEntropy(input.subarray(offset, offset + blockSize));
          const bar = '█'.repeat(Math.round((block / 8) * 32));
          lines.push(`${offset.toString(16).padStart(8, '0')}  ${block.toFixed(2)}  ${bar}`);
        }
      }
      return utf8Encode(lines.join('\n'));
    },
  },
  {
    id: 'frequency',
    name: 'Byte frequency',
    category: 'Analysis',
    description: 'Counts how often each byte occurs. The starting point for breaking a substitution cipher.',
    keywords: ['histogram', 'distribution', 'cryptanalysis', 'statistics'],
    args: [
      { name: 'top', label: 'Show top N', type: 'number', default: 16, min: 1, max: 256 },
      { name: 'printableOnly', type: 'boolean', default: false },
    ],
    examples: [{ input: 'aab', args: { top: 2 }, output: "'a' 0x61     2   66.7%  ████████████████████\n'b' 0x62     1   33.3%  ██████████" }],
    run(input, args) {
      const counts = new Uint32Array(256);
      for (let i = 0; i < input.length; i++) counts[input[i]]++;
      const printableOnly = getBoolean(args, 'printableOnly', false);

      const entries = Array.from(counts.entries())
        .filter(([byte, count]) => count > 0 && (!printableOnly || (byte >= 0x20 && byte < 0x7f)))
        .sort((a, b) => b[1] - a[1])
        .slice(0, getNumber(args, 'top', 16));

      if (entries.length === 0) return utf8Encode('No bytes to count.');
      const max = entries[0][1];
      const total = input.length || 1;

      return utf8Encode(
        entries
          .map(([byte, count]) => {
            const label = byte >= 0x20 && byte < 0x7f ? `'${String.fromCharCode(byte)}'` : '   ';
            const percent = ((count / total) * 100).toFixed(1).padStart(5);
            const bar = '█'.repeat(Math.max(1, Math.round((count / max) * 20)));
            return `${label} 0x${byte.toString(16).padStart(2, '0')}  ${String(count).padStart(4)}  ${percent}%  ${bar}`;
          })
          .join('\n'),
      );
    },
  },
  {
    id: 'detect-file-type',
    name: 'Detect file type',
    category: 'Analysis',
    description: 'Identifies the format from its magic bytes. Reports every signature that matches, since containers overlap.',
    keywords: ['magic', 'signature', 'mime', 'identify', 'file'],
    examples: [
      { name: 'PNG header', input: '89504e470d0a1a0a', inputEncoding: 'hex', output: 'PNG\nextension  .png\nmime       image/png\nmatched    8 bytes at offset 0' },
    ],
    run(input) {
      const matches = detectFileType(input);
      if (matches.length === 0) {
        return utf8Encode(
          `No known signature matched.\nfirst bytes  ${hexEncode(input.subarray(0, 16), ' ')}`,
        );
      }
      return utf8Encode(
        matches
          .map((m) =>
            [
              m.name,
              `extension  .${m.extension}`,
              `mime       ${m.mime}`,
              `matched    ${m.bytes.length} bytes at offset ${m.matchedAt}`,
              m.note ? `note       ${m.note}` : '',
            ]
              .filter(Boolean)
              .join('\n'),
          )
          .join('\n\n'),
      );
    },
  },
  {
    id: 'strings',
    name: 'Extract strings',
    category: 'Analysis',
    description: 'Pulls printable runs out of a binary, the way strings(1) does. Finds URLs, paths and error messages in a sample.',
    keywords: ['binary', 'malware', 'triage', 'ascii', 'unicode'],
    args: [
      { name: 'minLength', type: 'number', default: 4, min: 1 },
      { name: 'encoding', type: 'select', options: ['ASCII', 'UTF-16LE', 'Both'], default: 'Both' },
      { name: 'showOffsets', type: 'boolean', default: false },
    ],
    examples: [
      { name: 'Finds the readable run', input: '00006865782d68657265ff', inputEncoding: 'hex', args: { minLength: 4 }, output: 'hex-here' },
    ],
    run(input, args) {
      const minLength = Math.max(1, getNumber(args, 'minLength', 4));
      const encoding = getOption(args, 'encoding', ['ASCII', 'UTF-16LE', 'Both'] as const, 'Both');
      const showOffsets = getBoolean(args, 'showOffsets', false);
      const found: { offset: number; text: string }[] = [];

      if (encoding === 'ASCII' || encoding === 'Both') {
        let start = -1;
        let run = '';
        for (let i = 0; i <= input.length; i++) {
          const byte = i < input.length ? input[i] : 0;
          const printable = i < input.length && ((byte >= 0x20 && byte < 0x7f) || byte === 0x09);
          if (printable) {
            if (start < 0) start = i;
            run += String.fromCharCode(byte);
          } else {
            if (run.length >= minLength) found.push({ offset: start, text: run });
            start = -1;
            run = '';
          }
        }
      }

      if (encoding === 'UTF-16LE' || encoding === 'Both') {
        let start = -1;
        let run = '';
        for (let i = 0; i + 1 <= input.length; i += 2) {
          const low = input[i];
          const high = input[i + 1];
          const printable = high === 0 && ((low >= 0x20 && low < 0x7f) || low === 0x09);
          if (printable) {
            if (start < 0) start = i;
            run += String.fromCharCode(low);
          } else {
            if (run.length >= minLength) found.push({ offset: start, text: run });
            start = -1;
            run = '';
          }
        }
        if (run.length >= minLength) found.push({ offset: start, text: run });
      }

      const unique = new Map<string, number>();
      for (const item of found.sort((a, b) => a.offset - b.offset)) {
        if (!unique.has(item.text)) unique.set(item.text, item.offset);
      }

      const lines = Array.from(unique.entries()).map(([text, offset]) =>
        showOffsets ? `${offset.toString(16).padStart(8, '0')}  ${text}` : text,
      );
      return utf8Encode(lines.join('\n'));
    },
  },
  {
    id: 'analyse-hash',
    name: 'Identify hash',
    category: 'Analysis',
    description: 'Guesses what produced a hash from its length, alphabet and prefix. A shortlist, not an answer — many algorithms share a digest size.',
    keywords: ['hashid', 'identify', 'cracking', 'hashcat'],
    examples: [
      { input: '5d41402abc4b2a76b9719d911017c592', output: '32 hex characters (128 bits)\n\ncandidates\n  MD5\n  MD4\n  NTLM\n  LM (half)' },
    ],
    run(input) {
      const text = utf8Decode(input).trim();
      if (!text) throw new OperationError('Identify hash needs a hash to look at.');

      for (const [pattern, name] of HASH_PREFIXES) {
        if (pattern.test(text)) {
          return utf8Encode(`${name}\n\nIdentified by its prefix, so this one is unambiguous.`);
        }
      }

      const lines: string[] = [];
      if (/^[a-fA-F0-9]+$/.test(text)) {
        lines.push(`${text.length} hex characters (${text.length * 4} bits)`);
        const shape = HASH_SHAPES.find((s) => s.length === text.length);
        if (shape) lines.push('', 'candidates', ...shape.names.map((n) => `  ${n}`));
        else lines.push('', 'No standard digest has this length. It may be truncated or salted.');
      } else if (/^[A-Za-z0-9+/]+={0,2}$/.test(text)) {
        const bits = Math.floor((text.replace(/=/g, '').length * 6) / 8) * 8;
        lines.push(`${text.length} base64 characters (~${bits} bits decoded)`, '', 'Decode from Base64 and identify the raw digest length.');
      } else {
        lines.push('Not a bare hex or base64 digest.', '', 'It may be a full crypt(3) string, a JWT, or not a hash at all.');
      }
      return utf8Encode(lines.join('\n'));
    },
  },
  {
    id: 'take-bytes',
    name: 'Take bytes',
    category: 'Analysis',
    description: 'Keeps a slice of the input. Negative offsets count from the end.',
    keywords: ['slice', 'substring', 'cut', 'head', 'dd'],
    args: [
      { name: 'start', type: 'number', default: 0 },
      { name: 'length', type: 'number', default: 0, hint: '0 takes everything from start onwards' },
    ],
    examples: [{ input: 'Hello, world', args: { start: 7, length: 5 }, output: 'world' }],
    run(input, args) {
      const start = getNumber(args, 'start', 0);
      const length = getNumber(args, 'length', 0);
      const from = start < 0 ? Math.max(0, input.length + start) : Math.min(start, input.length);
      const to = length > 0 ? Math.min(from + length, input.length) : input.length;
      return input.slice(from, to);
    },
  },
  {
    id: 'drop-bytes',
    name: 'Drop bytes',
    category: 'Analysis',
    description: 'Removes a slice from the input — the inverse of Take bytes. Useful for stripping a header before decoding a payload.',
    keywords: ['slice', 'remove', 'strip', 'header'],
    args: [
      { name: 'start', type: 'number', default: 0 },
      { name: 'length', type: 'number', default: 1, min: 0 },
    ],
    examples: [{ input: 'XXHello', args: { start: 0, length: 2 }, output: 'Hello' }],
    run(input, args) {
      const start = Math.max(0, Math.min(getNumber(args, 'start', 0), input.length));
      const length = Math.max(0, getNumber(args, 'length', 1));
      const out = new Uint8Array(input.length - Math.min(length, input.length - start));
      out.set(input.subarray(0, start), 0);
      out.set(input.subarray(start + length), start);
      return out;
    },
  },
  {
    id: 'to-table',
    name: 'To table',
    category: 'Analysis',
    description: 'Aligns delimited text into fixed-width columns so it can be read without a spreadsheet.',
    keywords: ['align', 'columns', 'format', 'csv', 'tsv'],
    args: [
      { name: 'delimiter', type: 'select', options: ['Comma', 'Tab', 'Pipe', 'Semi-colon'], default: 'Comma' },
      { name: 'header', label: 'First row is a header', type: 'boolean', default: true },
    ],
    examples: [{ input: 'name,id\nana,1\nbo,22', output: 'name  id\n────  ──\nana   1\nbo    22' }],
    run(input, args) {
      const delimiterText: Record<string, string> = { Comma: ',', Tab: '\t', Pipe: '|', 'Semi-colon': ';' };
      const delimiter = delimiterText[getOption(args, 'delimiter', ['Comma', 'Tab', 'Pipe', 'Semi-colon'] as const, 'Comma')];

      const rows = utf8Decode(input)
        .split('\n')
        .filter((line) => line.trim() !== '')
        .map((line) => line.split(delimiter).map((cell) => cell.trim()));
      if (rows.length === 0) return utf8Encode('');

      const columnCount = Math.max(...rows.map((r) => r.length));
      const widths = Array.from({ length: columnCount }, (_, i) => Math.max(...rows.map((r) => (r[i] ?? '').length)));

      const render = (row: string[]): string =>
        row.map((cell, i) => cell.padEnd(widths[i])).join('  ').trimEnd();

      const lines = [render(rows[0])];
      if (getBoolean(args, 'header', true)) {
        lines.push(widths.map((w) => '─'.repeat(w)).join('  '));
      }
      lines.push(...rows.slice(1).map(render));
      return utf8Encode(lines.join('\n'));
    },
  },
  {
    id: 'to-raw',
    name: 'Show raw bytes',
    category: 'Analysis',
    description: 'Reinterprets the data as Latin-1 so every byte becomes one visible character. Nothing is lost, unlike a UTF-8 decode of binary data.',
    keywords: ['binary', 'latin1', 'view'],
    examples: [{ input: '48ff', inputEncoding: 'hex', output: 'Hÿ' }],
    run(input) {
      return utf8Encode(latin1Decode(input));
    },
  },
];
