/**
 * Data format operations — JSON, CSV, query strings, JWT.
 */

import { getBoolean, getKeyBytes, getNumber, getOption, getString, unescapeLiteral } from '../args.js';
import { base64Decode, utf8Decode, utf8Encode } from '../bytes.js';
import { OperationError, type Operation } from '../types.js';

function parseJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new OperationError(`Input is not valid JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/** Split a CSV line, honouring quoted fields and doubled quotes. */
function parseCsvLine(line: string, delimiter: string): string[] {
  const fields: string[] = [];
  let current = '';
  let inQuotes = false;

  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (inQuotes) {
      if (ch === '"') {
        if (line[i + 1] === '"') {
          current += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        current += ch;
      }
    } else if (ch === '"') {
      inQuotes = true;
    } else if (ch === delimiter) {
      fields.push(current);
      current = '';
    } else {
      current += ch;
    }
  }
  fields.push(current);
  return fields;
}

function toCsvField(value: unknown, delimiter: string): string {
  const text = value === null || value === undefined ? '' : typeof value === 'object' ? JSON.stringify(value) : String(value);
  return /["\n\r]/.test(text) || text.includes(delimiter) ? `"${text.replace(/"/g, '""')}"` : text;
}

function decodeJwtSegment(segment: string, label: string): unknown {
  try {
    return JSON.parse(utf8Decode(base64Decode(segment, 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_')));
  } catch {
    throw new OperationError(`The ${label} is not valid base64url-encoded JSON.`);
  }
}

const JWT_TIME_CLAIMS = new Set(['exp', 'iat', 'nbf', 'auth_time', 'updated_at']);

export const dataOps: Operation[] = [
  {
    id: 'json-format',
    name: 'Format JSON',
    category: 'Data',
    description: 'Re-indents JSON. Sorting keys makes two documents diffable.',
    keywords: ['pretty', 'beautify', 'indent'],
    args: [
      { name: 'indent', type: 'number', default: 2, min: 0, max: 8 },
      { name: 'sortKeys', type: 'boolean', default: false },
    ],
    examples: [{ input: '{"b":1,"a":2}', args: { indent: 2 }, output: '{\n  "b": 1,\n  "a": 2\n}' }],
    run(input, args) {
      const value = parseJson(utf8Decode(input));
      const sortKeys = getBoolean(args, 'sortKeys', false);
      const replacer = sortKeys
        ? (_key: string, val: unknown) => {
            if (val && typeof val === 'object' && !Array.isArray(val)) {
              return Object.fromEntries(Object.entries(val as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b)));
            }
            return val;
          }
        : undefined;
      return utf8Encode(JSON.stringify(value, replacer, getNumber(args, 'indent', 2)));
    },
  },
  {
    id: 'json-minify',
    name: 'Minify JSON',
    category: 'Data',
    description: 'Removes all insignificant whitespace from JSON.',
    keywords: ['compact', 'compress'],
    examples: [{ input: '{\n  "a": 1\n}', output: '{"a":1}' }],
    run(input) {
      return utf8Encode(JSON.stringify(parseJson(utf8Decode(input))));
    },
  },
  {
    id: 'json-path',
    name: 'JSON extract',
    category: 'Data',
    description: 'Reads a value out of a JSON document with a dotted path. Use [n] for array indices and [*] to map over every element.',
    keywords: ['jq', 'jsonpath', 'query', 'select'],
    args: [
      { name: 'path', type: 'string', default: '', placeholder: 'data.users[*].email' },
      { name: 'raw', label: 'Emit strings unquoted', type: 'boolean', default: true },
    ],
    examples: [
      { input: '{"users":[{"name":"ana"},{"name":"bo"}]}', args: { path: 'users[*].name' }, output: 'ana\nbo' },
    ],
    run(input, args) {
      const path = getString(args, 'path').trim();
      const root = parseJson(utf8Decode(input));
      if (!path) return utf8Encode(JSON.stringify(root, null, 2));

      const tokens = path.replace(/^\$\.?/, '').match(/[^.[\]]+|\[\*\]|\[\d+\]/g) ?? [];
      let current: unknown[] = [root];

      for (const token of tokens) {
        const next: unknown[] = [];
        const wildcard = token === '[*]';
        const indexMatch = /^\[(\d+)\]$/.exec(token);

        for (const value of current) {
          if (value === null || value === undefined) continue;
          if (wildcard) {
            if (Array.isArray(value)) next.push(...value);
            else if (typeof value === 'object') next.push(...Object.values(value as Record<string, unknown>));
          } else if (indexMatch) {
            if (Array.isArray(value)) next.push(value[Number(indexMatch[1])]);
          } else if (Array.isArray(value)) {
            // Reaching through an array without [*] maps the key over its items.
            for (const item of value) {
              if (item && typeof item === 'object') next.push((item as Record<string, unknown>)[token]);
            }
          } else if (typeof value === 'object') {
            next.push((value as Record<string, unknown>)[token]);
          }
        }
        current = next;
      }

      const defined = current.filter((v) => v !== undefined);
      if (defined.length === 0) throw new OperationError(`Path ${JSON.stringify(path)} matched nothing.`);

      const raw = getBoolean(args, 'raw', true);
      return utf8Encode(
        defined.map((v) => (raw && typeof v === 'string' ? v : JSON.stringify(v, null, defined.length === 1 ? 2 : 0))).join('\n'),
      );
    },
  },
  {
    id: 'csv-to-json',
    name: 'CSV to JSON',
    category: 'Data',
    description: 'Parses CSV into an array of objects, honouring quoted fields.',
    keywords: ['spreadsheet', 'tabular', 'convert'],
    args: [
      { name: 'delimiter', type: 'string', default: ',' },
      { name: 'header', label: 'First row is a header', type: 'boolean', default: true },
      { name: 'indent', type: 'number', default: 2, min: 0, max: 8 },
    ],
    examples: [{ input: 'a,b\n1,2', args: { indent: 0 }, output: '[{"a":"1","b":"2"}]' }],
    run(input, args) {
      const delimiter = unescapeLiteral(getString(args, 'delimiter', ','))[0] ?? ',';
      const lines = utf8Decode(input).replace(/\r\n/g, '\n').split('\n').filter((l) => l.trim() !== '');
      if (lines.length === 0) return utf8Encode('[]');

      const rows = lines.map((line) => parseCsvLine(line, delimiter));
      const indent = getNumber(args, 'indent', 2);

      if (!getBoolean(args, 'header', true)) {
        return utf8Encode(JSON.stringify(rows, null, indent));
      }
      const headers = rows[0];
      const objects = rows.slice(1).map((row) => Object.fromEntries(headers.map((h, i) => [h, row[i] ?? ''])));
      return utf8Encode(JSON.stringify(objects, null, indent));
    },
  },
  {
    id: 'json-to-csv',
    name: 'JSON to CSV',
    category: 'Data',
    description: 'Flattens an array of objects into CSV. The column set is the union of every object\'s keys.',
    keywords: ['spreadsheet', 'tabular', 'convert'],
    args: [
      { name: 'delimiter', type: 'string', default: ',' },
      { name: 'header', label: 'Emit a header row', type: 'boolean', default: true },
    ],
    examples: [{ input: '[{"a":1,"b":2}]', output: 'a,b\n1,2' }],
    run(input, args) {
      const value = parseJson(utf8Decode(input));
      if (!Array.isArray(value)) throw new OperationError('JSON to CSV needs an array of objects at the top level.');
      const delimiter = unescapeLiteral(getString(args, 'delimiter', ','))[0] ?? ',';

      const columns: string[] = [];
      for (const row of value) {
        if (row && typeof row === 'object' && !Array.isArray(row)) {
          for (const key of Object.keys(row as Record<string, unknown>)) {
            if (!columns.includes(key)) columns.push(key);
          }
        }
      }

      const lines: string[] = [];
      if (getBoolean(args, 'header', true)) lines.push(columns.map((c) => toCsvField(c, delimiter)).join(delimiter));
      for (const row of value) {
        const record = (row ?? {}) as Record<string, unknown>;
        lines.push(columns.map((c) => toCsvField(record[c], delimiter)).join(delimiter));
      }
      return utf8Encode(lines.join('\n'));
    },
  },
  {
    id: 'jwt-decode',
    name: 'JWT decode',
    category: 'Data',
    description: 'Splits a JSON Web Token and decodes its header and payload. This does not verify the signature — an unverified token proves nothing.',
    keywords: ['jsonwebtoken', 'bearer', 'token', 'auth', 'oauth'],
    args: [{ name: 'expandTimes', label: 'Show timestamps as dates', type: 'boolean', default: true }],
    examples: [
      {
        input: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ.sig',
        args: { expandTimes: false },
        output: 'header\n{\n  "alg": "HS256",\n  "typ": "JWT"\n}\n\npayload\n{\n  "sub": "123"\n}\n\nsignature\nsig (3 chars, base64url)',
      },
    ],
    run(input, args) {
      const token = utf8Decode(input).trim().replace(/^Bearer\s+/i, '');
      const parts = token.split('.');
      if (parts.length < 2) {
        throw new OperationError(`A JWT has 3 dot-separated parts; this input has ${parts.length}.`);
      }

      const header = decodeJwtSegment(parts[0], 'header');
      const payload = decodeJwtSegment(parts[1], 'payload');

      const sections = [`header\n${JSON.stringify(header, null, 2)}`, `payload\n${JSON.stringify(payload, null, 2)}`];

      if (getBoolean(args, 'expandTimes', true) && payload && typeof payload === 'object') {
        const times: string[] = [];
        for (const [key, value] of Object.entries(payload as Record<string, unknown>)) {
          if (JWT_TIME_CLAIMS.has(key) && typeof value === 'number') {
            const date = new Date(value * 1000);
            const relative = key === 'exp' ? (date.getTime() < Date.now() ? '  ← expired' : '  ← still valid') : '';
            times.push(`${key.padEnd(10)} ${date.toISOString()}${relative}`);
          }
        }
        if (times.length) sections.push(`claims as dates\n${times.join('\n')}`);
      }

      const signature = parts[2] ?? '';
      const alg = (header as { alg?: string })?.alg;
      sections.push(
        `signature\n${signature || '(none)'} (${signature.length} chars, base64url)` +
          (alg === 'none' ? '\n\nWarning: alg is "none". A verifier that honours this accepts any payload.' : ''),
      );

      return utf8Encode(sections.join('\n\n'));
    },
  },
  {
    id: 'jwt-verify',
    name: 'JWT verify (HMAC)',
    category: 'Data',
    description: 'Checks an HS256/384/512 signature against a shared secret and reports whether it holds.',
    keywords: ['jsonwebtoken', 'hs256', 'signature', 'auth'],
    args: [{ name: 'secret', type: 'key', default: '', defaultEncoding: 'utf8' }],
    async run(input, args) {
      const token = utf8Decode(input).trim().replace(/^Bearer\s+/i, '');
      const parts = token.split('.');
      if (parts.length !== 3) throw new OperationError(`A signed JWT has exactly 3 parts; this input has ${parts.length}.`);

      const header = decodeJwtSegment(parts[0], 'header') as { alg?: string };
      const hashByAlg: Record<string, string> = { HS256: 'SHA-256', HS384: 'SHA-384', HS512: 'SHA-512' };
      const hash = hashByAlg[header.alg ?? ''];
      if (!hash) {
        throw new OperationError(`This operation verifies HS256, HS384 and HS512. The token declares alg=${JSON.stringify(header.alg)}.`);
      }

      const key = await globalThis.crypto.subtle.importKey('raw', getKeyBytes(args, 'secret'), { name: 'HMAC', hash }, false, ['sign']);
      const signed = new Uint8Array(await globalThis.crypto.subtle.sign('HMAC', key, utf8Encode(`${parts[0]}.${parts[1]}`)));

      const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
      let expected = '';
      for (let i = 0; i < signed.length; i += 3) {
        const remaining = signed.length - i;
        const triple = (signed[i] << 16) | ((remaining > 1 ? signed[i + 1] : 0) << 8) | (remaining > 2 ? signed[i + 2] : 0);
        expected += alphabet[(triple >> 18) & 63] + alphabet[(triple >> 12) & 63];
        if (remaining > 1) expected += alphabet[(triple >> 6) & 63];
        if (remaining > 2) expected += alphabet[triple & 63];
      }

      const valid = expected === parts[2];
      return utf8Encode(
        valid
          ? `Signature is valid (${header.alg}).`
          : `Signature does NOT match (${header.alg}).\nexpected  ${expected}\nreceived  ${parts[2]}`,
      );
    },
  },
  {
    id: 'parse-query-string',
    name: 'Parse query string',
    category: 'Data',
    description: 'Breaks a query string or form body into key/value pairs, decoding percent escapes.',
    keywords: ['url', 'params', 'form', 'urlencoded'],
    args: [{ name: 'format', type: 'select', options: ['Table', 'JSON'], default: 'Table' }],
    examples: [{ input: 'a=1&b=hello%20world', output: 'a  1\nb  hello world' }],
    run(input, args) {
      const text = utf8Decode(input).trim().replace(/^[^?]*\?/, '');
      const pairs: [string, string][] = [];
      for (const chunk of text.split(/[&;]/)) {
        if (!chunk) continue;
        const index = chunk.indexOf('=');
        const key = index < 0 ? chunk : chunk.slice(0, index);
        const value = index < 0 ? '' : chunk.slice(index + 1);
        pairs.push([safeDecode(key), safeDecode(value)]);
      }

      if (getOption(args, 'format', ['Table', 'JSON'] as const, 'Table') === 'JSON') {
        return utf8Encode(JSON.stringify(Object.fromEntries(pairs), null, 2));
      }
      const width = Math.max(0, ...pairs.map(([k]) => k.length));
      return utf8Encode(pairs.map(([k, v]) => `${k.padEnd(width)}  ${v}`).join('\n'));
    },
  },
  {
    id: 'to-query-string',
    name: 'Build query string',
    category: 'Data',
    description: 'Turns a JSON object into a percent-encoded query string.',
    keywords: ['url', 'params', 'form'],
    examples: [{ input: '{"a":1,"b":"hello world"}', output: 'a=1&b=hello%20world' }],
    run(input) {
      const value = parseJson(utf8Decode(input));
      if (!value || typeof value !== 'object' || Array.isArray(value)) {
        throw new OperationError('Build query string needs a JSON object at the top level.');
      }
      return utf8Encode(
        Object.entries(value as Record<string, unknown>)
          .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v === null || v === undefined ? '' : String(v))}`)
          .join('&'),
      );
    },
  },
  {
    id: 'xml-format',
    name: 'Format XML',
    category: 'Data',
    description: 'Re-indents XML by nesting depth. A formatter, not a validator — it will not tell you the document is malformed.',
    keywords: ['pretty', 'beautify', 'html', 'indent'],
    args: [{ name: 'indent', type: 'number', default: 2, min: 0, max: 8 }],
    examples: [{ input: '<a><b>1</b></a>', output: '<a>\n  <b>1</b>\n</a>' }],
    run(input, args) {
      const unit = ' '.repeat(getNumber(args, 'indent', 2));
      const tokens = utf8Decode(input).replace(/>\s+</g, '><').trim().match(/<[^>]*>|[^<]+/g) ?? [];

      const lines: string[] = [];
      let depth = 0;

      for (let i = 0; i < tokens.length; i++) {
        const token = tokens[i];
        if (!token.trim()) continue;

        if (token.startsWith('</')) {
          depth = Math.max(0, depth - 1);
          lines.push(unit.repeat(depth) + token);
          continue;
        }
        if (!token.startsWith('<')) {
          lines.push(unit.repeat(depth) + token.trim());
          continue;
        }

        const selfClosing = /\/>$/.test(token) || /^<[?!]/.test(token);
        const text = tokens[i + 1];
        const closing = tokens[i + 2];

        // An element whose only child is text stays on one line.
        if (!selfClosing && text && !text.startsWith('<') && closing?.startsWith('</')) {
          lines.push(unit.repeat(depth) + token + text.trim() + closing);
          i += 2;
          continue;
        }

        lines.push(unit.repeat(depth) + token);
        if (!selfClosing) depth++;
      }
      return utf8Encode(lines.join('\n'));
    },
  },
];

function safeDecode(text: string): string {
  try {
    return decodeURIComponent(text.replace(/\+/g, ' '));
  } catch {
    return text;
  }
}
