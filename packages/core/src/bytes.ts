/**
 * Byte-level primitives.
 *
 * Base64 and hex are implemented here rather than borrowed from `Buffer` or
 * `atob` so that Node and the browser produce byte-identical results and so
 * that alphabet variants (URL-safe, unpadded, custom) are first-class.
 */

import { OperationError, type Bytes, type KeyEncoding, type KeyValue } from './types.js';

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: false });

export function utf8Encode(text: string): Bytes {
  return encoder.encode(text);
}

export function utf8Decode(bytes: Bytes): string {
  return decoder.decode(bytes);
}

export function latin1Encode(text: string): Bytes {
  const out = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i++) out[i] = text.charCodeAt(i) & 0xff;
  return out;
}

export function latin1Decode(bytes: Bytes): string {
  let out = '';
  // Chunked so very large inputs do not blow the argument limit of String.fromCharCode.
  for (let i = 0; i < bytes.length; i += 8192) {
    out += String.fromCharCode(...bytes.subarray(i, i + 8192));
  }
  return out;
}

const HEX = '0123456789abcdef';

export function hexEncode(bytes: Bytes, delimiter = ''): string {
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    if (i > 0 && delimiter) out += delimiter;
    out += HEX[bytes[i] >> 4] + HEX[bytes[i] & 0x0f];
  }
  return out;
}

export function hexDecode(text: string): Bytes {
  // Tolerate whitespace, 0x prefixes and any punctuation used as a separator.
  const clean = text.replace(/0x/gi, '').replace(/[^0-9a-fA-F]/g, '');
  if (clean.length === 0 && text.trim().length > 0) {
    throw new OperationError('Input contains no hexadecimal digits.');
  }
  if (clean.length % 2 !== 0) {
    throw new OperationError(`Hex input has an odd number of digits (${clean.length}).`);
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.substr(i * 2, 2), 16);
  }
  return out;
}

export const B64_STANDARD = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
export const B64_URLSAFE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

export function base64Encode(bytes: Bytes, alphabet = B64_STANDARD, pad = true): string {
  if (alphabet.length < 64) {
    throw new OperationError(`Base64 alphabet needs 64 characters, got ${alphabet.length}.`);
  }
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const remaining = bytes.length - i;
    const a = bytes[i];
    const b = remaining > 1 ? bytes[i + 1] : 0;
    const c = remaining > 2 ? bytes[i + 2] : 0;
    const triple = (a << 16) | (b << 8) | c;

    out += alphabet[(triple >> 18) & 0x3f];
    out += alphabet[(triple >> 12) & 0x3f];
    out += remaining > 1 ? alphabet[(triple >> 6) & 0x3f] : pad ? '=' : '';
    out += remaining > 2 ? alphabet[triple & 0x3f] : pad ? '=' : '';
  }
  return out;
}

export function base64Decode(text: string, alphabet = B64_STANDARD, strict = false): Bytes {
  const lookup = new Int16Array(128).fill(-1);
  for (let i = 0; i < 64; i++) lookup[alphabet.charCodeAt(i)] = i;

  const symbols: number[] = [];
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    const value = code < 128 ? lookup[code] : -1;
    if (value >= 0) {
      symbols.push(value);
    } else if (strict && text[i] !== '=' && !/\s/.test(text[i])) {
      throw new OperationError(`Character ${JSON.stringify(text[i])} is not in the Base64 alphabet.`);
    }
  }

  if (symbols.length % 4 === 1) {
    throw new OperationError('Base64 input is truncated — a group of 4 has only 1 character left over.');
  }

  const out = new Uint8Array(Math.floor((symbols.length * 3) / 4));
  let o = 0;
  for (let i = 0; i < symbols.length; i += 4) {
    const remaining = symbols.length - i;
    const quad =
      (symbols[i] << 18) |
      (symbols[i + 1] << 12) |
      ((remaining > 2 ? symbols[i + 2] : 0) << 6) |
      (remaining > 3 ? symbols[i + 3] : 0);
    out[o++] = (quad >> 16) & 0xff;
    if (remaining > 2) out[o++] = (quad >> 8) & 0xff;
    if (remaining > 3) out[o++] = quad & 0xff;
  }
  return out.subarray(0, o);
}

export function concat(...parts: Bytes[]): Bytes {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

export function equal(a: Bytes, b: Bytes): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/** Read a string in the named encoding into bytes. */
export function decodeAs(text: string, encoding: KeyEncoding): Bytes {
  switch (encoding) {
    case 'utf8':
      return utf8Encode(text);
    case 'hex':
      return hexDecode(text);
    case 'base64':
      return base64Decode(text);
    case 'latin1':
      return latin1Encode(text);
    default:
      throw new OperationError(`Unknown encoding ${JSON.stringify(encoding)}.`);
  }
}

/** Render bytes as a string in the named encoding. */
export function encodeAs(bytes: Bytes, encoding: KeyEncoding): string {
  switch (encoding) {
    case 'utf8':
      return utf8Decode(bytes);
    case 'hex':
      return hexEncode(bytes);
    case 'base64':
      return base64Encode(bytes);
    case 'latin1':
      return latin1Decode(bytes);
    default:
      throw new OperationError(`Unknown encoding ${JSON.stringify(encoding)}.`);
  }
}

export function keyToBytes(key: KeyValue): Bytes {
  return decodeAs(key.value, key.encoding);
}

/** True when the byte run looks like human-readable text rather than binary. */
export function looksPrintable(bytes: Bytes, threshold = 0.9): boolean {
  if (bytes.length === 0) return true;
  let printable = 0;
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    // Printable ASCII, plus tab/newline/carriage return, plus UTF-8 continuation range.
    if ((b >= 0x20 && b < 0x7f) || b === 0x09 || b === 0x0a || b === 0x0d || b >= 0x80) {
      printable++;
    }
  }
  return printable / bytes.length >= threshold;
}

/** Shannon entropy in bits per byte, 0–8. */
export function shannonEntropy(bytes: Bytes): number {
  if (bytes.length === 0) return 0;
  const counts = new Uint32Array(256);
  for (let i = 0; i < bytes.length; i++) counts[bytes[i]]++;
  let entropy = 0;
  for (let i = 0; i < 256; i++) {
    if (counts[i] === 0) continue;
    const p = counts[i] / bytes.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}
