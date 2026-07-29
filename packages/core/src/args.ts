/**
 * Argument coercion.
 *
 * Recipes arrive from three places — the UI, a JSON file, and a CLI string —
 * so every reader here accepts the loose form and returns the strict one.
 * Missing values fall back to the operation's declared default.
 */

import { decodeAs } from './bytes.js';
import {
  OperationError,
  type ArgDef,
  type Args,
  type ArgValue,
  type Bytes,
  type KeyEncoding,
  type KeyValue,
} from './types.js';

const KEY_ENCODINGS: readonly KeyEncoding[] = ['utf8', 'hex', 'base64', 'latin1'];

export function isKeyValue(value: unknown): value is KeyValue {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as KeyValue).value === 'string' &&
    KEY_ENCODINGS.includes((value as KeyValue).encoding)
  );
}

export function getString(args: Args, name: string, fallback = ''): string {
  const value = args[name];
  if (value === undefined || value === null) return fallback;
  if (isKeyValue(value)) return value.value;
  return String(value);
}

export function getNumber(args: Args, name: string, fallback = 0): number {
  const value = args[name];
  if (value === undefined || value === null || value === '') return fallback;
  const num = typeof value === 'number' ? value : Number(String(value).trim());
  if (!Number.isFinite(num)) {
    throw new OperationError(`Argument ${JSON.stringify(name)} must be a number, got ${JSON.stringify(value)}.`);
  }
  return num;
}

export function getBoolean(args: Args, name: string, fallback = false): boolean {
  const value = args[name];
  if (value === undefined || value === null || value === '') return fallback;
  if (typeof value === 'boolean') return value;
  const text = String(value).trim().toLowerCase();
  if (['true', '1', 'yes', 'on'].includes(text)) return true;
  if (['false', '0', 'no', 'off'].includes(text)) return false;
  throw new OperationError(`Argument ${JSON.stringify(name)} must be true or false, got ${JSON.stringify(value)}.`);
}

/**
 * Read a key/IV argument as bytes.
 *
 * Accepts the structured `{value, encoding}` form, or the CLI shorthand
 * `"hex:00112233"`. A bare string is read with `defaultEncoding`.
 */
export function getKeyBytes(args: Args, name: string, defaultEncoding: KeyEncoding = 'utf8'): Bytes {
  const value = args[name];
  if (value === undefined || value === null) return decodeAs('', defaultEncoding);
  if (isKeyValue(value)) return decodeAs(value.value, value.encoding);

  const text = String(value);
  const prefix = /^(utf8|hex|base64|latin1):([\s\S]*)$/.exec(text);
  if (prefix) return decodeAs(prefix[2], prefix[1] as KeyEncoding);
  return decodeAs(text, defaultEncoding);
}

/** Read a select argument, checking it against the declared option list. */
export function getOption<T extends string>(
  args: Args,
  name: string,
  options: readonly T[],
  fallback: T,
): T {
  const value = args[name];
  if (value === undefined || value === null || value === '') return fallback;
  const text = String(isKeyValue(value) ? value.value : value);
  const match = options.find((o) => o.toLowerCase() === text.toLowerCase());
  if (!match) {
    throw new OperationError(
      `Argument ${JSON.stringify(name)} must be one of ${options.map((o) => JSON.stringify(o)).join(', ')}, got ${JSON.stringify(text)}.`,
    );
  }
  return match;
}

/** Fill in every declared default that the caller left out. */
export function withDefaults(defs: readonly ArgDef[] | undefined, args: Args = {}): Args {
  const out: Args = { ...args };
  if (!defs) return out;
  for (const def of defs) {
    if (out[def.name] !== undefined) continue;
    const value = defaultFor(def);
    if (value !== undefined) out[def.name] = value;
  }
  return out;
}

export function defaultFor(def: ArgDef): ArgValue | undefined {
  switch (def.type) {
    case 'string':
      return def.default ?? '';
    case 'number':
      return def.default ?? 0;
    case 'boolean':
      return def.default ?? false;
    case 'select':
      return def.default ?? def.options[0];
    case 'key':
      return { value: def.default ?? '', encoding: def.defaultEncoding ?? 'utf8' };
  }
}

/**
 * Interpret backslash escapes in a delimiter or separator argument, so a
 * recipe can say `\n` or `\x00` where a literal newline is awkward to type.
 */
export function unescapeLiteral(text: string): string {
  return text.replace(/\\(u\{[0-9a-fA-F]+\}|u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|[nrtvfb0\\'"])/g, (_, seq: string) => {
    switch (seq[0]) {
      case 'n':
        return '\n';
      case 'r':
        return '\r';
      case 't':
        return '\t';
      case 'v':
        return '\v';
      case 'f':
        return '\f';
      case 'b':
        return '\b';
      case '0':
        return '\0';
      case '\\':
        return '\\';
      case "'":
        return "'";
      case '"':
        return '"';
      case 'x':
        return String.fromCharCode(parseInt(seq.slice(1), 16));
      case 'u':
        return seq[1] === '{'
          ? String.fromCodePoint(parseInt(seq.slice(2, -1), 16))
          : String.fromCharCode(parseInt(seq.slice(1), 16));
      default:
        return seq;
    }
  });
}
