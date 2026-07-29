/**
 * Command-line parsing.
 *
 * A step is written `op:key=value,key2=value2`. Values may be quoted when they
 * contain a comma, and a key argument may carry its encoding inline as
 * `key=hex:00ff`.
 */

import type { Args, RecipeStep } from '@zest/core';

export class UsageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UsageError';
  }
}

/** Split on `separator`, ignoring separators inside single or double quotes. */
function splitUnquoted(text: string, separator: string): string[] {
  const parts: string[] = [];
  let current = '';
  let quote: string | null = null;

  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (quote) {
      if (ch === quote) quote = null;
      else current += ch;
    } else if (ch === '"' || ch === "'") {
      quote = ch;
    } else if (ch === '\\' && i + 1 < text.length && text[i + 1] === separator) {
      current += separator;
      i++;
    } else if (ch === separator) {
      parts.push(current);
      current = '';
    } else {
      current += ch;
    }
  }
  parts.push(current);
  return parts;
}

function coerce(raw: string): string | number | boolean {
  if (raw === 'true') return true;
  if (raw === 'false') return false;
  // Only treat it as a number when the round-trip is exact, so "007" and
  // "1e5000" stay strings rather than becoming something else.
  if (/^-?\d+(\.\d+)?$/.test(raw) && String(Number(raw)) === raw) return Number(raw);
  return raw;
}

export function parseStep(token: string): RecipeStep {
  const separator = token.indexOf(':');
  if (separator < 0) return { op: token, args: {} };

  const op = token.slice(0, separator);
  const rest = token.slice(separator + 1);
  if (!op) throw new UsageError(`Step ${JSON.stringify(token)} has no operation name before the colon.`);

  const args: Args = {};
  for (const pair of splitUnquoted(rest, ',')) {
    if (!pair.trim()) continue;
    const equals = pair.indexOf('=');
    if (equals < 0) {
      throw new UsageError(
        `Argument ${JSON.stringify(pair)} in step ${JSON.stringify(op)} is missing a value. Write it as key=value.`,
      );
    }
    const key = pair.slice(0, equals).trim();
    const value = pair.slice(equals + 1).replace(/^["']|["']$/g, '');
    args[key] = coerce(value);
  }
  return { op, args };
}

export interface Flags {
  input?: string;
  file?: string;
  out?: string;
  inEncoding: 'utf8' | 'hex' | 'base64' | 'latin1';
  outEncoding?: 'utf8' | 'hex' | 'base64' | 'latin1';
  json: boolean;
  recipe?: string;
  saveRecipe?: string;
  quiet: boolean;
  timeoutMs: number;
}

export interface ParsedCommand {
  command: 'run' | 'ops' | 'op' | 'help' | 'version';
  /** Positional arguments left after flags are removed. */
  operands: string[];
  flags: Flags;
}

const ENCODINGS = ['utf8', 'hex', 'base64', 'latin1'] as const;

function readEncoding(value: string | undefined, flag: string): (typeof ENCODINGS)[number] {
  if (!value) throw new UsageError(`${flag} needs a value: ${ENCODINGS.join(', ')}.`);
  const match = ENCODINGS.find((e) => e === value.toLowerCase());
  if (!match) throw new UsageError(`${flag} must be one of ${ENCODINGS.join(', ')}, got ${JSON.stringify(value)}.`);
  return match;
}

export function parseArgv(argv: string[]): ParsedCommand {
  const flags: Flags = { inEncoding: 'utf8', json: false, quiet: false, timeoutMs: 0 };
  const operands: string[] = [];
  let command: ParsedCommand['command'] | undefined;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    const next = (): string => {
      const value = argv[++i];
      if (value === undefined) throw new UsageError(`${arg} needs a value.`);
      return value;
    };

    switch (arg) {
      case '-i':
      case '--input':
        flags.input = next();
        break;
      case '-f':
      case '--file':
        flags.file = next();
        break;
      case '-o':
      case '--out':
        flags.out = next();
        break;
      case '--in-encoding':
        flags.inEncoding = readEncoding(next(), '--in-encoding');
        break;
      case '--out-encoding':
        flags.outEncoding = readEncoding(next(), '--out-encoding');
        break;
      case '--json':
        flags.json = true;
        break;
      case '--recipe':
        flags.recipe = next();
        break;
      case '--save-recipe':
        flags.saveRecipe = next();
        break;
      case '--timeout':
        flags.timeoutMs = Number(next());
        break;
      case '-q':
      case '--quiet':
        flags.quiet = true;
        break;
      case '-h':
      case '--help':
        command = 'help';
        break;
      case '-v':
      case '--version':
        command = 'version';
        break;
      default: {
        if (arg.startsWith('-') && arg !== '-') {
          throw new UsageError(`Unknown flag ${JSON.stringify(arg)}. Run \`zest --help\` for the full list.`);
        }
        // The first bare word may be a subcommand; everything after is an operand.
        if (!command && operands.length === 0 && (arg === 'ops' || arg === 'op' || arg === 'help')) {
          command = arg === 'help' ? 'help' : (arg as 'ops' | 'op');
        } else {
          operands.push(arg);
        }
      }
    }
  }

  return { command: command ?? 'run', operands, flags };
}
