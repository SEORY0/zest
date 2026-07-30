#!/usr/bin/env node
/**
 * zest — a command-line data and security workbench.
 *
 * Designed to be driven by a person at a terminal or by an agent over stdio.
 * Every command accepts `--json`, nothing writes outside the paths you name,
 * and no operation touches the network.
 */

import { readFile, writeFile } from 'node:fs/promises';
import process from 'node:process';

import {
  CATEGORIES,
  decodeAs,
  encodeAs,
  getOperation,
  listOperations,
  looksPrintable,
  operationsByCategory,
  runRecipe,
  searchOperations,
  utf8Decode,
  withDefaults,
  type ArgDef,
  type Bytes,
  type Operation,
  type Recipe,
} from '@zest/core';

import { parseArgv, parseStep, UsageError, type Flags, type ParsedCommand } from './parse.js';

const VERSION = '0.1.0';

const EXIT_OK = 0;
const EXIT_FAILED = 1;
const EXIT_USAGE = 2;

// Downstream commands like `head` close the pipe early. That is a normal way
// for a pipeline to end, not an error worth a stack trace.
for (const stream of [process.stdout, process.stderr]) {
  stream.on('error', (error: NodeJS.ErrnoException) => {
    if (error.code === 'EPIPE') process.exit(EXIT_OK);
    throw error;
  });
}

// --- Terminal helpers -------------------------------------------------------

const useColour = process.stdout.isTTY && !process.env.NO_COLOR;
const paint = (code: string, text: string): string => (useColour ? `\u001b[${code}m${text}\u001b[0m` : text);
const bold = (t: string): string => paint('1', t);
const dim = (t: string): string => paint('2', t);
const cyan = (t: string): string => paint('36', t);
const red = (t: string): string => paint('31', t);

function print(text: string): void {
  process.stdout.write(`${text}\n`);
}

function printError(text: string): void {
  process.stderr.write(`${red('error')} ${text}\n`);
}

// --- Input and output -------------------------------------------------------

async function readStdin(): Promise<Bytes> {
  if (process.stdin.isTTY) return new Uint8Array(0);
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
  const joined = Buffer.concat(chunks);
  return new Uint8Array(joined.buffer.slice(joined.byteOffset, joined.byteOffset + joined.byteLength)) as Bytes;
}

async function resolveInput(flags: Flags): Promise<Bytes> {
  if (flags.inputEnv !== undefined) return decodeAs(flags.inputEnv, flags.inEncoding);
  if (flags.input !== undefined) return decodeAs(flags.input, flags.inEncoding);
  if (flags.file !== undefined) {
    const contents = await readFile(flags.file);
    const bytes = new Uint8Array(contents.buffer.slice(contents.byteOffset, contents.byteOffset + contents.byteLength)) as Bytes;
    // A file read as hex or base64 is text describing bytes, not the bytes.
    return flags.inEncoding === 'utf8' ? bytes : decodeAs(utf8Decode(bytes).trim(), flags.inEncoding);
  }
  const stdin = await readStdin();
  return flags.inEncoding === 'utf8' ? stdin : decodeAs(utf8Decode(stdin).trim(), flags.inEncoding);
}

/**
 * Choose how to render the result. Binary output is emitted as base64 rather
 * than mangled UTF-8, because a caller that cannot read the bytes back is
 * worse off than one that has to decode.
 */
function chooseOutputEncoding(data: Bytes, requested: Flags['outEncoding']): 'utf8' | 'hex' | 'base64' | 'latin1' {
  if (requested) return requested;
  return looksPrintable(data, 0.95) ? 'utf8' : 'base64';
}

// --- Rendering --------------------------------------------------------------

function describeArg(arg: ArgDef): string {
  const parts: string[] = [`${cyan(arg.name)}=${dim(`<${arg.type}>`)}`];
  if (arg.type === 'select') parts.push(dim(`one of ${arg.options.join(' | ')}`));
  if (arg.type === 'number' && (arg.min !== undefined || arg.max !== undefined)) {
    parts.push(dim(`range ${arg.min ?? '-∞'}..${arg.max ?? '∞'}`));
  }
  const defaults = withDefaults([arg], {});
  const value = defaults[arg.name];
  const shown = typeof value === 'object' && value !== null ? (value as { value: string }).value : value;
  if (shown !== '' && shown !== undefined) parts.push(dim(`default ${JSON.stringify(shown)}`));
  return parts.join('  ');
}

function renderOperation(operation: Operation): string {
  const lines = [
    `${bold(operation.name)}  ${dim(`(${operation.id})`)}`,
    dim(operation.category),
    '',
    operation.description,
  ];

  if (operation.args?.length) {
    lines.push('', bold('arguments'));
    for (const arg of operation.args) {
      lines.push(`  ${describeArg(arg)}`);
      if (arg.hint) lines.push(`    ${dim(arg.hint)}`);
    }
  }

  if (operation.examples?.length) {
    lines.push('', bold('examples'));
    for (const example of operation.examples) {
      const args = example.args
        ? `:${Object.entries(example.args)
            .map(([k, v]) => `${k}=${typeof v === 'object' && v !== null ? (v as { value: string }).value : v}`)
            .join(',')}`
        : '';
      lines.push(`  ${dim('$')} echo ${JSON.stringify(example.input)} | zest ${operation.id}${args}`);
      lines.push(`  ${example.output.split('\n').join('\n  ')}`);
      lines.push('');
    }
  }

  if (operation.keywords?.length) {
    lines.push(`${dim('also known as')} ${operation.keywords.join(', ')}`);
  }
  return lines.join('\n');
}

function operationToJson(operation: Operation): unknown {
  return {
    id: operation.id,
    name: operation.name,
    category: operation.category,
    description: operation.description,
    binaryOutput: operation.binaryOutput ?? false,
    keywords: operation.keywords ?? [],
    args: (operation.args ?? []).map((arg) => ({
      name: arg.name,
      label: arg.label ?? arg.name,
      type: arg.type,
      hint: arg.hint,
      default: withDefaults([arg], {})[arg.name],
      ...(arg.type === 'select' ? { options: arg.options } : {}),
      ...(arg.type === 'number' ? { min: arg.min, max: arg.max } : {}),
    })),
    examples: operation.examples ?? [],
  };
}

/** The first sentence of a description, for one-line listings. */
function firstSentence(description: string): string {
  const end = description.indexOf('. ');
  return end < 0 ? description : `${description.slice(0, end)}.`;
}

// --- Commands ---------------------------------------------------------------

function commandOps(operands: string[], flags: Flags): number {
  const query = operands.join(' ').trim();
  const matches = query ? searchOperations(query) : listOperations();

  if (flags.json) {
    print(JSON.stringify(matches.map(operationToJson), null, 2));
    return EXIT_OK;
  }

  if (matches.length === 0) {
    printError(`No operation matches ${JSON.stringify(query)}.`);
    return EXIT_FAILED;
  }

  if (query) {
    const width = Math.max(...matches.map((o) => o.id.length));
    for (const operation of matches) {
      print(`${cyan(operation.id.padEnd(width))}  ${firstSentence(operation.description)}`);
    }
    return EXIT_OK;
  }

  // No query: show the whole catalogue grouped, which is the useful default.
  const grouped = operationsByCategory();
  for (const category of CATEGORIES) {
    const operations = grouped.get(category);
    if (!operations?.length) continue;

    print(bold(category));
    const width = Math.max(...operations.map((o) => o.id.length));
    for (const operation of operations) {
      print(`  ${cyan(operation.id.padEnd(width))}  ${dim(operation.name)}`);
    }
    print('');
  }
  print(dim(`${listOperations().length} operations. \`zest op <id>\` for detail, \`zest ops <query>\` to search.`));
  return EXIT_OK;
}

function commandOp(operands: string[], flags: Flags): number {
  const id = operands[0];
  if (!id) throw new UsageError('`zest op` needs an operation id, e.g. `zest op from-base64`.');

  const operation = getOperation(id);
  print(flags.json ? JSON.stringify(operationToJson(operation), null, 2) : renderOperation(operation));
  return EXIT_OK;
}

async function commandRun(operands: string[], flags: Flags): Promise<number> {
  let recipe: Recipe;

  if (flags.recipe) {
    const contents = await readFile(flags.recipe, 'utf8');
    const parsed: unknown = JSON.parse(contents);
    const steps = Array.isArray(parsed) ? parsed : (parsed as { recipe?: unknown }).recipe;
    if (!Array.isArray(steps)) {
      throw new UsageError(`${flags.recipe} must contain a JSON array of steps, or an object with a "recipe" array.`);
    }
    recipe = steps as Recipe;
    // Steps given on the command line append to a loaded recipe.
    recipe.push(...operands.map(parseStep));
  } else {
    if (operands.length === 0) throw new UsageError('Name at least one operation, or pass --recipe. Try `zest ops`.');
    recipe = operands.map(parseStep);
  }

  // Resolve every operation up front so a typo fails before any work is done.
  for (const step of recipe) getOperation(step.op);

  const input = await resolveInput(flags);
  const result = await runRecipe(input, recipe, { timeoutMs: flags.timeoutMs });

  if (flags.saveRecipe) {
    await writeFile(flags.saveRecipe, `${JSON.stringify(recipe, null, 2)}\n`, 'utf8');
  }

  const encoding = chooseOutputEncoding(result.output, flags.outEncoding);
  const rendered = encodeAs(result.output, encoding);

  if (flags.json) {
    print(
      JSON.stringify(
        {
          ok: result.ok,
          error: result.error,
          failedAt: result.failedAt,
          output: rendered,
          outputEncoding: encoding,
          outputBytes: result.output.length,
          steps: result.steps.map((step, index) => ({
            index,
            op: step.op,
            ok: step.ok,
            skipped: step.skipped,
            error: step.error,
            outputBytes: step.output?.length ?? 0,
            durationMs: Number(step.durationMs.toFixed(3)),
          })),
          recipe,
        },
        null,
        2,
      ),
    );
    return result.ok ? EXIT_OK : EXIT_FAILED;
  }

  if (!result.ok) {
    printError(result.error ?? 'The recipe failed.');
    if (result.output.length > 0 && !flags.quiet) {
      process.stderr.write(`${dim('output before the failing step:')}\n`);
    }
  }

  if (flags.out) {
    await writeFile(flags.out, result.output);
    if (!flags.quiet) print(dim(`Wrote ${result.output.length} bytes to ${flags.out}.`));
  } else if (result.output.length > 0) {
    process.stdout.write(rendered);
    if (!rendered.endsWith('\n')) process.stdout.write('\n');
    if (encoding === 'base64' && !flags.outEncoding && !flags.quiet) {
      process.stderr.write(dim('(output is binary, shown as base64 — use --out-encoding hex or --out FILE)\n'));
    }
  }

  return result.ok ? EXIT_OK : EXIT_FAILED;
}

function commandHelp(): number {
  print(
    `${bold('zest')} ${dim(VERSION)} — local-first data and security workbench

${bold('usage')}
  zest <operation>[:args] [<operation>[:args] ...]   run a pipeline over stdin
  zest ops [query]                                   list or search operations
  zest op <id>                                       show one operation in detail

${bold('input')}
  -i, --input TEXT        use TEXT instead of reading stdin
      --input-env NAME    read input from environment variable NAME
  -f, --file PATH         read input from PATH
      --in-encoding ENC   read input as utf8 (default), hex, base64 or latin1

${bold('output')}
  -o, --out PATH          write raw bytes to PATH
      --out-encoding ENC  render output as utf8, hex, base64 or latin1
      --json              emit a structured result, including per-step timings
  -q, --quiet             suppress notes on stderr

${bold('recipes')}
      --recipe PATH       load a recipe from JSON; command-line steps append to it
      --save-recipe PATH  write the recipe that ran to PATH
      --timeout MS        abort any step that runs longer than MS

${bold('arguments')}
  Pass operation arguments after a colon, comma-separated:
    zest to-base64:alphabet=URL-safe,padding=false
  Quote a value that contains a comma:
    zest find-replace:find="a,b",replace=x
  Keys and IVs take an inline encoding:
    zest aes-decrypt:key=hex:00112233...,iv=hex:aabb...,mode=GCM

${bold('secrets')}
  Never write a key or password into an argument — argv is visible to anyone
  who can run \`ps\`, and it lands in shell history. Read it indirectly:
    zest hmac:key=env:SIGNING_SECRET
    zest aes-decrypt:key=file:/run/secrets/aes.key,iv=env:NONCE
  The resolved value keeps any encoding prefix it contains, so a variable
  holding "hex:00112233" is still read as hex.

${bold('examples')}
  ${dim('$')} echo 'SGVsbG8=' | zest from-base64
  ${dim('$')} echo -n 'hello' | zest sha2:size=SHA-256
  ${dim('$')} zest -i 'admin:secret' to-base64 to-hex
  ${dim('$')} cat suspicious.bin | zest magic:depth=3
  ${dim('$')} cat token.txt | zest jwt-decode
  ${dim('$')} zest -f capture.bin strings:minLength=8 | zest extract-indicators

Everything runs locally. No operation opens a network connection.`,
  );
  return EXIT_OK;
}

// --- Entry point ------------------------------------------------------------

async function main(): Promise<number> {
  let parsed: ParsedCommand;
  try {
    parsed = parseArgv(process.argv.slice(2));
  } catch (error) {
    printError(error instanceof Error ? error.message : String(error));
    return EXIT_USAGE;
  }

  const { command, operands, flags } = parsed;

  // Bare `zest` with nothing piped in is a request for help, not an empty run.
  if (command === 'run' && operands.length === 0 && !flags.recipe) return commandHelp();

  try {
    switch (command) {
      case 'help':
        return commandHelp();
      case 'version':
        print(VERSION);
        return EXIT_OK;
      case 'ops':
        return commandOps(operands, flags);
      case 'op':
        return commandOp(operands, flags);
      case 'run':
        return await commandRun(operands, flags);
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (flags.json) {
      print(JSON.stringify({ ok: false, error: message }, null, 2));
    } else {
      printError(message);
    }
    return error instanceof UsageError ? EXIT_USAGE : EXIT_FAILED;
  }
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (error: unknown) => {
    printError(error instanceof Error ? error.stack ?? error.message : String(error));
    process.exitCode = EXIT_FAILED;
  },
);
