/**
 * Core type vocabulary.
 *
 * Every operation is bytes in, bytes out. Text operations decode UTF-8
 * internally. Keeping one canonical currency means any operation can be
 * chained after any other without a conversion table.
 */

/**
 * Pinned to `ArrayBuffer` rather than `ArrayBufferLike` so byte arrays pass
 * straight into WebCrypto and the stream APIs, which reject SharedArrayBuffer
 * views. Every array Zest creates owns a plain buffer anyway.
 */
export type Bytes = Uint8Array<ArrayBuffer>;

export type MaybePromise<T> = T | Promise<T>;

/** How the literal text of a key, IV or delimiter argument should be read. */
export type KeyEncoding = 'utf8' | 'hex' | 'base64' | 'latin1';

export interface KeyValue {
  value: string;
  encoding: KeyEncoding;
}

export type ArgValue = string | number | boolean | KeyValue;

export type Args = Record<string, ArgValue>;

export const CATEGORIES = [
  'Encoding',
  'Hashing',
  'Encryption',
  'Text',
  'Data',
  'Compression',
  'Network',
  'Analysis',
  'Date & time',
  'Generate',
] as const;

export type Category = (typeof CATEGORIES)[number];

interface ArgBase {
  /** Machine name, used as the key in `Args` and on the CLI. */
  name: string;
  /** Human label. Falls back to `name`. */
  label?: string;
  hint?: string;
}

export interface StringArg extends ArgBase {
  type: 'string';
  default?: string;
  placeholder?: string;
  multiline?: boolean;
}

export interface NumberArg extends ArgBase {
  type: 'number';
  default?: number;
  min?: number;
  max?: number;
  step?: number;
}

export interface BooleanArg extends ArgBase {
  type: 'boolean';
  default?: boolean;
}

export interface SelectArg extends ArgBase {
  type: 'select';
  options: readonly string[];
  default?: string;
}

/** A byte string the user supplies in one of several encodings. */
export interface KeyArg extends ArgBase {
  type: 'key';
  default?: string;
  defaultEncoding?: KeyEncoding;
  encodings?: readonly KeyEncoding[];
}

export type ArgDef = StringArg | NumberArg | BooleanArg | SelectArg | KeyArg;

/**
 * A worked example. These are documentation, CLI help, and the test suite all
 * at once — `test/examples.test.ts` executes every one of them.
 */
export interface OperationExample {
  name?: string;
  input: string;
  args?: Args;
  output: string;
  /** How `input` should be read. Defaults to utf8. */
  inputEncoding?: KeyEncoding;
  /** How `output` should be rendered for comparison. Defaults to utf8. */
  outputEncoding?: KeyEncoding;
}

export interface Operation {
  /** Stable kebab-case identifier. This is what recipes and the CLI reference. */
  id: string;
  name: string;
  category: Category;
  description: string;
  args?: readonly ArgDef[];
  /** Output is bytes, not text — the UI shows a hex dump instead of a text pane. */
  binaryOutput?: boolean;
  /** Extra search terms so people find the op under the name they already know. */
  keywords?: readonly string[];
  examples?: readonly OperationExample[];
  run(input: Bytes, args: Args): MaybePromise<Bytes>;
}

export interface RecipeStep {
  op: string;
  args?: Args;
  disabled?: boolean;
}

export type Recipe = RecipeStep[];

export interface StepResult {
  op: string;
  ok: boolean;
  skipped: boolean;
  /** Output of this step, present when `ok`. */
  output?: Bytes;
  error?: string;
  durationMs: number;
}

export interface RunResult {
  ok: boolean;
  output: Bytes;
  steps: StepResult[];
  error?: string;
  /** Index of the step that failed, when `ok` is false. */
  failedAt?: number;
}

export class OperationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'OperationError';
  }
}
