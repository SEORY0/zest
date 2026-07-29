/**
 * Magic — speculative decoding.
 *
 * Given an unidentified blob, try the decoders whose input shape plausibly
 * matches, score what comes back, and recurse. The score is the whole trick:
 * a correct decode almost always lowers entropy and raises printability, so
 * the ranking surfaces the real answer without knowing what it is in advance.
 */

import { getOperation } from './registry.js';
import { runRecipe } from './run.js';
import { detectFileType } from './filetypes.js';
import { looksPrintable, shannonEntropy, utf8Decode, utf8Encode } from './bytes.js';
import type { Args, Bytes, Operation, Recipe } from './types.js';

export interface MagicMatch {
  recipe: Recipe;
  /** Human-readable form of the recipe, e.g. `from-base64 → gunzip`. */
  label: string;
  output: Bytes;
  preview: string;
  score: number;
  /** Why this scored the way it did. */
  reasons: string[];
}

export interface MagicOptions {
  /** How many decoders to chain. 3 is enough for the usual nested cases. */
  depth?: number;
  /** Only keep results containing this text. */
  crib?: string;
  /** Also try all 256 single-byte XOR keys at the first level. */
  intensive?: boolean;
  maxResults?: number;
}

interface Candidate {
  op: string;
  args?: Args;
  /** Cheap gate — skip the operation entirely when the input cannot be this format. */
  applies: (data: Bytes, text: string) => boolean;
}

const isMostlyText = (data: Bytes): boolean => looksPrintable(data, 0.95);

const CANDIDATES: Candidate[] = [
  {
    op: 'from-base64',
    applies: (d, t) => isMostlyText(d) && /^[A-Za-z0-9+/=\s]{8,}$/.test(t) && t.replace(/[\s=]/g, '').length % 4 !== 1,
  },
  {
    op: 'from-base64',
    args: { alphabet: 'URL-safe' },
    applies: (d, t) => isMostlyText(d) && /[-_]/.test(t) && /^[A-Za-z0-9\-_=\s]{8,}$/.test(t),
  },
  {
    op: 'from-hex',
    applies: (d, t) => isMostlyText(d) && /^[0-9a-fA-F\s:,-]{8,}$/.test(t) && t.replace(/[^0-9a-fA-F]/g, '').length % 2 === 0,
  },
  {
    op: 'from-base32',
    applies: (d, t) => isMostlyText(d) && /^[A-Z2-7=\s]{8,}$/.test(t),
  },
  {
    op: 'from-base58',
    applies: (d, t) => isMostlyText(d) && /^[1-9A-HJ-NP-Za-km-z]{8,}$/.test(t),
  },
  {
    op: 'from-base85',
    // Requires at least one character outside the Base64 alphabet, so plain
    // Base64 is not misread as Ascii85.
    applies: (d, t) => isMostlyText(d) && /^[!-u\s]{8,}$/.test(t) && /[!"#$%&'()*,.:;<=>?@[\]^`{|}~-]/.test(t),
  },
  {
    op: 'url-decode',
    applies: (_d, t) => /%[0-9a-fA-F]{2}/.test(t),
  },
  {
    op: 'from-html-entity',
    applies: (_d, t) => /&(#x?[0-9a-fA-F]+|[a-zA-Z]{2,10});/.test(t),
  },
  {
    op: 'from-quoted-printable',
    applies: (_d, t) => /=[0-9A-F]{2}/.test(t),
  },
  {
    op: 'from-binary',
    applies: (_d, t) => /^[01\s]{16,}$/.test(t) && t.replace(/\s/g, '').length % 8 === 0,
  },
  {
    op: 'from-decimal',
    applies: (_d, t) => /^(\d{1,3}[\s,;]+){3,}\d{1,3}$/.test(t.trim()),
  },
  {
    op: 'from-morse',
    applies: (_d, t) => /^[.\-/\s]{6,}$/.test(t) && /[.-]/.test(t),
  },
  {
    op: 'gunzip',
    applies: (d) => d.length > 2 && ((d[0] === 0x1f && d[1] === 0x8b) || d[0] === 0x78),
  },
  {
    op: 'rot',
    args: { amount: 13 },
    applies: (_d, t) => /[a-zA-Z]{4,}/.test(t) && t.length < 100_000,
  },
  {
    op: 'from-charcode',
    args: { base: 'Hexadecimal' },
    applies: (_d, t) => /^(0x[0-9a-fA-F]{1,2}[\s,]+){3,}/.test(t.trim()),
  },
  {
    op: 'jwt-decode',
    applies: (_d, t) => /^(Bearer\s+)?[\w-]+\.[\w-]+\.[\w-]*$/.test(t.trim()),
  },
];

const PRINTABLE_ASCII = /^[\x09\x0a\x0d\x20-\x7e]*$/;

/**
 * Score a decode attempt. Positive means "this looks like a real decoding";
 * results at or below zero are dropped.
 */
function score(before: Bytes, after: Bytes): { score: number; reasons: string[] } {
  const reasons: string[] = [];
  let total = 0;

  if (after.length === 0) return { score: -100, reasons: ['empty output'] };

  const text = utf8Decode(after);
  const beforeEntropy = shannonEntropy(before);
  const afterEntropy = shannonEntropy(after);

  const fileTypes = detectFileType(after);
  if (fileTypes.length > 0) {
    total += 60;
    reasons.push(`matches ${fileTypes[0].name} signature`);
  }

  if (PRINTABLE_ASCII.test(text)) {
    total += 25;
    reasons.push('fully printable ASCII');
  } else if (looksPrintable(after, 0.9)) {
    total += 12;
    reasons.push('mostly printable');
  } else {
    total -= 15;
    reasons.push('mostly non-printable');
  }

  // A real decode compresses the alphabet: base64 text spreads 6 bits over a
  // byte, so undoing it should push entropy up, while decrypting or
  // decompressing to text pushes it down. Either direction is informative.
  const entropyDelta = afterEntropy - beforeEntropy;
  if (entropyDelta < -0.5) {
    total += 15;
    reasons.push(`entropy fell ${Math.abs(entropyDelta).toFixed(2)} bits`);
  }

  if (/^\s*[{[]/.test(text)) {
    try {
      JSON.parse(text);
      total += 45;
      reasons.push('valid JSON');
    } catch {
      total += 5;
    }
  }

  if (/^\s*<\?xml|^\s*<[a-zA-Z][\w:-]*[\s>]/.test(text)) {
    total += 25;
    reasons.push('looks like XML or HTML');
  }

  if (/https?:\/\/[^\s]+/.test(text)) {
    total += 15;
    reasons.push('contains a URL');
  }

  // Word-shaped runs separated by spaces are the strongest signal for prose.
  const words = text.match(/\b[a-zA-Z]{2,}\b/g) ?? [];
  const wordCoverage = words.join('').length / text.length;
  if (words.length >= 3 && wordCoverage > 0.5) {
    total += 25;
    reasons.push('reads as natural language');
  }

  if (/\0{4,}/.test(text)) {
    total -= 10;
    reasons.push('long null runs');
  }

  return { score: total, reasons };
}

function labelFor(recipe: Recipe): string {
  return recipe
    .map((step) => {
      const args = step.args ? Object.entries(step.args).filter(([, v]) => v !== '' && v !== undefined) : [];
      const suffix = args.length ? `(${args.map(([k, v]) => `${k}=${formatArg(v)}`).join(', ')})` : '';
      return step.op + suffix;
    })
    .join(' → ');
}

function formatArg(value: unknown): string {
  if (value && typeof value === 'object' && 'value' in value) {
    const key = value as { value: string; encoding: string };
    return `${key.encoding}:${key.value}`;
  }
  return String(value);
}

function preview(data: Bytes, limit = 160): string {
  const text = utf8Decode(data.subarray(0, limit));
  const cleaned = Array.from(text)
    .map((ch) => {
      const code = ch.charCodeAt(0);
      return code < 0x20 && code !== 0x0a && code !== 0x09 ? '·' : ch;
    })
    .join('')
    .replace(/\n/g, '\\n');
  return data.length > limit ? `${cleaned}…` : cleaned;
}

/** Try every plausible decoding chain and return the best-scoring results. */
export async function magic(input: Bytes, options: MagicOptions = {}): Promise<MagicMatch[]> {
  const depth = Math.max(1, Math.min(options.depth ?? 3, 4));
  const maxResults = options.maxResults ?? 12;
  const crib = options.crib?.toLowerCase();

  const results: MagicMatch[] = [];
  const seen = new Set<string>();

  const walk = async (data: Bytes, recipe: Recipe, remaining: number): Promise<void> => {
    if (remaining === 0) return;
    const text = utf8Decode(data).trim();

    const attempts: { op: string; args?: Args }[] = CANDIDATES.filter((c) => {
      try {
        return c.applies(data, text);
      } catch {
        return false;
      }
    }).map((c) => ({ op: c.op, args: c.args }));

    if (options.intensive && recipe.length === 0) {
      for (let key = 1; key < 256; key++) {
        attempts.push({ op: 'xor', args: { key: `hex:${key.toString(16).padStart(2, '0')}` } });
      }
    }

    for (const attempt of attempts) {
      // Never immediately undo the step just taken.
      const previous = recipe[recipe.length - 1]?.op;
      if (previous && isInverse(previous, attempt.op)) continue;

      const nextRecipe: Recipe = [...recipe, { op: attempt.op, args: attempt.args }];
      const run = await runRecipe(data, [{ op: attempt.op, args: attempt.args }]);
      if (!run.ok || run.output.length === 0) continue;

      // Identity transforms carry no information.
      if (run.output.length === data.length && utf8Decode(run.output) === utf8Decode(data)) continue;

      const fingerprint = `${utf8Decode(run.output.subarray(0, 256))}|${run.output.length}`;
      if (!seen.has(fingerprint)) {
        seen.add(fingerprint);

        const assessment = score(data, run.output);
        const previewText = preview(run.output);
        const matchesCrib = !crib || previewText.toLowerCase().includes(crib) || utf8Decode(run.output).toLowerCase().includes(crib);

        if (matchesCrib && (assessment.score > 0 || crib)) {
          results.push({
            recipe: nextRecipe,
            label: labelFor(nextRecipe),
            output: run.output,
            preview: previewText,
            // Prefer the shortest chain that reaches an equally good answer.
            score: assessment.score + (crib ? 100 : 0) - (nextRecipe.length - 1) * 5,
            reasons: assessment.reasons,
          });
        }
      }

      await walk(run.output, nextRecipe, remaining - 1);
    }
  };

  await walk(input, [], depth);

  return results.sort((a, b) => b.score - a.score).slice(0, maxResults);
}

const INVERSE_PAIRS: [string, string][] = [
  ['from-base64', 'to-base64'],
  ['from-hex', 'to-hex'],
  ['from-base32', 'to-base32'],
  ['url-decode', 'url-encode'],
  ['gunzip', 'gzip'],
];

function isInverse(a: string, b: string): boolean {
  return INVERSE_PAIRS.some(([x, y]) => (a === x && b === y) || (a === y && b === x));
}

/** The registry-facing wrapper, so Magic is usable from the workbench too. */
export const magicOp: Operation = {
  id: 'magic',
  name: 'Magic',
  category: 'Analysis',
  description:
    'Works out what the input is by trying every plausible decoding and ranking the results. Start here when you do not know what you are holding.',
  keywords: ['detect', 'auto', 'identify', 'decode', 'guess', 'unknown'],
  args: [
    { name: 'depth', label: 'Chain up to N decoders', type: 'number', default: 3, min: 1, max: 4 },
    { name: 'crib', label: 'Known plaintext', type: 'string', default: '', hint: 'Only show results containing this text' },
    { name: 'intensive', label: 'Also try single-byte XOR', type: 'boolean', default: false },
  ],
  async run(input, args) {
    const matches = await magic(input, {
      depth: Number(args.depth ?? 3),
      crib: String(args.crib ?? '') || undefined,
      intensive: args.intensive === true || args.intensive === 'true',
    });

    if (matches.length === 0) {
      return utf8Encode('No decoding produced a better-looking result. The input may already be plaintext, or encrypted with an unknown key.');
    }

    return utf8Encode(
      matches
        .map((m, i) => `${String(i + 1).padStart(2)}. ${m.label}\n    score ${m.score}  (${m.reasons.join(', ')})\n    ${m.preview}`)
        .join('\n\n'),
    );
  },
};

/** Re-exported so callers can resolve an op referenced by a MagicMatch recipe. */
export { getOperation };
