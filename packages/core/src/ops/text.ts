/**
 * Text operations — line- and character-level manipulation.
 */

import { getBoolean, getNumber, getOption, getString, unescapeLiteral } from '../args.js';
import { utf8Decode, utf8Encode } from '../bytes.js';
import { OperationError, type Operation } from '../types.js';

const CASES = ['lower', 'UPPER', 'Title', 'Sentence', 'camelCase', 'snake_case', 'kebab-case', 'CONSTANT_CASE'] as const;

function splitWords(text: string): string[] {
  return text
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .split(/[^a-zA-Z0-9]+/)
    .filter(Boolean);
}

function changeCase(text: string, style: (typeof CASES)[number]): string {
  switch (style) {
    case 'lower':
      return text.toLowerCase();
    case 'UPPER':
      return text.toUpperCase();
    case 'Title':
      return text.replace(/\w\S*/g, (word) => word[0].toUpperCase() + word.slice(1).toLowerCase());
    case 'Sentence':
      return text.toLowerCase().replace(/(^\s*\w|[.!?]\s+\w)/g, (m) => m.toUpperCase());
    case 'camelCase':
      return splitWords(text)
        .map((w, i) => (i === 0 ? w.toLowerCase() : w[0].toUpperCase() + w.slice(1).toLowerCase()))
        .join('');
    case 'snake_case':
      return splitWords(text).map((w) => w.toLowerCase()).join('_');
    case 'kebab-case':
      return splitWords(text).map((w) => w.toLowerCase()).join('-');
    case 'CONSTANT_CASE':
      return splitWords(text).map((w) => w.toUpperCase()).join('_');
  }
}

function buildRegex(pattern: string, flags: string, literal: boolean): RegExp {
  const source = literal ? pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') : pattern;
  try {
    return new RegExp(source, flags);
  } catch (error) {
    throw new OperationError(`Invalid regular expression: ${error instanceof Error ? error.message : String(error)}`);
  }
}

export const textOps: Operation[] = [
  {
    id: 'change-case',
    name: 'Change case',
    category: 'Text',
    description: 'Converts text between the common casing conventions.',
    keywords: ['uppercase', 'lowercase', 'camel', 'snake', 'kebab'],
    args: [{ name: 'style', type: 'select', options: CASES, default: 'lower' }],
    examples: [
      { input: 'Hello World', args: { style: 'snake_case' }, output: 'hello_world' },
      { input: 'user_id_value', args: { style: 'camelCase' }, output: 'userIdValue' },
    ],
    run(input, args) {
      return utf8Encode(changeCase(utf8Decode(input), getOption(args, 'style', CASES, 'lower')));
    },
  },
  {
    id: 'reverse',
    name: 'Reverse',
    category: 'Text',
    description: 'Reverses the input by character, line or byte.',
    keywords: ['flip', 'mirror'],
    args: [{ name: 'by', type: 'select', options: ['Character', 'Line', 'Byte'], default: 'Character' }],
    examples: [{ input: 'abc\ndef', args: { by: 'Line' }, output: 'def\nabc' }],
    run(input, args) {
      const by = getOption(args, 'by', ['Character', 'Line', 'Byte'] as const, 'Character');
      if (by === 'Byte') return input.slice().reverse();
      const text = utf8Decode(input);
      if (by === 'Line') return utf8Encode(text.split('\n').reverse().join('\n'));
      return utf8Encode(Array.from(text).reverse().join(''));
    },
  },
  {
    id: 'sort-lines',
    name: 'Sort lines',
    category: 'Text',
    description: 'Sorts lines alphabetically, numerically or by length.',
    keywords: ['order', 'alphabetical'],
    args: [
      { name: 'order', type: 'select', options: ['Alphabetical', 'Numeric', 'Length', 'IP address'], default: 'Alphabetical' },
      { name: 'reverse', type: 'boolean', default: false },
      { name: 'caseSensitive', type: 'boolean', default: false },
    ],
    examples: [{ input: 'banana\napple\ncherry', output: 'apple\nbanana\ncherry' }],
    run(input, args) {
      const order = getOption(args, 'order', ['Alphabetical', 'Numeric', 'Length', 'IP address'] as const, 'Alphabetical');
      const caseSensitive = getBoolean(args, 'caseSensitive', false);
      const lines = utf8Decode(input).split('\n');

      const ipKey = (line: string): number => {
        const parts = line.trim().split('.').map(Number);
        if (parts.length !== 4 || parts.some((p) => !Number.isInteger(p) || p < 0 || p > 255)) return Number.MAX_SAFE_INTEGER;
        return ((parts[0] * 256 + parts[1]) * 256 + parts[2]) * 256 + parts[3];
      };

      lines.sort((a, b) => {
        switch (order) {
          case 'Numeric':
            return (parseFloat(a) || 0) - (parseFloat(b) || 0);
          case 'Length':
            return a.length - b.length || a.localeCompare(b);
          case 'IP address':
            return ipKey(a) - ipKey(b);
          default:
            return caseSensitive ? (a < b ? -1 : a > b ? 1 : 0) : a.toLowerCase().localeCompare(b.toLowerCase());
        }
      });

      if (getBoolean(args, 'reverse', false)) lines.reverse();
      return utf8Encode(lines.join('\n'));
    },
  },
  {
    id: 'unique-lines',
    name: 'Unique lines',
    category: 'Text',
    description: 'Removes duplicate lines, keeping the first occurrence of each.',
    keywords: ['dedupe', 'distinct', 'uniq'],
    args: [
      { name: 'caseSensitive', type: 'boolean', default: true },
      { name: 'showCounts', label: 'Prefix each line with its count', type: 'boolean', default: false },
    ],
    examples: [{ input: 'a\nb\na\nc', output: 'a\nb\nc' }],
    run(input, args) {
      const caseSensitive = getBoolean(args, 'caseSensitive', true);
      const showCounts = getBoolean(args, 'showCounts', false);
      const counts = new Map<string, { line: string; count: number }>();

      for (const line of utf8Decode(input).split('\n')) {
        const key = caseSensitive ? line : line.toLowerCase();
        const existing = counts.get(key);
        if (existing) existing.count++;
        else counts.set(key, { line, count: 1 });
      }

      return utf8Encode(
        Array.from(counts.values())
          .map((entry) => (showCounts ? `${String(entry.count).padStart(6)} ${entry.line}` : entry.line))
          .join('\n'),
      );
    },
  },
  {
    id: 'filter-lines',
    name: 'Filter lines',
    category: 'Text',
    description: 'Keeps or drops lines matching a pattern. The workhorse for cutting a log down to the interesting part.',
    keywords: ['grep', 'match', 'search'],
    args: [
      { name: 'pattern', type: 'string', default: '' },
      { name: 'literal', label: 'Treat pattern as literal text', type: 'boolean', default: false },
      { name: 'invert', label: 'Drop matching lines instead', type: 'boolean', default: false },
      { name: 'caseSensitive', type: 'boolean', default: true },
    ],
    examples: [{ input: 'error: a\nok: b\nerror: c', args: { pattern: '^error' }, output: 'error: a\nerror: c' }],
    run(input, args) {
      const pattern = getString(args, 'pattern');
      if (!pattern) return input;
      const regex = buildRegex(pattern, getBoolean(args, 'caseSensitive', true) ? '' : 'i', getBoolean(args, 'literal', false));
      const invert = getBoolean(args, 'invert', false);
      return utf8Encode(
        utf8Decode(input)
          .split('\n')
          .filter((line) => regex.test(line) !== invert)
          .join('\n'),
      );
    },
  },
  {
    id: 'find-replace',
    name: 'Find and replace',
    category: 'Text',
    description: 'Replaces matches of a pattern. Capture groups are available as $1, $2 and so on.',
    keywords: ['substitute', 'regex', 'sed'],
    args: [
      { name: 'find', type: 'string', default: '' },
      { name: 'replace', type: 'string', default: '' },
      { name: 'literal', label: 'Treat pattern as literal text', type: 'boolean', default: false },
      { name: 'global', type: 'boolean', default: true },
      { name: 'caseSensitive', type: 'boolean', default: true },
      { name: 'multiline', label: '^ and $ match each line', type: 'boolean', default: true },
    ],
    examples: [{ input: 'a1b2c3', args: { find: '[0-9]', replace: '#' }, output: 'a#b#c#' }],
    run(input, args) {
      const find = getString(args, 'find');
      if (!find) return input;
      let flags = '';
      if (getBoolean(args, 'global', true)) flags += 'g';
      if (!getBoolean(args, 'caseSensitive', true)) flags += 'i';
      if (getBoolean(args, 'multiline', true)) flags += 'm';
      const regex = buildRegex(find, flags, getBoolean(args, 'literal', false));
      return utf8Encode(utf8Decode(input).replace(regex, unescapeLiteral(getString(args, 'replace'))));
    },
  },
  {
    id: 'regex-extract',
    name: 'Regex extract',
    category: 'Text',
    description: 'Pulls out every match of a pattern, one per line. With a capture group, extracts the group instead of the whole match.',
    keywords: ['regex', 'match', 'scrape', 'grep -o'],
    args: [
      { name: 'pattern', type: 'string', default: '' },
      { name: 'caseSensitive', type: 'boolean', default: true },
      { name: 'unique', label: 'Remove duplicates', type: 'boolean', default: false },
    ],
    examples: [
      { input: 'a@x.test b@y.test', args: { pattern: '[\\w.]+@[\\w.]+' }, output: 'a@x.test\nb@y.test' },
    ],
    run(input, args) {
      const pattern = getString(args, 'pattern');
      if (!pattern) throw new OperationError('Regex extract needs a pattern.');
      const regex = buildRegex(pattern, getBoolean(args, 'caseSensitive', true) ? 'g' : 'gi', false);

      const results: string[] = [];
      for (const match of utf8Decode(input).matchAll(regex)) {
        results.push(match[1] !== undefined ? match[1] : match[0]);
      }
      const final = getBoolean(args, 'unique', false) ? Array.from(new Set(results)) : results;
      return utf8Encode(final.join('\n'));
    },
  },
  {
    id: 'split-join',
    name: 'Split and join',
    category: 'Text',
    description: 'Re-delimits a list: split on one string, join with another. Use \\n and \\t for whitespace.',
    keywords: ['delimiter', 'csv', 'implode', 'explode'],
    args: [
      { name: 'splitOn', type: 'string', default: ',' },
      { name: 'joinWith', type: 'string', default: '\\n' },
      { name: 'trim', label: 'Trim each part', type: 'boolean', default: true },
      { name: 'dropEmpty', type: 'boolean', default: false },
    ],
    examples: [{ input: 'a, b, c', args: { splitOn: ',', joinWith: '|' }, output: 'a|b|c' }],
    run(input, args) {
      const splitOn = unescapeLiteral(getString(args, 'splitOn', ','));
      const joinWith = unescapeLiteral(getString(args, 'joinWith', '\n'));
      let parts = utf8Decode(input).split(splitOn);
      if (getBoolean(args, 'trim', true)) parts = parts.map((p) => p.trim());
      if (getBoolean(args, 'dropEmpty', false)) parts = parts.filter(Boolean);
      return utf8Encode(parts.join(joinWith));
    },
  },
  {
    id: 'remove-whitespace',
    name: 'Remove whitespace',
    category: 'Text',
    description: 'Strips whitespace. Useful before decoding a value that was pretty-printed across lines.',
    keywords: ['trim', 'strip', 'clean'],
    args: [
      { name: 'spaces', type: 'boolean', default: true },
      { name: 'lineFeeds', type: 'boolean', default: true },
      { name: 'tabs', type: 'boolean', default: true },
      { name: 'carriageReturns', type: 'boolean', default: true },
    ],
    examples: [{ input: 'a b\nc\td', output: 'abcd' }],
    run(input, args) {
      let text = utf8Decode(input);
      if (getBoolean(args, 'spaces', true)) text = text.replace(/ /g, '');
      if (getBoolean(args, 'lineFeeds', true)) text = text.replace(/\n/g, '');
      if (getBoolean(args, 'tabs', true)) text = text.replace(/\t/g, '');
      if (getBoolean(args, 'carriageReturns', true)) text = text.replace(/\r/g, '');
      return utf8Encode(text);
    },
  },
  {
    id: 'trim-lines',
    name: 'Trim lines',
    category: 'Text',
    description: 'Removes leading and trailing whitespace from each line.',
    keywords: ['strip', 'clean'],
    args: [{ name: 'side', type: 'select', options: ['Both', 'Start', 'End'], default: 'Both' }],
    examples: [{ input: '  a  \n  b', output: 'a\nb' }],
    run(input, args) {
      const side = getOption(args, 'side', ['Both', 'Start', 'End'] as const, 'Both');
      return utf8Encode(
        utf8Decode(input)
          .split('\n')
          .map((line) => (side === 'Start' ? line.trimStart() : side === 'End' ? line.trimEnd() : line.trim()))
          .join('\n'),
      );
    },
  },
  {
    id: 'head-tail',
    name: 'Head / tail',
    category: 'Text',
    description: 'Keeps the first or last N lines.',
    keywords: ['limit', 'truncate', 'first', 'last'],
    args: [
      { name: 'end', type: 'select', options: ['Head', 'Tail'], default: 'Head' },
      { name: 'count', type: 'number', default: 10, min: 0 },
    ],
    examples: [{ input: 'a\nb\nc\nd', args: { count: 2 }, output: 'a\nb' }],
    run(input, args) {
      const lines = utf8Decode(input).split('\n');
      const count = getNumber(args, 'count', 10);
      const head = getOption(args, 'end', ['Head', 'Tail'] as const, 'Head') === 'Head';
      return utf8Encode((head ? lines.slice(0, count) : lines.slice(-count || lines.length)).join('\n'));
    },
  },
  {
    id: 'pad-lines',
    name: 'Pad lines',
    category: 'Text',
    description: 'Adds a prefix or suffix to every line. Handy for quoting a list into a SQL IN clause or a shell loop.',
    keywords: ['prefix', 'suffix', 'wrap', 'quote'],
    args: [
      { name: 'prefix', type: 'string', default: '' },
      { name: 'suffix', type: 'string', default: '' },
      { name: 'skipEmpty', type: 'boolean', default: true },
    ],
    examples: [{ input: 'a\nb', args: { prefix: "'", suffix: "'," }, output: "'a',\n'b'," }],
    run(input, args) {
      const prefix = unescapeLiteral(getString(args, 'prefix'));
      const suffix = unescapeLiteral(getString(args, 'suffix'));
      const skipEmpty = getBoolean(args, 'skipEmpty', true);
      return utf8Encode(
        utf8Decode(input)
          .split('\n')
          .map((line) => (skipEmpty && line === '' ? line : prefix + line + suffix))
          .join('\n'),
      );
    },
  },
  {
    id: 'count',
    name: 'Count',
    category: 'Text',
    description: 'Reports byte, character, word and line counts.',
    keywords: ['length', 'wc', 'statistics'],
    examples: [{ input: 'hello world', output: 'bytes       11\ncharacters  11\nwords        2\nlines        1' }],
    run(input) {
      const text = utf8Decode(input);
      const rows: [string, number][] = [
        ['bytes', input.length],
        ['characters', Array.from(text).length],
        ['words', text.trim() ? text.trim().split(/\s+/).length : 0],
        ['lines', text === '' ? 0 : text.split('\n').length],
      ];
      const width = Math.max(...rows.map((r) => r[0].length));
      const valueWidth = Math.max(...rows.map((r) => String(r[1]).length));
      return utf8Encode(rows.map(([k, v]) => `${k.padEnd(width)}  ${String(v).padStart(valueWidth)}`).join('\n'));
    },
  },
  {
    id: 'escape-string',
    name: 'Escape string',
    category: 'Text',
    description: 'Escapes text so it can be pasted into source code as a string literal.',
    keywords: ['quote', 'literal', 'json', 'python'],
    args: [
      { name: 'style', type: 'select', options: ['JSON', 'JavaScript', 'Python', 'Shell'], default: 'JSON' },
      { name: 'quotes', type: 'boolean', label: 'Include surrounding quotes', default: false },
    ],
    examples: [{ input: 'a"b\nc', output: 'a\\"b\\nc' }],
    run(input, args) {
      const style = getOption(args, 'style', ['JSON', 'JavaScript', 'Python', 'Shell'] as const, 'JSON');
      const text = utf8Decode(input);
      const quotes = getBoolean(args, 'quotes', false);

      if (style === 'Shell') {
        // Single quotes are literal in POSIX shells; the only escape needed is for ' itself.
        const escaped = text.replace(/'/g, `'\\''`);
        return utf8Encode(quotes ? `'${escaped}'` : escaped);
      }
      const json = JSON.stringify(text);
      return utf8Encode(quotes ? json : json.slice(1, -1));
    },
  },
  {
    id: 'unescape-string',
    name: 'Unescape string',
    category: 'Text',
    description: 'Resolves backslash escapes — \\n, \\t, \\xNN, \\uNNNN — back to the characters they stand for.',
    keywords: ['unquote', 'literal', 'json'],
    examples: [{ input: 'a\\nb\\x21', output: 'a\nb!' }],
    run(input) {
      return utf8Encode(unescapeLiteral(utf8Decode(input).replace(/^["']|["']$/g, '')));
    },
  },
];
