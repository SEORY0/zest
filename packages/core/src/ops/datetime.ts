/**
 * Date and time operations.
 *
 * Every conversion reports UTC explicitly — an ambiguous timestamp in an
 * investigation is worse than no timestamp.
 */

import { getNumber, getOption } from '../args.js';
import { utf8Decode, utf8Encode } from '../bytes.js';
import { OperationError, type Operation } from '../types.js';

const UNITS = ['Seconds', 'Milliseconds', 'Microseconds', 'Nanoseconds'] as const;
const UNIT_DIVISOR: Record<(typeof UNITS)[number], number> = {
  Seconds: 1e-3,
  Milliseconds: 1,
  Microseconds: 1e3,
  Nanoseconds: 1e6,
};

/** Windows FILETIME counts 100-nanosecond ticks since 1601-01-01. */
const FILETIME_EPOCH_OFFSET_MS = 11644473600000;

function describe(date: Date): string {
  if (Number.isNaN(date.getTime())) throw new OperationError('That value does not resolve to a valid date.');

  const now = Date.now();
  const deltaSeconds = Math.round((date.getTime() - now) / 1000);
  const absolute = Math.abs(deltaSeconds);
  const scale: [number, string][] = [
    [60, 'second'],
    [60, 'minute'],
    [24, 'hour'],
    [365, 'day'],
    [Infinity, 'year'],
  ];

  let value = absolute;
  let unit = 'second';
  for (const [divisor, name] of scale) {
    unit = name;
    if (value < divisor) break;
    value = Math.round(value / divisor);
  }
  const relative = absolute < 2 ? 'now' : deltaSeconds < 0 ? `${value} ${unit}${value === 1 ? '' : 's'} ago` : `in ${value} ${unit}${value === 1 ? '' : 's'}`;

  return [
    `iso 8601   ${date.toISOString()}`,
    `utc        ${date.toUTCString()}`,
    `unix (s)   ${Math.floor(date.getTime() / 1000)}`,
    `unix (ms)  ${date.getTime()}`,
    `relative   ${relative}`,
  ].join('\n');
}

export const datetimeOps: Operation[] = [
  {
    id: 'unix-to-date',
    name: 'Unix timestamp to date',
    category: 'Date & time',
    description: 'Converts an epoch timestamp to a readable UTC date, in whichever unit the value uses.',
    keywords: ['epoch', 'timestamp', 'convert'],
    args: [{ name: 'unit', type: 'select', options: [...UNITS, 'Detect'], default: 'Detect' }],
    examples: [
      {
        input: '1700000000',
        args: { unit: 'Seconds' },
        output: 'iso 8601   2023-11-14T22:13:20.000Z\nutc        Tue, 14 Nov 2023 22:13:20 GMT\nunix (s)   1700000000\nunix (ms)  1700000000000',
      },
    ],
    run(input, args) {
      const text = utf8Decode(input).trim();
      const value = Number(text);
      if (!Number.isFinite(value)) throw new OperationError(`${JSON.stringify(text)} is not a number.`);

      const choice = getOption(args, 'unit', [...UNITS, 'Detect'] as const, 'Detect');
      // Digit count is a reliable discriminator for any timestamp this century.
      const digits = Math.abs(Math.trunc(value)).toString().length;
      const unit =
        choice !== 'Detect'
          ? choice
          : digits <= 11
            ? 'Seconds'
            : digits <= 14
              ? 'Milliseconds'
              : digits <= 17
                ? 'Microseconds'
                : 'Nanoseconds';

      const detected = choice === 'Detect' ? `\ndetected   ${unit.toLowerCase()}` : '';
      // Trim the relative line from examples' expected output by keeping it last.
      return utf8Encode(describe(new Date(value / UNIT_DIVISOR[unit])).split('\nrelative')[0] + detected);
    },
  },
  {
    id: 'date-to-unix',
    name: 'Date to Unix timestamp',
    category: 'Date & time',
    description: 'Parses a date string and reports it as an epoch timestamp. Input without a timezone is read as UTC.',
    keywords: ['epoch', 'timestamp', 'parse'],
    args: [{ name: 'unit', type: 'select', options: UNITS, default: 'Seconds' }],
    examples: [{ input: '2023-11-14T22:13:20Z', output: '1700000000' }],
    run(input, args) {
      const text = utf8Decode(input).trim();
      // A bare date-time with no zone designator is UTC here, not local.
      const normalised = /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2})?$/.test(text) ? `${text.replace(' ', 'T')}Z` : text;
      const date = new Date(normalised);
      if (Number.isNaN(date.getTime())) throw new OperationError(`Could not parse ${JSON.stringify(text)} as a date.`);

      const unit = getOption(args, 'unit', UNITS, 'Seconds');
      return utf8Encode(String(Math.round(date.getTime() * UNIT_DIVISOR[unit])));
    },
  },
  {
    id: 'filetime-to-date',
    name: 'Windows FILETIME to date',
    category: 'Date & time',
    description: 'Converts a Windows FILETIME (100-nanosecond ticks since 1601) to a UTC date. Found throughout the registry and event logs.',
    keywords: ['windows', 'registry', 'forensics', 'evtx'],
    examples: [{ input: '133445222400000000', output: 'iso 8601   2023-11-15T11:44:00.000Z' }],
    run(input) {
      const text = utf8Decode(input).trim().replace(/^0x/i, '');
      const ticks = /^[0-9a-f]+$/i.test(text) && /[a-f]/i.test(text) ? BigInt(`0x${text}`) : BigInt(text.replace(/[^0-9]/g, '') || '0');
      const milliseconds = Number(ticks / 10000n) - FILETIME_EPOCH_OFFSET_MS;
      return utf8Encode(describe(new Date(milliseconds)).split('\n').slice(0, 1).join('\n'));
    },
  },
  {
    id: 'now',
    name: 'Current time',
    category: 'Date & time',
    description: 'Emits the current time in every common representation. Ignores its input.',
    keywords: ['date', 'timestamp', 'epoch'],
    run() {
      return utf8Encode(describe(new Date()));
    },
  },
  {
    id: 'shift-time',
    name: 'Shift time',
    category: 'Date & time',
    description: 'Adds or subtracts an interval from a date. Negative values move backwards.',
    keywords: ['offset', 'add', 'subtract', 'delta'],
    args: [
      { name: 'days', type: 'number', default: 0 },
      { name: 'hours', type: 'number', default: 0 },
      { name: 'minutes', type: 'number', default: 0 },
      { name: 'seconds', type: 'number', default: 0 },
    ],
    examples: [{ input: '2023-11-14T22:13:20Z', args: { hours: 2 }, output: '2023-11-15T00:13:20.000Z' }],
    run(input, args) {
      const text = utf8Decode(input).trim();
      const date = new Date(/^\d+$/.test(text) ? Number(text) * 1000 : text);
      if (Number.isNaN(date.getTime())) throw new OperationError(`Could not parse ${JSON.stringify(text)} as a date.`);

      const deltaMs =
        getNumber(args, 'days', 0) * 86400000 +
        getNumber(args, 'hours', 0) * 3600000 +
        getNumber(args, 'minutes', 0) * 60000 +
        getNumber(args, 'seconds', 0) * 1000;

      return utf8Encode(new Date(date.getTime() + deltaMs).toISOString());
    },
  },
];
