#!/usr/bin/env node
/**
 * Generates the operation reference from the registry.
 *
 * The catalogue an agent reads must match the code exactly, so it is derived
 * rather than maintained by hand. Run after adding or changing an operation:
 *
 *   npm run docs
 */

import { writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { CATEGORIES, listOperations, operationsByCategory, withDefaults } from '../packages/core/dist/index.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

function renderDefault(arg) {
  const value = withDefaults([arg], {})[arg.name];
  if (value && typeof value === 'object') return value.value === '' ? '—' : `\`${value.value}\``;
  if (value === '' || value === undefined) return '—';
  return `\`${value}\``;
}

function renderArgs(operation) {
  if (!operation.args?.length) return '_No arguments._\n';

  const rows = operation.args.map((arg) => {
    const type = arg.type === 'select' ? `select: ${arg.options.join(' \\| ')}` : arg.type;
    const notes = [arg.hint, arg.type === 'number' && (arg.min !== undefined || arg.max !== undefined)
      ? `range ${arg.min ?? '−∞'}…${arg.max ?? '∞'}`
      : '']
      .filter(Boolean)
      .join('. ');
    return `| \`${arg.name}\` | ${type} | ${renderDefault(arg)} | ${notes || '—'} |`;
  });

  return ['| Argument | Type | Default | Notes |', '| --- | --- | --- | --- |', ...rows].join('\n') + '\n';
}

function renderExamples(operation) {
  if (!operation.examples?.length) return '';

  const blocks = operation.examples.map((example) => {
    const args = example.args
      ? `:${Object.entries(example.args)
          .map(([k, v]) => `${k}=${v && typeof v === 'object' ? `${v.encoding}:${v.value}` : v}`)
          .join(',')}`
      : '';
    const inputNote = example.inputEncoding && example.inputEncoding !== 'utf8' ? ` --in-encoding ${example.inputEncoding}` : '';
    return [
      example.name ? `_${example.name}_` : '',
      '```console',
      `$ zest -i ${JSON.stringify(example.input)}${inputNote} ${operation.id}${args}`,
      example.output,
      '```',
    ]
      .filter(Boolean)
      .join('\n');
  });

  return `\n**Examples**\n\n${blocks.join('\n\n')}\n`;
}

const operations = listOperations();
const grouped = operationsByCategory();

const lines = [
  '# Zest operation reference',
  '',
  `Generated from the registry — ${operations.length} operations across ${CATEGORIES.filter((c) => grouped.has(c)).length} categories.`,
  'Do not edit by hand; run `npm run docs` instead.',
  '',
  '## Contents',
  '',
];

for (const category of CATEGORIES) {
  const list = grouped.get(category);
  if (!list?.length) continue;
  lines.push(`- **${category}** — ${list.map((o) => `\`${o.id}\``).join(', ')}`);
}

for (const category of CATEGORIES) {
  const list = grouped.get(category);
  if (!list?.length) continue;

  lines.push('', `## ${category}`, '');
  for (const operation of list) {
    lines.push(`### \`${operation.id}\``, '', `**${operation.name}** — ${operation.description}`, '');
    if (operation.keywords?.length) lines.push(`_Also known as: ${operation.keywords.join(', ')}._`, '');
    if (operation.binaryOutput) lines.push('_Produces binary output; chain `to-base64` or `to-hex` to make it printable._', '');
    lines.push(renderArgs(operation));
    const examples = renderExamples(operation);
    if (examples) lines.push(examples);
  }
}

const reference = `${lines.join('\n').replace(/\n{3,}/g, '\n\n')}\n`;

for (const target of ['skills/zest/references/operations.md', 'skills/zest-triage/references/operations.md']) {
  await writeFile(join(root, target), reference, 'utf8');
}

console.log(`Wrote operation reference for ${operations.length} operations.`);
