#!/usr/bin/env node
/**
 * Mirrors `skills/` into the standalone SEORY0/zest-skill repository.
 *
 * The monorepo stays the source of truth — `references/operations.md` is
 * generated from the operation registry — but people installing the skill
 * should not have to clone the whole workbench to get it. This publishes a
 * repo that contains nothing but the skills.
 *
 *   npm run publish:skill              # push if anything changed
 *   npm run publish:skill -- --dry-run # show what would change
 *
 * Requires `gh` to be authenticated with push access to the target repo.
 */

import { execFileSync } from 'node:child_process';
import { cpSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const TARGET = 'SEORY0/zest-skill';
const dryRun = process.argv.includes('--dry-run');

const run = (cmd, args, cwd) =>
  execFileSync(cmd, args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();

/** Pull `name` and `description` out of a SKILL.md front matter block. */
function readFrontMatter(path) {
  const text = readFileSync(path, 'utf8');
  const match = /^---\n([\s\S]*?)\n---/.exec(text);
  if (!match) throw new Error(`${path} has no front matter.`);

  const read = (key) => {
    const found = new RegExp(`^${key}:\\s*(.+)$`, 'm').exec(match[1]);
    if (!found) throw new Error(`${path} front matter has no ${key}.`);
    return found[1].trim();
  };
  return { name: read('name'), description: read('description') };
}

const skillNames = readdirSync(join(root, 'skills'), { withFileTypes: true })
  .filter((entry) => entry.isDirectory())
  .map((entry) => entry.name)
  .sort();

const skills = skillNames.map((name) => ({
  dir: name,
  ...readFrontMatter(join(root, 'skills', name, 'SKILL.md')),
}));

// The front-matter name is what agents match on, so a mismatch with the
// directory would install a skill under a name nobody references.
for (const skill of skills) {
  if (skill.name !== skill.dir) {
    throw new Error(`skills/${skill.dir}/SKILL.md declares name "${skill.name}"; they must match.`);
  }
}

function buildReadme() {
  const rows = skills
    .map((s) => `| [\`${s.name}\`](skills/${s.dir}/SKILL.md) | ${s.description.split('. ')[0]}. |`)
    .join('\n');

  return `# Zest skills

Agent skills for [Zest](https://github.com/SEORY0/zest) — a local-first data and security
workbench. Encode, decode, hash, encrypt, decompress and analyse data without anything leaving
the machine.

## Install

\`\`\`bash
npx skills add ${TARGET}
\`\`\`

To install just one:

\`\`\`bash
${skills.map((s) => `npx skills add ${TARGET} --skill ${s.name}`).join('\n')}
\`\`\`

## What is in here

| Skill | For |
| --- | --- |
${rows}

## The CLI

Both skills drive the \`zest\` command. Install it once — it needs Node 20 or newer:

\`\`\`bash
git clone https://github.com/SEORY0/zest.git
cd zest && npm install && npm run build && npm link -w @zest/cli
\`\`\`

\`\`\`console
$ echo 'SGVsbG8sIHdvcmxkIQ==' | zest from-base64
Hello, world!

$ echo 'U0dWc2JHOHNJSGR2Y214a0lRPT0=' | zest magic:depth=2
 1. from-base64 → from-base64
    score 35  (fully printable ASCII, entropy fell 0.74 bits)
    Hello, world!
\`\`\`

There is a browser version at <https://seory0.github.io/zest/> for when a command line is not
available.

## Note

This repository is generated. \`skills/\` is mirrored from the
[main repository](https://github.com/SEORY0/zest), where \`references/operations.md\` is built
from the operation registry itself — so the catalogue an agent reads always matches the code.
Open issues and pull requests there.

MIT licensed.
`;
}

const workDir = mkdtempSync(join(tmpdir(), 'zest-skill-'));
const checkout = join(workDir, 'repo');

try {
  let exists = true;
  try {
    run('gh', ['repo', 'view', TARGET, '--json', 'name']);
  } catch {
    exists = false;
  }

  if (!exists && dryRun) {
    // Nothing to clone or diff against, so just report what would be published.
    const listed = [
      'README.md',
      '.gitignore',
      ...readdirSync(join(root, 'skills'), { recursive: true, withFileTypes: true })
        .filter((e) => e.isFile())
        .map((e) => join('skills', e.parentPath.replace(join(root, 'skills'), '').replace(/^\//, ''), e.name)),
    ];
    console.log(`Would create ${TARGET} and publish:`);
    for (const file of listed) console.log(`  ${file}`);
    process.exit(0);
  }

  if (!exists) {
    console.log(`Creating ${TARGET}…`);
    run('gh', [
      'repo',
      'create',
      TARGET,
      '--public',
      '--description',
      'Agent skills for Zest — a local-first data and security workbench. 103 operations, no network calls.',
    ]);
  }

  run('git', ['clone', '--quiet', `https://github.com/${TARGET}.git`, checkout]);
  // A freshly created repo has no commits, so the branch is unborn.
  run('git', ['checkout', '--quiet', '-B', 'main'], checkout);

  // Replace the mirrored content wholesale so deletions propagate.
  rmSync(join(checkout, 'skills'), { recursive: true, force: true });
  cpSync(join(root, 'skills'), join(checkout, 'skills'), { recursive: true });
  writeFileSync(join(checkout, 'README.md'), buildReadme(), 'utf8');
  writeFileSync(join(checkout, '.gitignore'), 'node_modules/\n.DS_Store\n', 'utf8');

  run('git', ['add', '-A'], checkout);
  const staged = run('git', ['diff', '--cached', '--name-only'], checkout);

  if (!staged) {
    console.log('Already up to date.');
    process.exit(0);
  }

  console.log(`Changed:\n${staged.split('\n').map((l) => `  ${l}`).join('\n')}`);
  if (dryRun) {
    console.log('\nDry run — nothing pushed.');
    process.exit(0);
  }

  const sourceCommit = run('git', ['rev-parse', '--short', 'HEAD'], root);
  run('git', ['commit', '--quiet', '-m', `Sync skills from SEORY0/zest@${sourceCommit}`], checkout);
  run('git', ['push', '--quiet', '-u', 'origin', 'main'], checkout);

  console.log(`\nPushed to https://github.com/${TARGET}`);
  console.log(`Install with:  npx skills add ${TARGET}`);
} finally {
  rmSync(workDir, { recursive: true, force: true });
}
