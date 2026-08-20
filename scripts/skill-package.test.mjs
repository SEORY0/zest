import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { dirname, join, relative, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

test('zest-ctf is a standalone publishable skill', async () => {
  // Given: the skill directory that the installer publishes independently.
  const skillDirectory = join(root, 'skills', 'zest-ctf');
  const entrypoint = join(skillDirectory, 'SKILL.md');

  // When: the package surface is inspected without any companion skill.
  const isPresent = existsSync(entrypoint);

  // Then: the machine-consumed entrypoint exists and names the installed directory.
  assert.equal(isPresent, true, 'skills/zest-ctf/SKILL.md is missing');
  const contents = await readFile(entrypoint, 'utf8');
  const name = /^name:\s*(.+)$/m.exec(contents)?.[1]?.trim();
  assert.equal(name, 'zest-ctf');
});

test('zest-ctf keeps every relative document link inside its standalone package', async () => {
  // Given: the documents copied when an installer selects only zest-ctf.
  const skillDirectory = join(root, 'skills', 'zest-ctf');
  const documents = [join(skillDirectory, 'SKILL.md'), join(skillDirectory, 'references', 'playbooks.md')];

  // When: relative Markdown links are resolved from each document.
  for (const document of documents) {
    const contents = await readFile(document, 'utf8');
    const targets = Array.from(contents.matchAll(/\]\(([^)]+\.md)(?:#[^)]+)?\)/g), (match) => match[1]);

    // Then: every linked document ships inside this skill and exists.
    for (const target of targets) {
      const resolved = resolve(dirname(document), target);
      assert.equal(relative(skillDirectory, resolved).startsWith('..'), false, `${target} escapes the standalone skill`);
      assert.equal(existsSync(resolved), true, `${target} is missing from the standalone skill`);
    }
  }
});
