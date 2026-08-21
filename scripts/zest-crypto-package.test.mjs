import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { readdir, readFile } from 'node:fs/promises';
import { basename, dirname, extname, join, relative, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const shippedExtensions = new Set(['.json', '.md', '.py', '.sage']);

async function shippedFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const nested = await Promise.all(
    entries.map(async (entry) => {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) return shippedFiles(path);
      return shippedExtensions.has(extname(entry.name)) ? [path] : [];
    }),
  );
  return nested.flat();
}

function relativeMarkdownTargets(contents) {
  return Array.from(contents.matchAll(/\[[^\]]*\]\(([^)]+)\)/g), (match) => match[1].trim())
    .map((target) => target.replace(/^<(.+)>$/, '$1').split(/[?#]/, 1)[0])
    .filter((target) => target.length > 0 && !/^(?:[a-z][a-z\d+.-]*:|\/\/)/i.test(target));
}

function isInside(directory, path) {
  const pathFromDirectory = relative(directory, path);
  return pathFromDirectory !== '..' && !pathFromDirectory.startsWith('../') && !pathFromDirectory.startsWith('..\\');
}

test('zest-crypto is a standalone publishable skill', async () => {
  // Given: the skill directory that the installer publishes independently.
  const skillDirectory = join(root, 'skills', 'zest-crypto');
  const entrypoint = join(skillDirectory, 'SKILL.md');

  // When: the package entrypoint is inspected.
  const isPresent = existsSync(entrypoint);

  // Then: it exists, names its installed directory, and exposes routing terms.
  assert.equal(isPresent, true, 'skills/zest-crypto/SKILL.md is missing');
  const contents = await readFile(entrypoint, 'utf8');
  assert.equal(/^name:\s*zest-crypto$/m.test(contents), true);
  for (const fragment of ['paper-derived', 'math-heavy', 'zest-ctf']) {
    assert.equal(contents.includes(fragment), true, `entrypoint is missing routing fragment: ${fragment}`);
  }
});

test('zest-crypto ships only self-contained Markdown links', async () => {
  // Given: every file that belongs to the standalone package.
  const skillDirectory = join(root, 'skills', 'zest-crypto');
  const files = await shippedFiles(skillDirectory);

  // When: package-relative links in every shipped Markdown document are resolved.
  for (const document of files.filter((path) => extname(path) === '.md')) {
    const contents = await readFile(document, 'utf8');
    for (const target of relativeMarkdownTargets(contents)) {
      const resolved = resolve(dirname(document), target);

      // Then: each local target stays in the package and exists in the published copy.
      assert.equal(isInside(skillDirectory, resolved), true, `${document}: ${target} escapes the standalone skill`);
      assert.equal(existsSync(resolved), true, `${document}: ${target} is missing from the standalone skill`);
    }
  }
});

test('zest-crypto does not ship a package README', async () => {
  // Given: the files copied by the standalone skill publisher.
  const skillDirectory = join(root, 'skills', 'zest-crypto');
  const files = await shippedFiles(skillDirectory);

  // When: their names are checked.
  const readmes = files.filter((path) => basename(path) === 'README.md');

  // Then: package instructions remain progressively disclosed from SKILL.md.
  assert.deepEqual(readmes, []);
});
