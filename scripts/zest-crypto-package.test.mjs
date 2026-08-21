import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { mkdir, mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
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

function normalizeReferenceLabel(label) {
  return label.trim().replace(/\s+/g, ' ').toLowerCase();
}

function referenceDefinitions(contents) {
  return new Map(
    Array.from(contents.matchAll(/^ {0,3}\[([^\]\n]+)\]:[ \t]*(?:<([^>\n]+)>|(\S+))/gm), (match) => [
      normalizeReferenceLabel(match[1]),
      match[2] ?? match[3],
    ]),
  );
}

function referenceTargets(contents, definitions) {
  const explicit = Array.from(contents.matchAll(/!?\[([^\]\n]+)\]\[([^\]\n]*)\]/g), (match) => match[2] || match[1]);
  const shortcut = Array.from(contents.matchAll(/(?<!\])!?\[([^\]\n]+)\](?![\[(\:])/g), (match) => match[1]);
  return [...explicit, ...shortcut].map((label) => {
    const target = definitions.get(normalizeReferenceLabel(label));
    assert.notEqual(target, undefined, `unresolved Markdown reference: ${label}`);
    return target;
  });
}

function relativeMarkdownTargets(contents) {
  const inline = Array.from(contents.matchAll(/\[[^\]]*\]\(([^)]+)\)/g), (match) => match[1].trim());
  const referenced = referenceTargets(contents, referenceDefinitions(contents));
  return [...inline, ...referenced]
    .map((target) => target.replace(/^<(.+)>$/, '$1').split(/[?#]/, 1)[0])
    .filter((target) => target.length > 0 && !/^(?:[a-z][a-z\d+.-]*:|\/\/)/i.test(target));
}

function isInside(directory, path) {
  const pathFromDirectory = relative(directory, path);
  return pathFromDirectory !== '..' && !pathFromDirectory.startsWith('../') && !pathFromDirectory.startsWith('..\\');
}

async function assertLocalMarkdownLinks(skillDirectory) {
  const files = await shippedFiles(skillDirectory);
  for (const document of files.filter((path) => extname(path) === '.md')) {
    const contents = await readFile(document, 'utf8');
    for (const target of relativeMarkdownTargets(contents)) {
      const resolved = resolve(dirname(document), target);
      assert.equal(isInside(skillDirectory, resolved), true, `${document}: ${target} escapes the standalone skill`);
      assert.equal(existsSync(resolved), true, `${document}: ${target} is missing from the standalone skill`);
    }
  }
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

  // When: package-relative links in every shipped Markdown document are resolved.
  await assertLocalMarkdownLinks(skillDirectory);
});

test('zest-crypto rejects an escaping reference-style Markdown link', async () => {
  // Given: a standalone package with a reference-style link to an outside path.
  const fixtureRoot = await mkdtemp(join(tmpdir(), 'zest-crypto-package-'));
  const skillDirectory = join(fixtureRoot, 'zest-crypto');
  await mkdir(skillDirectory);
  await writeFile(
    join(skillDirectory, 'fixture.md'),
    '[Escaping reference][outside]\n\n[outside]: ../escape.md\n',
    'utf8',
  );

  try {
    // When: the package-boundary checker resolves its links.
    const check = assertLocalMarkdownLinks(skillDirectory);

    // Then: the escaped target is rejected rather than silently ignored.
    await assert.rejects(check, /escapes the standalone skill/);
  } finally {
    await rm(fixtureRoot, { force: true, recursive: true });
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
