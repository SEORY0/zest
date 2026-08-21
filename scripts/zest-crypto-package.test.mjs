import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { mkdir, mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, extname, join, relative } from 'node:path';
import test from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';

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

function isEscaped(characters, index) {
  let backslashes = 0;
  for (let cursor = index - 1; characters[cursor] === '\\'; cursor -= 1) backslashes += 1;
  return backslashes % 2 === 1;
}

function maskCode(contents) {
  const characters = contents.split('');
  let fence;
  let lineStart = 0;

  while (lineStart < contents.length) {
    const nextLine = contents.indexOf('\n', lineStart);
    const lineEnd = nextLine === -1 ? contents.length : nextLine;
    const line = contents.slice(lineStart, lineEnd);
    const openingFence = /^(?: {0,3})(`{3,}|~{3,})/.exec(line);

    if (fence) {
      characters.fill(' ', lineStart, lineEnd);
      if (new RegExp(`^ {0,3}${fence.marker}{${fence.length},}[ \\t]*$`).test(line)) fence = undefined;
    } else if (openingFence) {
      characters.fill(' ', lineStart, lineEnd);
      fence = { length: openingFence[1].length, marker: openingFence[1][0] };
    } else if (/^(?: {4}|\t)/.test(line)) {
      characters.fill(' ', lineStart, lineEnd);
    }

    lineStart = lineEnd + 1;
  }

  for (let start = 0; start < characters.length; start += 1) {
    if (characters[start] !== '`' || isEscaped(characters, start)) continue;
    let openingEnd = start;
    while (characters[openingEnd] === '`') openingEnd += 1;
    const length = openingEnd - start;

    for (let end = openingEnd; end < characters.length; end += 1) {
      if (characters[end] !== '`' || isEscaped(characters, end)) continue;
      let closingEnd = end;
      while (characters[closingEnd] === '`') closingEnd += 1;
      if (closingEnd - end !== length) {
        end = closingEnd - 1;
        continue;
      }
      characters.fill(' ', start, closingEnd);
      start = closingEnd - 1;
      break;
    }
  }

  return characters.join('');
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
  const markdown = maskCode(contents);
  const inline = Array.from(markdown.matchAll(/\[[^\]]*\]\(([^)]+)\)/g), (match) => match[1].trim());
  const referenced = referenceTargets(markdown, referenceDefinitions(markdown));
  return [...inline, ...referenced]
    .map((target) => target.replace(/^<(.+)>$/, '$1').split(/[?#]/, 1)[0])
    .filter((target) => target.length > 0 && !/^(?:[a-z][a-z\d+.-]*:|\/\/)/i.test(target));
}

function isInside(directory, path) {
  const pathFromDirectory = relative(directory, path);
  return pathFromDirectory !== '..' && !pathFromDirectory.startsWith('../') && !pathFromDirectory.startsWith('..\\');
}

function resolveMarkdownTarget(document, target) {
  try {
    return fileURLToPath(new URL(target, pathToFileURL(document)));
  } catch (error) {
    if (error instanceof TypeError || error instanceof URIError) {
      assert.fail(`${document}: ${target} is an invalid local Markdown URL`);
    }
    throw error;
  }
}

async function assertLocalMarkdownLinks(skillDirectory) {
  const files = await shippedFiles(skillDirectory);
  for (const document of files.filter((path) => extname(path) === '.md')) {
    const contents = await readFile(document, 'utf8');
    for (const target of relativeMarkdownTargets(contents)) {
      const resolved = resolveMarkdownTarget(document, target);
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

test('zest-crypto rejects percent-encoded parent traversal with an in-package decoy', async () => {
  // Given: an encoded parent link whose literal filesystem path exists inside the package.
  const fixtureRoot = await mkdtemp(join(tmpdir(), 'zest-crypto-package-'));
  const skillDirectory = join(fixtureRoot, 'zest-crypto');
  const decoyDirectory = join(skillDirectory, '%2e%2e');
  await mkdir(decoyDirectory, { recursive: true });
  await writeFile(join(skillDirectory, 'fixture.md'), '[Encoded escape](%2e%2e/escape.md)\n', 'utf8');
  await writeFile(join(decoyDirectory, 'escape.md'), 'decoy\n', 'utf8');

  try {
    // When: the package-boundary checker resolves the URL path.
    const check = assertLocalMarkdownLinks(skillDirectory);

    // Then: URL-normalized traversal is rejected despite the literal decoy.
    await assert.rejects(check, /escapes the standalone skill/);
  } finally {
    await rm(fixtureRoot, { force: true, recursive: true });
  }
});

test('zest-crypto rejects malformed percent encoding deterministically', async () => {
  // Given: a malformed URL path whose literal filesystem path exists inside the package.
  const fixtureRoot = await mkdtemp(join(tmpdir(), 'zest-crypto-package-'));
  const skillDirectory = join(fixtureRoot, 'zest-crypto');
  await mkdir(skillDirectory);
  await writeFile(join(skillDirectory, 'fixture.md'), '[Malformed](bad%ZZ.md)\n', 'utf8');
  await writeFile(join(skillDirectory, 'bad%ZZ.md'), 'decoy\n', 'utf8');

  try {
    // When: the package-boundary checker resolves the malformed URL path.
    const check = assertLocalMarkdownLinks(skillDirectory);

    // Then: malformed encoding is rejected with the checker-owned diagnostic.
    await assert.rejects(check, /invalid local Markdown URL/);
  } finally {
    await rm(fixtureRoot, { force: true, recursive: true });
  }
});

test('zest-crypto ignores code literals while resolving shortcut references', async () => {
  // Given: code literals plus a real shortcut reference in a package document.
  const fixtureRoot = await mkdtemp(join(tmpdir(), 'zest-crypto-package-'));
  const skillDirectory = join(fixtureRoot, 'zest-crypto');
  await mkdir(skillDirectory);
  await writeFile(
    join(skillDirectory, 'fixture.md'),
    [
      '```js',
      'const values = [1, 2];',
      '```',
      '',
      'Inline `const label = [literal];`.',
      '',
      '    const indices = [3, 4];',
      '',
      '[Genuine shortcut]',
      '',
      '[genuine shortcut]: fixture.md',
      '',
    ].join('\n'),
    'utf8',
  );

  try {
    // When: the package-boundary checker resolves Markdown links.
    const check = assertLocalMarkdownLinks(skillDirectory);

    // Then: it ignores code data and accepts the defined shortcut reference.
    await assert.doesNotReject(check);
  } finally {
    await rm(fixtureRoot, { force: true, recursive: true });
  }
});

test('zest-crypto rejects links between escaped backticks', async () => {
  // Given: genuine code spans and a copied package document with escaped backticks.
  const fixtureRoot = await mkdtemp(join(tmpdir(), 'zest-crypto-package-'));
  const skillDirectory = join(fixtureRoot, 'zest-crypto');
  await mkdir(skillDirectory);
  await writeFile(
    join(skillDirectory, 'code.md'),
    [
      '`[Ignored inline link](../outside.md)`',
      '\\\\`[Even parity code](../outside.md)`',
      '',
    ].join('\n'),
    'utf8',
  );

  try {
    // When: only genuine inline code is present.
    await assert.doesNotReject(assertLocalMarkdownLinks(skillDirectory));
    await writeFile(
      join(skillDirectory, 'escaped.md'),
      '\\`[Escaping link](../outside.md)\\`\n',
      'utf8',
    );

    // Then: odd-parity escaped backticks leave the escaping link active.
    await assert.rejects(assertLocalMarkdownLinks(skillDirectory), /escapes the standalone skill/);
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
