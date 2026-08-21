import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { existsSync } from 'node:fs';
import { lstat, mkdir, mkdtemp, readdir, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, extname, join, relative } from 'node:path';
import test from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { promisify } from 'node:util';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const execFileAsync = promisify(execFile);
const publisher = join(root, 'scripts', 'publish-skill.mjs');
const shippedExtensions = new Set(['.json', '.md', '.py', '.sage']);
const pythonScriptDirectory = join(root, 'skills', 'zest-crypto', 'scripts');
const splitPythonModules = new Set([
  'fingerprint.py',
  'zest_crypto_conditions.py',
  'zest_crypto_documents.py',
  'zest_crypto_fingerprint_extract.py',
  'zest_crypto_parse.py',
  'zest_crypto_parse_catalog.py',
  'zest_crypto_parse_conditions.py',
  'zest_crypto_parse_fingerprint.py',
  'zest_crypto_parse_values.py',
]);
const extractedPythonModules = [...splitPythonModules].filter((name) => name.startsWith('zest_crypto_') && ![
  'zest_crypto_conditions.py',
  'zest_crypto_parse.py',
].includes(name));

async function shippedFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const nested = await Promise.all(
    entries.map(async (entry) => {
      const path = join(directory, entry.name);
      assert.equal(
        entry.isSymbolicLink(),
        false,
        `${path}: symbolic links are not allowed in the standalone skill`,
      );
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

test('zest-crypto is enumerated as a one-skill install by the publication dry run', async () => {
  // Given: a dry-run publisher whose remote target is deliberately unavailable.
  const fakeBin = await mkdtemp(join(tmpdir(), 'zest-crypto-publisher-bin-'));
  const fakeGh = join(fakeBin, 'gh');
  await writeFile(fakeGh, '#!/bin/sh\nexit 1\n', { encoding: 'utf8', mode: 0o700 });

  try {
    // When: the real publisher derives its standalone README commands from tracked skills.
    const result = await execFileAsync(process.execPath, [publisher, '--dry-run'], {
      cwd: root,
      encoding: 'utf8',
      env: { ...process.env, PATH: `${fakeBin}:${process.env.PATH ?? ''}` },
    });

    // Then: the parsed skill enumeration exposes the crypto-only installation command.
    assert.match(result.stdout, /npx skills add SEORY0\/zest-skill --skill zest-crypto/);
    assert.equal(result.stderr, '');
  } finally {
    await rm(fakeBin, { force: true, recursive: true });
  }
});

test('zest-crypto production Python modules stay portable and publishable', async () => {
  // Given: every directly executable or importable Python module shipped by the standalone skill.
  const purePythonLineCount = (source) => source
    .split(/\r?\n/)
    .filter((line) => line.trim() && !line.trimStart().startsWith('#'))
    .length;
  const entries = await readdir(pythonScriptDirectory, { withFileTypes: true });
  const pythonNames = entries
    .filter((entry) => entry.isFile() && extname(entry.name) === '.py')
    .map((entry) => entry.name)
    .sort();
  const sources = new Map(await Promise.all(pythonNames.map(async (name) => [
    name,
    await readFile(join(pythonScriptDirectory, name), 'utf8'),
  ])));

  // When: module size, metadata, import topology, Git tracking, publication, and Python 3.8 imports are checked.
  for (const [name, source] of sources) {
    const pureLines = purePythonLineCount(source);
    assert.equal(pureLines <= 250, true, `${name}: ${pureLines} pure lines exceeds 250`);
    if (splitPythonModules.has(name)) {
      assert.equal(pureLines <= 230, true, `${name}: ${pureLines} pure lines exceeds split margin`);
    }
    assert.match(
      source,
      /^(?:#![^\n]*\r?\n)?# \/\/\/ script\r?\n# requires-python = ">=3\.8"\r?\n# dependencies = \[\]\r?\n# \/\/\//,
      `${name}: missing portable PEP 723 metadata`,
    );
    assert.doesNotMatch(source, /^from\s+\./m, `${name}: relative sibling imports break direct execution`);
  }

  assert.equal(pythonNames.includes('__init__.py'), false);
  const trackedResult = await execFileAsync('git', ['ls-files', '--', 'skills/zest-crypto/scripts'], {
    cwd: root,
    encoding: 'utf8',
  });
  const tracked = new Set(trackedResult.stdout.trim().split(/\r?\n/));
  for (const name of extractedPythonModules) {
    assert.equal(tracked.has(`skills/zest-crypto/scripts/${name}`), true, `${name}: missing from Git manifest`);
  }

  const fakeBin = await mkdtemp(join(tmpdir(), 'zest-crypto-python-publisher-bin-'));
  const fakeGh = join(fakeBin, 'gh');
  await writeFile(fakeGh, '#!/bin/sh\nexit 1\n', { encoding: 'utf8', mode: 0o700 });
  try {
    const published = await execFileAsync(process.execPath, [publisher, '--dry-run'], {
      cwd: root,
      encoding: 'utf8',
      env: { ...process.env, PATH: `${fakeBin}:${process.env.PATH ?? ''}` },
    });
    for (const name of extractedPythonModules) {
      assert.equal(
        published.stdout.includes(`skills/zest-crypto/scripts/${name}`),
        true,
        `${name}: missing from publication dry run`,
      );
    }
  } finally {
    await rm(fakeBin, { force: true, recursive: true });
  }

  const oversizedFixture = await mkdtemp(join(tmpdir(), 'zest-crypto-python-size-'));
  const oversizedPath = join(oversizedFixture, 'oversized.py');
  try {
    await writeFile(oversizedPath, 'pass\n'.repeat(251), 'utf8');
    const oversizedSource = await readFile(oversizedPath, 'utf8');
    assert.equal(purePythonLineCount(oversizedSource), 251);
    assert.equal(purePythonLineCount(oversizedSource) <= 250, false);
  } finally {
    await rm(oversizedFixture, { force: true, recursive: true });
  }

  const importNames = pythonNames.map((name) => name.slice(0, -3));
  const compileAndImport = [
    'import importlib, pathlib, sys',
    'root = pathlib.Path(sys.argv[1]).resolve()',
    "for path in sorted(root.glob('*.py')):",
    "  compile(path.read_text(encoding='utf-8'), str(path), 'exec')",
    'sys.path.insert(0, str(root))',
    'for name in sys.argv[2:]:',
    '  importlib.import_module(name)',
  ].join('\n');
  const imported = await execFileAsync('python3.8', [
    '-c',
    compileAndImport,
    pythonScriptDirectory,
    ...importNames,
  ], {
    cwd: tmpdir(),
    encoding: 'utf8',
    env: { ...process.env, PYTHONDONTWRITEBYTECODE: '1' },
  });

  // Then: the tracked publisher surface and arbitrary-CWD Python runtime accept every bounded module.
  assert.equal(imported.stdout, '');
  assert.equal(imported.stderr, '');
});

test('zest-crypto ships only self-contained Markdown links', async () => {
  // Given: every file that belongs to the standalone package.
  const skillDirectory = join(root, 'skills', 'zest-crypto');

  // When: package-relative links in every shipped Markdown document are resolved.
  await assertLocalMarkdownLinks(skillDirectory);
});

test('zest-crypto entrypoint directly exposes the catalog and every family reference', async () => {
  // Given: the only Markdown entrypoint guaranteed to be loaded with the skill.
  const skillDirectory = join(root, 'skills', 'zest-crypto');
  const entrypoint = join(skillDirectory, 'SKILL.md');
  const contents = await readFile(entrypoint, 'utf8');
  const expected = [
    'references/attack-cards.json',
    'references/literature.md',
    'references/families/ecc-and-signatures.md',
    'references/families/lattices-and-small-roots.md',
    'references/families/paper-derived-constructions.md',
    'references/families/prngs-streams-and-oracles.md',
    'references/families/rsa-and-number-theory.md',
  ];

  // When: active package-relative links are resolved from the entrypoint.
  const targets = new Set(relativeMarkdownTargets(contents));

  // Then: every progressive-disclosure surface is directly reachable.
  expected.forEach((target) => assert.equal(targets.has(target), true, `${target}: missing entrypoint link`));
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

test('zest-crypto rejects a symlinked package directory before recursion', async () => {
  // Given: a package directory symlink that points to the fixture parent.
  const fixtureRoot = await mkdtemp(join(tmpdir(), 'zest-crypto-package-'));
  const skillDirectory = join(fixtureRoot, 'zest-crypto');
  await mkdir(skillDirectory);
  await writeFile(join(skillDirectory, 'fixture.md'), 'No links.\n', 'utf8');
  await symlink('..', join(skillDirectory, 'outside'), 'dir');

  try {
    // When: the package walker encounters the directory entry.
    const check = assertLocalMarkdownLinks(skillDirectory);

    // Then: it rejects the symlink without following it or recursing forever.
    await assert.rejects(check, /symbolic links are not allowed in the standalone skill/);
  } finally {
    await rm(fixtureRoot, { force: true, recursive: true });
  }
});

test('zest-crypto rejects a symlinked package file that resolves outside', async () => {
  // Given: a lexically internal Markdown target symlinked to an outside file.
  const fixtureRoot = await mkdtemp(join(tmpdir(), 'zest-crypto-package-'));
  const skillDirectory = join(fixtureRoot, 'zest-crypto');
  await mkdir(skillDirectory);
  await writeFile(join(fixtureRoot, 'outside.md'), 'outside\n', 'utf8');
  await writeFile(join(skillDirectory, 'fixture.md'), '[Escape](escape.md)\n', 'utf8');
  await symlink('../outside.md', join(skillDirectory, 'escape.md'), 'file');

  try {
    // When: the package walker and link checker inspect the package.
    const check = assertLocalMarkdownLinks(skillDirectory);

    // Then: the symlink is rejected before its outside target can be accepted.
    await assert.rejects(check, /symbolic links are not allowed in the standalone skill/);
  } finally {
    await rm(fixtureRoot, { force: true, recursive: true });
  }
});

test('zest-crypto accepts ordinary internal package files', async () => {
  // Given: a package with a normal nested Markdown target.
  const fixtureRoot = await mkdtemp(join(tmpdir(), 'zest-crypto-package-'));
  const skillDirectory = join(fixtureRoot, 'zest-crypto');
  const referencesDirectory = join(skillDirectory, 'references');
  await mkdir(referencesDirectory, { recursive: true });
  await writeFile(join(skillDirectory, 'fixture.md'), '[Internal](references/internal.md)\n', 'utf8');
  await writeFile(join(referencesDirectory, 'internal.md'), 'internal\n', 'utf8');

  try {
    // When: the package walker and link checker inspect ordinary files.
    const check = assertLocalMarkdownLinks(skillDirectory);

    // Then: the self-contained package remains accepted.
    await assert.doesNotReject(check);
  } finally {
    await rm(fixtureRoot, { force: true, recursive: true });
  }
});

test('zest-crypto rejects broken symlinks deterministically', async () => {
  // Given: a Markdown target represented by a broken package symlink.
  const fixtureRoot = await mkdtemp(join(tmpdir(), 'zest-crypto-package-'));
  const skillDirectory = join(fixtureRoot, 'zest-crypto');
  await mkdir(skillDirectory);
  await writeFile(join(skillDirectory, 'fixture.md'), '[Broken](broken.md)\n', 'utf8');
  await symlink('missing.md', join(skillDirectory, 'broken.md'), 'file');

  try {
    // When: the package walker encounters the broken symlink.
    const check = assertLocalMarkdownLinks(skillDirectory);

    // Then: it reports the forbidden entry instead of depending on target existence.
    await assert.rejects(check, /broken\.md: symbolic links are not allowed in the standalone skill/);
  } finally {
    await rm(fixtureRoot, { force: true, recursive: true });
  }
});

test('zest-crypto reports missing internal link targets deterministically', async () => {
  // Given: a package with an ordinary missing Markdown target.
  const fixtureRoot = await mkdtemp(join(tmpdir(), 'zest-crypto-package-'));
  const skillDirectory = join(fixtureRoot, 'zest-crypto');
  await mkdir(skillDirectory);
  await writeFile(join(skillDirectory, 'fixture.md'), '[Missing](missing.md)\n', 'utf8');

  try {
    // When: the package link checker resolves the absent target.
    const check = assertLocalMarkdownLinks(skillDirectory);

    // Then: it reports the missing package file with a stable diagnostic.
    await assert.rejects(check, /fixture\.md: missing\.md is missing from the standalone skill/);
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

test('zest-crypto ships every catalog template inside the standalone package', async () => {
  // Given: the catalog paths installed with the standalone skill.
  const skillDirectory = join(root, 'skills', 'zest-crypto');
  const catalogPath = join(skillDirectory, 'references', 'attack-cards.json');
  const cards = JSON.parse(await readFile(catalogPath, 'utf8'));

  // When: each non-null solver template is resolved from the package root.
  const templates = cards.filter(({ template }) => template !== null).map(({ template }) => join(skillDirectory, template));

  // Then: every path remains internal and names a bundled regular package file.
  for (const template of templates) {
    assert.equal(isInside(skillDirectory, template), true, `${template}: catalog template escapes the standalone skill`);
    assert.equal(existsSync(template), true, `${template}: catalog template is missing from the standalone skill`);
    const metadata = await lstat(template);
    assert.equal(metadata.isSymbolicLink(), false, `${template}: catalog template must not be a symbolic link`);
    assert.equal(metadata.isFile(), true, `${template}: catalog template must be a regular file`);
  }
});
