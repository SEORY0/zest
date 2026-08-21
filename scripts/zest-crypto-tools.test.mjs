import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const validator = join(root, 'skills', 'zest-crypto', 'scripts', 'validate_attack_cards.py');
const invalidCatalog = join(root, 'scripts', 'fixtures', 'zest-crypto', 'catalog-invalid.json');
const catalog = join(root, 'skills', 'zest-crypto', 'references', 'attack-cards.json');
const hastadFingerprint = join(root, 'scripts', 'fixtures', 'zest-crypto', 'fingerprints', 'rsa-hastad.json');
const schemaReference = join(root, 'skills', 'zest-crypto', 'references', 'attack-card-schema.md');

function runValidator(catalogPath) {
  return new Promise((resolve, reject) => {
    execFile('python3', [validator, catalogPath], { cwd: root }, (error, stdout, stderr) => {
      if (error && typeof error.code !== 'number') {
        reject(error);
        return;
      }
      resolve({ code: error ? error.code : 0, stderr, stdout });
    });
  });
}

function runPython(script, args = []) {
  return new Promise((resolve, reject) => {
    execFile('python3', ['-c', script, ...args], { cwd: root }, (error, stdout, stderr) => {
      if (error && typeof error.code !== 'number') {
        reject(error);
        return;
      }
      resolve({ code: error ? error.code : 0, stderr, stdout });
    });
  });
}

function jsonFenceAfter(contents, marker) {
  const markerOffset = contents.indexOf(marker);
  assert.notEqual(markerOffset, -1, `schema reference is missing: ${marker}`);
  const fence = /```json\n([\s\S]*?)\n```/g;
  fence.lastIndex = markerOffset;
  const match = fence.exec(contents);
  assert.notEqual(match, null, `schema reference is missing JSON after: ${marker}`);
  return JSON.parse(match[1]);
}

test('validator reports an invalid card ID as a structured issue', async () => {
  // Given: a catalog containing an ID outside the public card-ID grammar.
  assert.equal(existsSync(invalidCatalog), true, 'malformed catalog fixture is missing');

  // When: the catalog validator processes it at the JSON boundary.
  const result = await runValidator(invalidCatalog);

  // Then: it fails without a traceback and preserves the stable issue boundary.
  assert.equal(result.code, 2);
  assert.equal(result.stderr, '');
  assert.deepEqual(JSON.parse(result.stdout), {
    ok: false,
    issues: [{ path: '$[0].id', code: 'invalid-card-id' }],
  });
});

test('validator reports a missing catalog input as a structured issue', async () => {
  // Given: the future bundled catalog path before Task 5 creates it.
  assert.equal(existsSync(catalog), false, 'Task 2 must not create the catalog');

  // When: the validator reads the absent input path.
  const result = await runValidator(catalog);
  const output = JSON.parse(result.stdout);

  // Then: the filesystem boundary is reported as data, not as a Python traceback.
  assert.equal(result.code, 2);
  assert.equal(result.stderr, '');
  assert.equal(output.ok, false);
  assert.deepEqual(output.issues.map(({ path, code }) => ({ path, code })), [
    { path: '$', code: 'input-unreadable' },
  ]);
});

test('validator accepts the documented complete AttackCard example', async () => {
  // Given: the complete schema example published with the portable skill.
  const contents = await readFile(schemaReference, 'utf8');
  const example = jsonFenceAfter(contents, 'The following complete card');
  const fixtureDirectory = await mkdtemp(join(tmpdir(), 'zest-crypto-schema-'));
  const fixturePath = join(fixtureDirectory, 'catalog.json');
  await writeFile(fixturePath, JSON.stringify(example), 'utf8');

  try {
    // When: it crosses the same CLI JSON boundary as a real catalog.
    const result = await runValidator(fixturePath);

    // Then: documentation cannot drift into an unparsable pseudo-schema.
    assert.equal(result.code, 0);
    assert.equal(result.stderr, '');
    assert.deepEqual(JSON.parse(result.stdout), { card_count: 1, issues: [], ok: true });
  } finally {
    await rm(fixtureDirectory, { force: true, recursive: true });
  }
});

test('validator rejects a non-normalized template path', async () => {
  // Given: an otherwise valid card whose template has redundant separators.
  const contents = await readFile(schemaReference, 'utf8');
  const example = jsonFenceAfter(contents, 'The following complete card');
  example[0].template = 'assets//solver-templates/example.py';
  const fixtureDirectory = await mkdtemp(join(tmpdir(), 'zest-crypto-template-'));
  const fixturePath = join(fixtureDirectory, 'catalog.json');
  await writeFile(fixturePath, JSON.stringify(example), 'utf8');

  try {
    // When: it is handled as an untrusted catalog path.
    const result = await runValidator(fixturePath);

    // Then: alternate spellings cannot bypass package-relative path validation.
    assert.equal(result.code, 2);
    assert.deepEqual(JSON.parse(result.stdout), {
      ok: false,
      issues: [{ path: '$[0].template', code: 'invalid-template-path' }],
    });
  } finally {
    await rm(fixtureDirectory, { force: true, recursive: true });
  }
});

test('validator rejects non-finite values outside the JSON grammar', async () => {
  // Given: a text file Python would otherwise decode as a non-finite float.
  const fixtureDirectory = await mkdtemp(join(tmpdir(), 'zest-crypto-json-'));
  const fixturePath = join(fixtureDirectory, 'catalog.json');
  await writeFile(fixturePath, 'NaN', 'utf8');

  try {
    // When: the validator decodes its only JSON input boundary.
    const result = await runValidator(fixturePath);

    // Then: non-standard JSON constants do not reach schema validation.
    assert.equal(result.code, 2);
    assert.deepEqual(JSON.parse(result.stdout), {
      ok: false,
      issues: [{ path: '$', code: 'invalid-json' }],
    });
  } finally {
    await rm(fixtureDirectory, { force: true, recursive: true });
  }
});

test('fingerprint parser preserves direct and derived evidence as frozen values', async () => {
  // Given: a public Håstad routing fingerprint with observed and derived facts.
  assert.equal(existsSync(hastadFingerprint), true, 'Håstad fingerprint fixture is missing');
  const parser = [
    'import json, sys',
    "sys.path.insert(0, 'skills/zest-crypto/scripts')",
    'from zest_crypto_parse import parse_fingerprint',
    'fingerprint = parse_fingerprint(json.load(open(sys.argv[1], encoding=\'utf-8\')))',
    "print(json.dumps({'facts': len(fingerprint.facts), 'network': fingerprint.constraints.network, 'derived': fingerprint.facts[-1].evidence.source_fact_ids[0]}))",
  ].join('; ');

  // When: the JSON value is parsed at the boundary.
  const result = await runPython(parser, [hastadFingerprint]);

  // Then: schema information becomes typed domain data without guessing facts.
  assert.equal(result.code, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout), { facts: 5, network: 'disabled', derived: 'fact-moduli' });
});

test('schema reference includes a parseable complete rank report', async () => {
  // Given: the public report example.
  const contents = await readFile(schemaReference, 'utf8');

  // When: consumers parse it as JSON.
  const report = jsonFenceAfter(contents, 'The ranker emits a versioned report');

  // Then: it exposes the stable rank-report top-level fields.
  assert.deepEqual(Object.keys(report).sort(), [
    'blocked',
    'catalog_sha256',
    'eligible',
    'fingerprint_sha256',
    'rejected',
    'schema_version',
  ]);
});
