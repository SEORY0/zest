import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { chmod, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { delimiter, dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const validator = join(root, 'skills', 'zest-crypto', 'scripts', 'validate_attack_cards.py');
const ranker = join(root, 'skills', 'zest-crypto', 'scripts', 'rank_attack_cards.py');
const fingerprint = join(root, 'skills', 'zest-crypto', 'scripts', 'fingerprint.py');
const invalidCatalog = join(root, 'scripts', 'fixtures', 'zest-crypto', 'catalog-invalid.json');
const catalog = join(root, 'skills', 'zest-crypto', 'references', 'attack-cards.json');
const hastadFingerprint = join(root, 'scripts', 'fixtures', 'zest-crypto', 'fingerprints', 'rsa-hastad.json');
const blockedSageFingerprint = join(root, 'scripts', 'fixtures', 'zest-crypto', 'fingerprints', 'blocked-sage.json');
const inferredFamilyFingerprint = join(root, 'scripts', 'fixtures', 'zest-crypto', 'fingerprints', 'inferred-family.json');
const challenge2026FingerprintDirectory = join(root, 'scripts', 'fixtures', 'zest-crypto', 'fingerprints', '2026');
const schemaReference = join(root, 'skills', 'zest-crypto', 'references', 'attack-card-schema.md');
const sourceFixtures = join(root, 'scripts', 'fixtures', 'zest-crypto', 'sources');
const challenge2026RoutingFixtures = [
  {
    name: 'MAT347',
    path: join(challenge2026FingerprintDirectory, 'mat347.json'),
    intendedCardId: 'lattice.subset-sum.query-schedule',
    expectedBucket: 'eligible',
    expectedTopThree: ['lattice.subset-sum.query-schedule'],
    expectedExample: {
      challenge_id: 'uoftctf-2026-mat347',
      repo_sha: '8519e2bb29b3e49b0e48a2078728f9fc6e6cb0ac',
      source_kind: 'remote',
      source_path: 'mat347/dist/chall.py',
      source_lines: 'L24-L55',
    },
  },
  {
    name: 'Rotor Cipher',
    path: join(challenge2026FingerprintDirectory, 'rotor-cipher.json'),
    intendedCardId: 'symmetric.rotor.group-conjugacy',
    expectedBucket: 'eligible',
    expectedTopThree: ['symmetric.rotor.group-conjugacy'],
    expectedExample: {
      challenge_id: 'uoftctf-2026-rotor-cipher',
      repo_sha: '8519e2bb29b3e49b0e48a2078728f9fc6e6cb0ac',
      source_kind: 'remote',
      source_path: 'rotor-cipher/rotor_cipher.py',
      source_lines: 'L46-L149',
    },
  },
  {
    name: 'lfstream',
    path: join(challenge2026FingerprintDirectory, 'lfstream.json'),
    intendedCardId: 'stream.lfsr.known-plaintext',
    expectedBucket: 'eligible',
    expectedTopThree: ['stream.lfsr.known-plaintext'],
    expectedExample: {
      challenge_id: 'bsidessf-2026-lfstream',
      repo_sha: '68ee0e460eb572aaec17f082071f8ebf1d6f7330',
      source_kind: 'remote',
      source_path: 'lfstream/challenge/lfsr_crypt.py',
      source_lines: 'L4-L45',
    },
  },
  {
    name: 'tokencrypt',
    path: join(challenge2026FingerprintDirectory, 'tokencrypt.json'),
    intendedCardId: 'symmetric.slide.periodic-round',
    expectedBucket: 'eligible',
    expectedTopThree: ['symmetric.slide.periodic-round'],
    expectedExample: {
      challenge_id: 'bsidessf-2026-tokencrypt-service',
      repo_sha: '68ee0e460eb572aaec17f082071f8ebf1d6f7330',
      source_kind: 'remote',
      source_path: 'tokencrypt/challenge/src/tc_demo.py',
      source_lines: 'L12-L175',
    },
  },
  {
    name: 'kproof',
    path: join(challenge2026FingerprintDirectory, 'kproof.json'),
    intendedCardId: 'oracle.goldwasser-micali.replication',
    expectedBucket: 'blocked',
    expectedRuleId: 'authorized-gm-wrapper-oracle',
    expectedTopThree: [
      'oracle.goldwasser-micali.replication',
      'prng.mt19937.state-clone',
      'rsa.hastad.broadcast',
    ],
    expectedExample: {
      challenge_id: 'bsidessf-2026-kproof',
      repo_sha: '68ee0e460eb572aaec17f082071f8ebf1d6f7330',
      source_kind: 'remote',
      source_path: 'kproof/challenge/src/kproof.go',
      source_lines: 'L64-L690',
    },
  },
];
const expectedCatalogIds = [
  'lattice.coppersmith.univariate-small-root',
  'lattice.subset-sum.query-schedule',
  'oracle.cbc-padding',
  'oracle.goldwasser-micali.replication',
  'paper.csidh.auxiliary-point-leak',
  'paper.ecdsa.lcg-nonce',
  'paper.frost.threshold-signature',
  'paper.matrix-product.trace-lattice',
  'paper.stream-cipher.fca-lwpm',
  'paper.uov.wrapper-structure',
  'paper.wagner.generalized-birthday',
  'prng.mt19937.state-clone',
  'rsa.common-modulus.coprime-exponents',
  'rsa.franklin-reiter.related-message',
  'rsa.hastad.broadcast',
  'rsa.wiener.small-d',
  'signature.ecdsa.partial-nonce-hnp',
  'signature.ecdsa.reused-nonce',
  'stream.lfsr.known-plaintext',
  'symmetric.rotor.group-conjugacy',
  'symmetric.slide.periodic-round',
];

function runValidator(catalogPath) {
  return runValidatorWith('python3', catalogPath);
}

function runValidatorWith(interpreter, catalogPath) {
  return new Promise((resolve, reject) => {
    execFile(interpreter, [validator, catalogPath], { cwd: root }, (error, stdout, stderr) => {
      if (error && typeof error.code !== 'number') {
        reject(error);
        return;
      }
      resolve({ code: error ? error.code : 0, stderr, stdout });
    });
  });
}

function commandAvailable(command) {
  return new Promise((resolve) => {
    execFile(command, ['--version'], (error) => resolve(error === null));
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

function runRanker(fingerprintPath, catalogPath, environment = process.env) {
  return new Promise((resolve, reject) => {
    execFile('python3', [ranker, fingerprintPath, catalogPath], { cwd: root, env: environment }, (error, stdout, stderr) => {
      if (error && typeof error.code !== 'number') {
        reject(error);
        return;
      }
      resolve({ code: error ? error.code : 0, stderr, stdout });
    });
  });
}

function runFingerprint(caseId, inputPaths, environment = process.env, interpreter = 'python3') {
  return new Promise((resolve, reject) => {
    execFile(interpreter, [fingerprint, caseId, ...inputPaths], { cwd: root, env: environment }, (error, stdout, stderr) => {
      if (error && typeof error.code !== 'number') {
        reject(error);
        return;
      }
      resolve({ code: error ? error.code : 0, stderr, stdout });
    });
  });
}

function runFingerprintBounded(caseId, inputPaths, timeout) {
  return new Promise((resolve, reject) => {
    execFile('python3', [fingerprint, caseId, ...inputPaths], { cwd: root, timeout }, (error, stdout, stderr) => {
      if (error && typeof error.code !== 'number' && !error.killed) {
        reject(error);
        return;
      }
      resolve({ code: error && typeof error.code === 'number' ? error.code : null, stderr, stdout, timedOut: error ? error.killed : false });
    });
  });
}

function fact(document, key) {
  const result = document.facts.find((item) => item.key === key);
  assert.notEqual(result, undefined, `missing fingerprint fact: ${key}`);
  return result;
}

function failureCode(result) {
  assert.equal(result.code, 2);
  assert.equal(result.stderr, '');
  const document = JSON.parse(result.stdout);
  assert.equal(document.ok, false);
  assert.equal(document.issues.length, 1);
  return document.issues[0].code;
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

async function withTemporaryCatalog(prefix, contents, operation) {
  const fixtureDirectory = await mkdtemp(join(tmpdir(), prefix));
  const fixturePath = join(fixtureDirectory, 'catalog.json');
  await writeFile(fixturePath, contents);
  try {
    return await operation(fixturePath);
  } finally {
    await rm(fixtureDirectory, { force: true, recursive: true });
  }
}

async function withTemporaryRankingInputs(prefix, fingerprint, catalogDocument, operation) {
  const fixtureDirectory = await mkdtemp(join(tmpdir(), prefix));
  const fingerprintPath = join(fixtureDirectory, 'fingerprint.json');
  const catalogPath = join(fixtureDirectory, 'catalog.json');
  await writeFile(fingerprintPath, JSON.stringify(fingerprint), 'utf8');
  await writeFile(catalogPath, JSON.stringify(catalogDocument), 'utf8');
  try {
    return await operation(fingerprintPath, catalogPath);
  } finally {
    await rm(fixtureDirectory, { force: true, recursive: true });
  }
}

async function withExecutableSentinels(operation) {
  const sentinelDirectory = await mkdtemp(join(tmpdir(), 'zest-crypto-sentinels-'));
  const markerPath = join(sentinelDirectory, 'invoked');
  const script = '#!/bin/sh\nprintf invoked > "$ZEST_CRYPTO_SENTINEL_MARKER"\nexit 97\n';
  const commandNames = ['sage', 'pip', 'pip3', 'pip3.8', 'uv', 'poetry', 'conda', 'apt', 'apt-get', 'brew', 'npm', 'yarn'];
  await Promise.all(commandNames.map(async (command) => {
    const commandPath = join(sentinelDirectory, command);
    await writeFile(commandPath, script, 'utf8');
    await chmod(commandPath, 0o755);
  }));
  try {
    return await operation({
      ...process.env,
      PATH: `${sentinelDirectory}${delimiter}${process.env.PATH ?? ''}`,
      ZEST_CRYPTO_SENTINEL_MARKER: markerPath,
    }, markerPath);
  } finally {
    await rm(sentinelDirectory, { force: true, recursive: true });
  }
}

async function documentedAttackCard() {
  const contents = await readFile(schemaReference, 'utf8');
  return jsonFenceAfter(contents, 'The following complete card')[0];
}

async function attackCardForSchema(schemaVersion) {
  const card = await documentedAttackCard();
  card.schema_version = schemaVersion;
  if (schemaVersion === 1) delete card.examples[0].source_kind;
  return card;
}

function cloneDocument(document) {
  return JSON.parse(JSON.stringify(document));
}

function canonicalJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(',')}]`;
  }
  if (value !== null && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function canonicalDigest(value) {
  return createHash('sha256').update(canonicalJson(value)).digest('hex');
}

function rankLibrary(fingerprintPath, catalogPath) {
  const script = [
    'import json, sys',
    "sys.path.insert(0, 'skills/zest-crypto/scripts')",
    'from zest_crypto_conditions import rank_cards',
    'from zest_crypto_parse import parse_catalog, parse_fingerprint',
    "with open(sys.argv[1], encoding='utf-8') as handle:",
    '  fingerprint = parse_fingerprint(json.load(handle))',
    "with open(sys.argv[2], encoding='utf-8') as handle:",
    '  cards = parse_catalog(json.load(handle))',
    'report = rank_cards(fingerprint, cards)',
    'print(json.dumps(report.to_document(), sort_keys=True))',
  ].join('\n');
  return runPython(script, [fingerprintPath, catalogPath]);
}

async function parseFingerprintDocument(document) {
  const fixtureDirectory = await mkdtemp(join(tmpdir(), 'zest-crypto-fingerprint-'));
  const fixturePath = join(fixtureDirectory, 'fingerprint.json');
  await writeFile(fixturePath, JSON.stringify(document), 'utf8');
  const parser = [
    'import json, sys',
    "sys.path.insert(0, 'skills/zest-crypto/scripts')",
    'from zest_crypto_parse import parse_fingerprint',
    'from zest_crypto_types import ParseError',
    'try:',
    '  parse_fingerprint(json.load(open(sys.argv[1], encoding=\'utf-8\')))',
    "  print(json.dumps({'ok': True}))",
    'except ParseError as error:',
    "  print(json.dumps({'ok': False, 'code': error.code, 'path': error.path}))",
  ].join('\n');
  try {
    const result = await runPython(parser, [fixturePath]);
    assert.equal(result.code, 0, result.stderr);
    return JSON.parse(result.stdout);
  } finally {
    await rm(fixtureDirectory, { force: true, recursive: true });
  }
}

test('catalog contains the exact supported attack families', async () => {
  // Given: the standalone decision catalog promised by the public skill contract.
  const cards = JSON.parse(await readFile(catalog, 'utf8'));

  // When: its stable card identifiers are enumerated.
  const cardIds = cards.map(({ id }) => id).sort();

  // Then: all and only the 21 supported attack families are present.
  assert.deepEqual(cardIds, expectedCatalogIds);
});

test('catalog cards provide complete bounded attack contracts', async () => {
  // Given: every card consumed by the validator, ranker, and solver workflow.
  const cards = JSON.parse(await readFile(catalog, 'utf8'));

  // When: the executable parts of each decision contract are inspected.
  for (const card of cards) {
    // Then: the card can be gated, falsified cheaply, attempted with a bound, sourced, and proved.
    assert.equal(card.requires.length > 0, true, `${card.id}: missing requirement`);
    assert.equal(card.rejects.length + card.negative_matches.length > 0, true, `${card.id}: missing rejection condition`);
    assert.equal(card.cheap_probes.length > 0, true, `${card.id}: missing cheap probe`);
    assert.equal(card.cheap_probes.every(({ max_seconds }) => Number.isInteger(max_seconds) && max_seconds >= 0), true, `${card.id}: unbounded cheap probe`);
    assert.equal(card.tooling.length > 0, true, `${card.id}: missing command contract`);
    assert.equal(card.procedure.length > 0, true, `${card.id}: missing procedure`);
    assert.equal(card.verification.length > 0, true, `${card.id}: missing proof step`);
    assert.equal(card.citations.length > 0, true, `${card.id}: missing canonical citation`);
    assert.equal(card.citations.every(({ assumptions }) => assumptions.length > 0), true, `${card.id}: citation assumptions are missing`);
    if (card.template === null) {
      assert.equal(card.procedure.some(({ id }) => id === 'solver-outline'), true, `${card.id}: missing explicit solver outline`);
    } else {
      assert.equal(existsSync(join(root, 'skills', 'zest-crypto', card.template)), true, `${card.id}: bundled template is missing`);
    }
  }
});

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
  // Given: an absent path distinct from the bundled catalog.
  const fixtureDirectory = await mkdtemp(join(tmpdir(), 'zest-crypto-missing-catalog-'));
  const missingCatalog = join(fixtureDirectory, 'missing.json');
  assert.equal(existsSync(missingCatalog), false);

  try {
    // When: the validator reads the absent input path.
    const result = await runValidator(missingCatalog);
    const output = JSON.parse(result.stdout);

    // Then: the filesystem boundary is reported as data, not as a Python traceback.
    assert.equal(result.code, 2);
    assert.equal(result.stderr, '');
    assert.equal(output.ok, false);
    assert.deepEqual(output.issues.map(({ path, code }) => ({ path, code })), [
      { path: '$', code: 'input-unreadable' },
    ]);
  } finally {
    await rm(fixtureDirectory, { force: true, recursive: true });
  }
});

test('validator lets parser ValueErrors propagate as programmer failures', async () => {
  // Given: a parser invariant failure injected after the JSON boundary succeeds.
  const harness = [
    'import contextlib, io, json, sys',
    "sys.path.insert(0, 'skills/zest-crypto/scripts')",
    'import validate_attack_cards as validator',
    'def programmer_bug(_raw):',
    "  raise ValueError('simulated parser invariant failure')",
    'validator.parse_catalog = programmer_bug',
    'captured = io.StringIO()',
    'with contextlib.redirect_stdout(captured):',
    '  try:',
    '    validator.main([sys.argv[1]])',
    '  except ValueError as error:',
    "    outcome = {'propagated': True, 'message': str(error)}",
    '  else:',
    "    outcome = {'propagated': False}",
    "outcome['stdout'] = captured.getvalue()",
    'print(json.dumps(outcome, sort_keys=True))',
  ].join('\n');

  // When: the validator reaches domain parsing.
  const result = await runPython(harness, [invalidCatalog]);

  // Then: an implementation defect is not relabeled as untrusted input.
  assert.equal(result.code, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout), {
    propagated: true,
    message: 'simulated parser invariant failure',
    stdout: '',
  });
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

test('validator normalizes invalid UTF-8 input at the CLI boundary', async () => {
  // Given: bytes that cannot be decoded with the declared UTF-8 input encoding.
  await withTemporaryCatalog('zest-crypto-utf8-', Buffer.from([0xff]), async (fixturePath) => {
    // When: the validator reads the untrusted catalog input.
    const result = await runValidator(fixturePath);

    // Then: decoding failure is structured data rather than a traceback.
    assert.equal(result.code, 2);
    assert.equal(result.stderr, '');
    assert.deepEqual(JSON.parse(result.stdout), {
      ok: false,
      issues: [{ path: '$', code: 'input-undecodable' }],
    });
  });
});

test('validator normalizes excessively nested JSON at the CLI boundary', async () => {
  // Given: an otherwise syntactic JSON value that exceeds the decoder recursion bound.
  const deeplyNestedJson = '['.repeat(1200) + ']'.repeat(1200);
  await withTemporaryCatalog('zest-crypto-depth-', deeplyNestedJson, async (fixturePath) => {
    // When: the validator decodes it.
    const result = await runValidator(fixturePath);

    // Then: recursion failure is normalized to a stable structured issue.
    assert.equal(result.code, 2);
    assert.equal(result.stderr, '');
    assert.deepEqual(JSON.parse(result.stdout), {
      ok: false,
      issues: [{ path: '$', code: 'input-too-deep' }],
    });
  });
});

test('validator rejects an embedded NUL template path without a traceback', async () => {
  // Given: a valid card whose untrusted package-relative path contains a NUL.
  const contents = await readFile(schemaReference, 'utf8');
  const example = jsonFenceAfter(contents, 'The following complete card');
  example[0].template = 'assets/\u0000x.py';
  await withTemporaryCatalog('zest-crypto-nul-', JSON.stringify(example), async (fixturePath) => {
    // When: the card reaches path validation.
    const result = await runValidator(fixturePath);

    // Then: it is rejected before filesystem resolution can raise ValueError.
    assert.equal(result.code, 2);
    assert.equal(result.stderr, '');
    assert.deepEqual(JSON.parse(result.stdout), {
      ok: false,
      issues: [{ path: '$[0].template', code: 'invalid-template-path' }],
    });
  });
});

test('validator rejects JSON numeric overflow before AttackCard parsing', async () => {
  // Given: a standards-shaped numeric literal that Python decodes as infinity.
  const contents = await readFile(schemaReference, 'utf8');
  const example = jsonFenceAfter(contents, 'The following complete card');
  const overflowCatalog = JSON.stringify(example)
    .replace('"rsa.public_exponent"', '"rsa.public_exponent_ratio"')
    .replace('"value":3', '"value":1e400');
  await withTemporaryCatalog('zest-crypto-overflow-', overflowCatalog, async (fixturePath) => {
    // When: the CLI decodes the catalog.
    const result = await runValidator(fixturePath);

    // Then: it fails at the JSON boundary instead of accepting infinity as a number.
    assert.equal(result.code, 2);
    assert.equal(result.stderr, '');
    assert.deepEqual(JSON.parse(result.stdout), {
      ok: false,
      issues: [{ path: '$', code: 'invalid-json' }],
    });
  });
});

test('validator normalizes oversized JSON integers on Python 3.11+', async (t) => {
  // Given: a JSON integer above Python 3.11's decoder digit limit.
  if (!(await commandAvailable('python3.11'))) {
    t.skip('python3.11 is unavailable; this runtime has no JSON integer digit limit');
    return;
  }
  const oversizedInteger = '[' + '9'.repeat(5000) + ']';

  await withTemporaryCatalog('zest-crypto-int-limit-', oversizedInteger, async (fixturePath) => {
    // When: the supported Python 3.11 runtime decodes the untrusted input.
    const result = await runValidatorWith('python3.11', fixturePath);

    // Then: decoder conversion failure is a structured input error, not a traceback.
    assert.equal(result.code, 2);
    assert.equal(result.stderr, '');
    assert.deepEqual(JSON.parse(result.stdout), {
      ok: false,
      issues: [{ path: '$', code: 'invalid-json' }],
    });
  });
});

test('validator fingerprint parser rejects programmatic non-finite numbers', async () => {
  // Given: a decoded object constructed by an in-process caller with infinity.
  const parser = [
    'import json, sys',
    "sys.path.insert(0, 'skills/zest-crypto/scripts')",
    'from zest_crypto_parse import parse_fingerprint',
    'from zest_crypto_types import ParseError',
    "raw = json.load(open(sys.argv[1], encoding='utf-8'))",
    "raw['facts'].append({'id': 'fact-ratio', 'key': 'rsa.public_exponent_ratio', 'value': float('inf'), 'value_type': 'number', 'status': 'observed', 'evidence': {'input_id': 'challenge.py', 'locator': 'line 14'}})",
    'try:',
    '  parse_fingerprint(raw)',
    "  print(json.dumps({'ok': True}))",
    'except ParseError as error:',
    "  print(json.dumps({'ok': False, 'code': error.code, 'path': error.path}))",
  ].join('\n');

  // When: the programmatic value reaches the strict parser.
  const result = await runPython(parser, [hastadFingerprint]);

  // Then: parser callers cannot bypass the finite-number invariant.
  assert.equal(result.code, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout), {
    ok: false,
    code: 'non-finite-number',
    path: '$.facts[5].value',
  });
});

test('validator enforces the condition operator/type matrix and list in semantics', async () => {
  // Given: one valid card varied across every predicate operator family.
  const contents = await readFile(schemaReference, 'utf8');
  const example = jsonFenceAfter(contents, 'The following complete card');
  const cases = [
    { label: 'neq', when: { fact: 'rsa.public_exponent', op: 'neq', value: 5 }, code: undefined },
    { label: 'comparison', when: { fact: 'rsa.public_exponent_ratio', op: 'gt', value: 0.5 }, code: undefined },
    { label: 'scalar in', when: { fact: 'rsa.public_exponent', op: 'in', value: [3, 5] }, code: undefined },
    { label: 'list in', when: { fact: 'rsa.public_exponents', op: 'in', value: [3, 5] }, code: undefined },
    { label: 'string contains', when: { fact: 'rsa.message_relation_type', op: 'contains', value: 'aff' }, code: undefined },
    { label: 'list contains', when: { fact: 'rsa.public_exponents', op: 'contains', value: 3 }, code: undefined },
    { label: 'length', when: { fact: 'rsa.moduli', op: 'len_gte', value: 3 }, code: undefined },
    { label: 'numeric length', when: { fact: 'rsa.public_exponent', op: 'len_eq', value: 1 }, code: 'invalid-condition-value' },
    { label: 'string comparison', when: { fact: 'rsa.message_relation_type', op: 'lt', value: 'z' }, code: 'invalid-condition-value' },
    { label: 'boolean contains', when: { fact: 'rsa.same_plaintext', op: 'contains', value: true }, code: 'invalid-condition-value' },
  ];

  for (const { label, when, code } of cases) {
    const variant = JSON.parse(JSON.stringify(example));
    variant[0].signals[0].when = when;
    await withTemporaryCatalog(`zest-crypto-${label}-`, JSON.stringify(variant), async (fixturePath) => {
      // When: a condition uses this operator/fact-type pairing.
      const result = await runValidator(fixturePath);

      // Then: supported pairs parse and unsupported pairs carry a typed issue.
      if (code === undefined) {
        assert.equal(result.code, 0, label);
      } else {
        assert.equal(result.code, 2, label);
        assert.deepEqual(JSON.parse(result.stdout), {
          ok: false,
          issues: [{ path: '$[0].signals[0].when.value', code }],
        });
      }
    });
  }
});

test('validator fingerprint parser requires a derivation rationale', async () => {
  // Given: a derived fact with source evidence but no derivation explanation.
  const fingerprint = JSON.parse(await readFile(hastadFingerprint, 'utf8'));
  delete fingerprint.facts[4].evidence.rationale;

  // When: the parser checks provenance.
  const result = await parseFingerprintDocument(fingerprint);

  // Then: a source list alone cannot satisfy the derived-fact boundary.
  assert.deepEqual(result, { ok: false, code: 'invalid-evidence', path: '$.facts[4].evidence' });
});

test('validator fingerprint parser rejects derived self references', async () => {
  // Given: a derived fact that cites itself as its only source.
  const fingerprint = JSON.parse(await readFile(hastadFingerprint, 'utf8'));
  fingerprint.facts[4].evidence.rationale = 'Computed pairwise gcds.';
  fingerprint.facts[4].evidence.source_fact_ids = ['fact-coprime'];

  // When: source references are checked after the complete fact index exists.
  const result = await parseFingerprintDocument(fingerprint);

  // Then: self-attestation is not accepted as a derivation.
  assert.deepEqual(result, {
    ok: false,
    code: 'self-referential-derived-fact',
    path: '$.facts[4].evidence.source_fact_ids[0]',
  });
});

test('validator fingerprint parser rejects cycles in derived evidence', async () => {
  // Given: two derived facts that mutually cite each other.
  const fingerprint = JSON.parse(await readFile(hastadFingerprint, 'utf8'));
  fingerprint.facts[0].status = 'derived';
  fingerprint.facts[0].evidence = {
    source_fact_ids: ['fact-coprime'],
    rationale: 'Supposedly reconstructed from the coprimality claim.',
  };
  fingerprint.facts[4].evidence = {
    source_fact_ids: ['fact-moduli'],
    rationale: 'Computed pairwise gcds.',
  };

  // When: the parser validates the derived-fact dependency graph.
  const result = await parseFingerprintDocument(fingerprint);

  // Then: cyclic evidence cannot be used to establish hard preconditions.
  assert.deepEqual(result, {
    ok: false,
    code: 'cyclic-derived-facts',
    path: '$.facts[0].evidence.source_fact_ids[0]',
  });
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

test('schema reference includes exact non-empty blocked and rejected rank entries', async () => {
  // Given: the public report example.
  const contents = await readFile(schemaReference, 'utf8');

  // When: consumers parse it as JSON.
  const report = jsonFenceAfter(contents, 'The ranker emits a versioned report');

  // Then: it exposes every top-level and non-eligible entry field explicitly.
  assert.deepEqual(Object.keys(report).sort(), [
    'blocked',
    'catalog_sha256',
    'eligible',
    'fingerprint_sha256',
    'rejected',
    'schema_version',
  ]);
  assert.deepEqual(report.blocked, [{
    card_id: 'lattice.coppersmith.univariate-small-root',
    rule_id: 'root-bound-known',
    reason: 'The unknown-root bound is absent.',
    evidence_fact_ids: [],
  }]);
  assert.deepEqual(report.rejected, [{
    card_id: 'rsa.hastad.broadcast',
    rule_id: 'moduli-are-coprime',
    reason: 'A shared factor was found between two moduli.',
    evidence_fact_ids: ['fact-moduli'],
  }]);
});

test('schema documents the one-fact-per-key FactIndex contract', async () => {
  // Given: the public schema and the implementation design that define v1 fingerprint input.
  const designSpecification = join(root, 'docs', 'superpowers', 'specs', '2026-08-20-zest-crypto-portable-skill-design.md');
  const [schema, design] = await Promise.all([
    readFile(schemaReference, 'utf8'),
    readFile(designSpecification, 'utf8'),
  ]);

  // When: a consumer checks the published uniqueness rules before constructing a fingerprint.
  for (const document of [schema, design]) {
    assert.match(document, /fact IDs and fact keys\s+must each be unique within a fingerprint/i);
    assert.match(document, /`FactIndex` maps each fact key to one fact/i);
  }

  // Then: the parser's stable duplicate-key boundary code is part of the exact schema.
  assert.match(schema, /`duplicate-fact-key`/);
});

test('ranker marks true hard requirements eligible', async () => {
  // Given: the documented card with an observed fact satisfying its hard requirement.
  const fingerprint = JSON.parse(await readFile(hastadFingerprint, 'utf8'));
  const card = await documentedAttackCard();
  card.tooling = [];

  await withTemporaryRankingInputs('zest-crypto-rank-eligible-', fingerprint, [card], async (fingerprintPath, catalogPath) => {
    // When: callers invoke the public ranking library interface.
    const result = await rankLibrary(fingerprintPath, catalogPath);

    // Then: the hard gate admits the card to the eligible array.
    assert.equal(result.code, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout).eligible.map(({ card_id }) => card_id), ['rsa.hastad.broadcast']);
  });
});

test('ranker rejects false hard requirements', async () => {
  // Given: an observed public exponent that contradicts a card requirement.
  const fingerprint = JSON.parse(await readFile(hastadFingerprint, 'utf8'));
  const card = await documentedAttackCard();
  card.tooling = [];
  card.requires = [{
    id: 'requires-e-five',
    when: { fact: 'rsa.public_exponent', op: 'eq', value: 5 },
    reason: 'This variant requires exponent five.',
  }];

  await withTemporaryRankingInputs('zest-crypto-rank-rejected-', fingerprint, [card], async (fingerprintPath, catalogPath) => {
    // When: the public library classifies the card.
    const result = await rankLibrary(fingerprintPath, catalogPath);

    // Then: an explicit contradiction is rejected with the defining rule.
    assert.equal(result.code, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout).rejected, [{
      card_id: 'rsa.hastad.broadcast',
      rule_id: 'requires-e-five',
      reason: 'This variant requires exponent five.',
      evidence_fact_ids: ['fact-exponent'],
    }]);
  });
});

test('ranker blocks missing hard requirements', async () => {
  // Given: a card that needs a fact the fingerprint does not contain.
  const fingerprint = JSON.parse(await readFile(hastadFingerprint, 'utf8'));
  const card = await documentedAttackCard();
  card.tooling = [];
  card.requires = [{
    id: 'root-bound-known',
    when: { fact: 'lattice.unknown_bound', op: 'gte', value: 1 },
    reason: 'The unknown-root bound is absent.',
  }];

  await withTemporaryRankingInputs('zest-crypto-rank-blocked-', fingerprint, [card], async (fingerprintPath, catalogPath) => {
    // When: the library applies the hard gate.
    const result = await rankLibrary(fingerprintPath, catalogPath);

    // Then: the card is blocked for evidence collection, not silently scored.
    assert.equal(result.code, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout).blocked, [{
      card_id: 'rsa.hastad.broadcast',
      rule_id: 'root-bound-known',
      reason: 'The unknown-root bound is absent.',
      evidence_fact_ids: [],
    }]);
  });
});

test('condition evaluator treats inferred facts as unknown for hard gates', async () => {
  // Given: one inferred family fact used in each class of hard rule.
  const card = await documentedAttackCard();
  card.requires = [{
    id: 'inferred-require',
    when: { fact: 'construction.canonical_family', op: 'eq', value: 'paper.example-family' },
    reason: 'Required inferred family.',
  }];
  card.rejects = [{
    id: 'inferred-reject',
    when: { fact: 'construction.canonical_family', op: 'eq', value: 'paper.example-family' },
    reason: 'Rejected inferred family.',
  }];
  card.negative_matches = [{
    id: 'inferred-negative',
    when: { fact: 'construction.canonical_family', op: 'eq', value: 'paper.example-family' },
    reason: 'Negative inferred family.',
    unknown_policy: 'ignore',
  }];
  await withTemporaryCatalog('zest-crypto-inferred-conditions-', JSON.stringify([card]), async (catalogPath) => {
    const script = [
      'import json, sys',
      "sys.path.insert(0, 'skills/zest-crypto/scripts')",
      'from zest_crypto_conditions import evaluate_condition',
      'from zest_crypto_parse import parse_catalog, parse_fingerprint',
      "with open(sys.argv[1], encoding='utf-8') as handle:",
      '  fingerprint = parse_fingerprint(json.load(handle))',
      "with open(sys.argv[2], encoding='utf-8') as handle:",
      '  card = parse_catalog(json.load(handle))[0]',
      'facts = {fact.key: fact for fact in fingerprint.facts}',
      "print(json.dumps([evaluate_condition(card.requires[0].when, facts, True).value, evaluate_condition(card.rejects[0].when, facts, True).value, evaluate_condition(card.negative_matches[0].when, facts, True).value]))",
    ].join('\n');

    // When: hard conditions are evaluated directly by library consumers.
    const result = await runPython(script, [inferredFamilyFingerprint, catalogPath]);

    // Then: inference cannot satisfy, reject, or negatively match a hard gate.
    assert.equal(result.code, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout), ['unknown', 'unknown', 'unknown']);
  });
});

test('ranker lets inferred facts contribute signal weight', async () => {
  // Given: a positive signal whose only evidence is explicitly inferred.
  const fingerprint = JSON.parse(await readFile(inferredFamilyFingerprint, 'utf8'));
  const card = await documentedAttackCard();
  card.tooling = [];
  card.requires = [];
  card.signals = [{
    id: 'inferred-family-signal',
    when: { fact: 'construction.canonical_family', op: 'eq', value: 'paper.example-family' },
    weight: 20,
    reason: 'The inferred family is a useful ranking signal.',
  }];

  await withTemporaryRankingInputs('zest-crypto-rank-inferred-signal-', fingerprint, [card], async (fingerprintPath, catalogPath) => {
    // When: ranking evaluates a non-hard signal.
    const result = await rankLibrary(fingerprintPath, catalogPath);

    // Then: the signal ranks the card without leaking inferred evidence as hard proof.
    assert.equal(result.code, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout).eligible, [{
      card_id: 'rsa.hastad.broadcast',
      score: 20,
      matched_signals: ['inferred-family-signal'],
      unmatched_signals: [],
      evidence_fact_ids: [],
      required_tools: [],
    }]);
  });
});

test('ranker blocks unknown negative matches with block policy', async () => {
  // Given: an inferred negative match that the card declares unsafe to ignore.
  const fingerprint = JSON.parse(await readFile(inferredFamilyFingerprint, 'utf8'));
  const card = await documentedAttackCard();
  card.tooling = [];
  card.requires = [];
  card.negative_matches = [{
    id: 'family-false-friend',
    when: { fact: 'construction.canonical_family', op: 'eq', value: 'paper.example-family' },
    reason: 'The false-friend check needs observed evidence.',
    unknown_policy: 'block',
  }];

  await withTemporaryRankingInputs('zest-crypto-rank-negative-block-', fingerprint, [card], async (fingerprintPath, catalogPath) => {
    // When: the negative-match policy is applied.
    const result = await rankLibrary(fingerprintPath, catalogPath);

    // Then: explicit block policy wins over heuristic scoring.
    assert.equal(result.code, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout).blocked, [{
      card_id: 'rsa.hastad.broadcast',
      rule_id: 'family-false-friend',
      reason: 'The false-friend check needs observed evidence.',
      evidence_fact_ids: [],
    }]);
  });
});

test('ranker applies the expected-cost penalty exactly once', async () => {
  // Given: two matched signals and a high-cost card.
  const fingerprint = JSON.parse(await readFile(hastadFingerprint, 'utf8'));
  const card = await documentedAttackCard();
  card.tooling = [];
  card.signals = [
    { id: 'small-e', when: { fact: 'rsa.public_exponent', op: 'eq', value: 3 }, weight: 20, reason: 'Observed low exponent.' },
    { id: 'same-message', when: { fact: 'rsa.same_plaintext', op: 'eq', value: true }, weight: 7, reason: 'Observed repeated message.' },
  ];
  card.expected_cost = { class: 'high', notes: 'This test exercises the fixed high-cost penalty.' };

  await withTemporaryRankingInputs('zest-crypto-rank-cost-', fingerprint, [card], async (fingerprintPath, catalogPath) => {
    // When: the library scores the eligible card.
    const result = await rankLibrary(fingerprintPath, catalogPath);

    // Then: 20 + 7 - 25 is charged once, not once per signal.
    assert.equal(result.code, 0, result.stderr);
    assert.equal(JSON.parse(result.stdout).eligible[0].score, 2);
  });
});

test('ranker sorts equal scores by ascending card ID', async () => {
  // Given: two otherwise identical cards in reverse lexical catalog order.
  const fingerprint = JSON.parse(await readFile(hastadFingerprint, 'utf8'));
  const laterCard = await documentedAttackCard();
  laterCard.id = 'rsa.zebra.example';
  laterCard.tooling = [];
  const earlierCard = cloneDocument(laterCard);
  earlierCard.id = 'rsa.alpha.example';

  await withTemporaryRankingInputs('zest-crypto-rank-ties-', fingerprint, [laterCard, earlierCard], async (fingerprintPath, catalogPath) => {
    // When: the public library builds the report.
    const result = await rankLibrary(fingerprintPath, catalogPath);

    // Then: lexical card ID is the deterministic tie breaker.
    assert.equal(result.code, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout).eligible.map(({ card_id }) => card_id), [
      'rsa.alpha.example',
      'rsa.zebra.example',
    ]);
  });
});

test('ranker applies hard-state ordering before unknown requirements', async () => {
  // Given: a card with both a matching rejection and a missing requirement.
  const fingerprint = JSON.parse(await readFile(hastadFingerprint, 'utf8'));
  const card = await documentedAttackCard();
  card.tooling = [];
  card.requires = [{
    id: 'missing-bound',
    when: { fact: 'lattice.unknown_bound', op: 'exists' },
    reason: 'The bound is absent.',
  }];
  card.rejects = [{
    id: 'known-broadcast-case',
    when: { fact: 'rsa.public_exponent', op: 'eq', value: 3 },
    reason: 'This regression card excludes the known broadcast case.',
  }];

  await withTemporaryRankingInputs('zest-crypto-rank-state-order-', fingerprint, [card], async (fingerprintPath, catalogPath) => {
    // When: the library resolves competing hard-state results.
    const result = await rankLibrary(fingerprintPath, catalogPath);

    // Then: a matched rejection takes priority over later blocked states.
    assert.equal(result.code, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout).rejected.map(({ rule_id }) => rule_id), ['known-broadcast-case']);
  });
});

test('ranker emits byte-identical canonical JSON and digests', async () => {
  // Given: one fixed fingerprint/catalog pair with non-semantic JSON key ordering.
  const fingerprint = JSON.parse(await readFile(hastadFingerprint, 'utf8'));
  const card = await documentedAttackCard();
  card.tooling = [];
  const catalogDocument = [card];

  await withTemporaryRankingInputs('zest-crypto-rank-deterministic-', fingerprint, catalogDocument, async (fingerprintPath, catalogPath) => {
    // When: the CLI ranks precisely the same input twice.
    const first = await runRanker(fingerprintPath, catalogPath);
    const second = await runRanker(fingerprintPath, catalogPath);

    // Then: its complete bytes and both canonical source digests are stable.
    assert.equal(first.code, 0, first.stderr);
    assert.equal(second.code, 0, second.stderr);
    assert.equal(first.stdout, second.stdout);
    const report = JSON.parse(first.stdout);
    assert.equal(report.fingerprint_sha256, canonicalDigest(fingerprint));
    assert.equal(report.catalog_sha256, canonicalDigest(catalogDocument));
  });
});

test('2026 challenge fingerprints route intended cards in deterministic top positions', async () => {
  // Given: five public 2026 challenge fingerprints with immutable source anchors.
  const topOneMatches = [];

  for (const fixture of challenge2026RoutingFixtures) {
    // When: the public ranker scores the fixture against the shipped catalog.
    const result = await runRanker(fixture.path, catalog);

    // Then: the intended card is inside the exact expected top-three order.
    assert.equal(result.code, 0, `${fixture.name}: ${result.stderr || result.stdout}`);
    const report = JSON.parse(result.stdout);
    const rankedBucket = report[fixture.expectedBucket];
    const topThree = rankedBucket.slice(0, 3).map(({ card_id: cardId }) => cardId);
    assert.deepEqual(topThree, fixture.expectedTopThree, fixture.name);
    assert.equal(topThree.includes(fixture.intendedCardId), true, fixture.name);
    if (fixture.expectedRuleId !== undefined) {
      assert.equal(rankedBucket[0].rule_id, fixture.expectedRuleId, fixture.name);
    }
    topOneMatches.push(fixture.expectedBucket === 'eligible' && topThree[0] === fixture.intendedCardId);
  }

  assert.equal(topOneMatches.filter(Boolean).length >= 4, true);
});

test('2026 routing fixtures bind to the intended card metadata', async () => {
  // Given: the shipped catalog card examples are the schema-owned metadata surface.
  const cards = JSON.parse(await readFile(catalog, 'utf8'));

  for (const fixture of challenge2026RoutingFixtures) {
    // When: the intended card metadata is selected by its stable ID.
    const card = cards.find(({ id }) => id === fixture.intendedCardId);
    assert.notEqual(card, undefined, fixture.name);

    // Then: a schema-valid pinned example matches the fixture's public source anchor.
    assert.equal(card.examples.some((example) => Object.entries(fixture.expectedExample)
      .every(([key, value]) => example[key] === value)), true, fixture.name);
  }
});

test('ranker blocks missing required commands without running installers', async () => {
  // Given: a capability record that explicitly marks Sage unavailable.
  const fingerprint = JSON.parse(await readFile(blockedSageFingerprint, 'utf8'));
  const card = await documentedAttackCard();
  card.id = 'lattice.sage.example';
  card.signals = [];
  card.requires = [{
    id: 'polynomial-present',
    when: { fact: 'lattice.polynomial', op: 'exists' },
    reason: 'The polynomial must be visible.',
  }];
  card.tooling = [{
    command: 'sage',
    required: true,
    packages: ['never-run-installer'],
    reason: 'SageMath is required for this card.',
  }];
  await withTemporaryRankingInputs('zest-crypto-rank-tool-', fingerprint, [card], async (fingerprintPath, catalogPath) => {
    await withExecutableSentinels(async (environment, markerPath) => {
      // When: a real CLI consumer receives executable Sage and installer sentinels first in PATH.
      const result = await runRanker(fingerprintPath, catalogPath, environment);

      // Then: it reports the missing tool without invoking Sage, pip, or a package manager.
      assert.equal(result.code, 0, result.stderr);
      assert.equal(existsSync(markerPath), false);
      assert.deepEqual(JSON.parse(result.stdout).blocked, [{
        card_id: 'lattice.sage.example',
        rule_id: 'tool:sage',
        reason: 'SageMath is required for this card.',
        evidence_fact_ids: [],
      }]);
    });
  });
});

test('direct fingerprint parsing rejects duplicate fact-key status and value permutations', async () => {
  // Given: observed/inferred and contradictory observed facts sharing one FactIndex key.
  const fingerprint = JSON.parse(await readFile(hastadFingerprint, 'utf8'));
  const exponent = fingerprint.facts.find(({ key }) => key === 'rsa.public_exponent');
  assert.notEqual(exponent, undefined);
  const inferred = { ...cloneDocument(exponent), id: 'fact-exponent-inferred', status: 'inferred', evidence: { rationale: 'Tentative source reading.' } };
  const derived = { ...cloneDocument(exponent), id: 'fact-exponent-derived', status: 'derived', evidence: { source_fact_ids: ['fact-moduli'], rationale: 'Derived from the public modulus record.' } };
  const five = { ...cloneDocument(exponent), id: 'fact-exponent-five', value: 5 };
  const withoutExponent = fingerprint.facts.filter(({ key }) => key !== 'rsa.public_exponent');
  const permutations = [
    [cloneDocument(exponent), inferred],
    [inferred, cloneDocument(exponent)],
    [cloneDocument(exponent), derived],
    [derived, inferred],
    [cloneDocument(exponent), five],
    [five, cloneDocument(exponent)],
  ].map((facts) => ({ ...cloneDocument(fingerprint), facts: [...withoutExponent, ...facts] }));

  for (const document of permutations) {
    // When: domain callers parse an otherwise valid fingerprint.
    const result = await parseFingerprintDocument(document);

    // Then: no fact ordering can silently choose a truth source for one key.
    assert.deepEqual(result, { ok: false, code: 'duplicate-fact-key', path: '$.facts[5].key' });
  }
});

test('ranker CLI rejects duplicate fact-key status and value permutations', async () => {
  // Given: the same order-sensitive duplicate-key fingerprints at the public CLI boundary.
  const fingerprint = JSON.parse(await readFile(hastadFingerprint, 'utf8'));
  const exponent = fingerprint.facts.find(({ key }) => key === 'rsa.public_exponent');
  assert.notEqual(exponent, undefined);
  const inferred = { ...cloneDocument(exponent), id: 'fact-exponent-inferred', status: 'inferred', evidence: { rationale: 'Tentative source reading.' } };
  const derived = { ...cloneDocument(exponent), id: 'fact-exponent-derived', status: 'derived', evidence: { source_fact_ids: ['fact-moduli'], rationale: 'Derived from the public modulus record.' } };
  const five = { ...cloneDocument(exponent), id: 'fact-exponent-five', value: 5 };
  const withoutExponent = fingerprint.facts.filter(({ key }) => key !== 'rsa.public_exponent');
  const card = await documentedAttackCard();
  card.tooling = [];
  const permutations = [
    [cloneDocument(exponent), inferred],
    [inferred, cloneDocument(exponent)],
    [cloneDocument(exponent), derived],
    [derived, inferred],
    [cloneDocument(exponent), five],
    [five, cloneDocument(exponent)],
  ].map((facts) => ({ ...cloneDocument(fingerprint), facts: [...withoutExponent, ...facts] }));

  for (const document of permutations) {
    await withTemporaryRankingInputs('zest-crypto-duplicate-key-', document, [card], async (fingerprintPath, catalogPath) => {
      // When: the ranker decodes the fingerprint once at its CLI boundary.
      const result = await runRanker(fingerprintPath, catalogPath);

      // Then: it rejects every order before any state or score can be selected.
      assert.equal(result.code, 2, result.stderr);
      assert.deepEqual(JSON.parse(result.stdout), {
        ok: false,
        issues: [{ path: '$.facts[5].key', code: 'duplicate-fact-key' }],
      });
    });
  }
});

test('fingerprint emits literal RSA broadcast facts without mutating its input', async () => {
  // Given: an immutable synthetic source with every broadcast relationship stated literally.
  assert.equal(existsSync(fingerprint), true, 'fingerprint CLI is missing');
  const source = join(sourceFixtures, 'rsa_broadcast.py');
  const before = await readFile(source);

  // When: the public fingerprint command inspects the source.
  const result = await runFingerprint('rsa-literals', [source]);

  // Then: exact source-backed facts and a valid derivation graph are emitted.
  assert.equal(result.code, 0, result.stderr);
  assert.equal(result.stderr, '');
  const document = JSON.parse(result.stdout);
  assert.equal(document.schema_version, 2);
  assert.equal(document.case_id, 'rsa-literals');
  assert.equal(document.inputs.length, 1);
  assert.equal(document.inputs[0].sha256, createHash('sha256').update(before).digest('hex'));
  assert.match(document.inputs[0].path, /^inputs\/[^/]+$/);
  assert.deepEqual(fact(document, 'rsa.public_exponent').value, 3);
  assert.deepEqual(fact(document, 'rsa.moduli').value, [101, 103, 107]);
  assert.deepEqual(fact(document, 'rsa.ciphertexts').value, [1, 2, 3]);
  assert.equal(fact(document, 'rsa.same_plaintext').value, true);
  for (const key of ['rsa.public_exponent', 'rsa.moduli', 'rsa.ciphertexts', 'rsa.same_plaintext']) {
    const observed = fact(document, key);
    assert.equal(observed.status, 'observed');
    assert.equal(observed.evidence.input_id, document.inputs[0].id);
    assert.match(observed.evidence.locator, /^line \d+$/);
  }
  const coprime = fact(document, 'rsa.moduli_pairwise_coprime');
  assert.equal(coprime.status, 'derived');
  assert.equal(coprime.value, true);
  assert.deepEqual(coprime.evidence.source_fact_ids, [fact(document, 'rsa.moduli').id]);
  assert.match(coprime.evidence.rationale, /gcd/i);
  assert.equal(new Set(document.facts.map(({ key }) => key)).size, document.facts.length);
  assert.deepEqual(await readFile(source), before);
});

test('fingerprint recognizes literal ECDSA samples sharing an r coordinate', async () => {
  // Given: two literal ECDSA signature tuples with an identical first coordinate.
  const source = join(sourceFixtures, 'ecdsa_reuse.py');

  // When: source extraction runs through the CLI boundary.
  const result = await runFingerprint('ecdsa-literals', [source]);

  // Then: it records the scheme, count, and repeated-r fact as direct observations.
  assert.equal(result.code, 0, result.stderr);
  const document = JSON.parse(result.stdout);
  assert.equal(fact(document, 'signature.scheme').value, 'ecdsa');
  assert.equal(fact(document, 'signature.sample_count').value, 2);
  assert.equal(fact(document, 'signature.repeated_r').value, true);
  for (const key of ['signature.scheme', 'signature.sample_count', 'signature.repeated_r']) {
    assert.equal(fact(document, key).status, 'observed');
  }
});

test('fingerprint records canonical paper IDs and one inferred family clue', async () => {
  // Given: a source with canonical citation URLs and one exact FROST clue.
  const source = join(sourceFixtures, 'paper_family.py');

  // When: conservative paper clue extraction runs.
  const result = await runFingerprint('paper-frost', [source]);

  // Then: citations are observed while the family remains explicitly inferred.
  assert.equal(result.code, 0, result.stderr);
  const document = JSON.parse(result.stdout);
  const paperIds = fact(document, 'construction.paper_ids');
  assert.equal(paperIds.status, 'observed');
  assert.deepEqual(paperIds.value, ['doi:10.1007/3-540-39799-X_29', 'eprint:2020/852']);
  const anchors = fact(document, 'construction.source_anchors');
  assert.equal(anchors.status, 'observed');
  assert.deepEqual(anchors.value, ['github.com/example/zest@8519e2bb29b3e49b0e48a2078728f9fc6e6cb0ac/challenge.py:L1-L20']);
  const family = fact(document, 'construction.canonical_family');
  assert.equal(family.status, 'inferred');
  assert.equal(family.value, 'paper.frost.threshold-signature');
  assert.match(family.evidence.rationale, /FROST/);
});

test('fingerprint preserves all exact family clues without claiming an ambiguous canonical family', async () => {
  // Given: multiple distinct clue families that would make a single conclusion speculative.
  const fixtureDirectory = await mkdtemp(join(tmpdir(), 'zest-crypto-clues-'));
  const source = join(fixtureDirectory, 'clues.py');
  await writeFile(source, '# small_roots LLL EllipticCurve MT19937 LFSR Goldwasser FROST UOV CSIDH repeated-round slide\n', 'utf8');

  try {
    // When: the CLI scans exact allowed clue tokens.
    const result = await runFingerprint('all-clues', [source]);

    // Then: they remain a source-backed signature instead of a fabricated one-family answer.
    assert.equal(result.code, 0, result.stderr);
    const document = JSON.parse(result.stdout);
    assert.deepEqual(fact(document, 'construction.parameter_signature').value, [
      'CSIDH', 'EllipticCurve', 'FROST', 'Goldwasser', 'LFSR', 'LLL', 'MT19937', 'UOV', 'repeated-round', 'slide', 'small_roots',
    ]);
    assert.equal(document.facts.some(({ key }) => key === 'construction.canonical_family'), false);
  } finally {
    await rm(fixtureDirectory, { force: true, recursive: true });
  }
});

test('fingerprint reads only literal Python assignments and labeled transcript hex integers', async () => {
  // Given: dynamic source code plus a transcript whose hexadecimal labels are explicit.
  const fixtureDirectory = await mkdtemp(join(tmpdir(), 'zest-crypto-literals-'));
  const dynamicSource = join(fixtureDirectory, 'dynamic.py');
  const transcript = join(fixtureDirectory, 'transcript.txt');
  await writeFile(dynamicSource, 'e = 3\nn = get_modulus()\n', 'utf8');
  await writeFile(transcript, 'n = 0x65\ne = 0x03\nc = 0x01\n', 'utf8');

  try {
    // When: each source crosses its appropriate conservative extractor.
    const dynamic = await runFingerprint('dynamic-expression', [dynamicSource]);
    const text = await runFingerprint('hex-transcript', [transcript]);

    // Then: a call result creates no modulus fact, while labeled transcript values do.
    assert.equal(dynamic.code, 0, dynamic.stderr);
    const dynamicDocument = JSON.parse(dynamic.stdout);
    assert.equal(dynamicDocument.facts.some(({ key }) => key === 'rsa.modulus' || key === 'rsa.moduli'), false);
    assert.equal(text.code, 0, text.stderr);
    const textDocument = JSON.parse(text.stdout);
    assert.equal(fact(textDocument, 'rsa.modulus').value, 101);
    assert.equal(fact(textDocument, 'rsa.public_exponent').value, 3);
    assert.deepEqual(fact(textDocument, 'rsa.ciphertexts').value, [1]);
  } finally {
    await rm(fixtureDirectory, { force: true, recursive: true });
  }
});

test('fingerprint safely retains malformed source artifacts without fabricated facts', async () => {
  // Given: source text that cannot form a Python AST.
  const fixtureDirectory = await mkdtemp(join(tmpdir(), 'zest-crypto-malformed-'));
  const malformed = join(fixtureDirectory, 'malformed.py');
  const contents = Buffer.from('e = 3\n(\n', 'utf8');
  await writeFile(malformed, contents);

  try {
    // When: the CLI is asked to fingerprint it.
    const result = await runFingerprint('malformed-source', [malformed]);

    // Then: immutable input metadata survives and AST-only facts remain absent.
    assert.equal(result.code, 0, result.stderr);
    const document = JSON.parse(result.stdout);
    assert.equal(document.inputs[0].sha256, createHash('sha256').update(contents).digest('hex'));
    assert.equal(document.facts.some(({ key }) => key.startsWith('rsa.')), false);
  } finally {
    await rm(fixtureDirectory, { force: true, recursive: true });
  }
});

test('fingerprint reports invalid UTF-8 and filesystem path boundaries as structured errors', async () => {
  // Given: invalid bytes, an absent path, a directory, a symlink, and repeated paths.
  const fixtureDirectory = await mkdtemp(join(tmpdir(), 'zest-crypto-paths-'));
  const invalidUtf8 = join(fixtureDirectory, 'invalid.py');
  const source = join(fixtureDirectory, 'source.py');
  const directory = join(fixtureDirectory, 'directory');
  const link = join(fixtureDirectory, 'source-link.py');
  await writeFile(invalidUtf8, Buffer.from([0xff]));
  await writeFile(source, 'e = 3\n', 'utf8');
  await mkdir(directory);
  await symlink(source, link);

  try {
    // When: each untrusted path crosses the public CLI boundary.
    const cases = [
      [await runFingerprint('invalid-utf8', [invalidUtf8]), 'input-undecodable'],
      [await runFingerprint('missing', [join(fixtureDirectory, 'missing.py')]), 'input-unreadable'],
      [await runFingerprint('directory', [directory]), 'input-not-file'],
      [await runFingerprint('symlink', [link]), 'input-symlink'],
      [await runFingerprint('duplicate', [source, source]), 'duplicate-input-path'],
    ];

    // Then: no boundary failure is exposed as a traceback or a partial fingerprint.
    for (const [result, expectedCode] of cases) {
      assert.equal(failureCode(result), expectedCode);
    }
  } finally {
    await rm(fixtureDirectory, { force: true, recursive: true });
  }
});

test('fingerprint assigns unique case paths to separate inputs with the same basename', async () => {
  // Given: distinct source files sharing a basename in different directories.
  const fixtureDirectory = await mkdtemp(join(tmpdir(), 'zest-crypto-same-name-'));
  const firstDirectory = join(fixtureDirectory, 'one');
  const secondDirectory = join(fixtureDirectory, 'two');
  const first = join(firstDirectory, 'challenge.py');
  const second = join(secondDirectory, 'challenge.py');
  await Promise.all([mkdir(firstDirectory), mkdir(secondDirectory)]);
  await Promise.all([writeFile(first, 'e = 3\n', 'utf8'), writeFile(second, 'n = 101\n', 'utf8')]);

  try {
    // When: both input paths are fingerprinted together.
    const result = await runFingerprint('same-basename', [first, second]);

    // Then: output input identifiers and case-relative paths remain unique.
    assert.equal(result.code, 0, result.stderr);
    const document = JSON.parse(result.stdout);
    assert.equal(new Set(document.inputs.map(({ id }) => id)).size, 2);
    assert.equal(new Set(document.inputs.map(({ path }) => path)).size, 2);
    assert.equal(document.inputs.every(({ path }) => path.startsWith('inputs/')), true);
  } finally {
    await rm(fixtureDirectory, { force: true, recursive: true });
  }
});

test('fingerprint discovers capabilities with shutil.which without executing tools', async () => {
  // Given: executable sentinels ahead of PATH for tools and package managers.
  const source = join(sourceFixtures, 'rsa_broadcast.py');
  await withExecutableSentinels(async (environment, markerPath) => {
    // When: fingerprinting discovers local capabilities.
    const result = await runFingerprint('capability-discovery', [source], environment);

    // Then: discovery observes the sentinel command but never runs it or an installer.
    assert.equal(result.code, 0, result.stderr);
    assert.equal(existsSync(markerPath), false);
    const sage = JSON.parse(result.stdout).capabilities.find(({ command }) => command === 'sage');
    assert.deepEqual(sage, { command: 'sage', available: true, version: null });
  });
});

test('fingerprint keeps structured invalid-input behavior on Python 3.8 when available', async (t) => {
  // Given: invalid UTF-8 at the supported minimum interpreter boundary.
  if (!(await commandAvailable('python3.8'))) {
    t.skip('python3.8 is unavailable');
    return;
  }
  const fixtureDirectory = await mkdtemp(join(tmpdir(), 'zest-crypto-python38-'));
  const invalidUtf8 = join(fixtureDirectory, 'invalid.py');
  await writeFile(invalidUtf8, Buffer.from([0xff]));

  try {
    // When: the Python 3.8 CLI receives untrusted bytes.
    const result = await runFingerprint('python38-invalid-utf8', [invalidUtf8], process.env, 'python3.8');

    // Then: the stable structured error contract remains available.
    assert.equal(failureCode(result), 'input-undecodable');
  } finally {
    await rm(fixtureDirectory, { force: true, recursive: true });
  }
});

test('fingerprint locators cover the exact citation and clue matches', async () => {
  // Given: a larger identifier before an exact call clue and citations on distinct lines.
  const fixtureDirectory = await mkdtemp(join(tmpdir(), 'zest-crypto-locators-'));
  const source = join(fixtureDirectory, 'evidence.py');
  await writeFile(source, [
    'myFROSThelper = 1',
    'protocol = FROST()',
    'paper = "https://eprint.iacr.org/2020/852"',
    'doi = "https://doi.org/10.1007/3-540-39799-X_29"',
  ].join('\n'), 'utf8');

  try {
    // When: observed paper IDs and the inferred family clue are extracted.
    const result = await runFingerprint('exact-locators', [source]);

    // Then: each aggregate locator covers its actual regex matches and the family cites FROST's call line.
    assert.equal(result.code, 0, result.stderr);
    const document = JSON.parse(result.stdout);
    assert.equal(fact(document, 'construction.paper_ids').evidence.locator, 'lines 3, 4');
    const family = fact(document, 'construction.canonical_family');
    assert.equal(family.evidence.locator, 'line 2');
    assert.match(family.evidence.rationale, /FROST/);
  } finally {
    await rm(fixtureDirectory, { force: true, recursive: true });
  }
});

test('fingerprint aggregates distinct labeled transcript samples in source order', async () => {
  // Given: a text transcript with distinct repeated modulus and ciphertext labels.
  const fixtureDirectory = await mkdtemp(join(tmpdir(), 'zest-crypto-transcript-samples-'));
  const source = join(fixtureDirectory, 'transcript.txt');
  await writeFile(source, [
    'n = 0x65',
    'n = 0x67',
    'e = 0x03',
    'c = 0x01',
    'c = 0x02',
  ].join('\n'), 'utf8');

  try {
    // When: transcript hex extraction runs.
    const result = await runFingerprint('transcript-samples', [source]);

    // Then: exact repeated samples are retained in appearance order without inferring a message relation.
    assert.equal(result.code, 0, result.stderr);
    const document = JSON.parse(result.stdout);
    assert.deepEqual(fact(document, 'rsa.moduli').value, [101, 103]);
    assert.equal(fact(document, 'rsa.moduli').evidence.locator, 'lines 1, 2');
    assert.deepEqual(fact(document, 'rsa.ciphertexts').value, [1, 2]);
    assert.equal(fact(document, 'rsa.ciphertexts').evidence.locator, 'lines 4, 5');
    assert.equal(document.facts.some(({ key }) => key === 'rsa.same_plaintext'), false);
  } finally {
    await rm(fixtureDirectory, { force: true, recursive: true });
  }
});

test('fingerprint retains descriptor bytes when os.open is followed by a pathname swap', async () => {
  // Given: a regular input and a replacement target.
  const fixtureDirectory = await mkdtemp(join(tmpdir(), 'zest-crypto-path-race-'));
  const victim = join(fixtureDirectory, 'victim.py');
  const target = join(fixtureDirectory, 'target.py');
  await writeFile(victim, 'n = 101\n', 'utf8');
  await writeFile(target, 'n = 99991\n', 'utf8');
  const originalDigest = createHash('sha256').update(await readFile(victim)).digest('hex');
  const harness = [
    'import json, os, sys',
    "sys.path.insert(0, 'skills/zest-crypto/scripts')",
    'import fingerprint',
    'victim, target = sys.argv[1:3]',
    'original_open = fingerprint.os.open',
    'swapped = [False]',
    'def open_then_swap(path, flags):',
    '  descriptor = original_open(path, flags)',
    '  if path == victim and not swapped[0]:',
    '    swapped[0] = True',
    "    os.replace(victim, victim + '.original')",
    '    os.symlink(target, victim)',
    '  return descriptor',
    'fingerprint.os.open = open_then_swap',
    'try:',
    "  document = fingerprint.fingerprint('path-race', [victim])",
    "  print(json.dumps({'ok': True, 'sha256': document['inputs'][0]['sha256'], 'facts': document['facts']}, sort_keys=True))",
    'except fingerprint.InputError as error:',
    "  print(json.dumps({'ok': False, 'code': error.code}, sort_keys=True))",
  ].join('\n');

  try {
    // When: the name changes immediately after the descriptor is opened.
    const result = await runPython(harness, [victim, target]);

    // Then: hashing and parsing retain the opened original bytes rather than the new pathname target.
    assert.equal(result.code, 0, result.stderr);
    const outcome = JSON.parse(result.stdout);
    assert.equal(outcome.ok, true);
    assert.equal(outcome.sha256, originalDigest);
    assert.deepEqual(outcome.facts.map(({ key, value }) => ({ key, value })), [{ key: 'rsa.modulus', value: 101 }]);
  } finally {
    await rm(fixtureDirectory, { force: true, recursive: true });
  }
});

test('fingerprint rejects an inode swap on the forced no-O_NOFOLLOW fallback', async () => {
  // Given: a regular victim and an alternate regular file after the fallback lstat seam.
  const fixtureDirectory = await mkdtemp(join(tmpdir(), 'zest-crypto-fallback-race-'));
  const victim = join(fixtureDirectory, 'victim.py');
  const target = join(fixtureDirectory, 'target.py');
  await writeFile(victim, 'n = 101\n', 'utf8');
  await writeFile(target, 'n = 99991\n', 'utf8');
  const harness = [
    'import json, os, sys',
    "sys.path.insert(0, 'skills/zest-crypto/scripts')",
    'import fingerprint',
    'victim, target = sys.argv[1:3]',
    'fingerprint.os.O_NOFOLLOW = None',
    'original_lstat = fingerprint.os.lstat',
    'swapped = [False]',
    'def lstat_then_swap(path):',
    '  result = original_lstat(path)',
    '  if path == victim and not swapped[0]:',
    '    swapped[0] = True',
    '    os.replace(target, victim)',
    '  return result',
    'fingerprint.os.lstat = lstat_then_swap',
    'try:',
    "  fingerprint.fingerprint('fallback-race', [victim])",
    'except fingerprint.InputError as error:',
    "  print(json.dumps({'ok': False, 'code': error.code}, sort_keys=True))",
    'else:',
    "  print(json.dumps({'ok': True}, sort_keys=True))",
  ].join('\n');

  try {
    // When: the fallback opens after the checked inode is replaced.
    const result = await runPython(harness, [victim, target]);

    // Then: the mismatch is a stable structured failure instead of replacement parsing.
    assert.equal(result.code, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout), { ok: false, code: 'input-unreadable' });
  } finally {
    await rm(fixtureDirectory, { force: true, recursive: true });
  }
});

test('fingerprint emits only documented immutable source anchors', async () => {
  // Given: one valid repository@SHA/path:line-range anchor and malformed variants.
  const fixtureDirectory = await mkdtemp(join(tmpdir(), 'zest-crypto-anchors-'));
  const validAnchor = 'github.com/example/zest@8519e2bb29b3e49b0e48a2078728f9fc6e6cb0ac/challenge.py:L1-L20';
  const variants = [
    ['valid.py', [validAnchor], true],
    ['bad-sha.py', ['github.com/example/zest@not-a-sha/challenge.py:L1-L20'], false],
    ['missing-path.py', ['github.com/example/zest@8519e2bb29b3e49b0e48a2078728f9fc6e6cb0ac/:L1-L20'], false],
    ['missing-lines.py', ['github.com/example/zest@8519e2bb29b3e49b0e48a2078728f9fc6e6cb0ac/challenge.py'], false],
    ['absolute-path.py', ['github.com/example/zest@8519e2bb29b3e49b0e48a2078728f9fc6e6cb0ac//challenge.py:L1-L20'], false],
    ['traversing-path.py', ['github.com/example/zest@8519e2bb29b3e49b0e48a2078728f9fc6e6cb0ac/../challenge.py:L1-L20'], false],
    ['empty.py', [], false],
    ['nul-repository.py', ['repo\u0000@8519e2bb29b3e49b0e48a2078728f9fc6e6cb0ac/challenge.py:L1-L20'], false],
    ['control-path.py', ['repo@8519e2bb29b3e49b0e48a2078728f9fc6e6cb0ac/challenge\u001f.py:L1-L20'], false],
    ['c1-path.py', ['repo@8519e2bb29b3e49b0e48a2078728f9fc6e6cb0ac/challenge\u0080.py:L1-L20'], false],
    ['bidi-path.py', ['repo@8519e2bb29b3e49b0e48a2078728f9fc6e6cb0ac/challenge\u202e.py:L1-L20'], false],
    ['arabic-digits.py', ['repo@8519e2bb29b3e49b0e48a2078728f9fc6e6cb0ac/challenge.py:L١-L٢'], false],
    ['superscript-digits.py', ['repo@8519e2bb29b3e49b0e48a2078728f9fc6e6cb0ac/challenge.py:L²-L²'], false],
    ['mixed.py', [validAnchor, 'github.com/example/zest@not-a-sha/challenge.py:L1-L20'], false],
  ];

  try {
    for (const [name, anchors, shouldEmit] of variants) {
      const source = join(fixtureDirectory, name);
      await writeFile(source, `source_anchors = ${JSON.stringify(anchors)}\n`, 'utf8');

      // When: the literal anchor list is fingerprinted at the source boundary.
      const result = await runFingerprint(`anchor-${name}`, [source]);

      // Then: only a complete immutable shape becomes a provenance fact.
      assert.equal(result.code, 0, result.stderr);
      const anchorFact = JSON.parse(result.stdout).facts.find(({ key }) => key === 'construction.source_anchors');
      assert.equal(anchorFact !== undefined, shouldEmit);
      if (shouldEmit) {
        assert.deepEqual(anchorFact.value, [validAnchor]);
      }
    }
  } finally {
    await rm(fixtureDirectory, { force: true, recursive: true });
  }
});

test('fingerprint requires complete paper URL token boundaries', async () => {
  // Given: embedded URL suffixes, trailing continuations, and canonical delimited paper URLs.
  const fixtureDirectory = await mkdtemp(join(tmpdir(), 'zest-crypto-eprint-'));
  const invalid = join(fixtureDirectory, 'invalid.py');
  const valid = join(fixtureDirectory, 'valid.py');
  const prose = join(fixtureDirectory, 'prose.py');
  await writeFile(invalid, [
    'prefix = "https://eprint.iacr.org/2020/852evil"',
    'query = "https://eprint.iacr.org/2020/852?download=1"',
    'fragment = "https://eprint.iacr.org/2020/852#page=1"',
    'semicolon = "https://eprint.iacr.org/2020/852;download=1"',
    'exclamation = "https://eprint.iacr.org/2020/852!suffix"',
    'comma = "https://eprint.iacr.org/2020/852,continued"',
    'path = "https://eprint.iacr.org/2020/852/appendix"',
    'alpha_eprint = "nothttps://eprint.iacr.org/2020/852"',
    'alpha_doi = "nothttps://doi.org/10.1000/example"',
    'uri_eprint = "urn:https://eprint.iacr.org/2021/123.pdf"',
    'uri_doi = "redirect=https://doi.org/10.1001/example"',
    'paper = "https://doi.org/10.1000/example?download=1"',
    'doi_fragment = "https://doi.org/10.1000/example#page=1"',
    'paper = "https://doi.org/10.1000/example@invalid"',
    'doi_semicolon = "https://doi.org/10.1000/example;download=1"',
    'doi_bang = "https://doi.org/10.1000/example!suffix"',
  ].join('\n'), 'utf8');
  await writeFile(valid, [
    'bare = "https://eprint.iacr.org/2020/852"',
    'pdf = "https://eprint.iacr.org/2021/123.pdf"',
    'doi = "https://doi.org/10.1000/example"',
    'parenthesized_doi = "https://doi.org/10.1000/example(foo)"',
  ].join('\n'), 'utf8');
  await writeFile(prose, [
    'bare = "See (https://eprint.iacr.org/2020/852), then continue."',
    'pdf = "Read https://eprint.iacr.org/2021/123.pdf; then continue."',
    'doi_comma = "Review https://doi.org/10.1000/example, then continue."',
    'paper = "See (https://doi.org/10.1000/example), then continue."',
    'paper = "See https://doi.org/10.1000/example."',
    'doi_balanced = "See (https://doi.org/10.1003/example(foo)), then continue."',
  ].join('\n'), 'utf8');

  try {
    // When: both citation texts are scanned.
    const invalidResult = await runFingerprint('invalid-eprint', [invalid]);
    const validResult = await runFingerprint('valid-eprint', [valid]);
    const proseResult = await runFingerprint('prose-eprint', [prose]);

    // Then: only complete canonical URL tokens become exact paper IDs.
    assert.equal(invalidResult.code, 0, invalidResult.stderr);
    assert.equal(JSON.parse(invalidResult.stdout).facts.some(({ key }) => key === 'construction.paper_ids'), false);
    assert.equal(validResult.code, 0, validResult.stderr);
    assert.deepEqual(fact(JSON.parse(validResult.stdout), 'construction.paper_ids').value, ['doi:10.1000/example', 'doi:10.1000/example(foo)', 'eprint:2020/852', 'eprint:2021/123']);
    assert.equal(proseResult.code, 0, proseResult.stderr);
    assert.deepEqual(fact(JSON.parse(proseResult.stdout), 'construction.paper_ids').value, [
      'doi:10.1000/example',
      'doi:10.1003/example(foo)',
      'eprint:2020/852',
      'eprint:2021/123',
    ]);
  } finally {
    await rm(fixtureDirectory, { force: true, recursive: true });
  }
});

test('fingerprint requires explicit aligned samples for either same_plaintext value', async () => {
  // Given: unaligned false evidence plus explicit aligned true and false evidence.
  const fixtureDirectory = await mkdtemp(join(tmpdir(), 'zest-crypto-alignment-'));
  const unaligned = join(fixtureDirectory, 'unaligned.py');
  const alignedTrue = join(fixtureDirectory, 'aligned-true.py');
  const alignedFalse = join(fixtureDirectory, 'aligned-false.py');
  await writeFile(unaligned, 'same_plaintext = False\n', 'utf8');
  await writeFile(alignedTrue, 'moduli = [101, 103]\nciphertexts = [1, 2]\nsame_plaintext = True\n', 'utf8');
  await writeFile(alignedFalse, 'moduli = [101, 103]\nciphertexts = [1, 2]\nsame_plaintext = False\n', 'utf8');

  try {
    // When: each explicit Boolean claim crosses the extraction boundary.
    const unalignedDocument = JSON.parse((await runFingerprint('unaligned-false', [unaligned])).stdout);
    const trueDocument = JSON.parse((await runFingerprint('aligned-true', [alignedTrue])).stdout);
    const falseDocument = JSON.parse((await runFingerprint('aligned-false', [alignedFalse])).stdout);

    // Then: only paired modulus/ciphertext sequences admit either relation value.
    assert.equal(unalignedDocument.facts.some(({ key }) => key === 'rsa.same_plaintext'), false);
    assert.equal(fact(trueDocument, 'rsa.same_plaintext').value, true);
    assert.equal(fact(falseDocument, 'rsa.same_plaintext').value, false);
  } finally {
    await rm(fixtureDirectory, { force: true, recursive: true });
  }
});

test('fingerprint unions source-backed raw and AST clues while withholding ambiguous family inference', async () => {
  // Given: one raw exact clue and one AST call-name clue in the same source.
  const fixtureDirectory = await mkdtemp(join(tmpdir(), 'zest-crypto-mixed-clues-'));
  const source = join(fixtureDirectory, 'mixed.py');
  await writeFile(source, '# UOV\nprotocol = FROST()\n', 'utf8');

  try {
    // When: both conservative clue channels inspect the source.
    const result = await runFingerprint('mixed-clues', [source]);

    // Then: every exact clue remains observed but competing family mappings prevent an inferred conclusion.
    assert.equal(result.code, 0, result.stderr);
    const document = JSON.parse(result.stdout);
    const clues = fact(document, 'construction.parameter_signature');
    assert.deepEqual(clues.value, ['FROST', 'UOV']);
    assert.equal(clues.evidence.locator, 'lines 1, 2');
    assert.equal(document.facts.some(({ key }) => key === 'construction.canonical_family'), false);
  } finally {
    await rm(fixtureDirectory, { force: true, recursive: true });
  }
});

test('fingerprint aggregates distinct transcript exponents and preserves a shared scalar exponent', async () => {
  // Given: one transcript with distinct exponents and another with an explicitly repeated value.
  const fixtureDirectory = await mkdtemp(join(tmpdir(), 'zest-crypto-transcript-exponents-'));
  const distinct = join(fixtureDirectory, 'distinct.txt');
  const shared = join(fixtureDirectory, 'shared.txt');
  await writeFile(distinct, 'e = 0x03\ne = 0x05\n', 'utf8');
  await writeFile(shared, 'e = 0x03\ne = 0x03\n', 'utf8');

  try {
    // When: labeled hexadecimal exponent samples are extracted.
    const distinctResult = await runFingerprint('distinct-exponents', [distinct]);
    const sharedResult = await runFingerprint('shared-exponents', [shared]);

    // Then: distinct observations form a list, while a shared value remains scalar with complete evidence lines.
    assert.equal(distinctResult.code, 0, distinctResult.stderr);
    const distinctDocument = JSON.parse(distinctResult.stdout);
    assert.deepEqual(fact(distinctDocument, 'rsa.public_exponents').value, [3, 5]);
    assert.equal(fact(distinctDocument, 'rsa.public_exponents').evidence.locator, 'lines 1, 2');
    assert.equal(distinctDocument.facts.some(({ key }) => key === 'rsa.public_exponent'), false);
    assert.equal(sharedResult.code, 0, sharedResult.stderr);
    const sharedExponent = fact(JSON.parse(sharedResult.stdout), 'rsa.public_exponent');
    assert.equal(sharedExponent.value, 3);
    assert.equal(sharedExponent.evidence.locator, 'lines 1, 2');
  } finally {
    await rm(fixtureDirectory, { force: true, recursive: true });
  }
});

test('fingerprint rejects FIFO inputs before the bounded CLI timeout', async () => {
  // Given: a FIFO path with no writer, which must never block artifact intake.
  const fixtureDirectory = await mkdtemp(join(tmpdir(), 'zest-crypto-fifo-'));
  const fifo = join(fixtureDirectory, 'challenge.pipe');
  const setup = await runPython('import os, sys\nos.mkfifo(sys.argv[1])', [fifo]);
  assert.equal(setup.code, 0, setup.stderr);

  try {
    // When: the CLI receives the FIFO under a sub-second execution bound.
    const result = await runFingerprintBounded('fifo-input', [fifo], 500);

    // Then: it returns the normal structured non-file boundary instead of waiting for a writer.
    assert.equal(result.timedOut, false);
    assert.equal(result.code, 2);
    assert.equal(result.stderr, '');
    assert.equal(JSON.parse(result.stdout).issues[0].code, 'input-not-file');
  } finally {
    await rm(fixtureDirectory, { force: true, recursive: true });
  }
});

test('fingerprint adversarial documents are deterministic and parse through the public boundary', async () => {
  // Given: a source combining exact facts, citations, a valid anchor, and a family clue.
  const fixtureDirectory = await mkdtemp(join(tmpdir(), 'zest-crypto-deterministic-'));
  const source = join(fixtureDirectory, 'adversarial.py');
  await writeFile(source, [
    'moduli = [101, 103]',
    'ciphertexts = [1, 2]',
    'same_plaintext = True',
    'paper = "https://eprint.iacr.org/2020/852.pdf"',
    'source_anchors = ["github.com/example/zest@8519e2bb29b3e49b0e48a2078728f9fc6e6cb0ac/challenge.py:L1-L20"]',
    'protocol = FROST()',
  ].join('\n'), 'utf8');

  try {
    // When: the exact same input is fingerprinted twice.
    const first = await runFingerprint('deterministic-adversarial', [source]);
    const second = await runFingerprint('deterministic-adversarial', [source]);

    // Then: bytes are stable and the parser accepts the emitted provenance graph.
    assert.equal(first.code, 0, first.stderr);
    assert.equal(second.code, 0, second.stderr);
    assert.equal(first.stdout, second.stdout);
    const document = JSON.parse(first.stdout);
    assert.equal(new Set(document.facts.map(({ key }) => key)).size, document.facts.length);
    assert.deepEqual(await parseFingerprintDocument(document), { ok: true });
  } finally {
    await rm(fixtureDirectory, { force: true, recursive: true });
  }
});

test('ranker CLI hashes exact decoded raw inputs with omitted constraint defaults', async () => {
  // Given: a valid fingerprint that leaves all optional constraint fields omitted.
  const fingerprint = JSON.parse(await readFile(hastadFingerprint, 'utf8'));
  fingerprint.constraints = {};
  const card = await documentedAttackCard();
  card.tooling = [];
  const catalogDocument = [card];

  await withTemporaryRankingInputs('zest-crypto-raw-digest-', fingerprint, catalogDocument, async (fingerprintPath, catalogPath) => {
    // When: the CLI parses valid default-free input documents.
    const result = await runRanker(fingerprintPath, catalogPath);

    // Then: both digests describe exactly the decoded raw JSON documents, not reconstructed defaults.
    assert.equal(result.code, 0, result.stderr);
    const report = JSON.parse(result.stdout);
    assert.equal(report.fingerprint_sha256, canonicalDigest(fingerprint));
    assert.equal(report.catalog_sha256, canonicalDigest(catalogDocument));
  });
});

test('rankers preserve declared v1 and v2 versions and version-specific digests', async () => {
  const baseFingerprint = JSON.parse(await readFile(hastadFingerprint, 'utf8'));
  for (const schemaVersion of [1, 2]) {
    const fingerprintDocument = { ...cloneDocument(baseFingerprint), schema_version: schemaVersion };
    const card = await attackCardForSchema(schemaVersion);
    card.tooling = [];
    const catalogDocument = [card];

    await withTemporaryRankingInputs(`zest-crypto-schema-v${schemaVersion}-`, fingerprintDocument, catalogDocument, async (fingerprintPath, catalogPath) => {
      for (const result of [await runRanker(fingerprintPath, catalogPath), await rankLibrary(fingerprintPath, catalogPath)]) {
        assert.equal(result.code, 0, result.stderr || result.stdout);
        const report = JSON.parse(result.stdout);
        assert.equal(report.schema_version, schemaVersion);
        assert.equal(report.fingerprint_sha256, canonicalDigest(fingerprintDocument));
        assert.equal(report.catalog_sha256, canonicalDigest(catalogDocument));
      }
    });
  }
});

test('ranker rejects fingerprint and catalog schema mismatches deterministically', async () => {
  const baseFingerprint = JSON.parse(await readFile(hastadFingerprint, 'utf8'));
  for (const [fingerprintVersion, catalogVersion] of [[1, 2], [2, 1]]) {
    const fingerprintDocument = { ...cloneDocument(baseFingerprint), schema_version: fingerprintVersion };
    const card = await attackCardForSchema(catalogVersion);
    card.tooling = [];
    await withTemporaryRankingInputs(
      `zest-crypto-schema-mismatch-${fingerprintVersion}-${catalogVersion}-`,
      fingerprintDocument,
      [card],
      async (fingerprintPath, catalogPath) => {
        const result = await runRanker(fingerprintPath, catalogPath);
        assert.equal(result.code, 2, result.stderr);
        assert.deepEqual(JSON.parse(result.stdout), {
          ok: false,
          issues: [{ path: '$[0].schema_version', code: 'schema-version-mismatch' }],
        });
      },
    );
  }
});

test('current v2 catalog and fingerprint fixtures round-trip as typed values', async () => {
  const fixturePaths = [blockedSageFingerprint, hastadFingerprint, inferredFamilyFingerprint,
    join(root, 'scripts', 'fixtures', 'zest-crypto', 'fingerprints', 'task5-review-ranks.json'),
    ...challenge2026RoutingFixtures.map(({ path }) => path)];
  const script = [
    'import json, sys',
    "sys.path.insert(0, 'skills/zest-crypto/scripts')",
    'from zest_crypto_conditions import _catalog_document, _fingerprint_document',
    'from zest_crypto_parse import parse_catalog, parse_fingerprint',
    "with open(sys.argv[1], encoding='utf-8') as handle:",
    '  raw_catalog = json.load(handle)',
    'cards = parse_catalog(raw_catalog)',
    'assert parse_catalog(list(_catalog_document(cards))) == cards',
    'documents = []',
    'for path in sys.argv[2:]:',
    "  with open(path, encoding='utf-8') as handle:",
    '    value = json.load(handle)',
    "  documents.extend(value.values() if isinstance(value, dict) and 'schema_version' not in value else (value,))",
    'fingerprints = [parse_fingerprint(document) for document in documents]',
    'assert all(parse_fingerprint(_fingerprint_document(item)) == item for item in fingerprints)',
    "print(json.dumps({'cards': len(cards), 'fingerprints': len(fingerprints), 'versions': sorted({card.schema_version for card in cards} | {item.schema_version for item in fingerprints}), 'source_kinds': sorted({example.source_kind for card in cards for example in card.examples}), 'inference_levels': sorted({example.inference_level for card in cards for example in card.examples})}))",
  ].join('\n');

  const result = await runPython(script, [catalog, ...fixturePaths]);
  assert.equal(result.code, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout), {
    cards: 21,
    fingerprints: 18,
    versions: [2],
    source_kinds: ['local', 'remote'],
    inference_levels: ['direct', 'inferred', 'variant'],
  });
});
