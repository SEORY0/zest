import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const schema = join(root, 'skills', 'zest-crypto', 'references', 'attack-card-schema.md');

function runPython(source, args) {
  return new Promise((resolve, reject) => {
    execFile('python3', ['-c', source, ...args], { cwd: root }, (error, stdout, stderr) => {
      if (error && typeof error.code !== 'number') {
        reject(error);
        return;
      }
      resolve({ code: error ? error.code : 0, stderr, stdout });
    });
  });
}

async function documentedCard() {
  const contents = await readFile(schema, 'utf8');
  const marker = contents.indexOf('The following complete card');
  assert.notEqual(marker, -1);
  const match = /```json\n([\s\S]*?)\n```/g;
  match.lastIndex = marker;
  const fenced = match.exec(contents);
  assert.notEqual(fenced, null);
  return JSON.parse(fenced[1])[0];
}

async function approvedV1Card() {
  const card = await documentedCard();
  card.schema_version = 1;
  delete card.examples[0].source_kind;
  return card;
}

async function parseCatalog(cards) {
  const directory = await mkdtemp(join(tmpdir(), 'zest-crypto-source-boundary-'));
  const path = join(directory, 'catalog.json');
  await writeFile(path, JSON.stringify(cards), 'utf8');
  const source = [
    'import json, sys',
    "sys.path.insert(0, 'skills/zest-crypto/scripts')",
    'from zest_crypto_parse import parse_catalog',
    'from zest_crypto_types import ParseError',
    'try:',
    "  with open(sys.argv[1], encoding='utf-8') as handle:",
    '    parse_catalog(json.load(handle))',
    "  print(json.dumps({'ok': True}))",
    'except ParseError as error:',
    "  print(json.dumps({'ok': False, 'code': error.code, 'path': error.path}))",
  ].join('\n');
  try {
    const result = await runPython(source, [path]);
    assert.equal(result.code, 0, result.stderr);
    return JSON.parse(result.stdout);
  } finally {
    await rm(directory, { force: true, recursive: true });
  }
}

async function inspectCatalog(cards) {
  const directory = await mkdtemp(join(tmpdir(), 'zest-crypto-schema-version-'));
  const path = join(directory, 'catalog.json');
  await writeFile(path, JSON.stringify(cards), 'utf8');
  const source = [
    'import json, sys',
    "sys.path.insert(0, 'skills/zest-crypto/scripts')",
    'from zest_crypto_conditions import _catalog_document',
    'from zest_crypto_parse import parse_catalog',
    'from zest_crypto_types import ParseError',
    'try:',
    "  with open(sys.argv[1], encoding='utf-8') as handle:",
    '    parsed = parse_catalog(json.load(handle))',
    "  print(json.dumps({'ok': True, 'schema_versions': [card.schema_version for card in parsed], 'source_kinds': [example.source_kind for card in parsed for example in card.examples], 'document': _catalog_document(parsed)}))",
    'except ParseError as error:',
    "  print(json.dumps({'ok': False, 'code': error.code, 'path': error.path}))",
  ].join('\n');
  try {
    const result = await runPython(source, [path]);
    assert.equal(result.code, 0, result.stderr);
    return JSON.parse(result.stdout);
  } finally {
    await rm(directory, { force: true, recursive: true });
  }
}

function fingerprintDocument(schemaVersion, key = 'rsa.public_exponent', value = 3, valueType = 'integer') {
  return {
    schema_version: schemaVersion,
    case_id: `schema-v${schemaVersion}`,
    inputs: [{ id: 'source', path: 'inputs/source.py', sha256: '0'.repeat(64), media_type: 'text/x-python' }],
    facts: [{
      id: 'fact', key, value, value_type: valueType, status: 'observed',
      evidence: { input_id: 'source', locator: 'line 1' },
    }],
    capabilities: [],
    constraints: { network: 'disabled' },
  };
}

async function parseFingerprintDocument(document) {
  const directory = await mkdtemp(join(tmpdir(), 'zest-crypto-fingerprint-schema-'));
  const path = join(directory, 'fingerprint.json');
  await writeFile(path, JSON.stringify(document), 'utf8');
  const source = [
    'import json, sys',
    "sys.path.insert(0, 'skills/zest-crypto/scripts')",
    'from zest_crypto_parse import parse_fingerprint',
    'from zest_crypto_types import ParseError',
    'try:',
    "  with open(sys.argv[1], encoding='utf-8') as handle:",
    '    parsed = parse_fingerprint(json.load(handle))',
    "  print(json.dumps({'ok': True, 'schema_version': parsed.schema_version}))",
    'except ParseError as error:',
    "  print(json.dumps({'ok': False, 'code': error.code, 'path': error.path}))",
  ].join('\n');
  try {
    const result = await runPython(source, [path]);
    assert.equal(result.code, 0, result.stderr);
    return JSON.parse(result.stdout);
  } finally {
    await rm(directory, { force: true, recursive: true });
  }
}

async function parseFingerprint(anchor) {
  const document = {
    schema_version: 2,
    case_id: 'source-anchor-boundary',
    inputs: [{ id: 'source', path: 'inputs/source.py', sha256: '0'.repeat(64), media_type: 'text/x-python' }],
    facts: [{
      id: 'anchor', key: 'construction.source_anchors', value: [anchor], value_type: 'string_list', status: 'observed',
      evidence: { input_id: 'source', locator: 'line 1' },
    }],
    capabilities: [],
    constraints: { network: 'disabled' },
  };
  const directory = await mkdtemp(join(tmpdir(), 'zest-crypto-anchor-boundary-'));
  const path = join(directory, 'fingerprint.json');
  await writeFile(path, JSON.stringify(document), 'utf8');
  const source = [
    'import json, sys',
    "sys.path.insert(0, 'skills/zest-crypto/scripts')",
    'from zest_crypto_parse import parse_fingerprint',
    'from zest_crypto_types import ParseError',
    'try:',
    "  with open(sys.argv[1], encoding='utf-8') as handle:",
    '    parse_fingerprint(json.load(handle))',
    "  print(json.dumps({'ok': True}))",
    'except ParseError as error:',
    "  print(json.dumps({'ok': False, 'code': error.code, 'path': error.path}))",
  ].join('\n');
  try {
    const result = await runPython(source, [path]);
    assert.equal(result.code, 0, result.stderr);
    return JSON.parse(result.stdout);
  } finally {
    await rm(directory, { force: true, recursive: true });
  }
}

test('catalog rejects malformed and noncanonical citation HTTPS URLs', async () => {
  const invalidUrls = [
    'https://',
    'https://user@example.com/paper.pdf',
    'https://github.com%2f..%2fevil',
    'https://example.com/%2e%2e/%2f',
    'https://example.com/path\u0001',
    'https://example.com\\@evil.example/paper.pdf',
    'https://example.com:bad/paper.pdf',
    'https://example..com/paper.pdf',
    'https://example.com/raw space.pdf',
    'https://example.com//paper.pdf',
    'https://example.com/%70aper.pdf',
    'https://example.com/paper%00.pdf',
    'https://example.com/paper.pdf?download=1',
    'https://example.com/paper.pdf#section',
    'HTTPS://EXAMPLE.COM/paper.pdf',
  ];
  for (const url of invalidUrls) {
    const card = await documentedCard();
    card.citations[0].url = url;
    const result = await parseCatalog([card]);
    assert.deepEqual(result, { ok: false, code: 'invalid-citation-url', path: '$[0].citations[0].url' }, url);
  }
});

test('catalog rejects citation URLs whose raw HTTPS prefix is not canonical', async () => {
  for (const url of [
    'HTTPS://example.com/paper.pdf',
    'hTtPs://example.com/paper.pdf',
    ' https://example.com/paper.pdf',
    'https://example.com/paper.pdf ',
  ]) {
    const card = await documentedCard();
    card.citations[0].url = url;
    assert.deepEqual(
      await parseCatalog([card]),
      { ok: false, code: 'invalid-citation-url', path: '$[0].citations[0].url' },
      url,
    );
  }
});

test('catalog rejects malformed and noncanonical remote repository URLs', async () => {
  const invalidUrls = [
    'https://',
    'https://user@github.com/example/zest',
    'https://github.com%2f..%2fevil',
    'https://github.com/example/%2e%2e/zest',
    'https://github.com/example//zest',
    'https://github.com/example/zest/',
    'https://github.com/example/raw space',
    'https://github.com/example/zest?ref=main',
    'https://github.com/example/zest#main',
  ];
  for (const repoUrl of invalidUrls) {
    const card = await documentedCard();
    card.examples[0].repo_url = repoUrl;
    const result = await parseCatalog([card]);
    assert.deepEqual(result, { ok: false, code: 'invalid-repository-url', path: '$[0].examples[0].repo_url' }, repoUrl);
  }
});

test('catalog rejects repository URLs whose raw HTTPS prefix is not canonical', async () => {
  for (const repoUrl of [
    'HTTPS://github.com/example/zest',
    'hTtPs://github.com/example/zest',
    ' https://github.com/example/zest',
    'https://github.com/example/zest ',
  ]) {
    const card = await documentedCard();
    card.examples[0].repo_url = repoUrl;
    assert.deepEqual(
      await parseCatalog([card]),
      { ok: false, code: 'invalid-repository-url', path: '$[0].examples[0].repo_url' },
      repoUrl,
    );
  }
});

test('approved v1 card migrates to a remote typed example and round-trips as v1', async () => {
  const card = await approvedV1Card();
  assert.equal(
    createHash('sha256').update(JSON.stringify([card])).digest('hex'),
    'a423d47fa7e73bfa2949f69e2edeaeabc8443fbc8fa18008e7a39a91ebce4b80',
    'legacy fixture must remain byte-equivalent to the approved Task 2 JSON example',
  );
  const result = await inspectCatalog([card]);
  assert.deepEqual(result, {
    ok: true,
    schema_versions: [1],
    source_kinds: ['remote'],
    document: [card],
  });
});

test('v2 card retains the explicit remote example shape on round-trip', async () => {
  const card = await documentedCard();
  card.schema_version = 2;
  const result = await inspectCatalog([card]);
  assert.deepEqual(result, {
    ok: true,
    schema_versions: [2],
    source_kinds: ['remote'],
    document: [card],
  });
});

test('v1 rejects all six v2-only fact keys in cards and fingerprints', async () => {
  const v2Facts = [
    ['signature.nonce_leak_orientation', 'msb', 'string'],
    ['signature.hnp_model', 'known-bits', 'string'],
    ['signature.hnp_parameter_bound_verified', true, 'boolean'],
    ['signature.nonce_projection_bound_verified', true, 'boolean'],
    ['oracle.recovery_bytes', 16, 'integer'],
    ['construction.exploit_invariant_verified', true, 'boolean'],
  ];
  for (const [key, value, valueType] of v2Facts) {
    const card = await approvedV1Card();
    card.parameter_signature = [key];
    assert.deepEqual(
      await parseCatalog([card]),
      { ok: false, code: 'unknown-fact-key', path: '$[0].parameter_signature[0]' },
      key,
    );
    assert.deepEqual(
      await parseFingerprintDocument(fingerprintDocument(1, key, value, valueType)),
      { ok: false, code: 'unknown-fact-key', path: '$.facts[0].key' },
      key,
    );
  }

  const conditionCard = await approvedV1Card();
  conditionCard.signals[0].when = { fact: 'oracle.recovery_bytes', op: 'eq', value: 1 };
  assert.deepEqual(
    await parseCatalog([conditionCard]),
    { ok: false, code: 'unknown-fact-key', path: '$[0].signals[0].when.fact' },
  );

  const probeCard = await approvedV1Card();
  probeCard.cheap_probes[0].produces_facts = ['construction.exploit_invariant_verified'];
  assert.deepEqual(
    await parseCatalog([probeCard]),
    { ok: false, code: 'unknown-fact-key', path: '$[0].cheap_probes[0].produces_facts[0]' },
  );
});

test('v2 accepts its expanded fact vocabulary in cards and fingerprints', async () => {
  const card = await documentedCard();
  card.schema_version = 2;
  card.parameter_signature = ['construction.exploit_invariant_verified'];
  assert.deepEqual(await parseCatalog([card]), { ok: true });
  assert.deepEqual(
    await parseFingerprintDocument(fingerprintDocument(2, 'oracle.recovery_bytes', 16, 'integer')),
    { ok: true, schema_version: 2 },
  );
});

test('example fields and inference levels cannot cross schema versions', async () => {
  const v1WithSourceKind = await approvedV1Card();
  v1WithSourceKind.examples[0].source_kind = 'remote';
  assert.deepEqual(
    await parseCatalog([v1WithSourceKind]),
    { ok: false, code: 'unknown-field', path: '$[0].examples[0].source_kind' },
  );

  const v1Variant = await approvedV1Card();
  v1Variant.examples[0].inference_level = 'variant';
  assert.deepEqual(
    await parseCatalog([v1Variant]),
    { ok: false, code: 'invalid-inference-level', path: '$[0].examples[0].inference_level' },
  );

  const v2WithoutSourceKind = await documentedCard();
  v2WithoutSourceKind.schema_version = 2;
  delete v2WithoutSourceKind.examples[0].source_kind;
  assert.deepEqual(
    await parseCatalog([v2WithoutSourceKind]),
    { ok: false, code: 'missing-field', path: '$[0].examples[0].source_kind' },
  );
});

test('catalog rejects mixed versions and parsers reject unknown v3 deterministically', async () => {
  const v1 = await approvedV1Card();
  const v2 = await documentedCard();
  v2.schema_version = 2;
  v2.id = 'rsa.hastad.schema-v2';
  assert.deepEqual(
    await parseCatalog([v1, v2]),
    { ok: false, code: 'mixed-schema-versions', path: '$[1].schema_version' },
  );

  const v3Card = await documentedCard();
  v3Card.schema_version = 3;
  assert.deepEqual(
    await parseCatalog([v3Card]),
    { ok: false, code: 'unknown-schema-version', path: '$[0].schema_version' },
  );
  assert.deepEqual(
    await parseFingerprintDocument(fingerprintDocument(3)),
    { ok: false, code: 'unknown-schema-version', path: '$.schema_version' },
  );
});

test('catalog parses distinct canonical remote and local package examples', async () => {
  const remote = await documentedCard();
  remote.examples[0] = {
    challenge_id: 'remote-example', event: 'Remote Example', year: 2026, source_kind: 'remote',
    repo_url: 'https://github.com/example/zest', repo_sha: 'a'.repeat(40),
    source_path: 'challenge/source.py', source_lines: 'L10-L20', inference_level: 'direct',
  };
  const local = await documentedCard();
  local.id = 'rsa.hastad.local-example';
  local.examples[0] = {
    challenge_id: 'local-template', event: 'Zest crypto package', year: 2026, source_kind: 'local',
    repo_url: null, repo_sha: null, source_path: 'assets/solver-templates/rsa_hastad.py',
    source_lines: 'L1-L20', inference_level: 'direct',
  };
  assert.deepEqual(await parseCatalog([remote, local]), { ok: true });
});

test('catalog rejects ambiguous remote/local source forms and noncanonical ranges', async () => {
  for (const sourceLines of ['complete source', 'L0-L2', 'L02-L3', 'L3-L2', 'L1-L2,L4-L5']) {
    const card = await documentedCard();
    card.examples[0].source_kind = 'remote';
    card.examples[0].source_lines = sourceLines;
    const result = await parseCatalog([card]);
    assert.deepEqual(result, { ok: false, code: 'invalid-source-lines', path: '$[0].examples[0].source_lines' }, sourceLines);
  }
  const local = await documentedCard();
  local.examples[0].source_kind = 'local';
  const result = await parseCatalog([local]);
  assert.deepEqual(result, { ok: false, code: 'invalid-local-example', path: '$[0].examples[0].repo_url' });
});

test('direct fingerprint parsing enforces canonical immutable source anchors', async () => {
  const valid = 'github.com/maple3142/My-CTF-Challenges@7b3e786a2c20812f4da23536c7817bdfe8113dd6/HITCON%20CTF%202024/ECLCG/dist/chall.py:L25-L64';
  assert.deepEqual(await parseFingerprint(valid), { ok: true });
  for (const invalid of [
    'repo@' + 'a'.repeat(40) + '/source.py:L1-L2',
    'github.com/example/zest@' + 'a'.repeat(40) + '/../source.py:L1-L2',
    'github.com/example/zest@' + 'a'.repeat(40) + '/%2e%2e/source.py:L1-L2',
    'github.com/example/zest@' + 'a'.repeat(40) + '/path%2Fsource.py:L1-L2',
    'github.com/example/zest@' + 'a'.repeat(40) + '//source.py:L1-L2',
    'github.com/example/zest@' + 'a'.repeat(40) + '/raw source.py:L1-L2',
    'github.com/example/zest@' + 'a'.repeat(40) + '/source%00.py:L1-L2',
    'github.com/example/zest@' + 'a'.repeat(40) + '/source.py:L02-L3',
  ]) {
    const result = await parseFingerprint(invalid);
    assert.deepEqual(result, { ok: false, code: 'invalid-source-anchor', path: '$.facts[0].value[0]' }, invalid);
  }
});
