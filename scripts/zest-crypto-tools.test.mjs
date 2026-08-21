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
