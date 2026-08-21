import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const ranker = join(root, 'skills', 'zest-crypto', 'scripts', 'rank_attack_cards.py');
const catalogPath = join(root, 'skills', 'zest-crypto', 'references', 'attack-cards.json');
const casesPath = join(root, 'scripts', 'fixtures', 'zest-crypto', 'fingerprints', 'task5-review-ranks.json');
const coastSourcePath = join(root, 'scripts', 'fixtures', 'zest-crypto', 'sources', 'coast-prime-degrees.json');
const kproofPath = join(root, 'scripts', 'fixtures', 'zest-crypto', 'fingerprints', '2026', 'kproof.json');

function runRanker(fingerprintPath) {
  return new Promise((resolve, reject) => {
    execFile('python3', [ranker, fingerprintPath, catalogPath], { cwd: root }, (error, stdout, stderr) => {
      if (error && typeof error.code !== 'number') {
        reject(error);
        return;
      }
      resolve({ code: error ? error.code : 0, stderr, stdout });
    });
  });
}

async function rank(document) {
  const directory = await mkdtemp(join(tmpdir(), 'zest-crypto-task5-rank-'));
  const fingerprintPath = join(directory, 'fingerprint.json');
  await writeFile(fingerprintPath, JSON.stringify(document), 'utf8');
  try {
    const result = await runRanker(fingerprintPath);
    assert.equal(result.code, 0, result.stderr || result.stdout);
    return JSON.parse(result.stdout);
  } finally {
    await rm(directory, { force: true, recursive: true });
  }
}

function entry(report, cardId) {
  for (const state of ['eligible', 'blocked', 'rejected']) {
    const match = report[state].find(({ card_id: id }) => id === cardId);
    if (match) return { ...match, state };
  }
  assert.fail(`missing rank entry: ${cardId}`);
}

function observedFact(id, key, value, valueType, locator = 'source-derived') {
  return {
    id, key, value, value_type: valueType, status: 'observed',
    evidence: { input_id: 'source', locator },
  };
}

function fingerprint(caseId, facts, capabilities) {
  return {
    schema_version: 2,
    case_id: caseId,
    inputs: [{
      id: 'source', path: 'inputs/source.py', sha256: '3'.repeat(64), media_type: 'text/x-python',
    }],
    facts,
    capabilities,
    constraints: { network: 'disabled', max_memory_mb: 4096, max_seconds: 3600 },
  };
}

function withConstraints(document, constraints) {
  return {
    ...document,
    case_id: `${document.case_id}-constraints-${Object.entries(constraints).map(([key, value]) => `${key}-${value}`).join('-')}`,
    constraints: { ...document.constraints, ...constraints },
  };
}

function hnpFingerprint(caseId, model, orientation, evidenceKey, evidenceValue) {
  return fingerprint(caseId, [
    observedFact('scheme', 'signature.scheme', 'ecdsa', 'string'),
    observedFact('samples', 'signature.sample_count', 32, 'integer'),
    observedFact('public-key', 'signature.public_key_present', true, 'boolean'),
    observedFact('orientation', 'signature.nonce_leak_orientation', orientation, 'string'),
    observedFact('model', 'signature.hnp_model', model, 'string'),
    observedFact('bound', 'signature.hnp_parameter_bound_verified', true, 'boolean'),
    observedFact('evidence', evidenceKey, evidenceValue, 'integer'),
  ], [{ command: 'sage', available: true, version: 'test' }]);
}

function coastFingerprint(caseId, parameterToken) {
  return fingerprint(caseId, [
    observedFact('family', 'construction.canonical_family', 'paper.csidh.auxiliary-point-leak', 'string'),
    observedFact('paper', 'construction.paper_ids', ['eprint:2018/383'], 'string_list'),
    observedFact('anchors', 'construction.source_anchors', [
      'github.com/maple3142/My-CTF-Challenges@7b3e786a2c20812f4da23536c7817bdfe8113dd6/ImaginaryCTF%202024/coast/README.md:L11-L15',
      'github.com/maple3142/My-CTF-Challenges@7b3e786a2c20812f4da23536c7817bdfe8113dd6/ImaginaryCTF%202024/coast/chall.sage:L6-L16',
    ], 'string_list'),
    observedFact('parameters', 'construction.parameter_signature', [
      'auxiliary-point-order-divisor-leak', parameterToken,
    ], 'string_list'),
    observedFact('toy', 'construction.toy_invariant_verified', true, 'boolean'),
  ], [{ command: 'sage', available: true, version: 'test' }]);
}

function predicates(condition) {
  if (condition.fact) return [condition];
  if (condition.not) return predicates(condition.not);
  return [...(condition.all ?? []), ...(condition.any ?? [])].flatMap(predicates);
}

test('every challenge-specific route binds its exact immutable source anchors', async () => {
  const expected = {
    'paper.matrix-product.trace-lattice': [
      'github.com/maple3142/My-CTF-Challenges@7b3e786a2c20812f4da23536c7817bdfe8113dd6/HITCON%20CTF%202024/MatProd/dist/chall.py:L6-L60',
      'github.com/maple3142/My-CTF-Challenges@7b3e786a2c20812f4da23536c7817bdfe8113dd6/HITCON%20CTF%202024/MatProd/dist/chall.py:L199-L228',
    ],
    'paper.stream-cipher.fca-lwpm': ['github.com/maple3142/My-CTF-Challenges@7b3e786a2c20812f4da23536c7817bdfe8113dd6/HITCON%20CTF%202024/Hyper512/dist/chall.py:L4-L64'],
    'paper.ecdsa.lcg-nonce': [
      'github.com/maple3142/My-CTF-Challenges@7b3e786a2c20812f4da23536c7817bdfe8113dd6/HITCON%20CTF%202024/ECLCG/dist/chall.py:L25-L64',
      'github.com/maple3142/My-CTF-Challenges@7b3e786a2c20812f4da23536c7817bdfe8113dd6/HITCON%20CTF%202024/ECLCG/solution/solve_lance_roy.sage:L8-L50',
    ],
    'paper.frost.threshold-signature': ['github.com/project-sekai-ctf/sekaictf-2025@683dd81ae520581add40ec21c4819866e28cbde4/crypto/law-and-order/challenge/app/chall.py:L150-L311'],
    'paper.uov.wrapper-structure': ['github.com/project-sekai-ctf/sekaictf-2025@683dd81ae520581add40ec21c4819866e28cbde4/crypto/unfairy-ring/dist/chall.py:L10-L18'],
    'paper.csidh.auxiliary-point-leak': [
      'github.com/maple3142/My-CTF-Challenges@7b3e786a2c20812f4da23536c7817bdfe8113dd6/ImaginaryCTF%202024/coast/README.md:L11-L15',
      'github.com/maple3142/My-CTF-Challenges@7b3e786a2c20812f4da23536c7817bdfe8113dd6/ImaginaryCTF%202024/coast/chall.sage:L6-L16',
    ],
    'lattice.subset-sum.query-schedule': ['github.com/UofTCTF/uoftctf-2026-chals-public@8519e2bb29b3e49b0e48a2078728f9fc6e6cb0ac/mat347/dist/chall.py:L24-L55'],
    'stream.lfsr.known-plaintext': ['github.com/BSidesSF/ctf-2026-release@68ee0e460eb572aaec17f082071f8ebf1d6f7330/lfstream/challenge/lfsr_crypt.py:L4-L45'],
    'symmetric.slide.periodic-round': [
      'github.com/BSidesSF/ctf-2026-release@68ee0e460eb572aaec17f082071f8ebf1d6f7330/tokencrypt/challenge/src/tc_demo.py:L12-L175',
      'github.com/BSidesSF/ctf-2026-release@68ee0e460eb572aaec17f082071f8ebf1d6f7330/tokencrypt/challenge/src/tokencrypt.py:L11-L326',
    ],
    'oracle.goldwasser-micali.replication': ['github.com/BSidesSF/ctf-2026-release@68ee0e460eb572aaec17f082071f8ebf1d6f7330/kproof/challenge/src/kproof.go:L64-L690'],
    'symmetric.rotor.group-conjugacy': ['github.com/UofTCTF/uoftctf-2026-chals-public@8519e2bb29b3e49b0e48a2078728f9fc6e6cb0ac/rotor-cipher/rotor_cipher.py:L46-L149'],
  };
  const cards = JSON.parse(await readFile(catalogPath, 'utf8'));
  for (const [cardId, anchors] of Object.entries(expected)) {
    const card = cards.find(({ id }) => id === cardId);
    assert.notEqual(card, undefined);
    const gates = card.requires.flatMap(({ when }) => predicates(when));
    for (const anchor of anchors) {
      assert.equal(gates.some(({ fact, op, value }) => fact === 'construction.source_anchors' && op === 'contains' && value === anchor), true, `${cardId}: ${anchor}`);
    }
    assert.equal(gates.some(({ fact, op }) => fact === 'construction.source_anchors' && op === 'exists'), false, cardId);
  }
});

test('MAT347 requires its pinned source and nonstandard signature law while rejecting Wagner', async () => {
  const cases = JSON.parse(await readFile(casesPath, 'utf8'));
  const valid = await rank(cases.mat347_valid);
  assert.equal(valid.eligible[0].card_id, 'lattice.subset-sum.query-schedule');
  const wagner = entry(valid, 'paper.wagner.generalized-birthday');
  assert.deepEqual({ ruleId: wagner.rule_id, state: wagner.state }, { ruleId: 'adaptive-query-schedule', state: 'rejected' });
  assert.equal(entry(await rank(cases.mat347_unrelated_anchor), 'lattice.subset-sum.query-schedule').state, 'rejected');
  assert.equal(entry(await rank(cases.mat347_standard_ecdsa), 'lattice.subset-sum.query-schedule').state, 'rejected');
  const independent = await rank(cases.mat347_independent_lists);
  assert.equal(entry(independent, 'lattice.subset-sum.query-schedule').state, 'rejected');
  assert.equal(entry(independent, 'paper.wagner.generalized-birthday').state, 'rejected');
});

test('ECLCG requires the pinned cross-modulus lift and orthogonal Stern bridge', async () => {
  const cases = JSON.parse(await readFile(casesPath, 'utf8'));
  assert.equal(entry(await rank(cases.eclcg_valid), 'paper.ecdsa.lcg-nonce').state, 'eligible');
  assert.equal(entry(await rank(cases.eclcg_same_modulus), 'paper.ecdsa.lcg-nonce').state, 'rejected');
  assert.equal(entry(await rank(cases.eclcg_unrelated_anchor), 'paper.ecdsa.lcg-nonce').state, 'rejected');
  for (const sampleCount of [16, 4]) {
    const insufficient = structuredClone(cases.eclcg_valid);
    insufficient.case_id = `eclcg-insufficient-${sampleCount}-samples`;
    insufficient.facts.find(({ key }) => key === 'signature.sample_count').value = sampleCount;
    assert.equal(entry(await rank(insufficient), 'paper.ecdsa.lcg-nonce').state, 'rejected');
  }
  const failedBound = structuredClone(cases.eclcg_valid);
  failedBound.case_id = 'eclcg-failed-projection-bound';
  failedBound.facts.find(({ key }) => key === 'signature.nonce_projection_bound_verified').value = false;
  assert.equal(entry(await rank(failedBound), 'paper.ecdsa.lcg-nonce').state, 'rejected');
});

test('HNP hard gates couple each source model to its own orientation and evidence', async () => {
  const knownBits = hnpFingerprint('hnp-known-bits', 'known-bits', 'msb', 'signature.nonce_leak_bits', 8);
  const bias = hnpFingerprint('hnp-bias', 'eprint-2019-023-bias', 'centered-bias', 'signature.nonce_bias_bound', 2);
  const crossedKnownBits = hnpFingerprint(
    'hnp-known-bits-crossed', 'known-bits', 'centered-bias', 'signature.nonce_bias_bound', 2,
  );
  const crossedBias = hnpFingerprint(
    'hnp-bias-crossed', 'eprint-2019-023-bias', 'lsb', 'signature.nonce_leak_bits', 8,
  );
  assert.equal(entry(await rank(knownBits), 'signature.ecdsa.partial-nonce-hnp').state, 'eligible');
  assert.equal(entry(await rank(bias), 'signature.ecdsa.partial-nonce-hnp').state, 'eligible');
  assert.equal(entry(await rank(crossedKnownBits), 'signature.ecdsa.partial-nonce-hnp').state, 'rejected');
  assert.equal(entry(await rank(crossedBias), 'signature.ecdsa.partial-nonce-hnp').state, 'rejected');
});

test('coast rank eligibility uses the 128-degree count from both pinned source lists', async () => {
  const source = JSON.parse(await readFile(coastSourcePath, 'utf8'));
  assert.equal(source.challenge_prime_degrees.length, 128);
  assert.deepEqual(source.solution_prime_degrees, source.challenge_prime_degrees);
  const parameterToken = `${source.challenge_prime_degrees.length}-prime-degree-tests`;
  assert.equal(entry(await rank(coastFingerprint('coast-128-degrees', parameterToken)),
    'paper.csidh.auxiliary-point-leak').state, 'eligible');
  assert.equal(entry(await rank(coastFingerprint('coast-stale-124-degrees', '124-prime-degree-tests')),
    'paper.csidh.auxiliary-point-leak').state, 'rejected');
});

test('CBC one-byte probe rejects under-budget cases before network authorization', async () => {
  const cases = JSON.parse(await readFile(casesPath, 'utf8'));
  assert.equal(entry(await rank(cases.cbc_insufficient), 'oracle.cbc-padding').state, 'rejected');
  assert.equal(entry(await rank(cases.cbc_constraint_capped), 'oracle.cbc-padding').state, 'rejected');
  assert.equal(entry(await rank(withConstraints(cases.cbc_insufficient, { network: 'allowed', oracle_access: 'allowed' })), 'oracle.cbc-padding').state, 'rejected');
  assert.equal(entry(await rank(withConstraints(cases.cbc_constraint_capped, { network: 'allowed', oracle_access: 'allowed' })), 'oracle.cbc-padding').state, 'rejected');
});

test('CBC one-byte probe requires independent network and oracle authorization', async () => {
  const cases = JSON.parse(await readFile(casesPath, 'utf8'));
  const disabled = entry(await rank(cases.cbc_sufficient), 'oracle.cbc-padding');
  assert.deepEqual(
    { state: disabled.state, ruleId: disabled.rule_id },
    { state: 'blocked', ruleId: 'constraint:network-disabled' },
  );
  const oracleOnly = entry(await rank(withConstraints(cases.cbc_sufficient, { oracle_access: 'allowed' })), 'oracle.cbc-padding');
  assert.deepEqual(
    { state: oracleOnly.state, ruleId: oracleOnly.rule_id },
    { state: 'blocked', ruleId: 'constraint:network-disabled' },
  );
  const networkOnly = entry(await rank(withConstraints(cases.cbc_sufficient, { network: 'allowed' })), 'oracle.cbc-padding');
  assert.deepEqual(
    { state: networkOnly.state, ruleId: networkOnly.rule_id },
    { state: 'blocked', ruleId: 'constraint:oracle-access-disabled' },
  );
  assert.equal(entry(await rank(withConstraints(cases.cbc_sufficient, { network: 'allowed', oracle_access: 'allowed' })), 'oracle.cbc-padding').state, 'eligible');
});

test('kproof remains blocked by its inferred authorization gate', async () => {
  const report = await rank(JSON.parse(await readFile(kproofPath, 'utf8')));
  const kproof = entry(report, 'oracle.goldwasser-micali.replication');
  assert.deepEqual(
    { state: kproof.state, ruleId: kproof.rule_id },
    { state: 'blocked', ruleId: 'authorized-gm-wrapper-oracle' },
  );
});

test('challenge-faithful null-template and wrapper procedures expose executable stages', async () => {
  const cards = JSON.parse(await readFile(catalogPath, 'utf8'));
  const expected = {
    'oracle.goldwasser-micali.replication': {
      parameters: ['captured-128-bit-gm-ciphertext-vector', 'replicate-each-captured-ciphertext-128-times', 'hash-certificate-bit-classifier'],
      procedures: ['replicate-captured-ciphertext', 'classify-hash-certificate', 'recover-transcript-key'],
    },
    'symmetric.slide.periodic-round': {
      parameters: ['chosen-16-round-pairs', 'feistel-subkey-16-bit', 'affine-map-24x24', 'flag-1024-rounds-64-chunks', 'public-counter-xor-wrapper'],
      procedures: ['recover-16-bit-subkey', 'recover-affine-map', 'invert-64-chunks'],
    },
    'paper.uov.wrapper-structure': {
      parameters: ['xor-public-map-equals-shake256-44', 'bounded-65536-candidate-search'],
      procedures: ['solver-outline', 'verify-xor-public-map'],
    },
    'paper.csidh.auxiliary-point-leak': {
      parameters: ['auxiliary-point-order-divisor-leak', '128-prime-degree-tests'],
      procedures: ['solver-outline', 'replay-isogeny-degree-vector'],
    },
  };
  for (const [cardId, contract] of Object.entries(expected)) {
    const card = cards.find(({ id }) => id === cardId);
    assert.notEqual(card, undefined);
    const hardParameters = new Set(card.requires.flatMap(({ when }) => predicates(when))
      .filter(({ fact, op }) => fact === 'construction.parameter_signature' && op === 'contains')
      .map(({ value }) => value));
    contract.parameters.forEach((parameter) => assert.equal(hardParameters.has(parameter), true, `${cardId}: ${parameter}`));
    const procedureIds = new Set(card.procedure.map(({ id }) => id));
    contract.procedures.forEach((id) => assert.equal(procedureIds.has(id), true, `${cardId}: ${id}`));
  }
});

test('HNP and bounded RSA/signature variants expose honest machine contracts', async () => {
  const cards = JSON.parse(await readFile(catalogPath, 'utf8'));
  const hnp = cards.find(({ id }) => id === 'signature.ecdsa.partial-nonce-hnp');
  const hnpPredicates = hnp.requires.flatMap(({ when }) => predicates(when));
  assert.equal(hnpPredicates.some(({ fact, op, value }) => fact === 'signature.sample_count' && op === 'gte' && value === 4), false);
  assert.equal(hnp.citations.some(({ paper_id: id }) => id === 'eprint:2019/023'), true);
  const franklin = cards.find(({ id }) => id === 'rsa.franklin-reiter.related-message');
  assert.equal(franklin.canonical_family_id, 'rsa.related-message-affine-e-3-5-7');
  const reuse = cards.find(({ id }) => id === 'signature.ecdsa.reused-nonce');
  assert.equal(reuse.procedure.some(({ id }) => id === 'try-opposite-nonce-sign'), true);
  const cbc = cards.find(({ id }) => id === 'oracle.cbc-padding');
  assert.equal(cbc.citations.some(({ url }) => url === 'https://www.iacr.org/archive/eurocrypt2002/23320530/cbc02_e02d.pdf'), true);
  const wagner = cards.find(({ id }) => id === 'paper.wagner.generalized-birthday');
  assert.equal(wagner.examples.some(({ challenge_id: id, inference_level: level }) => id === 'hitcon-2025-pedantic' && level === 'variant'), true);
});

test('source-derived algorithms cite exact implementation and output spans', async () => {
  const cards = JSON.parse(await readFile(catalogPath, 'utf8'));
  const expectedUrls = {
    'paper.matrix-product.trace-lattice': [
      'https://github.com/maple3142/My-CTF-Challenges/blob/7b3e786a2c20812f4da23536c7817bdfe8113dd6/HITCON%20CTF%202024/MatProd/dist/chall.py#L199-L228',
    ],
    'paper.csidh.auxiliary-point-leak': [
      'https://github.com/maple3142/My-CTF-Challenges/blob/7b3e786a2c20812f4da23536c7817bdfe8113dd6/ImaginaryCTF%202024/coast/chall.sage#L6-L16',
      'https://github.com/maple3142/My-CTF-Challenges/blob/7b3e786a2c20812f4da23536c7817bdfe8113dd6/ImaginaryCTF%202024/coast/solve.sage#L7-L17',
    ],
    'symmetric.slide.periodic-round': [
      'https://github.com/BSidesSF/ctf-2026-release/blob/68ee0e460eb572aaec17f082071f8ebf1d6f7330/tokencrypt/solution/recover_round.py#L134-L178',
    ],
  };
  for (const [cardId, urls] of Object.entries(expectedUrls)) {
    const card = cards.find(({ id }) => id === cardId);
    assert.notEqual(card, undefined);
    const actual = new Set(card.citations.map(({ url }) => url));
    urls.forEach((url) => assert.equal(actual.has(url), true, `${cardId}: ${url}`));
  }
});
