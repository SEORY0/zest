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

function predicates(condition) {
  if (condition.fact) return [condition];
  if (condition.not) return predicates(condition.not);
  return [...(condition.all ?? []), ...(condition.any ?? [])].flatMap(predicates);
}

test('every challenge-specific route binds its exact immutable source anchors', async () => {
  const expected = {
    'paper.matrix-product.trace-lattice': ['github.com/maple3142/My-CTF-Challenges@7b3e786a2c20812f4da23536c7817bdfe8113dd6/HITCON%20CTF%202024/MatProd/dist/chall.py:L6-L60'],
    'paper.stream-cipher.fca-lwpm': ['github.com/maple3142/My-CTF-Challenges@7b3e786a2c20812f4da23536c7817bdfe8113dd6/HITCON%20CTF%202024/Hyper512/dist/chall.py:L4-L64'],
    'paper.ecdsa.lcg-nonce': ['github.com/maple3142/My-CTF-Challenges@7b3e786a2c20812f4da23536c7817bdfe8113dd6/HITCON%20CTF%202024/ECLCG/dist/chall.py:L25-L64'],
    'paper.frost.threshold-signature': ['github.com/project-sekai-ctf/sekaictf-2025@683dd81ae520581add40ec21c4819866e28cbde4/crypto/law-and-order/challenge/app/chall.py:L150-L311'],
    'paper.uov.wrapper-structure': ['github.com/project-sekai-ctf/sekaictf-2025@683dd81ae520581add40ec21c4819866e28cbde4/crypto/unfairy-ring/dist/chall.py:L10-L18'],
    'paper.csidh.auxiliary-point-leak': ['github.com/maple3142/My-CTF-Challenges@7b3e786a2c20812f4da23536c7817bdfe8113dd6/ImaginaryCTF%202024/coast/README.md:L11-L15'],
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
});

test('CBC one-byte probe requires the declared worst-case budget under case constraints', async () => {
  const cases = JSON.parse(await readFile(casesPath, 'utf8'));
  assert.equal(entry(await rank(cases.cbc_insufficient), 'oracle.cbc-padding').state, 'rejected');
  assert.equal(entry(await rank(cases.cbc_constraint_capped), 'oracle.cbc-padding').state, 'rejected');
  assert.equal(entry(await rank(cases.cbc_sufficient), 'oracle.cbc-padding').state, 'eligible');
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
      parameters: ['auxiliary-point-order-divisor-leak', '124-prime-degree-tests'],
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
