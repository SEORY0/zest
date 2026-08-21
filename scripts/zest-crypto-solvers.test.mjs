import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import test from 'node:test';

import {
  assertFailure, fixtures, parseSuccess, python, registerReaderTests, run, sageAvailable, templates,
} from './zest-crypto-solvers.test-support.mjs';

const jsonSuccessCases = [
  {
    name: 'Wiener recovers factors and proves the RSA round trip',
    script: 'rsa_wiener.py', fixture: 'rsa-wiener.json',
    expected: { d: 5, factors: [1009, 1013], message: 42 },
  },
  {
    name: 'common modulus recovers one message and proves both ciphertext equations',
    script: 'rsa_common_modulus.py', fixture: 'rsa-common-modulus.json',
    expected: { message: 42, recomputed: [240, 205] },
  },
  {
    name: 'Hastad requires an exact integer root and proves every ciphertext equation',
    script: 'rsa_hastad.py', fixture: 'rsa-hastad.json',
    expected: { message: 42, recomputed: [5610, 4110, 7540] },
  },
  {
    name: 'ECDSA nonce reuse proves both signatures and the public key',
    script: 'ecdsa_nonce_reuse.py', fixture: 'ecdsa-nonce-reuse.json',
    expected: { k: 77, private_scalar: 123, signatures_verified: 2 },
  },
  {
    name: 'four-list Wagner search returns an exact modular list sum',
    script: 'wagner_generalized_birthday.py', fixture: 'wagner-four-list.json',
    expected: { indices: [0, 0, 0, 0], residue: 10, sum: 10, values: [1, 2, 3, 4] },
  },
];
const jsonScripts = [...jsonSuccessCases.map(({ script }) => script), 'rotor_group_conjugacy.py',
  'coppersmith_univariate.sage'];

for (const scenario of jsonSuccessCases) {
  test(scenario.name, async () => {
    // Given: an independent public synthetic construction fixture.
    const args = [join(templates, scenario.script), join(fixtures, scenario.fixture)];

    // When: the copied-template CLI is executed twice.
    const first = await run(python, args);
    const second = await run(python, args);

    // Then: exact proof fields are present and stdout is deterministic.
    const document = parseSuccess(first);
    assert.equal(second.stdout, first.stdout);
    for (const [key, value] of Object.entries(scenario.expected)) {
      assert.deepEqual(document[key] ?? document.proof[key], value);
    }
  });
}

const failureCases = [
  ['rsa_wiener.py', 'rsa-wiener-bad-type.json', 'invalid-input'],
  ['rsa_common_modulus.py', 'rsa-common-modulus-noncoprime.json', 'exponents-not-coprime'],
  ['rsa_common_modulus.py', 'rsa-common-modulus-no-inverse.json', 'non-invertible-ciphertext'],
  ['rsa_hastad.py', 'rsa-hastad-wrong-equation.json', 'inexact-root'],
  ['rsa_hastad.py', 'rsa-hastad-noncoprime.json', 'moduli-not-coprime'],
  ['ecdsa_nonce_reuse.py', 'ecdsa-nonce-reuse-wrong-equation.json', 'proof-mismatch'],
  ['wagner_generalized_birthday.py', 'wagner-oversized.json', 'work-bound-exceeded'],
];

for (const [script, fixture, code] of failureCases) {
  test(`${script} rejects ${fixture} without a traceback`, async () => {
    // Given: a public adversarial fixture that violates one exact precondition.
    const args = [join(templates, script), join(fixtures, fixture)];

    // When: the template processes the fixture.
    const result = await run(python, args);

    // Then: it returns one stable structured failure and never verifies.
    assertFailure(result, code);
  });
}

for (const script of jsonSuccessCases.map(({ script }) => script)) {
  test(`${script} rejects malformed JSON structurally`, async () => {
    // Given: truncated untrusted JSON.
    const malformed = join(fixtures, 'malformed.json');

    // When: the template parses its only input boundary.
    const result = await run(python, [join(templates, script), malformed]);

    // Then: no traceback or false verification escapes the CLI.
    assertFailure(result, 'invalid-json');
  });
}

test('LFSR recovers state and taps, replays the prefix, and proves the plaintext digest', async () => {
  // Given: encrypted synthetic PNG bytes, a known PNG header, and a public digest.
  const metadata = JSON.parse(await readFile(join(fixtures, 'lfsr-known-plaintext.json'), 'utf8'));
  const args = [join(templates, 'lfsr_known_plaintext.py'), join(fixtures, 'lfsr-ciphertext.hex'),
    join(fixtures, 'lfsr-known-prefix.hex'), metadata.expected_plaintext_sha256,
    String(metadata.width), String(metadata.max_candidates), String(metadata.max_steps)];

  // When: the bounded Galois-LFSR recovery CLI runs.
  const document = parseSuccess(await run(python, args));

  // Then: the recovered recurrence and exact digest match independent fixture values.
  assert.deepEqual(
    { digest: document.plaintext_sha256, state: document.initial_state, taps: document.tap_mask },
    { digest: metadata.expected_plaintext_sha256, state: metadata.expected_state, taps: metadata.expected_taps },
  );
  assert.deepEqual(document.proof, { ciphertext_replayed: true, known_prefix_replayed: true });
});

test('LFSR rejects malformed hex and a plaintext digest proof mismatch', async () => {
  // Given: one malformed stream and one false public digest.
  const mismatch = JSON.parse(await readFile(join(fixtures, 'lfsr-proof-mismatch.json'), 'utf8'));
  const base = [join(templates, 'lfsr_known_plaintext.py')];

  // When: each adversarial boundary is executed.
  const malformed = await run(python, [...base, join(fixtures, 'lfsr-malformed.hex'),
    join(fixtures, 'lfsr-known-prefix.hex'), mismatch.expected_plaintext_sha256, '8', '65536', '5000000']);
  const wrongDigest = await run(python, [...base, join(fixtures, 'lfsr-ciphertext.hex'),
    join(fixtures, 'lfsr-known-prefix.hex'), mismatch.expected_plaintext_sha256, '8', '65536', '5000000']);

  // Then: neither can be labeled verified.
  assertFailure(malformed, 'invalid-hex');
  assertFailure(wrongDigest, 'proof-mismatch');
});

test('rotor solver recovers a unique conjugator and independently replays mappings', async () => {
  // Given: two training conjugacies and mappings excluded from candidate search.
  const args = [join(templates, 'rotor_group_conjugacy.py'), join(fixtures, 'rotor-conjugacy.json')];

  // When: the bounded permutation search runs.
  const document = parseSuccess(await run(python, args));

  // Then: the exact wiring and both proof classes are reported.
  assert.deepEqual(document.permutation, [2, 5, 1, 4, 0, 3]);
  assert.deepEqual(document.proof, { conjugacy_equations: 2, replay_mappings: 6 });
});

test('rotor solver rejects independent replay proof mismatch and malformed JSON', async () => {
  // Given: one false replay mapping and one truncated fixture.
  const script = join(templates, 'rotor_group_conjugacy.py');

  // When: each adversarial fixture runs.
  const mismatch = await run(python, [script, join(fixtures, 'rotor-proof-mismatch.json')]);
  const malformed = await run(python, [script, join(fixtures, 'malformed.json')]);

  // Then: both failures are structured and non-verifying.
  assertFailure(mismatch, 'proof-mismatch');
  assertFailure(malformed, 'invalid-json');
});

for (const [fixture, code] of [
  ['duplicate-top-level.json', 'invalid-json'],
  ['duplicate-nested.json', 'invalid-json'],
  ['deep-json.json', 'invalid-json'],
  ['nonstandard-constant.json', 'invalid-json'],
  ['float-overflow.json', 'invalid-json'],
  ['integer-token-at-limit.json', 'invalid-input'],
  ['integer-token-oversized.json', 'invalid-json'],
]) {
  test(`every JSON template gives one stable result for ${fixture}`, async () => {
    // Given: one adversarial JSON token/structure shared by every JSON boundary.
    const path = join(fixtures, fixture);

    // When: every self-contained JSON template parses it.
    const results = await Promise.all(jsonScripts.map((script) => run(python, [join(templates, script), path])));

    // Then: parser behavior is identical across templates and Python versions.
    results.forEach((result) => assertFailure(result, code));
  });
}

registerReaderTests(test, jsonScripts);

for (const [fixture, code] of [
  ['rsa-wiener-repeated-prime.json', 'invalid-factorization'],
  ['rsa-wiener-composite-factors.json', 'invalid-factorization'],
]) {
  test(`Wiener rejects ${fixture} before claiming an RSA private exponent`, async () => {
    const result = await run(python, [join(templates, 'rsa_wiener.py'), join(fixtures, fixture)]);
    assertFailure(result, code);
  });
}

test('Hastad applies root and product limits to their own values', async () => {
  const result = await run(python, [join(templates, 'rsa_hastad.py'),
    join(fixtures, 'rsa-hastad-large-product-small-root.json')]);
  const document = parseSuccess(result);
  assert.equal(document.message, 2);
  assert.deepEqual(document.proof.recomputed, [8, 8, 8]);
});

for (const [fixture, code] of [
  ['ecdsa-singular-curve.json', 'invalid-curve'],
  ['ecdsa-composite-field.json', 'invalid-field'],
  ['ecdsa-multiple-order.json', 'invalid-order'],
]) {
  test(`ECDSA rejects unsupported domain fixture ${fixture}`, async () => {
    const result = await run(python, [join(templates, 'ecdsa_nonce_reuse.py'), join(fixtures, fixture)]);
    assertFailure(result, code);
  });
}

test('ECDSA reduces a bounded nonnegative z representative modulo the subgroup order', async () => {
  const result = await run(python, [join(templates, 'ecdsa_nonce_reuse.py'),
    join(fixtures, 'ecdsa-z-plus-order.json')]);
  const document = parseSuccess(result);
  assert.deepEqual({ k: document.k, privateScalar: document.private_scalar }, { k: 77, privateScalar: 123 });
});

test('LFSR uniqueness accepts the public 24-bit observation', async () => {
  const metadata = JSON.parse(await readFile(join(fixtures, 'lfsr-24bit.json'), 'utf8'));
  const result = await run(python, [join(templates, 'lfsr_known_plaintext.py'),
    join(fixtures, 'lfsr-24bit-ciphertext.hex'), join(fixtures, 'lfsr-24bit-known-prefix.hex'),
    metadata.expected_plaintext_sha256, String(metadata.width), String(metadata.max_candidates),
    String(metadata.max_steps)]);
  const document = parseSuccess(result);
  assert.deepEqual({ state: document.initial_state, taps: document.tap_mask }, { state: 1, taps: 128 });
});

test('LFSR rejects a candidate-observation product beyond the explicit step budget', async () => {
  const metadata = JSON.parse(await readFile(join(fixtures, 'lfsr-work-bound.json'), 'utf8'));
  const result = await run(python, [join(templates, 'lfsr_known_plaintext.py'),
    join(fixtures, 'lfsr-ciphertext.hex'), join(fixtures, 'lfsr-known-prefix.hex'),
    metadata.expected_plaintext_sha256, String(metadata.width), String(metadata.max_candidates),
    String(metadata.max_steps)]);
  assertFailure(result, 'work-bound-exceeded');
});

for (const fixture of ['rotor-duplicate-replay.json', 'rotor-conflicting-replay.json']) {
  test(`rotor rejects repeated replay evidence in ${fixture}`, async () => {
    const result = await run(python, [join(templates, 'rotor_group_conjugacy.py'), join(fixtures, fixture)]);
    assertFailure(result, 'duplicate-replay-input');
  });
}

test('solver package contains exactly eight bounded self-contained templates', async () => {
  // Given: the standalone solver-template directory.
  const expected = ['coppersmith_univariate.sage', 'ecdsa_nonce_reuse.py', 'lfsr_known_plaintext.py',
    'rotor_group_conjugacy.py', 'rsa_common_modulus.py', 'rsa_hastad.py', 'rsa_wiener.py',
    'wagner_generalized_birthday.py'];

  // When: files and Python AST imports/calls are inspected.
  const entries = await readdir(templates, { withFileTypes: true });
  assert.deepEqual(entries.filter((entry) => entry.isFile()).map((entry) => entry.name).sort(), expected);
  const scanner = 'import ast,json,sys; t=ast.parse(open(sys.argv[1],encoding="utf-8").read()); '
    + 'print(json.dumps({"imports":[(n.names[0].name if isinstance(n,ast.Import) else n.module).split(".")[0] for n in ast.walk(t) if isinstance(n,(ast.Import,ast.ImportFrom))],'
    + '"calls":[n.func.id if isinstance(n.func,ast.Name) else n.func.attr for n in ast.walk(t) if isinstance(n,ast.Call) and isinstance(n.func,(ast.Name,ast.Attribute))],'
    + '"strings":[n.value for n in ast.walk(t) if isinstance(n,ast.Constant) and isinstance(n.value,str)]}))';

  // Then: Python deps are empty and executable import/dynamic-code escape hatches are absent.
  for (const filename of expected) {
    const path = join(templates, filename);
    const source = await readFile(path, 'utf8');
    const scan = await run(python, ['-c', scanner, path]);
    assert.equal(scan.code, 0, scan.stderr);
    const structure = JSON.parse(scan.stdout);
    if (filename.endsWith('.py')) assert.match(source, /# dependencies = \[\]/);
    for (const forbidden of ['http', 'importlib', 'requests', 'socket', 'subprocess', 'urllib']) {
      assert.equal(structure.imports.includes(forbidden), false, `${filename}: forbidden import ${forbidden}`);
    }
    for (const forbidden of ['__import__', 'compile', 'eval', 'exec']) {
      assert.equal(structure.calls.includes(forbidden), false, `${filename}: forbidden call ${forbidden}`);
    }
    if (filename.endsWith('.sage')) {
      for (const required of ['Fraction', 'PolynomialRing', 'Zmod', 'gcd', 'loads', 'small_roots']) {
        assert.equal(structure.calls.includes(required), true, `${filename}: missing structural call ${required}`);
      }
      for (const code of ['invalid-beta', 'invalid-bound', 'polynomial-not-monic']) {
        assert.equal(structure.strings.includes(code), true, `${filename}: missing structural guard ${code}`);
      }
    }
  }
});

test('Coppersmith preflight rejects malformed, non-monic, and oversized inputs without Sage', async () => {
  // Given: invalid public fixtures that must be rejected before lattice execution.
  const script = join(templates, 'coppersmith_univariate.sage');
  const cases = [
    ['malformed.json', 'invalid-json'],
    ['coppersmith-nonmonic.json', 'polynomial-not-monic'],
    ['coppersmith-oversized-bound.json', 'invalid-bound'],
  ];

  // When: the syntactically portable preflight is run with Python only.
  const results = await Promise.all(cases.map(([fixture]) => run(python, [script, join(fixtures, fixture)])));

  // Then: every boundary failure is structured before Sage is imported or installed.
  results.forEach((result, index) => assertFailure(result, cases[index][1]));
});

test('Coppersmith template has structural guards and executes only when Sage is installed',
  { skip: sageAvailable ? false : 'SageMath is genuinely absent from PATH; runtime installation is prohibited' },
  async () => {
    // Given: a monic polynomial with the exact small root 12 modulo 10403.
    const script = join(templates, 'coppersmith_univariate.sage');

    // When: the installed Sage runtime executes the fixture.
    const document = parseSuccess(await run('sage', [script, join(fixtures, 'coppersmith-univariate.json')]));
    const factorDocument = parseSuccess(await run('sage', [script, join(fixtures, 'coppersmith-factor-root.json')]));

    // Then: full-modulus and beta-factor roots carry exact divisor witnesses.
    assert.deepEqual(document.roots, [12]);
    assert.deepEqual(document.proof.divisor_witnesses, [10403]);
    assert.deepEqual(factorDocument.roots, [1]);
    assert.deepEqual(factorDocument.proof.divisor_witnesses, [103]);
  });
