import assert from 'node:assert/strict';
import { execFile, spawnSync } from 'node:child_process';
import { readdir, readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

const execFileAsync = promisify(execFile);
const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const templates = join(root, 'skills', 'zest-crypto', 'assets', 'solver-templates');
const fixtures = join(root, 'scripts', 'fixtures', 'zest-crypto', 'solvers');
const python = process.env.PYTHON ?? 'python3';
const sageAvailable = spawnSync('sage', ['--version'], { stdio: 'ignore' }).status === 0;

async function run(command, args) {
  try {
    const result = await execFileAsync(command, args, { encoding: 'utf8', timeout: 10_000 });
    return { code: 0, stderr: result.stderr, stdout: result.stdout };
  } catch (error) {
    return {
      code: typeof error.code === 'number' ? error.code : -1,
      stderr: error.stderr ?? '',
      stdout: error.stdout ?? '',
    };
  }
}

function parseSuccess(result) {
  assert.equal(result.code, 0, result.stderr || result.stdout);
  assert.equal(result.stderr, '');
  assert.equal(result.stdout.endsWith('\n'), true);
  const document = JSON.parse(result.stdout);
  assert.equal(document.verified, true);
  return document;
}

function assertFailure(result, code) {
  assert.notEqual(result.code, 0);
  assert.equal(result.stderr, '');
  const document = JSON.parse(result.stdout);
  assert.deepEqual(document, { error: { code }, verified: false });
  assert.equal(result.stdout.includes('Traceback'), false);
}

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
    String(metadata.width), String(metadata.max_candidates)];

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
    join(fixtures, 'lfsr-known-prefix.hex'), mismatch.expected_plaintext_sha256, '8', '65536']);
  const wrongDigest = await run(python, [...base, join(fixtures, 'lfsr-ciphertext.hex'),
    join(fixtures, 'lfsr-known-prefix.hex'), mismatch.expected_plaintext_sha256, '8', '65536']);

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
      for (const required of ['PolynomialRing', 'Zmod', 'load', 'small_roots']) {
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

    // Then: every reported root was checked in the original congruence.
    assert.deepEqual(document.roots, [12]);
  });
