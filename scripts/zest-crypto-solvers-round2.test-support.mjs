import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { pathToFileURL } from 'node:url';
import { promisify } from 'node:util';

import {
  assertFailure, fixtures, parseSuccess, python, root, run, templates,
} from './zest-crypto-solvers.test-support.mjs';

const execFileAsync = promisify(execFile);

test('Wiener verifies recovered 65-bit prime factors inside its published proof range', async () => {
  // Given: an exact Wiener construction whose two independently checked factors are 65-bit primes.
  const args = [join(templates, 'rsa_wiener.py'), join(fixtures, 'rsa-wiener-65bit.json')];

  // When: the bounded standalone solver runs.
  const result = await run(python, args);
  const document = parseSuccess(result);

  // Then: the private exponent, prime factors, and RSA round trip are exact.
  assert.deepEqual({ d: document.d, message: document.message }, { d: 3, message: 42 });
  assert.match(result.stdout, /"factors":\[18446744073709551629,18446744073709552697\]/);
});

test('Wiener rejects a factor at the exclusive deterministic-primality boundary', async () => {
  // Given: a recoverable factorization at the first excluded Miller-Rabin proof value.
  const args = [join(templates, 'rsa_wiener.py'), join(fixtures, 'rsa-wiener-prime-proof-bound.json')];

  // When: factor recovery reaches the explicitly unsupported proof boundary.
  const result = await run(python, args);

  // Then: the solver reports the domain limit instead of claiming primality.
  assertFailure(result, 'unsupported-domain');
});

test('ECDSA verifies an exact NIST P-256 reused-nonce construction', async () => {
  // Given: audited P-256 parameters and two signatures generated with k=77 and d=123.
  const args = [join(templates, 'ecdsa_nonce_reuse.py'), join(fixtures, 'ecdsa-p256-nonce-reuse.json')];

  // When: the solver recovers and replays the nonce, key, and signatures.
  const document = parseSuccess(await run(python, args));

  // Then: both recovered secrets and both conventional signature checks agree.
  assert.deepEqual(
    { k: document.k, privateScalar: document.private_scalar, signatures: document.proof.signatures_verified },
    { k: 77, privateScalar: 123, signatures: 2 },
  );
});

test('ECDSA verifies the opposite-nonce variant on exact NIST P-256 parameters', async () => {
  // Given: the same audited P-256 construction with the second scalar normalized to q-s.
  const args = [join(templates, 'ecdsa_nonce_reuse.py'),
    join(fixtures, 'ecdsa-p256-nonce-reuse-opposite.json')];

  // When: the solver checks both repeated-r nonce-point signs.
  const document = parseSuccess(await run(python, args));

  // Then: the P-256 allowlist and opposite relation both remain fully proved.
  assert.deepEqual(
    {
      k: document.k,
      nonceRelation: document.nonce_relation,
      nonceSigns: document.proof.nonce_signs,
      privateScalar: document.private_scalar,
    },
    { k: 77, nonceRelation: 'opposite', nonceSigns: [1, -1], privateScalar: 123 },
  );
});

test('ECDSA rejects a mutated large standard domain outside the audited tuple allowlist', async () => {
  // Given: P-256-sized values with a one-unit mutation to the standard curve coefficient.
  const args = [join(templates, 'ecdsa_nonce_reuse.py'), join(fixtures, 'ecdsa-p256-mutated-domain.json')];

  // When: the large-domain gate runs before scalar proof work.
  const result = await run(python, args);

  // Then: the nonstandard tuple is explicitly unsupported and cannot verify.
  assertFailure(result, 'unsupported-domain');
});

test('Sage availability probing treats a stuck executable as unavailable within a bounded timeout', async () => {
  // Given: a PATH-leading Sage executable that never returns.
  const temporary = await mkdtemp(join(tmpdir(), 'zest-crypto-sage-probe-'));
  const fakeSage = join(temporary, 'sage');
  await writeFile(fakeSage, '#!/bin/sh\nwhile :; do :; done\n', { encoding: 'utf8', mode: 0o700 });
  const supportUrl = pathToFileURL(join(root, 'scripts', 'zest-crypto-solvers.test-support.mjs')).href;
  const source = `const m = await import(${JSON.stringify(supportUrl)}); process.stdout.write(String(m.sageAvailable) + '\\n');`;
  try {
    // When: a fresh Node process imports the real availability probe.
    const result = await execFileAsync(process.execPath, ['--input-type=module', '--eval', source], {
      cwd: root,
      encoding: 'utf8',
      env: { ...process.env, PATH: `${temporary}:${process.env.PATH ?? ''}` },
      timeout: 2_000,
    });

    // Then: discovery completes and reports the unusable runtime as absent.
    assert.deepEqual({ stderr: result.stderr, stdout: result.stdout }, { stderr: '', stdout: 'false\n' });
  } finally {
    await rm(temporary, { force: true, recursive: true });
  }
});
