import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import test from 'node:test';

import {
  assertFailure, fixtures, parseSuccess, python, run, templates,
} from './zest-crypto-solvers.test-support.mjs';

test('LFSR replays the pinned whole-state big-endian block schedule', async () => {
  // Given: a synthetic vector derived from the pinned seed, tap mask, and word schedule.
  const metadata = JSON.parse(await readFile(join(fixtures, 'lfsr-state-word.json'), 'utf8'));
  const args = [join(templates, 'lfsr_known_plaintext.py'),
    join(fixtures, 'lfsr-state-word-ciphertext.hex'),
    join(fixtures, 'lfsr-state-word-known-prefix.hex'),
    metadata.expected_plaintext_sha256, String(metadata.width), String(metadata.max_candidates),
    String(metadata.max_steps), metadata.schedule];

  // When: the standalone solver selects the whole-state schedule.
  const document = parseSuccess(await run(python, args));

  // Then: it recovers the pinned recurrence and proves the entire synthetic plaintext.
  assert.deepEqual(
    { digest: document.plaintext_sha256, schedule: document.schedule, state: document.initial_state, taps: document.tap_mask },
    { digest: metadata.expected_plaintext_sha256, schedule: 'state-word-be', state: 0x074188a5, taps: 0x82800010 },
  );
  assert.deepEqual(document.proof, { ciphertext_replayed: true, known_prefix_replayed: true });
});

test('LFSR state-word schedule rejects non-byte-aligned widths structurally', async () => {
  // Given: otherwise valid state-word inputs with sub-byte and unaligned widths.
  const metadata = JSON.parse(await readFile(join(fixtures, 'lfsr-state-word.json'), 'utf8'));
  const base = [join(templates, 'lfsr_known_plaintext.py'),
    join(fixtures, 'lfsr-state-word-ciphertext.hex'),
    join(fixtures, 'lfsr-state-word-known-prefix.hex'), metadata.expected_plaintext_sha256];

  // When: the standalone boundary receives invalid word widths.
  const results = await Promise.all([7, 10].map((width) => run(python,
    [...base, String(width), '1', String(metadata.max_steps), metadata.schedule])));

  // Then: both fail with the stable error contract and no traceback.
  results.forEach((result) => assertFailure(result, 'invalid-arguments'));
});

test('ECDSA recovers the key when the second repeated-r signature uses q minus k', async () => {
  // Given: two valid secp256k1 signatures whose nonce points are exact opposites.
  const args = [join(templates, 'ecdsa_nonce_reuse.py'),
    join(fixtures, 'ecdsa-nonce-reuse-opposite.json')];

  // When: the standalone solver evaluates both equal-r nonce relations.
  const document = parseSuccess(await run(python, args));

  // Then: the first nonce and private scalar are exact, with explicit opposite signs.
  assert.deepEqual(
    {
      k: document.k,
      noncePoints: document.proof.nonce_points_verified,
      nonceRelation: document.nonce_relation,
      nonceSigns: document.proof.nonce_signs,
      privateScalar: document.private_scalar,
      signatures: document.proof.signatures_verified,
    },
    {
      k: 77, noncePoints: 2, nonceRelation: 'opposite', nonceSigns: [1, -1],
      privateScalar: 123, signatures: 2,
    },
  );
});

test('ECDSA rejects duplicate signatures that cannot determine a nonce relation', async () => {
  // Given: the same valid signature repeated twice, with no independent second equation.
  const args = [join(templates, 'ecdsa_nonce_reuse.py'),
    join(fixtures, 'ecdsa-nonce-reuse-ambiguous.json')];

  // When: both candidate nonce relations are considered.
  const result = await run(python, args);

  // Then: the solver reports underdetermination instead of a key or a traceback.
  assertFailure(result, 'ambiguous-nonce-relation');
});

test('ECDSA skips a noninvertible same-nonce denominator and proves the opposite relation', async () => {
  // Given: a valid opposite-nonce pair with s1=s2, so only the opposite denominator is usable.
  const args = [join(templates, 'ecdsa_nonce_reuse.py'),
    join(fixtures, 'ecdsa-nonce-reuse-opposite-fallback.json')];

  // When: candidate relations are evaluated independently.
  const document = parseSuccess(await run(python, args));

  // Then: failure of the same-nonce denominator cannot mask the verified opposite candidate.
  assert.deepEqual(
    { k: document.k, nonceRelation: document.nonce_relation, privateScalar: document.private_scalar },
    { k: 77, nonceRelation: 'opposite', privateScalar: 123 },
  );
});
