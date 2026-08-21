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
