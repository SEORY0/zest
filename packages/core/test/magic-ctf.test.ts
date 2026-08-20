import assert from 'node:assert/strict';
import test from 'node:test';

import { decodeAs, encodeAs, magic, utf8Encode } from '../src/index.js';

test('Magic recovers ROT47 text when a CTF crib is known', async () => {
  // Given: printable text obscured with ROT47 and a known plaintext fragment.
  const input = utf8Encode('w6==@[ (@C=5P');

  // When: Magic explores one decoding layer.
  const matches = await magic(input, { depth: 1, crib: 'Hello' });

  // Then: the ROT47 recipe restores the hand-checked plaintext.
  assert.equal(matches[0]?.label, 'rot47');
  assert.equal(encodeAs(matches[0]?.output ?? new Uint8Array(), 'utf8'), 'Hello, World!');
});

test('Magic recovers a bitwise-NOT obfuscated flag', async () => {
  // Given: the literal bytewise complement of "flag{zest_ctf}".
  const input = decodeAs('99939e9884859a8c8ba09c8b9982', 'hex');

  // When: Magic searches for the known flag prefix.
  const matches = await magic(input, { depth: 1, crib: 'flag{' });

  // Then: the reversible bitwise-NOT step exposes the flag.
  assert.equal(matches[0]?.label, 'bitwise-not');
  assert.equal(encodeAs(matches[0]?.output ?? new Uint8Array(), 'utf8'), 'flag{zest_ctf}');
});
