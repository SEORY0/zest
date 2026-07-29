/**
 * Published test vectors for the primitives implemented from scratch.
 *
 * These are the parts of the codebase where a subtle bug would be silent, so
 * each is checked against the value in its defining document.
 */

import assert from 'node:assert/strict';
import test from 'node:test';

import { decodeAs, encodeAs, hexEncode, runRecipe, utf8Encode } from '../src/index.js';

async function apply(op: string, input: string, args?: Record<string, unknown>): Promise<string> {
  const result = await runRecipe(utf8Encode(input), [{ op, args: args as never }]);
  assert.equal(result.ok, true, result.error ?? "");
  return encodeAs(result.output, 'utf8');
}

test('MD5 — RFC 1321 appendix A.5', async () => {
  const vectors: [string, string][] = [
    ['', 'd41d8cd98f00b204e9800998ecf8427e'],
    ['a', '0cc175b9c0f1b6a831c399e269772661'],
    ['abc', '900150983cd24fb0d6963f7d28e17f72'],
    ['message digest', 'f96b697d7cb7938d525a2f31aaf161d0'],
    ['abcdefghijklmnopqrstuvwxyz', 'c3fcd3d76192e4007dfb496cca67e13b'],
    ['ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789', 'd174ab98d277d9f5a5611c2c9f419d9f'],
    ['12345678901234567890123456789012345678901234567890123456789012345678901234567890', '57edf4a22be3c955ac49da2e2107b67a'],
  ];
  for (const [input, expected] of vectors) {
    assert.equal(await apply('md5', input), expected, `md5(${JSON.stringify(input)})`);
  }
});

test('SHA-3 — FIPS 202 vectors', async () => {
  assert.equal(await apply('sha3', '', { size: '224' }), '6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7');
  assert.equal(await apply('sha3', '', { size: '256' }), 'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a');
  assert.equal(
    await apply('sha3', '', { size: '512' }),
    'a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26',
  );
  assert.equal(await apply('sha3', 'abc', { size: '256' }), '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532');
});

test('Keccak-256 — the pre-standard padding Ethereum uses', async () => {
  assert.equal(await apply('keccak', '', { size: '256' }), 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470');
  assert.equal(await apply('keccak', 'abc', { size: '256' }), '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45');
});

test('CRC-32 — the check value from the CRC catalogue', async () => {
  assert.equal(await apply('crc32', '123456789'), 'cbf43926');
});

test('Adler-32 — zlib check value', async () => {
  assert.equal(await apply('adler32', 'Wikipedia'), '11e60398');
});

test('HMAC — RFC 4231 test cases', async () => {
  assert.equal(
    await apply('hmac', 'Hi There', { key: 'hex:0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b', algorithm: 'SHA-256' }),
    'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7',
  );
  assert.equal(
    await apply('hmac', 'what do ya want for nothing?', { key: 'Jefe', algorithm: 'SHA-256' }),
    '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843',
  );
  assert.equal(
    await apply('hmac', 'what do ya want for nothing?', { key: 'Jefe', algorithm: 'SHA-512' }),
    '164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737',
  );
});

test('HMAC-MD5 — RFC 2202 test case 1', async () => {
  assert.equal(
    await apply('hmac', 'Hi There', { key: 'hex:0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b', algorithm: 'MD5' }),
    '9294727a3638bb1c13f48ef8158bfc9d',
  );
});

test('PBKDF2 — RFC 6070 test cases', async () => {
  assert.equal(
    await apply('pbkdf2', 'password', { salt: 'salt', iterations: 1, keyLength: 160, hash: 'SHA-1' }),
    '0c60c80f961f0e71f3a9b524af6012062fe037a6',
  );
  assert.equal(
    await apply('pbkdf2', 'password', { salt: 'salt', iterations: 4096, keyLength: 160, hash: 'SHA-1' }),
    '4b007901b765489abead49d926f721d065a429c1',
  );
});

test('RC4 — RFC 6229 key stream applied to a known plaintext', async () => {
  const encrypted = await apply('rc4', 'Plaintext', { key: 'Key', output: 'Hex' });
  assert.equal(encrypted, 'bbf316e8d940af0ad3');

  // RC4 is symmetric: re-running the cipher over the ciphertext restores the input.
  const result = await runRecipe(decodeAs(encrypted, 'hex'), [{ op: 'rc4', args: { key: 'Key' } }]);
  assert.equal(encodeAs(result.output, 'utf8'), 'Plaintext');
});

test('Base32 — RFC 4648 vectors', async () => {
  const vectors: [string, string][] = [
    ['', ''],
    ['f', 'MY======'],
    ['fo', 'MZXQ===='],
    ['foo', 'MZXW6==='],
    ['foob', 'MZXW6YQ='],
    ['fooba', 'MZXW6YTB'],
    ['foobar', 'MZXW6YTBOI======'],
  ];
  for (const [input, expected] of vectors) {
    assert.equal(await apply('to-base32', input), expected, `to-base32(${JSON.stringify(input)})`);
    assert.equal(await apply('from-base32', expected), input, `from-base32(${JSON.stringify(expected)})`);
  }
});

test('Base64 — RFC 4648 vectors', async () => {
  const vectors: [string, string][] = [
    ['', ''],
    ['f', 'Zg=='],
    ['fo', 'Zm8='],
    ['foo', 'Zm9v'],
    ['foob', 'Zm9vYg=='],
    ['fooba', 'Zm9vYmE='],
    ['foobar', 'Zm9vYmFy'],
  ];
  for (const [input, expected] of vectors) {
    assert.equal(await apply('to-base64', input), expected);
    assert.equal(await apply('from-base64', expected), input);
  }
});

test('Base58 — the canonical Bitcoin address vector', async () => {
  const payload = '00010966776006953d5567439e5e39f86a0d273beed61967f6';
  const address = '16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM';

  const encoded = await runRecipe(decodeAs(payload, 'hex'), [{ op: 'to-base58' }]);
  assert.equal(encodeAs(encoded.output, 'utf8'), address);

  const decoded = await runRecipe(utf8Encode(address), [{ op: 'from-base58' }]);
  assert.equal(hexEncode(decoded.output), payload);
});

test('Base58 — a leading zero byte becomes a leading 1', async () => {
  const payload = '0000010966776006953d5567439e5e39f86a0d273bee';
  const encoded = await runRecipe(decodeAs(payload, 'hex'), [{ op: 'to-base58' }]);
  assert.equal(encodeAs(encoded.output, 'utf8'), '11qb3y62fmEEVTPySXPQ77WXok6H');

  const decoded = await runRecipe(encoded.output, [{ op: 'from-base58' }]);
  assert.equal(hexEncode(decoded.output), payload);
});

test('Magic ranks a doubly-encoded payload above the single decode', async () => {
  const { magic } = await import('../src/index.js');
  const matches = await magic(utf8Encode('U0dWc2JHOHNJSGR2Y214a0lRPT0='), { depth: 2 });

  assert.ok(matches.length > 0, 'magic should find something');
  assert.equal(matches[0].label, 'from-base64 → from-base64');
  assert.equal(encodeAs(matches[0].output, 'utf8'), 'Hello, world!');
});

test('Magic finds a single-byte XOR key when given a crib', async () => {
  const { magic } = await import('../src/index.js');
  const scrambled = new Uint8Array(Array.from(utf8Encode('the secret is here'), (b) => b ^ 0x5a));

  const matches = await magic(scrambled, { depth: 1, intensive: true, crib: 'secret' });
  assert.ok(matches.length > 0, 'crib search should find the key');
  assert.equal(encodeAs(matches[0].output, 'utf8'), 'the secret is here');
});

test('Ascii85 round-trips arbitrary bytes, including the z shortcut', async () => {
  const original = decodeAs('00000000deadbeef0102', 'hex');
  const encoded = await runRecipe(original, [{ op: 'to-base85' }]);
  const decoded = await runRecipe(encoded.output, [{ op: 'from-base85' }]);
  assert.equal(hexEncode(decoded.output), '00000000deadbeef0102');
  assert.match(encodeAs(encoded.output, 'utf8'), /^z/, 'a four-byte zero run should encode as z');
});

test('AES-GCM round-trips and rejects a tampered tag', async () => {
  const key = 'hex:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
  const iv = 'hex:000102030405060708090a0b';

  const encrypted = await runRecipe(utf8Encode('the eagle has landed'), [
    { op: 'aes-encrypt', args: { key, iv, mode: 'GCM', output: 'Hex' } },
  ]);
  assert.equal(encrypted.ok, true, encrypted.error ?? "");

  const decrypted = await runRecipe(encrypted.output, [{ op: 'aes-decrypt', args: { key, iv, mode: 'GCM', input: 'Hex' } }]);
  assert.equal(encodeAs(decrypted.output, 'utf8'), 'the eagle has landed');

  // Flip one bit of the ciphertext; GCM must refuse it.
  const tampered = encodeAs(encrypted.output, 'utf8').replace(/.$/, (c) => (c === '0' ? '1' : '0'));
  const failed = await runRecipe(utf8Encode(tampered), [{ op: 'aes-decrypt', args: { key, iv, mode: 'GCM', input: 'Hex' } }]);
  assert.equal(failed.ok, false);
});

test('AES-CBC matches a known NIST SP 800-38A vector', async () => {
  // F.2.1 CBC-AES128.Encrypt, first block.
  const result = await runRecipe(decodeAs('6bc1bee22e409f96e93d7e117393172a', 'hex'), [
    {
      op: 'aes-encrypt',
      args: { key: 'hex:2b7e151628aed2a6abf7158809cf4f3c', iv: 'hex:000102030405060708090a0b0c0d0e0f', mode: 'CBC', output: 'Hex' },
    },
  ]);
  assert.equal(result.ok, true, result.error ?? "");
  // WebCrypto always applies PKCS#7, so the first block is the vector and the
  // second is the padding block.
  assert.equal(encodeAs(result.output, 'utf8').slice(0, 32), '7649abac8119b246cee98e9b12e9197d');
});

test('TOTP — RFC 6238 vectors for SHA-1', async () => {
  // The RFC's seed is the ASCII string "12345678901234567890", Base32-encoded.
  const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
  assert.equal(await apply('generate-totp', secret, { at: 59, digits: 8 }), '94287082');
  assert.equal(await apply('generate-totp', secret, { at: 1111111109, digits: 8 }), '07081804');
  assert.equal(await apply('generate-totp', secret, { at: 2000000000, digits: 8 }), '69279037');
});

test('Gzip round-trips through the platform compression streams', async () => {
  const text = 'the quick brown fox '.repeat(50);
  const compressed = await runRecipe(utf8Encode(text), [{ op: 'gzip' }]);
  assert.equal(compressed.ok, true, compressed.error ?? "");
  assert.ok(compressed.output.length < text.length, 'gzip should shrink repetitive text');
  assert.equal(compressed.output[0], 0x1f);

  const restored = await runRecipe(compressed.output, [{ op: 'gunzip' }]);
  assert.equal(encodeAs(restored.output, 'utf8'), text);
});

test('a failing step reports its index and keeps the output so far', async () => {
  const result = await runRecipe(utf8Encode('hello'), [
    { op: 'to-base64' },
    { op: 'from-hex' },
    { op: 'to-base64' },
  ]);
  assert.equal(result.ok, false);
  assert.equal(result.failedAt, 1);
  assert.match(result.error!, /Step 2 \(from-hex\)/);
  assert.equal(encodeAs(result.output, 'utf8'), 'aGVsbG8=', 'output should be what step 1 produced');
});

test('disabled steps pass their input through untouched', async () => {
  const result = await runRecipe(utf8Encode('hello'), [
    { op: 'to-base64', disabled: true },
    { op: 'to-hex', args: { separator: 'None' } },
  ]);
  assert.equal(encodeAs(result.output, 'utf8'), '68656c6c6f');
  assert.equal(result.steps[0].skipped, true);
});
