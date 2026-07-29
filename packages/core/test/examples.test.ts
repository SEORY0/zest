/**
 * Runs every example declared on every operation.
 *
 * Examples are documentation first — they appear in the UI, in `zest op` and
 * in the agent skill — so testing them keeps the docs honest by construction.
 */

import assert from 'node:assert/strict';
import test from 'node:test';

import { decodeAs, encodeAs, listOperations, runRecipe, withDefaults } from '../src/index.js';

for (const operation of listOperations()) {
  if (!operation.examples?.length) continue;

  test(`${operation.id} examples`, async (t) => {
    for (const [index, example] of operation.examples!.entries()) {
      const label = example.name ?? `example ${index + 1}`;

      await t.test(label, async () => {
        const input = decodeAs(example.input, example.inputEncoding ?? 'utf8');
        const result = await runRecipe(input, [{ op: operation.id, args: example.args }]);

        assert.equal(result.ok, true, `run failed: ${result.error ?? ""}`);
        assert.equal(encodeAs(result.output, example.outputEncoding ?? 'utf8'), example.output);
      });
    }
  });
}

test('every operation declares the metadata the UI and CLI rely on', () => {
  const seen = new Set<string>();

  for (const operation of listOperations()) {
    assert.match(operation.id, /^[a-z0-9-]+$/, `${operation.id} must be kebab-case`);
    assert.equal(seen.has(operation.id), false, `duplicate id ${operation.id}`);
    seen.add(operation.id);

    assert.ok(operation.name.length > 0, `${operation.id} needs a name`);
    assert.ok(operation.description.length > 20, `${operation.id} needs a real description`);

    // Defaults must be complete: the UI renders an op with no arguments supplied.
    const defaults = withDefaults(operation.args, {});
    for (const arg of operation.args ?? []) {
      assert.notEqual(defaults[arg.name], undefined, `${operation.id}.${arg.name} has no default`);
      assert.match(arg.name, /^[a-zA-Z][a-zA-Z0-9]*$/, `${operation.id}.${arg.name} must be a plain identifier`);
    }
  }
});

test('every operation runs on empty input without crashing the process', async () => {
  for (const operation of listOperations()) {
    const result = await runRecipe(new Uint8Array(0), [{ op: operation.id }]);
    // Failing is fine — throwing something that is not an Error is not.
    if (!result.ok) assert.equal(typeof result.error, 'string');
  }
});
