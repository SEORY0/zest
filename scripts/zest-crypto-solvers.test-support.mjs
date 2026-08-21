import assert from 'node:assert/strict';
import { execFile, spawnSync } from 'node:child_process';
import { mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

const execFileAsync = promisify(execFile);
export const root = join(dirname(fileURLToPath(import.meta.url)), '..');
export const templates = join(root, 'skills', 'zest-crypto', 'assets', 'solver-templates');
export const fixtures = join(root, 'scripts', 'fixtures', 'zest-crypto', 'solvers');
export const python = process.env.PYTHON ?? 'python3';
const sageProbeTimeoutMs = 500;
export const sageAvailable = spawnSync('sage', ['--version'], {
  stdio: 'ignore', timeout: sageProbeTimeoutMs, killSignal: 'SIGKILL',
}).status === 0;

export async function run(command, args) {
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

export function parseSuccess(result) {
  assert.equal(result.code, 0, result.stderr || result.stdout);
  assert.equal(result.stderr, '');
  assert.equal(result.stdout.endsWith('\n'), true);
  const document = JSON.parse(result.stdout);
  assert.equal(document.verified, true);
  return document;
}

export function assertFailure(result, code) {
  assert.notEqual(result.code, 0);
  assert.equal(result.stderr, '');
  const document = JSON.parse(result.stdout);
  assert.deepEqual(document, { error: { code }, verified: false });
  assert.equal(result.stdout.includes('Traceback'), false);
}

export function registerReaderTests(test, jsonScripts) {
  test('all eight readers reject symlinks and special files without blocking', async () => {
    const temporary = await mkdtemp(join(tmpdir(), 'zest-crypto-readers-'));
    const link = join(temporary, 'linked-input');
    const fifo = join(temporary, 'input.fifo');
    await symlink(join(fixtures, 'rsa-wiener.json'), link);
    assert.equal((await run('mkfifo', [fifo])).code, 0);
    const scripts = [...jsonScripts, 'lfsr_known_plaintext.py'];
    const argsFor = (script, input) => script === 'lfsr_known_plaintext.py'
      ? [join(templates, script), input, join(fixtures, 'lfsr-known-prefix.hex'), '0'.repeat(64), '8', '65536', '5000000']
      : [join(templates, script), input];
    try {
      for (const input of [link, '/dev/null', fifo]) {
        const results = await Promise.all(scripts.map((script) => run(
          'timeout', ['--signal=KILL', '2s', python, ...argsFor(script, input)],
        )));
        results.forEach((result) => assertFailure(result, 'input-unreadable'));
      }
    } finally {
      await rm(temporary, { force: true, recursive: true });
    }
  });

  test('all eight readers enforce their byte limit on a regular file', async () => {
    const temporary = await mkdtemp(join(tmpdir(), 'zest-crypto-readers-'));
    const jsonInput = join(temporary, 'large.json');
    const hexInput = join(temporary, 'large.hex');
    await writeFile(jsonInput, ' '.repeat(1_000_001), 'ascii');
    await writeFile(hexInput, '0'.repeat(2_000_001), 'ascii');
    try {
      const jsonResults = await Promise.all(jsonScripts.map((script) => run(python, [join(templates, script), jsonInput])));
      const lfsr = await run(python, [join(templates, 'lfsr_known_plaintext.py'), hexInput,
        join(fixtures, 'lfsr-known-prefix.hex'), '0'.repeat(64), '8', '65536', '5000000']);
      jsonResults.forEach((result) => assertFailure(result, 'input-too-large'));
      assertFailure(lfsr, 'input-too-large');
    } finally {
      await rm(temporary, { force: true, recursive: true });
    }
  });
}
