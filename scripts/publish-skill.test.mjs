import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import {
  copyFile, mkdir, mkdtemp, readFile, rm, rmdir, symlink, writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const publisher = join(root, 'scripts', 'publish-skill.mjs');

async function run(command, args, options = {}) {
  try {
    const result = await execFileAsync(command, args, { encoding: 'utf8', ...options });
    return { code: 0, stderr: result.stderr, stdout: result.stdout };
  } catch (error) {
    return {
      code: typeof error.code === 'number' ? error.code : -1,
      stderr: error.stderr ?? '',
      stdout: error.stdout ?? '',
    };
  }
}

async function makeMissingTargetBin(directory) {
  const fakeGh = join(directory, 'gh');
  await writeFile(fakeGh, '#!/bin/sh\nexit 1\n', { encoding: 'utf8', mode: 0o700 });
  return { ...process.env, PATH: `${directory}:${process.env.PATH ?? ''}` };
}

async function makeExistingTargetBin(directory, targetRepo, options = {}) {
  const realGit = (await execFileAsync('which', ['git'], { encoding: 'utf8' })).stdout.trim();
  const gitLog = join(directory, 'git.log');
  const ghLog = join(directory, 'gh.log');
  const fakeGh = join(directory, 'gh');
  const fakeGit = join(directory, 'git');
  await writeFile(fakeGh, `#!/bin/sh
printf '%s\\n' "$*" >> "$PUBLISHER_GH_LOG"
if [ "$1" = "repo" ] && [ "$2" = "view" ]; then
  printf '{"name":"zest-skill"}\\n'
  exit 0
fi
if [ "$1" = "repo" ] && [ "$2" = "create" ]; then
  exit 97
fi
exit 98
`, { encoding: 'utf8', mode: 0o700 });
  await writeFile(fakeGit, `#!/bin/sh
printf '%s\\n' "$*" >> "$PUBLISHER_GIT_LOG"
if [ "$1" = "clone" ] && [ "$2" = "--quiet" ] && [ "$3" = "https://github.com/SEORY0/zest-skill.git" ]; then
  exec "$REAL_GIT" clone --quiet "$PUBLISHER_TARGET_REPO" "$4"
fi
if [ "$1" = "add" ] && [ "$2" = "-A" ] && [ -n "$PUBLISHER_CAPTURE_DIR" ]; then
  rm -rf "$PUBLISHER_CAPTURE_DIR"
  mkdir -p "$PUBLISHER_CAPTURE_DIR"
  cp -R . "$PUBLISHER_CAPTURE_DIR/repo"
fi
if [ "$1" = "commit" ] || [ "$1" = "push" ]; then
  if [ "$PUBLISHER_ALLOW_MUTATION" = "1" ]; then
    exit 0
  fi
  exit 96
fi
exec "$REAL_GIT" "$@"
`, { encoding: 'utf8', mode: 0o700 });
  return {
    env: {
      ...process.env,
      PATH: `${directory}:${process.env.PATH ?? ''}`,
      PUBLISHER_ALLOW_MUTATION: options.allowMutation ? '1' : '0',
      PUBLISHER_CAPTURE_DIR: options.captureDir ?? '',
      PUBLISHER_GH_LOG: ghLog,
      PUBLISHER_GIT_LOG: gitLog,
      PUBLISHER_TARGET_REPO: targetRepo,
      REAL_GIT: realGit,
    },
    ghLog,
    gitLog,
  };
}

async function createPublisherFixture() {
  const directory = await mkdtemp(join(tmpdir(), 'zest-publisher-fixture-'));
  await mkdir(join(directory, 'scripts'));
  await mkdir(join(directory, 'skills', 'demo', 'assets'), { recursive: true });
  await copyFile(publisher, join(directory, 'scripts', 'publish-skill.mjs'));
  await writeFile(
    join(directory, 'skills', 'demo', 'SKILL.md'),
    '---\nname: demo\ndescription: Fixture skill.\n---\n',
    'utf8',
  );
  await writeFile(join(directory, 'skills', 'demo', 'assets', 'resource.txt'), 'tracked resource\n', 'utf8');
  await execFileAsync('git', ['init', '--quiet'], { cwd: directory });
  await execFileAsync('git', ['config', 'user.name', 'Publisher Test'], { cwd: directory });
  await execFileAsync('git', ['config', 'user.email', 'publisher@example.invalid'], { cwd: directory });
  await execFileAsync('git', ['add', 'skills'], { cwd: directory });
  await execFileAsync('git', ['commit', '--quiet', '-m', 'fixture'], { cwd: directory });
  return directory;
}

async function createTargetRepo() {
  const directory = await mkdtemp(join(tmpdir(), 'zest-publisher-target-'));
  await execFileAsync('git', ['init', '--quiet'], { cwd: directory });
  await execFileAsync('git', ['config', 'user.name', 'Publisher Test'], { cwd: directory });
  await execFileAsync('git', ['config', 'user.email', 'publisher@example.invalid'], { cwd: directory });
  await writeFile(join(directory, 'README.md'), '# Old target\n', 'utf8');
  await execFileAsync('git', ['add', 'README.md'], { cwd: directory });
  await execFileAsync('git', ['commit', '--quiet', '-m', 'target'], { cwd: directory });
  return directory;
}

test('publisher help, missing mode, and unknown arguments never trigger publishing', async () => {
  // Given: a valid source fixture and a gh executable that leaves evidence if it is called.
  const directory = await createPublisherFixture();
  const fakeBin = await mkdtemp(join(tmpdir(), 'zest-publisher-argument-bin-'));
  const marker = join(fakeBin, 'gh-called');
  const fakeGh = join(fakeBin, 'gh');
  await writeFile(fakeGh, '#!/bin/sh\n: > "$PUBLISHER_GH_MARKER"\nexit 99\n', {
    encoding: 'utf8',
    mode: 0o700,
  });
  const env = {
    ...process.env,
    PATH: `${fakeBin}:${process.env.PATH ?? ''}`,
    PUBLISHER_GH_MARKER: marker,
  };

  try {
    // When: users request help or pass an unsupported option.
    const help = await run(process.execPath, [join(directory, 'scripts', 'publish-skill.mjs'), '--help'], {
      cwd: directory,
      env,
    });
    const shortHelp = await run(process.execPath, [join(directory, 'scripts', 'publish-skill.mjs'), '-h'], {
      cwd: directory,
      env,
    });
    const missing = await run(process.execPath, [join(directory, 'scripts', 'publish-skill.mjs')], {
      cwd: directory,
      env,
    });
    const unknown = await run(process.execPath, [join(directory, 'scripts', 'publish-skill.mjs'), '--unknown'], {
      cwd: directory,
      env,
    });
    const multiple = await run(
      process.execPath,
      [join(directory, 'scripts', 'publish-skill.mjs'), '--dry-run', '--publish'],
      { cwd: directory, env },
    );

    // Then: both paths terminate locally before any GitHub target operation.
    assert.equal(help.code, 0, help.stderr || help.stdout);
    assert.match(help.stdout, /^Usage: /);
    assert.equal(help.stderr, '');
    assert.equal(shortHelp.code, 0, shortHelp.stderr || shortHelp.stdout);
    assert.match(shortHelp.stdout, /^Usage: /);
    assert.equal(shortHelp.stderr, '');
    assert.equal(missing.code, 2);
    assert.equal(missing.stdout, '');
    assert.match(missing.stderr, /Unsupported arguments:/);
    assert.equal(unknown.code, 2);
    assert.equal(unknown.stdout, '');
    assert.match(unknown.stderr, /Unsupported arguments:/);
    assert.equal(multiple.code, 2);
    assert.equal(multiple.stdout, '');
    assert.match(multiple.stderr, /Unsupported arguments:/);
    assert.equal(existsSync(marker), false);
  } finally {
    await rm(directory, { force: true, recursive: true });
    await rm(fakeBin, { force: true, recursive: true });
  }
});

test('missing-target dry run publishes exactly tracked skill resources', async () => {
  // Given: tracked skill resources plus generated bytecode and another untracked file in the package tree.
  const fakeBin = await mkdtemp(join(tmpdir(), 'zest-publisher-bin-'));
  const cacheDirectory = join(root, 'skills', 'zest-crypto', 'assets', 'solver-templates', '__pycache__');
  const cacheDirectoryExisted = existsSync(cacheDirectory);
  const bytecode = join(cacheDirectory, `publisher-${process.pid}.pyc`);
  const unexpected = join(root, 'skills', 'zest-crypto', `publisher-${process.pid}.secret`);
  await mkdir(cacheDirectory, { recursive: true });
  await writeFile(bytecode, 'generated bytecode', 'utf8');
  await writeFile(unexpected, 'not a published resource', 'utf8');

  try {
    // When: a safely mocked missing-target dry run executes the real publisher.
    const env = await makeMissingTargetBin(fakeBin);
    const result = await run(process.execPath, [publisher, '--dry-run'], { cwd: root, env });
    const trackedResult = await execFileAsync('git', ['ls-files', '-z', '--', 'skills'], {
      cwd: root, encoding: 'utf8',
    });
    const tracked = trackedResult.stdout.split('\0').filter(Boolean).sort();
    const listed = result.stdout.split('\n').filter((line) => line.startsWith('  ')).map((line) => line.slice(2));

    // Then: every tracked resource and only tracked resources are enumerated without contacting GitHub.
    assert.equal(result.code, 0, result.stderr || result.stdout);
    assert.equal(result.stderr, '');
    assert.deepEqual(listed, ['README.md', '.gitignore', ...tracked]);
    assert.equal(listed.includes('skills/zest-crypto/assets/solver-templates/__pycache__/' + bytecode.split('/').at(-1)), false);
    assert.equal(listed.includes(`skills/zest-crypto/publisher-${process.pid}.secret`), false);
  } finally {
    await rm(bytecode, { force: true });
    await rm(unexpected, { force: true });
    if (!cacheDirectoryExisted) {
      try {
        await rmdir(cacheDirectory);
      } catch (error) {
        if (error.code !== 'ENOENT' && error.code !== 'ENOTEMPTY') throw error;
      }
    }
    await rm(fakeBin, { force: true, recursive: true });
  }
});

test('publisher dry run mirrors committed blobs, not dirty tracked worktree bytes or symlink swaps', async () => {
  // Given: a committed source snapshot, then dirty tracked bytes and a worktree symlink swap.
  const directory = await createPublisherFixture();
  const targetRepo = await createTargetRepo();
  const fakeBin = await mkdtemp(join(tmpdir(), 'zest-publisher-existing-bin-'));
  const captureDir = await mkdtemp(join(tmpdir(), 'zest-publisher-capture-'));
  const assets = join(directory, 'skills', 'demo', 'assets');
  const outside = join(directory, 'outside');

  try {
    await writeFile(
      join(directory, 'skills', 'demo', 'SKILL.md'),
      '---\nname: escaped\ndescription: Dirty skill.\n---\n',
      'utf8',
    );
    await rm(assets, { recursive: true });
    await mkdir(outside);
    await writeFile(join(outside, 'resource.txt'), 'outside replacement\n', 'utf8');
    await symlink('../../outside', assets, 'dir');
    const { env, ghLog, gitLog } = await makeExistingTargetBin(fakeBin, targetRepo, { captureDir });

    // When: dry-run builds the mirror checkout through the real publisher.
    const result = await run(
      process.execPath,
      [join(directory, 'scripts', 'publish-skill.mjs'), '--dry-run'],
      { cwd: directory, env },
    );

    // Then: captured mirror bytes come from immutable HEAD blobs, with no mutation commands.
    assert.equal(result.code, 0, result.stderr || result.stdout);
    assert.match(result.stdout, /Dry run/);
    assert.equal(
      await readFile(join(captureDir, 'repo', 'skills', 'demo', 'SKILL.md'), 'utf8'),
      '---\nname: demo\ndescription: Fixture skill.\n---\n',
    );
    assert.equal(
      await readFile(join(captureDir, 'repo', 'skills', 'demo', 'assets', 'resource.txt'), 'utf8'),
      'tracked resource\n',
    );
    assert.equal(readFileSync(ghLog, 'utf8').includes('repo create'), false);
    assert.equal(readFileSync(gitLog, 'utf8').includes('commit '), false);
    assert.equal(readFileSync(gitLog, 'utf8').includes('push '), false);
  } finally {
    await rm(directory, { force: true, recursive: true });
    await rm(targetRepo, { force: true, recursive: true });
    await rm(fakeBin, { force: true, recursive: true });
    await rm(captureDir, { force: true, recursive: true });
  }
});

test('publisher publish mode is the only mode that reaches commit and push', async () => {
  // Given: a valid source snapshot and isolated fake GitHub/Git mutation endpoints.
  const directory = await createPublisherFixture();
  const targetRepo = await createTargetRepo();
  const fakeBin = await mkdtemp(join(tmpdir(), 'zest-publisher-publish-bin-'));

  try {
    const { env, ghLog, gitLog } = await makeExistingTargetBin(fakeBin, targetRepo, { allowMutation: true });

    // When: the exact live publishing flag is used.
    const result = await run(
      process.execPath,
      [join(directory, 'scripts', 'publish-skill.mjs'), '--publish'],
      { cwd: directory, env },
    );

    // Then: the fake live path observes commit and push, but no repository create is needed.
    assert.equal(result.code, 0, result.stderr || result.stdout);
    assert.match(result.stdout, /Pushed to https:\/\/github\.com\/SEORY0\/zest-skill/);
    assert.match(readFileSync(gitLog, 'utf8'), /commit --quiet -m Sync skills from SEORY0\/zest@[0-9a-f]{40}\n/);
    assert.match(readFileSync(gitLog, 'utf8'), /push --quiet -u origin main\n/);
    assert.equal(readFileSync(ghLog, 'utf8').includes('repo create'), false);
  } finally {
    await rm(directory, { force: true, recursive: true });
    await rm(targetRepo, { force: true, recursive: true });
    await rm(fakeBin, { force: true, recursive: true });
  }
});

for (const scenario of [
  {
    name: 'symlink',
    expected: /Tracked skill entry has unsupported mode 120000: skills\/demo\/linked\.md/,
    prepare: async (directory) => {
      await symlink('SKILL.md', join(directory, 'skills', 'demo', 'linked.md'));
      await execFileAsync('git', ['add', 'skills/demo/linked.md'], { cwd: directory });
      await execFileAsync('git', ['commit', '--quiet', '-m', 'unsafe symlink'], { cwd: directory });
    },
  },
  {
    name: 'special gitlink',
    expected: /Tracked skill entry has unsupported mode 160000: skills\/demo\/nested-repo/,
    prepare: async (directory) => {
      const { stdout } = await execFileAsync('git', ['rev-parse', 'HEAD'], { cwd: directory, encoding: 'utf8' });
      await execFileAsync(
        'git',
        ['update-index', '--add', '--cacheinfo', `160000,${stdout.trim()},skills/demo/nested-repo`],
        { cwd: directory },
      );
      await execFileAsync('git', ['commit', '--quiet', '-m', 'unsafe gitlink'], { cwd: directory });
    },
  },
]) {
  test(`publisher rejects a tracked ${scenario.name} before publishing`, async () => {
    // Given: a temporary source repository whose manifest contains one unsafe tracked entry.
    const directory = await createPublisherFixture();
    const fakeBin = await mkdtemp(join(tmpdir(), 'zest-publisher-bin-'));
    try {
      await scenario.prepare(directory);
      const env = await makeMissingTargetBin(fakeBin);

      // When: the copied real publisher validates the source manifest.
      const result = await run(
        process.execPath,
        [join(directory, 'scripts', 'publish-skill.mjs'), '--dry-run'],
        { cwd: directory, env },
      );

      // Then: it fails deterministically before any target operation.
      assert.notEqual(result.code, 0);
      assert.equal(result.stdout, '');
      assert.match(result.stderr, scenario.expected);
    } finally {
      await rm(directory, { force: true, recursive: true });
      await rm(fakeBin, { force: true, recursive: true });
    }
  });
}
