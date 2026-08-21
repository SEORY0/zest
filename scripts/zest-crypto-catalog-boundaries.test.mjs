import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const schema = join(root, 'skills', 'zest-crypto', 'references', 'attack-card-schema.md');

function runPython(source, args) {
  return new Promise((resolve, reject) => {
    execFile('python3', ['-c', source, ...args], { cwd: root }, (error, stdout, stderr) => {
      if (error && typeof error.code !== 'number') {
        reject(error);
        return;
      }
      resolve({ code: error ? error.code : 0, stderr, stdout });
    });
  });
}

async function documentedCard() {
  const contents = await readFile(schema, 'utf8');
  const marker = contents.indexOf('The following complete card');
  assert.notEqual(marker, -1);
  const match = /```json\n([\s\S]*?)\n```/g;
  match.lastIndex = marker;
  const fenced = match.exec(contents);
  assert.notEqual(fenced, null);
  return JSON.parse(fenced[1])[0];
}

async function parseCatalog(cards) {
  const directory = await mkdtemp(join(tmpdir(), 'zest-crypto-source-boundary-'));
  const path = join(directory, 'catalog.json');
  await writeFile(path, JSON.stringify(cards), 'utf8');
  const source = [
    'import json, sys',
    "sys.path.insert(0, 'skills/zest-crypto/scripts')",
    'from zest_crypto_parse import parse_catalog',
    'from zest_crypto_types import ParseError',
    'try:',
    "  with open(sys.argv[1], encoding='utf-8') as handle:",
    '    parse_catalog(json.load(handle))',
    "  print(json.dumps({'ok': True}))",
    'except ParseError as error:',
    "  print(json.dumps({'ok': False, 'code': error.code, 'path': error.path}))",
  ].join('\n');
  try {
    const result = await runPython(source, [path]);
    assert.equal(result.code, 0, result.stderr);
    return JSON.parse(result.stdout);
  } finally {
    await rm(directory, { force: true, recursive: true });
  }
}

async function parseFingerprint(anchor) {
  const document = {
    schema_version: 1,
    case_id: 'source-anchor-boundary',
    inputs: [{ id: 'source', path: 'inputs/source.py', sha256: '0'.repeat(64), media_type: 'text/x-python' }],
    facts: [{
      id: 'anchor', key: 'construction.source_anchors', value: [anchor], value_type: 'string_list', status: 'observed',
      evidence: { input_id: 'source', locator: 'line 1' },
    }],
    capabilities: [],
    constraints: { network: 'disabled' },
  };
  const directory = await mkdtemp(join(tmpdir(), 'zest-crypto-anchor-boundary-'));
  const path = join(directory, 'fingerprint.json');
  await writeFile(path, JSON.stringify(document), 'utf8');
  const source = [
    'import json, sys',
    "sys.path.insert(0, 'skills/zest-crypto/scripts')",
    'from zest_crypto_parse import parse_fingerprint',
    'from zest_crypto_types import ParseError',
    'try:',
    "  with open(sys.argv[1], encoding='utf-8') as handle:",
    '    parse_fingerprint(json.load(handle))',
    "  print(json.dumps({'ok': True}))",
    'except ParseError as error:',
    "  print(json.dumps({'ok': False, 'code': error.code, 'path': error.path}))",
  ].join('\n');
  try {
    const result = await runPython(source, [path]);
    assert.equal(result.code, 0, result.stderr);
    return JSON.parse(result.stdout);
  } finally {
    await rm(directory, { force: true, recursive: true });
  }
}

test('catalog rejects malformed and noncanonical citation HTTPS URLs', async () => {
  const invalidUrls = [
    'https://',
    'https://user@example.com/paper.pdf',
    'https://github.com%2f..%2fevil',
    'https://example.com/%2e%2e/%2f',
    'https://example.com/path\u0001',
    'https://example.com\\@evil.example/paper.pdf',
    'https://example.com:bad/paper.pdf',
    'https://example..com/paper.pdf',
    'https://example.com/raw space.pdf',
    'https://example.com//paper.pdf',
    'https://example.com/%70aper.pdf',
    'https://example.com/paper%00.pdf',
    'https://example.com/paper.pdf?download=1',
    'https://example.com/paper.pdf#section',
    'HTTPS://EXAMPLE.COM/paper.pdf',
  ];
  for (const url of invalidUrls) {
    const card = await documentedCard();
    card.citations[0].url = url;
    const result = await parseCatalog([card]);
    assert.deepEqual(result, { ok: false, code: 'invalid-citation-url', path: '$[0].citations[0].url' }, url);
  }
});

test('catalog rejects malformed and noncanonical remote repository URLs', async () => {
  const invalidUrls = [
    'https://',
    'https://user@github.com/example/zest',
    'https://github.com%2f..%2fevil',
    'https://github.com/example/%2e%2e/zest',
    'https://github.com/example//zest',
    'https://github.com/example/zest/',
    'https://github.com/example/raw space',
    'https://github.com/example/zest?ref=main',
    'https://github.com/example/zest#main',
  ];
  for (const repoUrl of invalidUrls) {
    const card = await documentedCard();
    card.examples[0].repo_url = repoUrl;
    const result = await parseCatalog([card]);
    assert.deepEqual(result, { ok: false, code: 'invalid-repository-url', path: '$[0].examples[0].repo_url' }, repoUrl);
  }
});

test('catalog parses distinct canonical remote and local package examples', async () => {
  const remote = await documentedCard();
  remote.examples[0] = {
    challenge_id: 'remote-example', event: 'Remote Example', year: 2026, source_kind: 'remote',
    repo_url: 'https://github.com/example/zest', repo_sha: 'a'.repeat(40),
    source_path: 'challenge/source.py', source_lines: 'L10-L20', inference_level: 'direct',
  };
  const local = await documentedCard();
  local.id = 'rsa.hastad.local-example';
  local.examples[0] = {
    challenge_id: 'local-template', event: 'Zest crypto package', year: 2026, source_kind: 'local',
    repo_url: null, repo_sha: null, source_path: 'assets/solver-templates/rsa_hastad.py',
    source_lines: 'L1-L20', inference_level: 'direct',
  };
  assert.deepEqual(await parseCatalog([remote, local]), { ok: true });
});

test('catalog rejects ambiguous remote/local source forms and noncanonical ranges', async () => {
  for (const sourceLines of ['complete source', 'L0-L2', 'L02-L3', 'L3-L2', 'L1-L2,L4-L5']) {
    const card = await documentedCard();
    card.examples[0].source_kind = 'remote';
    card.examples[0].source_lines = sourceLines;
    const result = await parseCatalog([card]);
    assert.deepEqual(result, { ok: false, code: 'invalid-source-lines', path: '$[0].examples[0].source_lines' }, sourceLines);
  }
  const local = await documentedCard();
  local.examples[0].source_kind = 'local';
  const result = await parseCatalog([local]);
  assert.deepEqual(result, { ok: false, code: 'invalid-local-example', path: '$[0].examples[0].repo_url' });
});

test('direct fingerprint parsing enforces canonical immutable source anchors', async () => {
  const valid = 'github.com/maple3142/My-CTF-Challenges@7b3e786a2c20812f4da23536c7817bdfe8113dd6/HITCON%20CTF%202024/ECLCG/dist/chall.py:L25-L64';
  assert.deepEqual(await parseFingerprint(valid), { ok: true });
  for (const invalid of [
    'repo@' + 'a'.repeat(40) + '/source.py:L1-L2',
    'github.com/example/zest@' + 'a'.repeat(40) + '/../source.py:L1-L2',
    'github.com/example/zest@' + 'a'.repeat(40) + '/%2e%2e/source.py:L1-L2',
    'github.com/example/zest@' + 'a'.repeat(40) + '/path%2Fsource.py:L1-L2',
    'github.com/example/zest@' + 'a'.repeat(40) + '//source.py:L1-L2',
    'github.com/example/zest@' + 'a'.repeat(40) + '/raw source.py:L1-L2',
    'github.com/example/zest@' + 'a'.repeat(40) + '/source%00.py:L1-L2',
    'github.com/example/zest@' + 'a'.repeat(40) + '/source.py:L02-L3',
  ]) {
    const result = await parseFingerprint(invalid);
    assert.deepEqual(result, { ok: false, code: 'invalid-source-anchor', path: '$.facts[0].value[0]' }, invalid);
  }
});
