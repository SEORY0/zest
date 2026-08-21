import { useState } from 'react';
import { CATEGORIES, listOperations, operationsByCategory } from '@zest/core';

const REPO_URL = 'https://github.com/SEORY0/zest';
const SKILL_REPO = 'SEORY0/zest-skill';
const INSTALL_COMMAND = `npx skills add ${SKILL_REPO}`;

const RECIPES: { task: string; command: string }[] = [
  { task: 'Decode an unknown blob', command: 'cat blob.txt | zest magic:depth=3' },
  { task: 'Find a CTF flag', command: "zest -f challenge.txt magic:depth=4,crib='flag{',intensive=true" },
  { task: 'Inspect a bearer token', command: 'zest -i "$TOKEN" jwt-decode' },
  { task: 'Verify a webhook signature', command: 'zest -f body.json hmac:key=env:SIGNING_SECRET' },
  { task: 'Pull indicators from a log', command: 'zest -f mail.eml extract-indicators' },
  { task: 'Triage a suspicious file', command: 'zest -f sample.bin detect-file-type entropy' },
  { task: 'Recover a XOR-obfuscated string', command: 'zest -i "$HEX" xor-brute-force:crib=http' },
  { task: 'Decrypt captured ciphertext', command: 'zest -f ct.hex aes-decrypt:key=env:AES_KEY,iv=env:AES_IV,mode=GCM,input=Hex' },
  { task: 'Read a Windows event timestamp', command: 'zest -i 133445222400000000 filetime-to-date' },
];

export function SkillPage(): JSX.Element {
  const [copied, setCopied] = useState(false);
  const operations = listOperations();
  const grouped = operationsByCategory();

  const copy = async (): Promise<void> => {
    await navigator.clipboard.writeText(INSTALL_COMMAND);
    setCopied(true);
    setTimeout(() => setCopied(false), 1400);
  };

  return (
    <main className="page">
      <div className="page-hero">
        <div className="eyebrow">Agent skill</div>
        <h1 className="page-title">Give your agent a security workbench.</h1>
        <p className="page-lede">
          The skill teaches an agent to reach for <code>zest</code> instead of writing throwaway Python for every decode,
          hash and cipher. {operations.length} operations, one binary, no network calls — so an agent can work on a
          token, a capture or a malware sample without sending any of it anywhere.
        </p>

        <div className="stat-row">
          <div>
            <div className="stat-value">{operations.length}</div>
            <div className="stat-label">operations</div>
          </div>
          <div>
            <div className="stat-value">{CATEGORIES.filter((c) => grouped.has(c)).length}</div>
            <div className="stat-label">categories</div>
          </div>
          <div>
            <div className="stat-value">0</div>
            <div className="stat-label">network calls</div>
          </div>
        </div>
      </div>

      <section className="section">
        <h2 className="section-title">Install</h2>
        <div className="command">
          <span className="command-prompt">$</span>
          <span className="command-text">{INSTALL_COMMAND}</span>
          <button type="button" className="button is-quiet" onClick={() => void copy()}>
            {copied ? 'Copied' : 'Copy'}
          </button>
        </div>
        <p style={{ marginTop: '0.75rem' }}>
          That installs four skills: <code>zest</code> for everyday encoding and crypto work, <code>zest-ctf</code> for
          byte and encoding puzzles, <code>zest-crypto</code> for math-heavy, paper-derived RSA, ECC, lattice,
          signature, PRNG and oracle work, and <code>zest-triage</code> for working through an unknown file. It writes to
          whichever agents it finds, so Claude Code, Codex, Gemini CLI and the rest all pick them up. For just the
          mathematical cryptanalysis workflow, use <code>npx skills add {SKILL_REPO} --skill zest-crypto</code>. It solves
          supported families, researches exact sources when authorized, and reports blocked or unsupported cases rather
          than claiming every construction is solvable.
        </p>
        <p>
          The skills drive the <code>zest</code> CLI, so install that as well. It needs Node 20 or newer:
        </p>
        <pre className="code-block">
{`git clone ${REPO_URL}.git
cd zest
npm install
npm run build
npm link -w @zest/cli`}
        </pre>
        <p style={{ marginTop: '0.75rem' }}>
          Zest CLI and browser byte processing stay local by default, so no data leaves them. <code>zest-crypto</code>{' '}
          may make outbound paper, challenge or oracle requests only when the user or case explicitly authorizes network
          access; it never does so automatically. No API key is needed for local processing. All four skills are listed on{' '}
          <a href={`https://www.skills.sh/${SKILL_REPO}`} target="_blank" rel="noreferrer noopener">
            skills.sh
          </a>
          .
        </p>
      </section>

      <section className="section">
        <h2 className="section-title">How the agent uses it</h2>
        <p>
          Operations chain left to right, each one taking the previous step&rsquo;s bytes. The agent discovers what is
          available with <code>zest ops</code>, reads an operation&rsquo;s arguments with <code>zest op &lt;id&gt;</code>,
          and adds <code>--json</code> when it wants a structured result rather than text.
        </p>
        <pre className="code-block">
{`$ zest ops jwt
jwt-decode  Splits a JSON Web Token and decodes its header and payload.
jwt-verify  Checks an HS256/384/512 signature against a shared secret.

$ echo 'SGVsbG8sIHdvcmxkIQ==' | zest from-base64
Hello, world!

$ zest -i 'hello' md5 --json
{
  "ok": true,
  "output": "5d41402abc4b2a76b9719d911017c592",
  "outputEncoding": "utf8",
  "outputBytes": 32,
  "steps": [{ "index": 0, "op": "md5", "ok": true, "durationMs": 0.39 }]
}`}
        </pre>
      </section>

      <section className="section">
        <h2 className="section-title">Start here when you do not know what you are holding</h2>
        <p>
          <code>magic</code> ranks a bounded set of decoders and simple transforms whose input shape fits, scores what
          comes back by printability, entropy and format signatures, and recurses. A known flag prefix can be supplied
          as a crib; no result is not proof that the input is plaintext or encrypted.
        </p>
        <pre className="code-block">
{`$ echo 'U0dWc2JHOHNJSGR2Y214a0lRPT0=' | zest magic:depth=2
 1. from-base64 → from-base64
    score 35  (fully printable ASCII, entropy fell 0.74 bits)
    Hello, world!

 2. from-base64
    score 25  (fully printable ASCII)
    SGVsbG8sIHdvcmxkIQ==`}
        </pre>
      </section>

      <section className="section">
        <h2 className="section-title">Secrets stay out of the command line</h2>
        <p>
          A key written into an argument is readable by any process through <code>ps</code> and is saved to shell
          history — and an agent that follows such an example writes the secret verbatim into its own transcript. Keys
          are read indirectly instead, so the value never enters <code>argv</code>.
        </p>
        <pre className="code-block">
{`zest hmac:key=env:SIGNING_SECRET,algorithm=SHA-256
zest aes-decrypt:key=file:/run/secrets/aes.key,iv=env:NONCE,mode=GCM,input=Hex
zest --input-env SESSION_TOKEN jwt-decode`}
        </pre>
        <p style={{ marginTop: '0.75rem' }}>
          The resolved value keeps any encoding prefix it carries, so a variable holding <code>hex:00112233</code> is
          still read as hex.
        </p>
      </section>

      <section className="section">
        <h2 className="section-title">Common tasks</h2>
        <table className="table">
          <thead>
            <tr>
              <th style={{ width: '40%' }}>Task</th>
              <th>Command</th>
            </tr>
          </thead>
          <tbody>
            {RECIPES.map((recipe) => (
              <tr key={recipe.task}>
                <td style={{ fontFamily: 'var(--font-sans)', fontSize: '0.8125rem' }}>{recipe.task}</td>
                <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem' }}>{recipe.command}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section className="section">
        <h2 className="section-title">What is in the box</h2>
        <div className="grid-2">
          {CATEGORIES.filter((category) => grouped.has(category)).map((category) => (
            <div className="tile" key={category}>
              <h3 className="tile-title">
                {category} <span className="muted">· {grouped.get(category)!.length}</span>
              </h3>
              <p className="tile-body">
                {grouped
                  .get(category)!
                  .slice(0, 6)
                  .map((operation) => operation.name)
                  .join(', ')}
                {grouped.get(category)!.length > 6 ? '…' : ''}
              </p>
            </div>
          ))}
        </div>
      </section>

      <section className="section">
        <h2 className="section-title">What it will not do</h2>
        <p>
          Zest transforms data you already have. It does not fetch URLs, scan hosts, look anything up in a threat feed or
          call a model. When an operation is a toy — ROT, Vigenère, RC4 — the description says so, so an agent does not
          reach for it as if it were security.
        </p>
      </section>
    </main>
  );
}
