import { listOperations, operationsByCategory, CATEGORIES } from '@zest/core';

import {
  ByteFacesFigure,
  ByteFieldFigure,
  EncodingSizeFigure,
  EntropyFigure,
  PipelineFigure,
} from '../components/figures.js';

export function AboutPage(): JSX.Element {
  const operations = listOperations();
  const grouped = operationsByCategory();

  return (
    <main className="page">
      <div className="page-hero">
        <div className="eyebrow">About</div>
        <h1 className="page-title">Everything is bytes. The rest is a point of view.</h1>
        <p className="page-lede">
          Zest is a workbench for the moment you are holding data and do not yet know what it is. It chains{' '}
          {operations.length} operations into a recipe — decode, decrypt, decompress, measure — and runs the whole thing
          on your own machine.
        </p>
      </div>

      <section className="section">
        <h2 className="section-title">A file has a texture</h2>
        <p>
          Before any decoding, a file already tells you something. Draw each byte as a cell, dark for a high value, and
          the regions separate themselves: fixed headers, readable text, and the flat noise of something encrypted.
        </p>
        <ByteFieldFigure />
      </section>

      <section className="section">
        <h2 className="section-title">One byte, several faces</h2>
        <p>
          A byte has no native representation. <code>74</code>, <code>4a</code>, <code>0b01001010</code> and{' '}
          <code>J</code> are the same eight bits under different conventions — and almost every &ldquo;encoding
          bug&rdquo; is really a disagreement about which convention was in force.
        </p>
        <ByteFacesFigure />
      </section>

      <section className="section">
        <h2 className="section-title">Encodings are not free</h2>
        <p>
          Turning bytes into text that survives a URL, an email header or a JSON string always costs space, because
          fewer symbols have to carry the same information. How much depends on the alphabet.
        </p>
        <EncodingSizeFigure />
      </section>

      <section className="section">
        <h2 className="section-title">Entropy answers the first question</h2>
        <p>
          Faced with an unfamiliar blob, the useful question is not &ldquo;what is this&rdquo; but &ldquo;is there
          structure left to find&rdquo;. Entropy answers it in one number, and it costs a single pass over the bytes.
        </p>
        <EntropyFigure />
      </section>

      <section className="section">
        <h2 className="section-title">Operations chain</h2>
        <p>
          Real data is wrapped more than once. Base64 around gzip around JSON is the ordinary shape of a compressed API
          response, and unwrapping it is three steps, not one clever regular expression.
        </p>
        <PipelineFigure />
        <p>
          When you do not know the chain, <code>magic</code> searches for it: it tries every decoder whose input shape
          fits, scores the results by printability, entropy change and format signatures, and recurses.
        </p>
      </section>

      <section className="section">
        <h2 className="section-title">Why it runs locally</h2>
        <p>
          The data you most want to inspect is the data you least want to paste into someone else&rsquo;s website — a
          session token, a customer export, a sample from a compromised host. So Zest has no backend. The browser app is
          static files, the CLI opens no sockets, and no operation takes a URL.
        </p>
        <p>
          That is a design constraint, not a promise about your network. It is also why there is no &ldquo;look this
          hash up&rdquo; button: that would be the one operation that leaks.
        </p>
      </section>

      <section className="section">
        <h2 className="section-title">How correctness is kept</h2>
        <p>
          Ciphers go through the platform&rsquo;s WebCrypto rather than a hand-rolled implementation, because
          reimplementing a block cipher is exactly the thing a tool like this should not do. What WebCrypto does not
          offer is implemented here and checked against the document that defines it.
        </p>

        <table className="table">
          <thead>
            <tr>
              <th style={{ width: '38%' }}>Implemented here</th>
              <th>Checked against</th>
            </tr>
          </thead>
          <tbody>
            <tr><td>MD5</td><td>RFC 1321, appendix A.5</td></tr>
            <tr><td>HMAC-MD5</td><td>RFC 2202</td></tr>
            <tr><td>SHA-3, Keccak</td><td>FIPS 202</td></tr>
            <tr><td>CRC-32, Adler-32</td><td>CRC catalogue check values</td></tr>
            <tr><td>Base32, Base64</td><td>RFC 4648</td></tr>
            <tr><td>Base58</td><td>Bitcoin address vector</td></tr>
            <tr><td>Ascii85</td><td>Round-trip against Python&rsquo;s <code>base64</code></td></tr>
            <tr><td>TOTP</td><td>RFC 6238</td></tr>
            <tr><td>AES-CBC via WebCrypto</td><td>NIST SP 800-38A</td></tr>
          </tbody>
        </table>

        <p style={{ marginTop: '1rem' }}>
          Beyond that, every operation carries worked examples, and those examples <em>are</em> the test suite. The
          documentation cannot drift from the behaviour, because a stale example fails the build.
        </p>

        <div className="stat-row">
          <div>
            <div className="stat-value">{operations.length}</div>
            <div className="stat-label">operations</div>
          </div>
          <div>
            <div className="stat-value">217</div>
            <div className="stat-label">tests</div>
          </div>
          <div>
            <div className="stat-value">{CATEGORIES.filter((c) => grouped.has(c)).length}</div>
            <div className="stat-label">categories</div>
          </div>
          <div>
            <div className="stat-value">0</div>
            <div className="stat-label">runtime dependencies</div>
          </div>
        </div>
      </section>

      <section className="section">
        <h2 className="section-title">What it will not do</h2>
        <p>
          Zest transforms data you already have. It does not fetch URLs, scan hosts, query a threat feed or call a model.
          Where an operation is a toy rather than security — ROT, Vigenère, RC4, MD5 — its own description says so, so
          neither a person nor an agent reaches for it by mistake.
        </p>
      </section>

      <section className="section">
        <h2 className="section-title">Colophon</h2>
        <p>
          The interface borrows its design system from{' '}
          <a href="https://oklch.fyi" target="_blank" rel="noreferrer noopener">
            oklch.fyi
          </a>
          : a twelve-step grey ramp, surfaces raised by a hairline ring and a soft shadow instead of a border, and a
          strict split between sans for the interface and mono for data. Figures on this page are drawn from values
          measured by the engine as the page loads, not from stored images.
        </p>
        <p>
          Source at{' '}
          <a href="https://github.com/SEORY0/zest" target="_blank" rel="noreferrer noopener">
            github.com/SEORY0/zest
          </a>
          . MIT licensed.
        </p>
      </section>
    </main>
  );
}
