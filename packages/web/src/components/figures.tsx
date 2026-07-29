/**
 * Figures for the About page.
 *
 * Every number here is measured at render time by the same engine the
 * workbench uses — nothing is a hard-coded illustration. If an operation
 * changes, the diagrams change with it.
 *
 * Colour follows one rule: grey carries the magnitude, and a single blue
 * marks the one datum the surrounding prose is talking about. Every mark is
 * directly labelled, so identity never rests on colour alone.
 */

import { useEffect, useMemo, useState } from 'react';
import { base64Encode, hexEncode, runRecipe, shannonEntropy, utf8Encode, type Bytes } from '@zest/core';

const HIGHLIGHT = 'var(--blue)';

/**
 * A deterministic byte source, so the page renders identically every visit.
 *
 * Takes bits 16–23 rather than the low byte: the low bits of a linear
 * congruential generator cycle with a very short period, which would show up
 * here as an implausibly perfect entropy reading.
 */
function lcg(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state * 1664525 + 1013904223) >>> 0;
    return (state >>> 16) & 0xff;
  };
}

// --- Figure 1: what a file looks like ---------------------------------------

interface Region {
  label: string;
  bytes: number[];
  note: string;
}

/**
 * Regions are sized so their entropy figures mean something: a run of N bytes
 * cannot measure above log2(N), so a 96-byte sample of encrypted data would
 * report 6.58 no matter how random it truly was.
 */
function buildSampleFile(): Region[] {
  const random = lcg(20260730);
  const text =
    'GET /admin HTTP/1.1 Host: internal.test Authorization: Bearer eyJhbGci ' +
    'User-Agent: curl/8.4.0 Accept: */* Connection: keep-alive Cookie: sid=';

  return [
    {
      label: 'header',
      note: 'Fixed magic bytes and padding. A signature, so the format is knowable without the filename.',
      bytes: [...[0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], ...Array<number>(56).fill(0x00)],
    },
    {
      label: 'text',
      note: 'Readable ASCII, clustered in a narrow band of values. Visible as an even mid tone.',
      bytes: Array.from(text.slice(0, 128), (c) => c.charCodeAt(0)),
    },
    {
      label: 'encrypted',
      note: 'Every value equally likely, so no pattern survives. This is what the ceiling looks like.',
      bytes: Array.from({ length: 320 }, () => random()),
    },
  ];
}

export function ByteFieldFigure(): JSX.Element {
  const regions = useMemo(buildSampleFile, []);
  const [hovered, setHovered] = useState<number | null>(null);

  const columns = 32;
  const cell = 11;
  const gap = 2;
  const all = regions.flatMap((region, index) => region.bytes.map((byte) => ({ byte, region: index })));
  const rows = Math.ceil(all.length / columns);

  return (
    <figure className="figure">
      <div className="figure-body">
        <svg
          viewBox={`0 0 ${columns * (cell + gap)} ${rows * (cell + gap)}`}
          className="figure-svg"
          role="img"
          aria-label="A byte field: a fixed header, a readable text region, then an encrypted region where every byte value is equally likely."
        >
          {all.map((item, index) => {
            const x = (index % columns) * (cell + gap);
            const y = Math.floor(index / columns) * (cell + gap);
            // Value is carried by ink density against the surface, not by a
            // fixed light-to-dark ramp — otherwise the field would invert in
            // dark mode and low bytes would become the most prominent.
            const ink = 0.08 + (item.byte / 255) * 0.92;
            const dimmed = hovered !== null && hovered !== item.region;

            return (
              <rect
                key={index}
                x={x}
                y={y}
                width={cell}
                height={cell}
                rx={2.5}
                fill="currentColor"
                opacity={dimmed ? ink * 0.16 : ink}
                style={{ transition: 'opacity 140ms ease' }}
              />
            );
          })}
        </svg>

        <div className="figure-legend">
          {regions.map((region, index) => (
            <button
              key={region.label}
              type="button"
              className={`legend-item${hovered === index ? ' is-active' : ''}`}
              onMouseEnter={() => setHovered(index)}
              onMouseLeave={() => setHovered(null)}
              onFocus={() => setHovered(index)}
              onBlur={() => setHovered(null)}
            >
              <span className="legend-label">{region.label}</span>
              <span className="legend-note">{region.note}</span>
              <span className="legend-value">
                {shannonEntropy(Uint8Array.from(region.bytes) as Bytes).toFixed(2)} bits/byte
              </span>
            </button>
          ))}
        </div>
      </div>
      <figcaption className="figure-caption">
        One file, three regions. You can see the difference before decoding anything — which is why the first question
        in triage is what the bytes look like, not what the extension says.
      </figcaption>
    </figure>
  );
}

// --- Figure 2: one byte, many representations -------------------------------

const BYTE = 0x4a;

export function ByteFacesFigure(): JSX.Element {
  const faces: { label: string; value: string; wide?: boolean }[] = [
    { label: 'character', value: String.fromCharCode(BYTE) },
    { label: 'hex', value: BYTE.toString(16).padStart(2, '0') },
    { label: 'decimal', value: String(BYTE) },
    { label: 'octal', value: BYTE.toString(8) },
    { label: 'binary', value: BYTE.toString(2).padStart(8, '0'), wide: true },
  ];

  return (
    <figure className="figure">
      <div className="figure-body">
        <div className="faces">
          {faces.map((face) => (
            <div className="face" key={face.label}>
              <div className={`face-value${face.wide ? ' is-wide' : ''}`}>{face.value}</div>
              <div className="face-label">{face.label}</div>
            </div>
          ))}
        </div>

        <div className="bits">
          {Array.from({ length: 8 }, (_, i) => {
            const on = (BYTE >> (7 - i)) & 1;
            return (
              <div className={`bit${on ? ' is-on' : ''}`} key={i}>
                {on}
              </div>
            );
          })}
        </div>
      </div>
      <figcaption className="figure-caption">
        Every one of these is the same byte. An encoding tool does not change data — it changes which of these faces you
        are looking at, and the whole job is knowing which one you have.
      </figcaption>
    </figure>
  );
}

// --- Figure 3: what encodings cost ------------------------------------------

interface SizeRow {
  label: string;
  op: string;
  bytes: number;
  ratio: number;
  sample: string;
  highlight?: boolean;
}

const SIZE_SAMPLE = 'The quick brown fox jumps over the lazy dog, twice over.';

export function EncodingSizeFigure(): JSX.Element {
  const [rows, setRows] = useState<SizeRow[]>([]);

  useEffect(() => {
    const source = utf8Encode(SIZE_SAMPLE);

    const measure = async (): Promise<void> => {
      const codecs: { label: string; op: string; args?: Record<string, unknown> }[] = [
        { label: 'raw bytes', op: '' },
        { label: 'Ascii85', op: 'to-base85' },
        { label: 'Base64', op: 'to-base64' },
        { label: 'Base32', op: 'to-base32' },
        { label: 'hex', op: 'to-hex', args: { separator: 'None' } },
      ];

      const measured: SizeRow[] = [];
      for (const codec of codecs) {
        const output = codec.op
          ? (await runRecipe(source, [{ op: codec.op, args: codec.args as never }])).output
          : source;
        measured.push({
          label: codec.label,
          op: codec.op,
          bytes: output.length,
          ratio: output.length / source.length,
          sample: new TextDecoder().decode(output.subarray(0, 22)),
          highlight: codec.label === 'Base64',
        });
      }
      setRows(measured);
    };

    void measure();
  }, []);

  const max = Math.max(1, ...rows.map((row) => row.bytes));

  return (
    <figure className="figure">
      <div className="figure-body">
        <div className="bars">
          {rows.map((row) => (
            <div className="bar-row" key={row.label}>
              <div className="bar-label">{row.label}</div>
              <div className="bar-track">
                <div
                  className="bar-fill"
                  style={{
                    width: `${(row.bytes / max) * 100}%`,
                    background: row.highlight ? HIGHLIGHT : 'var(--gray-800)',
                  }}
                />
                <span className="bar-value">
                  {row.bytes} bytes
                  <span className="bar-ratio">×{row.ratio.toFixed(2)}</span>
                </span>
              </div>
            </div>
          ))}
        </div>
        {rows.length === 0 && <p className="figure-pending">Measuring…</p>}
      </div>
      <figcaption className="figure-caption">
        The same {SIZE_SAMPLE.length} bytes, encoded five ways and measured by the engine on this page. Base64 is the
        common default at a third larger; hex doubles it. Worth knowing before you put one in a URL or a database column.
      </figcaption>
    </figure>
  );
}

// --- Figure 4: entropy as a triage instrument -------------------------------

interface EntropyRow {
  label: string;
  entropy: number;
  note: string;
  highlight?: boolean;
}

export function EntropyFigure(): JSX.Element {
  const [rows, setRows] = useState<EntropyRow[]>([]);

  useEffect(() => {
    const random = lcg(981);
    const prose =
      'It was the best of times, it was the worst of times, it was the age of wisdom, it was the age of foolishness. ';
    const source = 'export function run(input, args) { return encode(input, args.alphabet); } '.repeat(3);

    const build = async (): Promise<void> => {
      // Samples are kept large on purpose. Entropy over N bytes cannot exceed
      // log2(N), so a short sample understates a random one badly.
      const proseBytes = utf8Encode(prose.repeat(24));
      const b64 = utf8Encode(base64Encode(proseBytes));

      // Compress varied text rather than one repeated line, so the output is
      // long enough for its own entropy to be meaningful.
      const varied = Array.from(
        { length: 120 },
        (_, i) => `${1700000000 + i * 37} GET /orders/${i * 7} 200 ${i * 13}ms client=10.0.${i % 255}.${(i * 3) % 255}`,
      ).join('\n');
      const gz = (await runRecipe(utf8Encode(varied), [{ op: 'gzip' }])).output;
      const randomBytes = Uint8Array.from({ length: 4096 }, () => random()) as Bytes;

      setRows([
        { label: 'English prose', entropy: shannonEntropy(proseBytes), note: 'few letters, unevenly used' },
        { label: 'source code', entropy: shannonEntropy(utf8Encode(source)), note: 'prose plus punctuation' },
        { label: 'Base64 text', entropy: shannonEntropy(b64), note: '64 symbols, so 6 bits is its ceiling' },
        { label: 'gzip output', entropy: shannonEntropy(gz), note: 'redundancy already removed', highlight: true },
        { label: 'random bytes', entropy: shannonEntropy(randomBytes), note: 'the ceiling: 8 bits', highlight: true },
      ]);
    };

    void build();
  }, []);

  return (
    <figure className="figure">
      <div className="figure-body">
        <div className="scale">
          <div className="scale-head">
            <span>0</span>
            <span>8 bits</span>
          </div>

          <div className="scale-rows">
            {/* Position comes from CSS, which knows the label column width. */}
            <div className="scale-threshold" aria-hidden="true">
              <span className="scale-threshold-label">7.5 — compressed or encrypted above here</span>
            </div>
            {rows.map((row) => (
              <div className="scale-row" key={row.label}>
                <div className="scale-label">
                  {row.label}
                  <span className="scale-note">{row.note}</span>
                </div>
                <div className="scale-track">
                  <div
                    className="scale-fill"
                    style={{
                      width: `${(row.entropy / 8) * 100}%`,
                      background: row.highlight ? HIGHLIGHT : 'var(--gray-800)',
                    }}
                  />
                  <span className="scale-value">{row.entropy.toFixed(2)}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
        {rows.length === 0 && <p className="figure-pending">Measuring…</p>}
      </div>
      <figcaption className="figure-caption">
        Shannon entropy in bits per byte, measured live. It is the cheapest useful question you can ask of an unknown
        file: above roughly 7.5 there is no structure left to find, so no amount of decoding will help without a key.
      </figcaption>
    </figure>
  );
}

// --- Figure 5: how a recipe runs --------------------------------------------

interface Stage {
  op: string;
  label: string;
  bytes: number;
  preview: string;
}

export function PipelineFigure(): JSX.Element {
  const [stages, setStages] = useState<Stage[]>([]);

  useEffect(() => {
    const build = async (): Promise<void> => {
      const original = utf8Encode(JSON.stringify({ user: 'ana', role: 'admin', mfa: false }));
      const packed = await runRecipe(original, [{ op: 'gzip' }, { op: 'to-base64' }]);

      // Now run the recipe a reader would actually type, and record each stage.
      const recipe = [{ op: 'from-base64' }, { op: 'gunzip' }, { op: 'json-format', args: { indent: 2 } }];
      const result = await runRecipe(packed.output, recipe);

      const labels = ['from-base64', 'gunzip', 'json-format'];
      const collected: Stage[] = [
        { op: 'input', label: 'what you paste', bytes: packed.output.length, preview: preview(packed.output) },
      ];
      result.steps.forEach((step, index) => {
        if (!step.output) return;
        collected.push({ op: labels[index], label: '', bytes: step.output.length, preview: preview(step.output) });
      });
      setStages(collected);
    };

    void build();
  }, []);

  return (
    <figure className="figure">
      <div className="figure-body">
        <ol className="pipeline">
          {stages.map((stage, index) => (
            <li className="pipeline-stage" key={stage.op}>
              <div className="pipeline-op">
                {index > 0 && <span className="pipeline-arrow" aria-hidden="true">↓</span>}
                <code>{stage.op}</code>
                <span className="pipeline-bytes">{stage.bytes} bytes</span>
              </div>
              <div className="pipeline-preview">{stage.preview}</div>
            </li>
          ))}
        </ol>
        {stages.length === 0 && <p className="figure-pending">Running…</p>}
      </div>
      <figcaption className="figure-caption">
        A recipe actually executing on this page. Each step takes the previous step&rsquo;s bytes, so the byte count is
        the honest signal that something happened — and the first step where it stops making sense is the one to look at.
      </figcaption>
    </figure>
  );
}

function preview(bytes: Bytes, limit = 46): string {
  const printable = bytes.every((b) => (b >= 0x20 && b < 0x7f) || b === 0x0a);
  const text = printable
    ? new TextDecoder().decode(bytes.subarray(0, limit)).replace(/\n\s*/g, ' ')
    : hexEncode(bytes.subarray(0, limit / 3), ' ');
  return bytes.length > limit / (printable ? 1 : 3) ? `${text}…` : text;
}
