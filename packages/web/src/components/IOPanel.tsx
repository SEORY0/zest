import { useRef, useState } from 'react';
import { detectFileType, encodeAs, shannonEntropy, type Bytes, type KeyEncoding } from '@zest/core';

const ENCODINGS: KeyEncoding[] = ['utf8', 'hex', 'base64', 'latin1'];

interface InputProps {
  value: string;
  encoding: KeyEncoding;
  onChange: (value: string) => void;
  onEncodingChange: (encoding: KeyEncoding) => void;
  onLoadFile: (bytes: Bytes, name: string) => void;
  byteLength: number;
}

export function InputPanel({
  value,
  encoding,
  onChange,
  onEncodingChange,
  onLoadFile,
  byteLength,
}: InputProps): JSX.Element {
  const [dragActive, setDragActive] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);

  const readFile = async (file: File): Promise<void> => {
    const buffer = await file.arrayBuffer();
    onLoadFile(new Uint8Array(buffer) as Bytes, file.name);
  };

  return (
    <section className="panel" aria-label="Input">
      <header className="panel-header">
        <h2 className="panel-title">Input</h2>
        <div className="panel-actions">
          <select
            className="field"
            style={{ width: '5.5rem' }}
            value={encoding}
            aria-label="Input encoding"
            onChange={(event) => onEncodingChange(event.target.value as KeyEncoding)}
          >
            {ENCODINGS.map((option) => (
              <option key={option} value={option}>
                {option}
              </option>
            ))}
          </select>
          <button type="button" className="button is-quiet" onClick={() => fileInput.current?.click()}>
            Open file
          </button>
          <button type="button" className="button is-quiet" onClick={() => onChange('')} disabled={!value}>
            Clear
          </button>
        </div>
      </header>

      <div className="panel-body">
        <div
          className={`dropzone${dragActive ? ' is-active' : ''}`}
          onDragOver={(event) => {
            event.preventDefault();
            setDragActive(true);
          }}
          onDragLeave={() => setDragActive(false)}
          onDrop={(event) => {
            event.preventDefault();
            setDragActive(false);
            const file = event.dataTransfer.files[0];
            if (file) void readFile(file);
          }}
        >
          <textarea
            className="io-textarea mono"
            value={value}
            spellCheck={false}
            placeholder="Paste or type here, or drop a file."
            aria-label="Input data"
            onChange={(event) => onChange(event.target.value)}
          />
        </div>

        <input
          ref={fileInput}
          type="file"
          hidden
          onChange={(event) => {
            const file = event.target.files?.[0];
            if (file) void readFile(file);
            event.target.value = '';
          }}
        />

        <div className="io-meta">
          <span>
            length <span className="io-meta-value">{value.length}</span>
          </span>
          <span>
            bytes <span className="io-meta-value">{byteLength}</span>
          </span>
        </div>
      </div>
    </section>
  );
}

interface OutputProps {
  output: Bytes;
  ok: boolean;
  error?: string;
  running: boolean;
}

export function OutputPanel({ output, ok, error, running }: OutputProps): JSX.Element {
  const [encoding, setEncoding] = useState<KeyEncoding>('utf8');
  const [copied, setCopied] = useState(false);

  const rendered = safeEncode(output, encoding);
  const entropy = output.length > 0 ? shannonEntropy(output) : 0;
  const fileType = output.length > 0 ? detectFileType(output)[0] : undefined;

  const copy = async (): Promise<void> => {
    await navigator.clipboard.writeText(rendered);
    setCopied(true);
    setTimeout(() => setCopied(false), 1400);
  };

  const download = (): void => {
    const blob = new Blob([output as BlobPart], { type: fileType?.mime ?? 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `zest-output.${fileType?.extension ?? 'bin'}`;
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <section className="panel" aria-label="Output">
      <header className="panel-header">
        <h2 className="panel-title">Output</h2>
        {running ? (
          <span className="badge">running…</span>
        ) : ok ? (
          <span className="badge is-ok">ok</span>
        ) : (
          <span className="badge is-error">failed</span>
        )}

        <div className="panel-actions">
          <select
            className="field"
            style={{ width: '5.5rem' }}
            value={encoding}
            aria-label="Output encoding"
            onChange={(event) => setEncoding(event.target.value as KeyEncoding)}
          >
            {ENCODINGS.map((option) => (
              <option key={option} value={option}>
                {option}
              </option>
            ))}
          </select>
          <button type="button" className="button is-quiet" onClick={() => void copy()} disabled={output.length === 0}>
            {copied ? 'Copied' : 'Copy'}
          </button>
          <button type="button" className="button is-quiet" onClick={download} disabled={output.length === 0}>
            Save
          </button>
        </div>
      </header>

      <div className="panel-body">
        <textarea
          className="io-textarea mono"
          value={error && output.length === 0 ? error : rendered}
          readOnly
          spellCheck={false}
          aria-label="Output data"
          style={{ minHeight: '14rem' }}
        />

        <div className="io-meta">
          <span>
            bytes <span className="io-meta-value">{output.length}</span>
          </span>
          <span>
            entropy <span className="io-meta-value">{entropy.toFixed(2)}</span> bits/byte
          </span>
          {fileType && (
            <span>
              looks like <span className="io-meta-value">{fileType.name}</span>
            </span>
          )}
        </div>
      </div>
    </section>
  );
}

function safeEncode(bytes: Bytes, encoding: KeyEncoding): string {
  try {
    return encodeAs(bytes, encoding);
  } catch {
    return '';
  }
}
