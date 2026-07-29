/**
 * Compression operations, built on the platform's CompressionStream.
 */

import { getOption } from '../args.js';
import { OperationError, type Bytes, type Operation } from '../types.js';

type StreamFormat = 'gzip' | 'deflate' | 'deflate-raw';

const FORMAT_LABELS = ['Gzip', 'Zlib (deflate)', 'Raw deflate'] as const;
const FORMAT_BY_LABEL: Record<(typeof FORMAT_LABELS)[number], StreamFormat> = {
  Gzip: 'gzip',
  'Zlib (deflate)': 'deflate',
  'Raw deflate': 'deflate-raw',
};

function requireStreams(): void {
  if (typeof globalThis.CompressionStream !== 'function' || typeof globalThis.DecompressionStream !== 'function') {
    throw new OperationError('CompressionStream is unavailable. Zest needs Node 18+ or a current browser.');
  }
}

async function drain(stream: ReadableStream<Uint8Array>): Promise<Bytes> {
  const chunks: Uint8Array[] = [];
  let total = 0;
  const reader = stream.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    total += value.length;
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

function sourceOf(input: Bytes): ReadableStream<Bytes> {
  return new ReadableStream<Bytes>({
    start(controller) {
      controller.enqueue(input);
      controller.close();
    },
  });
}

async function compress(input: Bytes, format: StreamFormat): Promise<Bytes> {
  requireStreams();
  return drain(sourceOf(input).pipeThrough(new CompressionStream(format)));
}

async function decompress(input: Bytes, format: StreamFormat): Promise<Bytes> {
  requireStreams();
  try {
    return await drain(sourceOf(input).pipeThrough(new DecompressionStream(format)));
  } catch (error) {
    throw new OperationError(
      `Decompression failed for format ${JSON.stringify(format)}. ` +
        `Gzip starts with 1f 8b, zlib usually with 78. ${error instanceof Error ? error.message : ''}`.trim(),
    );
  }
}

export const compressionOps: Operation[] = [
  {
    id: 'gzip',
    name: 'Gzip',
    category: 'Compression',
    description: 'Compresses with gzip. Output is binary — follow with To Base64 or To Hex to make it printable.',
    keywords: ['compress', 'deflate', 'zip'],
    binaryOutput: true,
    args: [{ name: 'format', type: 'select', options: FORMAT_LABELS, default: 'Gzip' }],
    run(input, args) {
      return compress(input, FORMAT_BY_LABEL[getOption(args, 'format', FORMAT_LABELS, 'Gzip')]);
    },
  },
  {
    id: 'gunzip',
    name: 'Gunzip',
    category: 'Compression',
    description: 'Decompresses gzip, zlib or raw deflate data.',
    keywords: ['decompress', 'inflate', 'unzip'],
    args: [{ name: 'format', type: 'select', options: [...FORMAT_LABELS, 'Detect'], default: 'Detect' }],
    async run(input, args) {
      const choice = getOption(args, 'format', [...FORMAT_LABELS, 'Detect'] as const, 'Detect');

      if (choice !== 'Detect') {
        return decompress(input, FORMAT_BY_LABEL[choice]);
      }
      // Sniff the header, then fall through the remaining formats.
      const candidates: StreamFormat[] =
        input[0] === 0x1f && input[1] === 0x8b
          ? ['gzip', 'deflate', 'deflate-raw']
          : input[0] === 0x78
            ? ['deflate', 'deflate-raw', 'gzip']
            : ['deflate-raw', 'deflate', 'gzip'];

      const failures: string[] = [];
      for (const format of candidates) {
        try {
          return await decompress(input, format);
        } catch (error) {
          failures.push(format);
        }
      }
      throw new OperationError(`Could not decompress this input as ${failures.join(', ')}. Check that it is really compressed data.`);
    },
  },
];
