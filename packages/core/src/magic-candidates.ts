import { looksPrintable } from './bytes.js';
import type { Args, Bytes } from './types.js';

export interface MagicAttempt {
  readonly op: string;
  readonly args?: Args;
}

interface Candidate extends MagicAttempt {
  readonly applies: (data: Bytes, text: string) => boolean;
}

const isMostlyText = (data: Bytes): boolean => looksPrintable(data, 0.95);

const looksLikeBitwiseNot = (data: Bytes): boolean => {
  if (data.length < 4) return false;
  let printable = 0;
  for (const byte of data) {
    const inverted = ~byte & 0xff;
    if ((inverted >= 0x20 && inverted <= 0x7e) || inverted === 0x09 || inverted === 0x0a || inverted === 0x0d) {
      printable++;
    }
  }
  return printable / data.length >= 0.9;
};

const CANDIDATES: readonly Candidate[] = [
  {
    op: 'from-base64',
    applies: (data, text) =>
      isMostlyText(data) && /^[A-Za-z0-9+/=\s]{8,}$/.test(text) && text.replace(/[\s=]/g, '').length % 4 !== 1,
  },
  {
    op: 'from-base64',
    args: { alphabet: 'URL-safe' },
    applies: (data, text) =>
      isMostlyText(data) && /[-_]/.test(text) && /^[A-Za-z0-9\-_=\s]{8,}$/.test(text),
  },
  {
    op: 'from-hex',
    applies: (data, text) =>
      isMostlyText(data) && /^[0-9a-fA-F\s:,-]{8,}$/.test(text) && text.replace(/[^0-9a-fA-F]/g, '').length % 2 === 0,
  },
  { op: 'from-base32', applies: (data, text) => isMostlyText(data) && /^[A-Z2-7=\s]{8,}$/.test(text) },
  { op: 'from-base58', applies: (data, text) => isMostlyText(data) && /^[1-9A-HJ-NP-Za-km-z]{8,}$/.test(text) },
  {
    op: 'from-base85',
    applies: (data, text) =>
      isMostlyText(data) && /^[!-u\s]{8,}$/.test(text) && /[!"#$%&'()*,.:;<=>?@[\]^`{|}~-]/.test(text),
  },
  { op: 'url-decode', applies: (_data, text) => /%[0-9a-fA-F]{2}/.test(text) },
  { op: 'from-html-entity', applies: (_data, text) => /&(#x?[0-9a-fA-F]+|[a-zA-Z]{2,10});/.test(text) },
  { op: 'from-quoted-printable', applies: (_data, text) => /=[0-9A-F]{2}/.test(text) },
  { op: 'from-binary', applies: (_data, text) => /^[01\s]{16,}$/.test(text) && text.replace(/\s/g, '').length % 8 === 0 },
  { op: 'from-decimal', applies: (_data, text) => /^(\d{1,3}[\s,;]+){3,}\d{1,3}$/.test(text.trim()) },
  { op: 'from-morse', applies: (_data, text) => /^[.\-/\s]{6,}$/.test(text) && /[.-]/.test(text) },
  { op: 'gunzip', applies: (data) => data.length > 2 && ((data[0] === 0x1f && data[1] === 0x8b) || data[0] === 0x78) },
  { op: 'bitwise-not', applies: (data) => looksLikeBitwiseNot(data) },
  { op: 'rot', args: { amount: 13 }, applies: (_data, text) => /[a-zA-Z]{4,}/.test(text) && text.length < 100_000 },
  { op: 'rot47', applies: (_data, text) => /[!-~]{4,}/.test(text) && text.length < 100_000 },
  {
    op: 'from-charcode',
    args: { base: 'Hexadecimal' },
    applies: (_data, text) => /^(0x[0-9a-fA-F]{1,2}[\s,]+){3,}/.test(text.trim()),
  },
  { op: 'jwt-decode', applies: (_data, text) => /^(Bearer\s+)?[\w-]+\.[\w-]+\.[\w-]*$/.test(text.trim()) },
] as const;

export function candidateAttempts(data: Bytes, text: string): MagicAttempt[] {
  const attempts: MagicAttempt[] = [];
  for (const candidate of CANDIDATES) {
    try {
      if (candidate.applies(data, text)) attempts.push({ op: candidate.op, args: candidate.args });
    } catch {
      // A shape probe is advisory. A decoder can still report real operation errors when selected.
    }
  }
  return attempts;
}
