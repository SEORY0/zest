/**
 * File type detection by magic bytes.
 *
 * Signatures are matched at a declared offset so container formats (RIFF, ISO
 * base media) can be distinguished by their sub-type rather than just their
 * header.
 */

import type { Bytes } from './types.js';

export interface FileTypeSignature {
  name: string;
  extension: string;
  mime: string;
  /** Byte pattern; `null` matches any byte at that position. */
  bytes: (number | null)[];
  offset?: number;
  note?: string;
}

export interface FileTypeMatch extends FileTypeSignature {
  matchedAt: number;
}

const S = (hex: string): number[] => {
  const out: number[] = [];
  for (let i = 0; i < hex.length; i += 2) out.push(parseInt(hex.substr(i, 2), 16));
  return out;
};

const A = (text: string): number[] => Array.from(text).map((c) => c.charCodeAt(0));

export const SIGNATURES: FileTypeSignature[] = [
  // Archives and compression
  { name: 'ZIP archive', extension: 'zip', mime: 'application/zip', bytes: S('504b0304'), note: 'Also the container for docx, xlsx, jar, apk and epub' },
  { name: 'ZIP archive (empty)', extension: 'zip', mime: 'application/zip', bytes: S('504b0506') },
  { name: 'Gzip', extension: 'gz', mime: 'application/gzip', bytes: S('1f8b') },
  { name: 'Zlib stream', extension: 'zlib', mime: 'application/zlib', bytes: [0x78, null], note: 'Second byte is usually 01, 9c or da' },
  { name: 'BZip2', extension: 'bz2', mime: 'application/x-bzip2', bytes: A('BZh') },
  { name: 'XZ', extension: 'xz', mime: 'application/x-xz', bytes: S('fd377a585a00') },
  { name: 'Zstandard', extension: 'zst', mime: 'application/zstd', bytes: S('28b52ffd') },
  { name: '7-Zip', extension: '7z', mime: 'application/x-7z-compressed', bytes: S('377abcaf271c') },
  { name: 'RAR archive', extension: 'rar', mime: 'application/vnd.rar', bytes: S('526172211a07') },
  { name: 'TAR archive', extension: 'tar', mime: 'application/x-tar', bytes: A('ustar'), offset: 257 },

  // Documents
  { name: 'PDF', extension: 'pdf', mime: 'application/pdf', bytes: A('%PDF-') },
  { name: 'RTF', extension: 'rtf', mime: 'application/rtf', bytes: A('{\\rtf') },
  { name: 'Legacy MS Office (OLE2)', extension: 'doc', mime: 'application/x-ole-storage', bytes: S('d0cf11e0a1b11ae1'), note: 'doc, xls, ppt and msi all share this header' },

  // Images
  { name: 'PNG', extension: 'png', mime: 'image/png', bytes: S('89504e470d0a1a0a') },
  { name: 'JPEG', extension: 'jpg', mime: 'image/jpeg', bytes: S('ffd8ff') },
  { name: 'GIF', extension: 'gif', mime: 'image/gif', bytes: A('GIF8') },
  { name: 'BMP', extension: 'bmp', mime: 'image/bmp', bytes: A('BM') },
  { name: 'WebP', extension: 'webp', mime: 'image/webp', bytes: A('WEBP'), offset: 8 },
  { name: 'TIFF (little-endian)', extension: 'tif', mime: 'image/tiff', bytes: S('49492a00') },
  { name: 'TIFF (big-endian)', extension: 'tif', mime: 'image/tiff', bytes: S('4d4d002a') },
  { name: 'ICO', extension: 'ico', mime: 'image/x-icon', bytes: S('00000100') },
  { name: 'SVG', extension: 'svg', mime: 'image/svg+xml', bytes: A('<svg') },
  { name: 'AVIF', extension: 'avif', mime: 'image/avif', bytes: A('ftypavif'), offset: 4 },
  { name: 'HEIC', extension: 'heic', mime: 'image/heic', bytes: A('ftypheic'), offset: 4 },

  // Audio and video
  { name: 'MP3 (ID3)', extension: 'mp3', mime: 'audio/mpeg', bytes: A('ID3') },
  { name: 'WAV', extension: 'wav', mime: 'audio/wav', bytes: A('WAVE'), offset: 8 },
  { name: 'FLAC', extension: 'flac', mime: 'audio/flac', bytes: A('fLaC') },
  { name: 'OGG', extension: 'ogg', mime: 'audio/ogg', bytes: A('OggS') },
  { name: 'MP4 / QuickTime', extension: 'mp4', mime: 'video/mp4', bytes: A('ftyp'), offset: 4 },
  { name: 'Matroska / WebM', extension: 'mkv', mime: 'video/x-matroska', bytes: S('1a45dfa3') },
  { name: 'AVI', extension: 'avi', mime: 'video/x-msvideo', bytes: A('AVI '), offset: 8 },

  // Executables and binaries — the ones that matter most in triage
  { name: 'Windows PE / DOS MZ', extension: 'exe', mime: 'application/vnd.microsoft.portable-executable', bytes: A('MZ'), note: 'Check for a PE\\0\\0 signature at the e_lfanew offset to confirm' },
  { name: 'ELF', extension: 'elf', mime: 'application/x-elf', bytes: S('7f454c46') },
  { name: 'Mach-O (64-bit)', extension: 'macho', mime: 'application/x-mach-binary', bytes: S('cffaedfe') },
  { name: 'Mach-O (32-bit)', extension: 'macho', mime: 'application/x-mach-binary', bytes: S('cefaedfe') },
  { name: 'Mach-O universal binary', extension: 'macho', mime: 'application/x-mach-binary', bytes: S('cafebabf') },
  { name: 'Java class file', extension: 'class', mime: 'application/java-vm', bytes: S('cafebabe') },
  { name: 'WebAssembly', extension: 'wasm', mime: 'application/wasm', bytes: S('0061736d') },
  { name: 'Python bytecode', extension: 'pyc', mime: 'application/x-python-code', bytes: [null, null, 0x0d, 0x0a] },
  { name: 'Shebang script', extension: 'sh', mime: 'text/x-shellscript', bytes: A('#!') },

  // Crypto and certificates
  { name: 'PEM certificate or key', extension: 'pem', mime: 'application/x-pem-file', bytes: A('-----BEGIN') },
  { name: 'PuTTY private key', extension: 'ppk', mime: 'application/x-putty-key', bytes: A('PuTTY-User-Key-File') },
  { name: 'OpenSSH private key', extension: 'key', mime: 'application/x-openssh-key', bytes: A('-----BEGIN OPENSSH') },
  { name: 'PGP message', extension: 'asc', mime: 'application/pgp', bytes: A('-----BEGIN PGP') },

  // Databases and data
  { name: 'SQLite database', extension: 'sqlite', mime: 'application/vnd.sqlite3', bytes: A('SQLite format 3\0') },
  { name: 'Parquet', extension: 'parquet', mime: 'application/vnd.apache.parquet', bytes: A('PAR1') },
  { name: 'PCAP capture', extension: 'pcap', mime: 'application/vnd.tcpdump.pcap', bytes: S('d4c3b2a1') },
  { name: 'PCAPNG capture', extension: 'pcapng', mime: 'application/x-pcapng', bytes: S('0a0d0d0a') },

  // Text encodings
  { name: 'UTF-8 with BOM', extension: 'txt', mime: 'text/plain', bytes: S('efbbbf') },
  { name: 'UTF-16 LE with BOM', extension: 'txt', mime: 'text/plain', bytes: S('fffe') },
  { name: 'UTF-16 BE with BOM', extension: 'txt', mime: 'text/plain', bytes: S('feff') },
];

function matchesAt(data: Bytes, signature: FileTypeSignature): boolean {
  const offset = signature.offset ?? 0;
  if (data.length < offset + signature.bytes.length) return false;
  for (let i = 0; i < signature.bytes.length; i++) {
    const expected = signature.bytes[i];
    if (expected !== null && data[offset + i] !== expected) return false;
  }
  return true;
}

/** All signatures matching this data, most specific (longest, deepest) first. */
export function detectFileType(data: Bytes): FileTypeMatch[] {
  return SIGNATURES.filter((signature) => matchesAt(data, signature))
    .map((signature) => ({ ...signature, matchedAt: signature.offset ?? 0 }))
    .sort((a, b) => b.bytes.length + b.matchedAt - (a.bytes.length + a.matchedAt));
}
