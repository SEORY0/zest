/**
 * Network operations — addresses, URLs and the defanging conventions used when
 * indicators of compromise are shared in documents that auto-link.
 */

import { getBoolean, getOption } from '../args.js';
import { utf8Decode, utf8Encode } from '../bytes.js';
import { OperationError, type Operation } from '../types.js';

function ipv4ToInt(ip: string): number {
  const parts = ip.trim().split('.');
  if (parts.length !== 4) throw new OperationError(`${JSON.stringify(ip)} is not an IPv4 address.`);
  let value = 0;
  for (const part of parts) {
    const octet = Number(part);
    if (!Number.isInteger(octet) || octet < 0 || octet > 255) {
      throw new OperationError(`${JSON.stringify(ip)} has an octet outside 0–255.`);
    }
    value = value * 256 + octet;
  }
  return value >>> 0;
}

function intToIpv4(value: number): string {
  return [(value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff].join('.');
}

const PRIVATE_RANGES: [string, number, string][] = [
  ['10.0.0.0', 8, 'private (RFC 1918)'],
  ['172.16.0.0', 12, 'private (RFC 1918)'],
  ['192.168.0.0', 16, 'private (RFC 1918)'],
  ['127.0.0.0', 8, 'loopback'],
  ['169.254.0.0', 16, 'link-local'],
  ['100.64.0.0', 10, 'carrier-grade NAT (RFC 6598)'],
  ['224.0.0.0', 4, 'multicast'],
  ['0.0.0.0', 8, 'this network'],
];

function classifyIpv4(ip: number): string {
  for (const [base, bits, label] of PRIVATE_RANGES) {
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    if ((ip & mask) >>> 0 === (ipv4ToInt(base) & mask) >>> 0) return label;
  }
  return 'public';
}

export const networkOps: Operation[] = [
  {
    id: 'defang',
    name: 'Defang indicator',
    category: 'Network',
    description: 'Neuters URLs, domains and IPs so they will not auto-link or be clicked by accident. The convention for sharing indicators in a report.',
    keywords: ['ioc', 'threat', 'sanitise', 'sanitize', 'phishing'],
    args: [
      { name: 'dots', label: 'Bracket dots', type: 'boolean', default: true },
      { name: 'scheme', label: 'Break http scheme', type: 'boolean', default: true },
      { name: 'at', label: 'Bracket @ in addresses', type: 'boolean', default: true },
    ],
    examples: [
      { input: 'https://evil.test/a', output: 'hxxps://evil[.]test/a' },
      { input: 'user@evil.test', output: 'user[@]evil[.]test' },
    ],
    run(input, args) {
      let text = utf8Decode(input);
      if (getBoolean(args, 'scheme', true)) text = text.replace(/\bhttp(s?):\/\//gi, (_m, s: string) => `hxxp${s}://`);
      if (getBoolean(args, 'dots', true)) text = text.replace(/\./g, '[.]');
      if (getBoolean(args, 'at', true)) text = text.replace(/@/g, '[@]');
      return utf8Encode(text);
    },
  },
  {
    id: 'fang',
    name: 'Refang indicator',
    category: 'Network',
    description: 'Reverses defanging so an indicator becomes usable again. Accepts the [.], (.), {.} and hxxp variants.',
    keywords: ['ioc', 'threat', 'restore'],
    examples: [{ input: 'hxxps://evil[.]test/a', output: 'https://evil.test/a' }],
    run(input) {
      const text = utf8Decode(input)
        .replace(/\bhxxp(s?)(:\/\/|\[:\]\/\/)/gi, (_m, s: string) => `http${s}://`)
        .replace(/[[({]\s*\.\s*[\])}]/g, '.')
        .replace(/[[({]\s*@\s*[\])}]/g, '@')
        .replace(/[[({]\s*:\s*[\])}]/g, ':')
        .replace(/\s+dot\s+/gi, '.')
        .replace(/\s+at\s+/gi, '@');
      return utf8Encode(text);
    },
  },
  {
    id: 'ip-to-int',
    name: 'IPv4 to integer',
    category: 'Network',
    description: 'Converts dotted-quad addresses to their 32-bit integer form, one per line.',
    keywords: ['address', 'convert', 'long'],
    examples: [{ input: '192.168.1.1', output: '3232235777' }],
    run(input) {
      return utf8Encode(
        utf8Decode(input)
          .split('\n')
          .map((line) => line.trim())
          .filter(Boolean)
          .map((line) => String(ipv4ToInt(line)))
          .join('\n'),
      );
    },
  },
  {
    id: 'int-to-ip',
    name: 'Integer to IPv4',
    category: 'Network',
    description: 'Converts 32-bit integers back to dotted-quad addresses.',
    keywords: ['address', 'convert', 'long'],
    examples: [{ input: '3232235777', output: '192.168.1.1' }],
    run(input) {
      return utf8Encode(
        utf8Decode(input)
          .split('\n')
          .map((line) => line.trim())
          .filter(Boolean)
          .map((line) => {
            const value = Number(line);
            if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
              throw new OperationError(`${JSON.stringify(line)} is not a 32-bit unsigned integer.`);
            }
            return intToIpv4(value);
          })
          .join('\n'),
      );
    },
  },
  {
    id: 'parse-cidr',
    name: 'Parse CIDR',
    category: 'Network',
    description: 'Expands a CIDR block into its network address, broadcast address, mask, host count and scope.',
    keywords: ['subnet', 'netmask', 'range', 'network'],
    args: [{ name: 'listAddresses', label: 'List every address (max 4096)', type: 'boolean', default: false }],
    examples: [
      {
        input: '192.168.1.0/24',
        output: [
          'network    192.168.1.0',
          'broadcast  192.168.1.255',
          'first host 192.168.1.1',
          'last host  192.168.1.254',
          'netmask    255.255.255.0',
          'wildcard   0.0.0.255',
          'addresses  256',
          'usable     254',
          'scope      private (RFC 1918)',
        ].join('\n'),
      },
    ],
    run(input, args) {
      const text = utf8Decode(input).trim();
      const match = /^([0-9.]+)\s*\/\s*(\d{1,2})$/.exec(text);
      if (!match) throw new OperationError(`${JSON.stringify(text)} is not CIDR notation, e.g. 10.0.0.0/8.`);

      const bits = Number(match[2]);
      if (bits < 0 || bits > 32) throw new OperationError(`Prefix length must be 0–32, got ${bits}.`);

      const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
      const network = (ipv4ToInt(match[1]) & mask) >>> 0;
      const broadcast = (network | (~mask >>> 0)) >>> 0;
      const total = 2 ** (32 - bits);

      const rows = [
        ['network', intToIpv4(network)],
        ['broadcast', intToIpv4(broadcast)],
        ['first host', total > 2 ? intToIpv4(network + 1) : intToIpv4(network)],
        ['last host', total > 2 ? intToIpv4(broadcast - 1) : intToIpv4(broadcast)],
        ['netmask', intToIpv4(mask)],
        ['wildcard', intToIpv4(~mask >>> 0)],
        ['addresses', String(total)],
        ['usable', String(Math.max(total > 2 ? total - 2 : total, 0))],
        ['scope', classifyIpv4(network)],
      ];

      const width = Math.max(...rows.map((r) => r[0].length));
      let out = rows.map(([k, v]) => `${k.padEnd(width)} ${v}`).join('\n');

      if (getBoolean(args, 'listAddresses', false)) {
        if (total > 4096) throw new OperationError(`That block holds ${total} addresses; listing is capped at 4096.`);
        const addresses: string[] = [];
        for (let i = 0; i < total; i++) addresses.push(intToIpv4(network + i));
        out += `\n\n${addresses.join('\n')}`;
      }
      return utf8Encode(out);
    },
  },
  {
    id: 'parse-uri',
    name: 'Parse URI',
    category: 'Network',
    description: 'Breaks a URL into its parts and lists the query parameters separately.',
    keywords: ['url', 'components', 'query', 'host'],
    examples: [
      {
        input: 'https://user:pw@host.test:8443/a/b?x=1&y=2#frag',
        output: [
          'scheme    https:',
          'username  user',
          'password  pw',
          'host      host.test',
          'port      8443',
          'path      /a/b',
          'query     ?x=1&y=2',
          'fragment  #frag',
          '',
          'parameters',
          '  x  1',
          '  y  2',
        ].join('\n'),
      },
    ],
    run(input) {
      const text = utf8Decode(input).trim();
      let url: URL;
      try {
        url = new URL(text);
      } catch {
        throw new OperationError(`${JSON.stringify(text)} is not an absolute URL. Include the scheme, e.g. https://.`);
      }

      const rows: [string, string][] = [
        ['scheme', url.protocol],
        ['username', url.username],
        ['password', url.password],
        ['host', url.hostname],
        ['port', url.port],
        ['path', url.pathname],
        ['query', url.search],
        ['fragment', url.hash],
      ];
      const width = Math.max(...rows.map((r) => r[0].length));
      const lines = rows.map(([k, v]) => `${k.padEnd(width)}  ${v}`);

      const params = Array.from(url.searchParams.entries());
      if (params.length) {
        const keyWidth = Math.max(...params.map(([k]) => k.length));
        lines.push('', 'parameters', ...params.map(([k, v]) => `  ${k.padEnd(keyWidth)}  ${v}`));
      }
      return utf8Encode(lines.join('\n'));
    },
  },
  {
    id: 'extract-indicators',
    name: 'Extract indicators',
    category: 'Network',
    description: 'Pulls URLs, domains, IPs, email addresses and hashes out of unstructured text — a first pass over a log, a phishing mail or a report.',
    keywords: ['ioc', 'threat', 'scrape', 'hunt'],
    args: [
      { name: 'kind', type: 'select', options: ['All', 'URL', 'Domain', 'IPv4', 'IPv6', 'Email', 'Hash'], default: 'All' },
      { name: 'defangInput', label: 'Refang the input first', type: 'boolean', default: true },
      { name: 'unique', type: 'boolean', default: true },
    ],
    examples: [
      {
        input: 'contact a@b.test or visit https://x.test from 10.0.0.1',
        args: { kind: 'All' },
        output: 'URL\nhttps://x.test\n\nIPv4\n10.0.0.1\n\nEmail\na@b.test',
      },
    ],
    run(input, args) {
      let text = utf8Decode(input);
      if (getBoolean(args, 'defangInput', true)) {
        text = text
          .replace(/\bhxxp(s?)(:\/\/|\[:\]\/\/)/gi, (_m, s: string) => `http${s}://`)
          .replace(/[[({]\s*\.\s*[\])}]/g, '.')
          .replace(/[[({]\s*@\s*[\])}]/g, '@');
      }

      const patterns: [string, RegExp][] = [
        ['URL', /\bhttps?:\/\/[^\s"'<>)\]]+/gi],
        ['Domain', /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/gi],
        ['IPv4', /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g],
        ['IPv6', /\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b/gi],
        ['Email', /\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,24}\b/gi],
        ['Hash', /\b[a-f0-9]{32}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{64}\b/gi],
      ];

      const kind = getOption(args, 'kind', ['All', 'URL', 'Domain', 'IPv4', 'IPv6', 'Email', 'Hash'] as const, 'All');
      const unique = getBoolean(args, 'unique', true);
      const sections: string[] = [];

      for (const [label, pattern] of patterns) {
        if (kind !== 'All' && kind !== label) continue;
        let matches: string[] = text.match(pattern) ?? [];

        // Domains and IPs also appear inside URLs and emails; only report them standalone.
        if (label === 'Domain') {
          const inUrls = (text.match(/\bhttps?:\/\/[^\s"'<>)\]]+/gi) ?? []).join(' ');
          const inEmails = (text.match(/\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,24}\b/gi) ?? []).join(' ');
          matches = matches.filter((m) => !inUrls.includes(m) && !inEmails.includes(m));
        }
        if (unique) matches = Array.from(new Set(matches));
        if (matches.length) sections.push(`${label}\n${matches.join('\n')}`);
      }

      return utf8Encode(sections.length ? sections.join('\n\n') : 'No indicators found.');
    },
  },
];
