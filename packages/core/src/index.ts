/**
 * @zest/core — a local-first data and security operation engine.
 *
 * Nothing here touches the network or the filesystem. The same module powers
 * the browser workbench, the `zest` CLI and the agent skill.
 */

import { analysisOps } from './ops/analysis.js';
import { compressionOps } from './ops/compression.js';
import { dataOps } from './ops/data.js';
import { datetimeOps } from './ops/datetime.js';
import { encodingOps } from './ops/encoding.js';
import { encryptionOps } from './ops/encryption.js';
import { generateOps } from './ops/generate.js';
import { hashingOps } from './ops/hashing.js';
import { networkOps } from './ops/network.js';
import { textOps } from './ops/text.js';
import { magicOp } from './magic.js';
import { register } from './registry.js';

register(
  ...encodingOps,
  ...hashingOps,
  ...encryptionOps,
  ...textOps,
  ...dataOps,
  ...compressionOps,
  ...networkOps,
  ...analysisOps,
  ...datetimeOps,
  ...generateOps,
  magicOp,
);

export * from './types.js';
export * from './bytes.js';
export * from './args.js';
export * from './registry.js';
export * from './run.js';
export * from './magic.js';
export { detectFileType, type FileTypeMatch } from './filetypes.js';
