// Configuration for the GitHub inbox adapter. Strict: unknown keys are refused, the pinned
// repository/issue/owner must be repeated exactly, every path is derived from (and checked
// against) the workspace root, and the gh executable must be an existing absolute file.
import { existsSync, statSync } from 'node:fs';
import path from 'node:path';
import { readJson } from '../../local-coordinator/src/util.mjs';
import { validateExe } from '../../local-coordinator/src/notifier.mjs';
import { PINNED, POLL_DEFAULT_S, POLL_MIN_S } from './constants.mjs';

const KEYS = ['workspaceRoot', 'connectionPath', 'ghBin', 'owner', 'repo', 'issue', 'ownerLogin', 'ownerId', 'stateDir', 'pollSeconds', 'checkpointPath'];

const samePath = (a, b, platform) => {
  const x = path.resolve(a), y = path.resolve(b);
  return platform === 'win32' ? x.toLowerCase() === y.toLowerCase() : x === y;
};

export class ConfigError extends Error {}

/**
 * Validate a parsed config object. `fsCheck` lets tests skip the filesystem checks for the
 * workspace and gh executable; production always checks.
 */
export function validateConfig(raw, { platform = process.platform, fsCheck = true } = {}) {
  const bad = (m) => { throw new ConfigError(m); };
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) bad('config must be a JSON object');
  for (const k of Object.keys(raw)) if (!KEYS.includes(k)) bad(`unknown config key: ${k}`);
  for (const k of ['owner', 'repo', 'issue', 'ownerLogin', 'ownerId']) {
    if (raw[k] !== PINNED[k]) bad(`config.${k} must be exactly the pinned value ${JSON.stringify(PINNED[k])}`);
  }
  const ws = raw.workspaceRoot;
  if (typeof ws !== 'string' || !path.isAbsolute(ws)) bad('workspaceRoot must be an absolute path');
  const workspaceRoot = path.resolve(ws);
  if (fsCheck && !existsSync(path.join(workspaceRoot, 'coordination', 'issue-ledger.json'))) bad('workspaceRoot has no coordination/issue-ledger.json');
  const expectConn = path.join(workspaceRoot, 'coordination', 'ui-control', 'connection.json');
  if (typeof raw.connectionPath !== 'string' || !samePath(raw.connectionPath, expectConn, platform)) bad('connectionPath must be <workspaceRoot>/coordination/ui-control/connection.json');
  const expectState = path.join(workspaceRoot, 'coordination', 'ui-control', 'github-inbox');
  if (typeof raw.stateDir !== 'string' || !samePath(raw.stateDir, expectState, platform)) bad('stateDir must be <workspaceRoot>/coordination/ui-control/github-inbox');
  const expectCheckpoint = path.join(workspaceRoot, 'coordination', 'checkpoints', 'devnet-policy-blocker.json');
  if (raw.checkpointPath !== undefined && (typeof raw.checkpointPath !== 'string' || !samePath(raw.checkpointPath, expectCheckpoint, platform))) {
    bad('checkpointPath, if given, must be <workspaceRoot>/coordination/checkpoints/devnet-policy-blocker.json');
  }
  if (typeof raw.ghBin !== 'string' || !path.isAbsolute(raw.ghBin)) bad('ghBin must be an absolute path to the existing gh executable');
  let ghBin = path.resolve(raw.ghBin);
  if (fsCheck) {
    try { ghBin = validateExe(raw.ghBin, { platform, label: 'gh' }); } catch (e) { bad(`ghBin: ${e.message}`); }
  }
  let pollSeconds = POLL_DEFAULT_S;
  if (raw.pollSeconds !== undefined) {
    if (!Number.isInteger(raw.pollSeconds) || raw.pollSeconds < POLL_MIN_S || raw.pollSeconds > 3600) bad(`pollSeconds must be an integer in ${POLL_MIN_S}..3600`);
    pollSeconds = raw.pollSeconds;
  }
  return Object.freeze({
    ...PINNED,
    workspaceRoot,
    connectionPath: expectConn,
    stateDir: expectState,
    checkpointPath: expectCheckpoint,
    ghBin,
    pollSeconds,
  });
}

export function loadConfig(file, opts = {}) {
  if (typeof file !== 'string' || !file) throw new ConfigError('--config FILE is required');
  let st = null;
  try { st = statSync(file); } catch { /* missing */ }
  if (!st || !st.isFile() || st.size > 64 * 1024) throw new ConfigError('config file missing, not a file, or larger than 64 KiB');
  const raw = readJson(file, undefined);
  if (raw === undefined) throw new ConfigError('config file is not valid JSON');
  return validateConfig(raw, opts);
}
