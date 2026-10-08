// Private persistent state of the adapter (coordination/ui-control/github-inbox), written
// atomically with a recovery backup, and the OS-level single-process lease.
//
// Write protocol: the new state goes to a fresh temp file (written, fsynced, closed); the current
// file is renamed to inbox-journal.json.bak; the temp file is renamed to inbox-journal.json. Every file
// carries a SHA-256 digest of its body. On load a missing or invalid main file falls back to a valid
// backup (a crash between the two renames, or a torn/corrupt main file). If files exist but none is
// valid the adapter refuses to start: it never silently restarts from an empty state, which would
// re-deliver or re-publish. Every state transition is designed to be safe to replay after falling
// back one save (broker idempotency keys and publication markers make replays idempotent).
//
// Lease: Windows uses a named pipe derived from the state directory; libuv creates it with
// FILE_FLAG_FIRST_PIPE_INSTANCE, so a second process gets EADDRINUSE, and the OS releases it when the
// process exits or is killed. No lock file exists, so there is nothing stale to delete. Elsewhere a
// Unix socket file in the state directory is used; a leftover socket after a crash is NOT deleted
// automatically: the adapter reports it and the operator removes it after checking no adapter runs.
import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, writeSync } from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { isoNow, sha256 } from '../../local-coordinator/src/util.mjs';

export const STATE_FILE = 'inbox-journal.json';
export const BACKUP_FILE = 'inbox-journal.json.bak';
export const ACTIVATION_FILE = 'activation.json';
const FORMAT = 'pocol-github-inbox-state/1';
const MAX_STATE_BYTES = 16 * 1024 * 1024;

export class JournalError extends Error {}

export function freshState(now = Date.now()) {
  return {
    version: 1,
    createdAt: isoNow(now),
    cursor: { page: 1, cyclesSinceFullScan: 0 },
    records: {},        // commentId -> accepted request record
    requestIds: {},     // requestId -> commentId of the first accepted comment (deterministic owner)
    ignored: {},        // commentId -> { reason, digest, at }
    markers: {},        // publication key -> GitHub comment id (seen on GitHub)
    rate: { nextAllowedAt: null, consecutiveFailures: 0, lastReason: null },
    lastCycle: null,
  };
}

function wrap(body, now) {
  const text = JSON.stringify(body);
  return JSON.stringify({ format: FORMAT, savedAt: isoNow(now), digest: sha256(text), body: text }) + '\n';
}

function unwrap(raw) {
  try {
    if (raw.length > MAX_STATE_BYTES) return null;
    const w = JSON.parse(raw);
    if (!w || w.format !== FORMAT || typeof w.body !== 'string' || w.digest !== sha256(w.body)) return null;
    const body = JSON.parse(w.body);
    if (!body || body.version !== 1 || typeof body.records !== 'object' || typeof body.requestIds !== 'object') return null;
    return body;
  } catch { return null; }
}

function readMaybe(file) {
  try { return readFileSync(file, 'utf8'); } catch (e) { if (e.code === 'ENOENT') return null; throw new JournalError(`cannot read ${path.basename(file)}: ${e.code || 'error'}`); }
}

export class Journal {
  constructor(stateDir, { now = Date.now } = {}) {
    this.dir = stateDir;
    this.main = path.join(stateDir, STATE_FILE);
    this.backup = path.join(stateDir, BACKUP_FILE);
    this.now = now;
    this.recoveredFromBackup = false;
  }

  /** Returns the state. Throws JournalError if state files exist but none is valid. */
  load() {
    const mainRaw = readMaybe(this.main), bakRaw = readMaybe(this.backup);
    if (mainRaw !== null) { const b = unwrap(mainRaw); if (b) return b; }
    if (bakRaw !== null) {
      const b = unwrap(bakRaw);
      if (b) { this.recoveredFromBackup = true; return b; }
    }
    if (mainRaw === null && bakRaw === null) return freshState(this.now());
    throw new JournalError('adapter state is corrupt and its backup is not usable; refusing to start from an empty state. Inspect coordination/ui-control/github-inbox manually.');
  }

  save(state) {
    mkdirSync(this.dir, { recursive: true });
    const tmp = path.join(this.dir, `${STATE_FILE}.${process.pid}.${randomBytes(4).toString('hex')}.tmp`);
    const fd = openSync(tmp, 'wx', 0o600);
    try {
      writeSync(fd, wrap(state, this.now()));
      fsyncSync(fd);
    } finally { closeSync(fd); }
    if (existsSync(this.main)) renameSync(this.main, this.backup);
    renameSync(tmp, this.main);
  }

  /**
   * Root-recorded activation evidence. Read only; the adapter never writes this file. Valid only
   * with connectionVerified === true and a non-empty evidence object.
   */
  activation() {
    const raw = readMaybe(path.join(this.dir, ACTIVATION_FILE));
    if (raw === null) return { connectionVerified: false, reason: 'noActivationRecord' };
    try {
      const a = JSON.parse(raw);
      const ev = a && a.evidence;
      const ok = a && a.connectionVerified === true && ev && typeof ev === 'object'
        && typeof ev.roundtripCommentUrl === 'string' && ev.duplicateCheck === 'passed' && ev.restartCheck === 'passed'
        && typeof a.recordedBy === 'string' && typeof a.recordedAt === 'string';
      return ok ? { connectionVerified: true, recordedAt: a.recordedAt } : { connectionVerified: false, reason: 'activationRecordIncomplete' };
    } catch { return { connectionVerified: false, reason: 'activationRecordUnreadable' }; }
  }
}

export function leaseName(stateDir, platform = process.platform) {
  const norm = platform === 'win32' ? path.resolve(stateDir).toLowerCase() : path.resolve(stateDir);
  return platform === 'win32' ? `\\\\.\\pipe\\pocol-github-inbox-${sha256(norm).slice(0, 24)}` : path.join(stateDir, 'adapter.sock');
}

export class LeaseError extends Error {}

/** Acquire the single-process lease. Resolves { name, release() }; rejects with LeaseError. */
export function acquireLease(stateDir, { platform = process.platform, netImpl = net } = {}) {
  mkdirSync(stateDir, { recursive: true });
  const name = leaseName(stateDir, platform);
  return new Promise((resolve, reject) => {
    const server = netImpl.createServer((sock) => sock.destroy());
    server.once('error', (e) => {
      if (e.code !== 'EADDRINUSE') return reject(new LeaseError(`cannot acquire adapter lease: ${e.code || 'error'}`));
      if (platform === 'win32') return reject(new LeaseError('another GitHub inbox adapter process is running for this workspace'));
      // POSIX: is someone listening, or is it a leftover socket file?
      const probe = netImpl.connect(name);
      probe.once('connect', () => { probe.destroy(); reject(new LeaseError('another GitHub inbox adapter process is running for this workspace')); });
      probe.once('error', () => reject(new LeaseError(`a leftover lease socket exists (${path.basename(name)}); it is not deleted automatically. Remove it manually after confirming no adapter is running.`)));
    });
    server.listen(name, () => {
      server.unref();
      let released = false;
      resolve({ name, release: () => new Promise((r) => { if (released) return r(); released = true; server.close(() => r()); }) });
    });
  });
}
