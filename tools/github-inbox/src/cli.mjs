// GitHub inbox adapter command line (Node 22, standard library only).
//
//   node src/cli.mjs --config FILE --once     one cycle, then exit (exit 0 ok, 1 cycle reported an error, 2 usage/config/lease)
//   node src/cli.mjs --config FILE --poll     cycles every pollSeconds (>= 30, default 60); failures back off
//                                             exponentially up to 900 s; GitHub Retry-After/rate limits are respected
//   node src/cli.mjs --config FILE --status   print the sanitized status (no lease, no network)
//   node src/cli.mjs --config FILE --retry-delivery REQUEST_ID
//                                             operator retry (0.42): re-enable delivery of ONE stalled or failed request
//                                             with the SAME broker key, comment ID and request ID (no new item). Takes the
//                                             lease, changes only that record, sends nothing itself; the next cycle delivers.
//                                             Exit 0 re-enabled, 1 not applicable, 2 usage/config/lease.
//   node src/cli.mjs --config FILE --reset-journal
//                                             operator reset (0.42): rename (never delete) the journal files to dated
//                                             evidence names and start a fresh journal WITH a reconciliation barrier, so no
//                                             existing reply is reposted. Coordinator items keep their keys. Takes the lease.
//
// Stop --poll with Ctrl+C (or by ending THIS process). That never touches the coordinator, its pause
// control or any author job. The adapter prints no "ACTIVE" claim: connectionVerified stays false
// until root records end-to-end evidence in activation.json by hand (see README).
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { appendLog, readJson } from '../../local-coordinator/src/util.mjs';
import { Adapter, publicStatus, resetJournal } from './adapter.mjs';
import { BrokerClient, loadConnection } from './broker-client.mjs';
import { loadConfig } from './config.mjs';
import { BACKOFF_MAX_S, REQUEST_ID_RE } from './constants.mjs';
import { GhClient } from './gh.mjs';
import { acquireLease, Journal } from './journal.mjs';
import { publicText } from './sanitize.mjs';

function parseArgs(argv) {
  const out = { config: null, mode: null, requestId: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--config') { out.config = argv[++i] ?? null; continue; }
    if (['--once', '--poll', '--status', '--retry-delivery', '--reset-journal'].includes(a)) {
      if (out.mode) throw new Error('choose exactly one of --once, --poll, --status, --retry-delivery, --reset-journal');
      out.mode = a.slice(2);
      if (a === '--retry-delivery') {
        out.requestId = argv[++i] ?? null;
        if (!REQUEST_ID_RE.test(out.requestId || '')) throw new Error('--retry-delivery needs a valid request ID');
      }
      continue;
    }
    throw new Error(`unknown argument ${JSON.stringify(a).slice(0, 40)}`);
  }
  if (!out.config || !out.mode) throw new Error('usage: --config FILE (--once | --poll | --status | --retry-delivery REQUEST_ID | --reset-journal)');
  return out;
}

/** Wire production dependencies for a validated config. */
export function buildAdapter(config, { now = Date.now } = {}) {
  const journal = new Journal(config.stateDir, { now });
  const gh = new GhClient({ ghBin: config.ghBin, cwd: config.workspaceRoot });
  const brokerFactory = () => {
    const c = loadConnection(config.connectionPath, config.workspaceRoot);
    return new BrokerClient({ port: c.port, controlToken: c.controlToken });
  };
  const readCheckpoint = () => readJson(config.checkpointPath, null);
  const logFile = path.join(config.stateDir, 'adapter.log');
  const log = (record) => appendLog(logFile, record);
  return { journal, adapter: new Adapter({ journal, gh, brokerFactory, readCheckpoint, now, log }) };
}

/** Delay before the next poll cycle, in ms. */
export function nextDelayMs({ pollSeconds, state, now = Date.now() }) {
  const failures = state.rate.consecutiveFailures || 0;
  let s = failures > 0 ? Math.min(BACKOFF_MAX_S, pollSeconds * 2 ** Math.min(10, failures)) : pollSeconds;
  const until = state.rate.nextAllowedAt ? Date.parse(state.rate.nextAllowedAt) - now : 0;
  if (until > s * 1000) s = Math.min(BACKOFF_MAX_S, Math.ceil(until / 1000));
  return s * 1000;
}

export async function main(argv = process.argv.slice(2), { stdout = process.stdout, stderr = process.stderr } = {}) {
  if (Number(process.versions.node.split('.')[0]) < 22) { stderr.write('Node.js 22 or newer is required\n'); return 2; }
  let args, config;
  try { args = parseArgs(argv); config = loadConfig(args.config); } catch (e) { stderr.write(publicText(String(e.message), 400) + '\n'); return 2; }
  if (args.mode === 'status') {
    try {
      const j = new Journal(config.stateDir);
      stdout.write(JSON.stringify(publicStatus(j.load(), j.activation()), null, 2) + '\n');
      return 0;
    } catch (e) { stderr.write(publicText(String(e.message), 400) + '\n'); return 2; }
  }
  let lease;
  try { lease = await acquireLease(config.stateDir); } catch (e) { stderr.write(publicText(String(e.message), 400) + '\n'); return 2; }
  if (args.mode === 'reset-journal') {
    try { const archived = resetJournal(new Journal(config.stateDir)); stdout.write(JSON.stringify({ reset: true, archived, reconcileBarrier: true }) + '\n'); return 0; }
    catch (e) { stderr.write(publicText(String(e.message), 400) + '\n'); return 2; }
    finally { await lease.release(); }
  }
  let built;
  try { built = buildAdapter(config); } catch (e) { await lease.release(); stderr.write(publicText(String(e.message), 400) + '\n'); return 2; }
  const { adapter } = built;
  const print = (sum) => stdout.write(JSON.stringify(sum) + '\n');
  if (args.mode === 'retry-delivery') {
    try { const r = adapter.operatorRetry(args.requestId); print(r); return r.ok ? 0 : 1; }
    catch (e) { stderr.write(publicText(String(e.message), 400) + '\n'); return 2; }
    finally { await lease.release(); }
  }
  if (args.mode === 'once') {
    try { const sum = await adapter.cycle(); print(sum); return sum.error ? 1 : 0; }
    catch (e) { stderr.write(publicText(String(e.message), 400) + '\n'); return 1; }
    finally { await lease.release(); }
  }
  // --poll: one cycle at a time; never overlapping; stops between cycles on a signal.
  let stopping = false, wake = null;
  const stop = () => { stopping = true; if (wake) wake(); };
  process.on('SIGINT', stop); process.on('SIGTERM', stop);
  try {
    while (!stopping) {
      try { print(await adapter.cycle()); }
      catch (e) { stderr.write(publicText(String(e.message), 400) + '\n'); adapter.state.rate.consecutiveFailures += 1; }
      if (stopping) break;
      const ms = nextDelayMs({ pollSeconds: config.pollSeconds, state: adapter.state });
      // Referenced timer: it is what keeps --poll alive between cycles (the lease handle is unref'd).
      await new Promise((r) => { const t = setTimeout(r, ms); wake = () => { clearTimeout(t); r(); }; });
      wake = null;
    }
  } finally {
    process.off('SIGINT', stop); process.off('SIGTERM', stop);
    await lease.release();
  }
  return 0;
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  main().then((code) => { process.exitCode = code; });
}
