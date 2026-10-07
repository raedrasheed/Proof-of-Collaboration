import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Controller } from '../src/broker.mjs';
import { buildNotifyArgs, notificationMessage, Notifier, parseQueueId } from '../src/notifier.mjs';
import { MASK } from '../src/redact.mjs';
import { clock, fakeSpawner, makeWorkspace, resultLine } from './helpers.mjs';

const THREAD = '11111111-2222-4333-8444-555555555555';
const GH = 'ghp_' + 'b'.repeat(36);

/** Injected transport: records each send; results are scripted (default: delivered). */
function fakeNotifier({ results = [], onSend } = {}) {
  const sends = [];
  return {
    sends,
    configured: () => ({ ok: true }),
    describe: () => ({ configured: true, remote: 'unix://', threadId: THREAD }),
    send(info) { sends.push(info); onSend?.(info); const r = results.length ? results.shift() : { ok: true, queueId: 'queued-0001', output: 'queued queued-0001' }; return r instanceof Promise ? r : Promise.resolve(r); },
  };
}

function setup({ notifier = fakeNotifier(), ws = makeWorkspace(), c = clock(), sp = fakeSpawner(), hold = false } = {}) {
  const ctl = new Controller({ workspace: ws, claudeBin: 'claude-fake', spawnImpl: sp.spawnImpl, isAlive: () => false, now: c.now, notifier, holdNotifications: hold });
  return { ws, c, sp, ctl, notifier };
}
const notes = (ctl) => Object.values(ctl.state.notifications);

test('nothing is sent before the item and the attempt are durable; delivery is not attach/claim/ack', async () => {
  let onDisk = null, stateFile = null;
  const n = fakeNotifier({ onSend: () => { onDisk = JSON.parse(readFileSync(stateFile, 'utf8')); } });
  const { ctl } = setup({ notifier: n });
  stateFile = ctl.stateFile;
  const { item } = ctl.submitGuidance({ text: 'please look at 0.8', idempotencyKey: 'notify-guide-1' });
  assert.equal(n.sends.length, 1);
  assert.equal(onDisk.items[item.id].status, 'queued', 'item persisted before the send');
  const rec = onDisk.notifications[`queued:${item.id}`];
  assert.equal(rec.status, 'sending'); assert.equal(rec.attempts[0].status, 'sending', 'attempt persisted before the send');
  await ctl.notifyIdle();
  const done = ctl.state.notifications[`queued:${item.id}`];
  assert.equal(done.status, 'delivered'); assert.equal(done.queueId, 'queued-0001'); assert.ok(done.deliveredAt);
  assert.equal(ctl.state.items[item.id].status, 'queued', 'delivery does not claim or acknowledge');
  assert.equal(ctl.reviewerStatus().status, 'disconnected', 'delivery is not reviewer presence');
  assert.deepEqual(Object.keys(n.sends[0]).sort(), ['connectionPath', 'itemId', 'kind', 'reason', 'status']);
  assert.ok(!JSON.stringify(n.sends).includes('please look at 0.8'), 'browser text never reaches the transport');
});

test('duplicate idempotency key never re-queues or re-notifies; pause/resume do not notify', async () => {
  const { ctl, notifier } = setup();
  ctl.submitGuidance({ text: 'x', idempotencyKey: 'notify-dup-001' });
  ctl.submitGuidance({ text: 'x', idempotencyKey: 'notify-dup-001' });
  ctl.requestAuthorJob({ mode: 'smoke', idempotencyKey: 'notify-dup-job' });
  ctl.requestAuthorJob({ mode: 'smoke', idempotencyKey: 'notify-dup-job' });
  ctl.submitOwnerAnswer({ questionId: 'UI-TEST', choice: 'yes', idempotencyKey: 'notify-dup-own' });
  ctl.submitOwnerAnswer({ questionId: 'UI-TEST', choice: 'yes', idempotencyKey: 'notify-dup-own' });
  ctl.pause({ idempotencyKey: 'notify-pause-1' }); ctl.resume({ idempotencyKey: 'notify-resum-1' });
  await ctl.notifyIdle();
  assert.equal(notifier.sends.length, 3);
  assert.equal(notes(ctl).length, 3);
  assert.equal(ctl.state.order.length, 3);
  const job = ctl.state.items[ctl.state.order[1]];
  assert.equal(job.status, 'queued', 'a delivered notification never approves an author job');
});

test('restart during a send: the attempt becomes uncertain and is never replayed; explicit retry reuses the item', async () => {
  const ws = makeWorkspace(); const c = clock();
  const hang = fakeNotifier({ results: [new Promise(() => {})] });                  // the process "dies" mid-send
  const a = setup({ ws, c, notifier: hang }).ctl;
  const { item } = a.submitGuidance({ text: 'x', idempotencyKey: 'notify-crash-1' });
  assert.equal(hang.sends.length, 1);
  const n2 = fakeNotifier();
  const b = setup({ ws, c, notifier: n2 }).ctl;
  b.recover();
  const rec = b.state.notifications[`queued:${item.id}`];
  assert.equal(rec.status, 'uncertain'); assert.match(rec.error, /لا إعادة تلقائية/);
  assert.equal(n2.sends.length, 0, 'reload does not replay');
  const r = b.retryNotification({ notificationId: rec.id, idempotencyKey: 'notify-retry-01' });
  assert.equal(r.duplicate, false);
  await b.notifyIdle();
  assert.equal(n2.sends.length, 1); assert.equal(n2.sends[0].itemId, item.id);
  assert.equal(b.state.notifications[rec.id].status, 'delivered');
  assert.equal(b.state.notifications[rec.id].attempts.length, 2);
  assert.equal(b.state.order.length, 1, 'same queue item, nothing re-queued');
  const c2 = setup({ ws, c, notifier: fakeNotifier() }).ctl; c2.recover();
  assert.equal(c2.state.notifications[rec.id].status, 'delivered', 'delivered stays delivered across restarts');
});

test('held notifications (server start) are sent once on release, not before', async () => {
  const n = fakeNotifier();
  const { ctl } = setup({ notifier: n, hold: true });
  const { item } = ctl.submitGuidance({ text: 'x', idempotencyKey: 'notify-held-01' });
  assert.equal(n.sends.length, 0);
  assert.equal(ctl.state.notifications[`queued:${item.id}`].status, 'held');
  ctl.releaseNotifications(); ctl.releaseNotifications();
  await ctl.notifyIdle();
  assert.equal(n.sends.length, 1);
});

test('failed delivery: honest redacted error, no automatic retry, explicit retry, duplicate retry ignored', async () => {
  const n = fakeNotifier({ results: [{ ok: false, code: 1, error: 'codex queue exit 1', stderr: `daemon not running token ${GH}` }] });
  const { ctl, c } = setup({ notifier: n });
  const { item } = ctl.submitGuidance({ text: 'x', idempotencyKey: 'notify-fail-01' });
  await ctl.notifyIdle();
  const id = `queued:${item.id}`;
  assert.equal(ctl.state.notifications[id].status, 'failed');
  assert.match(ctl.state.notifications[id].error, /daemon not running/);
  assert.ok(!ctl.state.notifications[id].error.includes(GH) && ctl.state.notifications[id].error.includes(MASK));
  c.advance(600_000); ctl.tryDispatch(); await ctl.notifyIdle();
  assert.equal(n.sends.length, 1, 'no automatic retry');
  assert.equal(ctl.state.items[item.id].status, 'queued', 'the request itself stays durable');
  ctl.retryNotification({ notificationId: id, idempotencyKey: 'notify-retry-02' });
  const dup = ctl.retryNotification({ notificationId: id, idempotencyKey: 'notify-retry-02' });
  assert.equal(dup.duplicate, true);
  await ctl.notifyIdle();
  assert.equal(n.sends.length, 2);
  assert.equal(ctl.state.notifications[id].status, 'delivered');
  assert.throws(() => ctl.retryNotification({ notificationId: id, idempotencyKey: 'notify-retry-03' }), /سُلّم/);
});

test('more than 25 explicit failed retries: unique increasing attempts, none stuck, old keys never resend (also after reload)', async () => {
  const n = fakeNotifier({ results: Array.from({ length: 40 }, () => ({ ok: false, code: 1, error: 'daemon down' })) });
  const { ws, c, ctl } = setup({ notifier: n });
  const { item } = ctl.submitGuidance({ text: 'x', idempotencyKey: 'notify-many-base' });
  await ctl.notifyIdle();
  const id = `queued:${item.id}`;
  const keys = [];
  for (let k = 1; k <= 27; k++) {
    const key = `notify-many-${String(k).padStart(3, '0')}`;
    keys.push(key);
    assert.equal(ctl.retryNotification({ notificationId: id, idempotencyKey: key }).duplicate, false);
    await ctl.notifyIdle();
    assert.equal(ctl.state.notifications[id].status, 'failed', `retry ${k} completed (not stuck sending)`);
  }
  const rec = ctl.state.notifications[id];
  assert.equal(n.sends.length, 28);
  assert.equal(rec.attemptSeq, 28);
  assert.equal(rec.attempts.length, 20, 'display history is bounded');
  assert.deepEqual(rec.attempts.map((a) => a.n), Array.from({ length: 20 }, (_, k) => k + 9), 'unique, increasing, newest kept');
  assert.ok(rec.attempts.every((a) => a.status === 'failed'));
  for (const key of keys) assert.equal(ctl.retryNotification({ notificationId: id, idempotencyKey: key }).duplicate, true, `old key ${key}`);
  assert.equal(n.sends.length, 28, 'old accepted keys never cause another attempt');
  const n2 = fakeNotifier();
  const b = setup({ ws, c, notifier: n2 }).ctl;
  b.recover();
  for (const key of keys) assert.equal(b.retryNotification({ notificationId: id, idempotencyKey: key }).duplicate, true);
  assert.equal(n2.sends.length, 0, 'nor after a reload');
  b.retryNotification({ notificationId: id, idempotencyKey: 'notify-many-new01' });
  await b.notifyIdle();
  assert.equal(n2.sends.length, 1);
  assert.equal(b.state.notifications[id].attemptSeq, 29);
  assert.equal(b.state.notifications[id].status, 'delivered');
});

test('state written before the fix migrates: counter from the highest attempt, legacy keys kept', async () => {
  const ws = makeWorkspace(); const c = clock();
  const uiDir = path.join(ws, 'coordination', 'ui-control');
  mkdirSync(uiDir, { recursive: true });
  const itemId = '0f0e0d0c-0b0a-4908-8706-050403020101';
  const id = `queued:${itemId}`;
  const attempts = Array.from({ length: 20 }, (_, k) => ({ n: k + 2, status: 'failed', startedAt: 't', endedAt: 't' }));   // old trimmed history 2..21
  writeFileSync(path.join(uiDir, 'state.json'), JSON.stringify({
    schema: 'pocol-local-coordinator/1', paused: false, items: { [itemId]: { id: itemId, kind: 'guidance', status: 'queued', payload: { text: 'x' } } },
    order: [itemId], keys: {}, reviewer: null, currentJob: null, reviews: [], ownerAnswers: {}, events: [],
    notifications: { [id]: { id, itemId, reason: 'queued', status: 'failed', attempts, retryKeys: ['legacy-key-0001'] } },
  }));
  const n = fakeNotifier();
  const { ctl } = setup({ ws, c, notifier: n });
  assert.equal(ctl.retryNotification({ notificationId: id, idempotencyKey: 'legacy-key-0001' }).duplicate, true);
  assert.equal(n.sends.length, 0);
  ctl.retryNotification({ notificationId: id, idempotencyKey: 'fresh-key-00001' });
  await ctl.notifyIdle();
  const rec = ctl.state.notifications[id];
  assert.equal(rec.attempts.at(-1).n, 22, 'continues after the highest prior attempt');
  assert.equal(rec.status, 'delivered');
  assert.equal(new Set(rec.attempts.map((a) => a.n)).size, rec.attempts.length);
});

test('special keys: item and retry keys dedup, stay tied to their own notification, survive reload', async () => {
  const fail = () => ({ ok: false, code: 1, error: 'daemon down' });
  const n = fakeNotifier({ results: [fail(), fail(), fail(), fail()] });
  const { ws, c, ctl } = setup({ notifier: n });
  const g1 = ctl.submitGuidance({ text: 'one', idempotencyKey: '__proto__' }).item;
  const g2 = ctl.submitGuidance({ text: 'two', idempotencyKey: 'constructor' }).item;
  assert.equal(ctl.submitGuidance({ text: 'one', idempotencyKey: '__proto__' }).item.id, g1.id);
  await ctl.notifyIdle();
  assert.equal(n.sends.length, 2, 'one notification per item');
  const id1 = `queued:${g1.id}`, id2 = `queued:${g2.id}`;
  assert.equal(ctl.retryNotification({ notificationId: id1, idempotencyKey: 'toString' }).duplicate, false);
  await ctl.notifyIdle();
  const dup = ctl.retryNotification({ notificationId: id1, idempotencyKey: 'toString' });
  assert.equal(dup.duplicate, true); assert.equal(dup.notification.id, id1);
  const cross = ctl.retryNotification({ notificationId: id2, idempotencyKey: 'toString' });
  assert.equal(cross.duplicate, true, 'an accepted key never causes another attempt');
  assert.equal(cross.notification.id, id1, 'the key stays tied to the notification it was accepted for');
  assert.equal(ctl.retryNotification({ notificationId: id2, idempotencyKey: '__proto__' }).duplicate, false, 'retry keys are their own namespace');
  await ctl.notifyIdle();
  assert.equal(n.sends.length, 4);
  assert.deepEqual(n.sends.slice(2).map((s) => s.itemId), [g1.id, g2.id]);
  assert.equal(Object.getPrototypeOf(ctl.state.notifyRetryKeys), null);
  assert.throws(() => ctl.retryNotification({ notificationId: 'constructor', idempotencyKey: 'fresh-key-0001' }), /غير موجود/, 'inherited names are not notifications');
  assert.throws(() => ctl.retryNotification({ notificationId: '__proto__', idempotencyKey: 'fresh-key-0002' }), /غير موجود/);
  assert.equal(Object.getPrototypeOf({}), Object.prototype);
  assert.deepEqual(Object.keys(Object.prototype), []);

  const n2 = fakeNotifier();
  const b = setup({ ws, c, notifier: n2 }).ctl;
  b.recover();
  assert.equal(Object.getPrototypeOf(b.state.notifyRetryKeys), null);
  assert.equal(b.retryNotification({ notificationId: id1, idempotencyKey: 'toString' }).notification.id, id1);
  const after = b.retryNotification({ notificationId: id2, idempotencyKey: '__proto__' });
  assert.equal(after.duplicate, true); assert.equal(after.notification.id, id2);
  assert.equal(b.submitGuidance({ text: 'one', idempotencyKey: '__proto__' }).item.id, g1.id);
  assert.equal(b.submitGuidance({ text: 'two', idempotencyKey: 'constructor' }).duplicate, true);
  await b.notifyIdle();
  assert.equal(n2.sends.length, 0, 'no replay, no automatic retry after reload');
  assert.equal(b.state.order.length, 2);
});

test('no transport configured: request saved, honest notConfigured state', async () => {
  const ws = makeWorkspace();
  const ctl = new Controller({ workspace: ws, isAlive: () => false });
  const { item } = ctl.submitGuidance({ text: 'x', idempotencyKey: 'notify-none-01' });
  const rec = ctl.state.notifications[`queued:${item.id}`];
  assert.equal(rec.status, 'notConfigured'); assert.match(rec.error, /--codex-bin/);
  assert.equal(ctl.view().notifier.configured, false);
  assert.equal(ctl.state.items[item.id].status, 'queued');
});

test('job completion requests a review exactly once, even with repeated callbacks', async () => {
  const { ctl, sp, notifier } = setup();
  ctl.attach({ reviewerId: 'codex-host-sim' });                                      // actual presence, simulated host
  const { item } = ctl.requestAuthorJob({ mode: 'smoke', idempotencyKey: 'notify-job-001' });
  ctl.ack({ itemId: item.id, dispatch: {} });
  writeFileSync(path.join(ctl.uiDir, 'jobs', item.id, 'receipt.jsonl'), resultLine(false));
  const child = sp.calls[0].child;
  child.emit('exit', 0, null); child.emit('error', new Error('late error')); child.emit('exit', 0, null);
  ctl.finishJob(item.id, { code: 0, recovered: true });                             // e.g. the watch timer also fires
  await ctl.notifyIdle();
  const finished = notifier.sends.filter((s) => s.reason === 'jobFinished');
  assert.equal(finished.length, 1);
  assert.equal(finished[0].status, 'completed');
  assert.equal(ctl.state.reviews.length, 0, 'a notification is never a review');
  assert.equal(ctl.state.items[item.id].status, 'completed');
});

test('failed CLI run: bounded, redacted stderr excerpt is visible; executable-not-found is explicit', async () => {
  const { ctl, sp, notifier } = setup();
  ctl.attach({ reviewerId: 'codex-host-sim' });
  const a = ctl.requestAuthorJob({ mode: 'smoke', idempotencyKey: 'notify-stderr1' }).item;
  ctl.ack({ itemId: a.id, dispatch: {} });
  writeFileSync(path.join(ctl.uiDir, 'jobs', a.id, 'stderr.log'), 'x'.repeat(9000) + `\nError: No conversation found with session ID 83a0 (token ${GH})\n`);
  sp.calls[0].child.emit('exit', 1, null);
  const failed = ctl.state.items[a.id];
  assert.equal(failed.status, 'failed');
  assert.match(failed.stderrExcerpt, /No conversation found/);
  assert.ok(!failed.stderrExcerpt.includes(GH) && failed.stderrExcerpt.includes(MASK), 'secrets masked in the excerpt');
  assert.ok(failed.stderrExcerpt.length < 2200, 'excerpt is bounded');
  assert.match(failed.error, /No conversation found/);
  const viewed = JSON.stringify(ctl.view());
  assert.ok(viewed.includes('No conversation found') && !viewed.includes(GH));
  ctl.review({ jobId: a.id, verdict: 'revise', summaryAr: 'جلسة غير موجودة' });

  const b = ctl.requestAuthorJob({ mode: 'smoke', idempotencyKey: 'notify-enoent1' }).item;
  ctl.ack({ itemId: b.id, dispatch: {} });
  const err = Object.assign(new Error('spawn C:\\missing\\claude.exe ENOENT'), { code: 'ENOENT' });
  sp.calls[1].child.emit('error', err);
  const nf = ctl.state.items[b.id];
  assert.equal(nf.status, 'failed');
  assert.match(nf.error, /ENOENT/); assert.match(nf.error, /لم يُعثر على ملف claude/);
  assert.equal(ctl.worker.readLease(), null);
  await ctl.notifyIdle();
  assert.equal(notifier.sends.filter((s) => s.reason === 'jobFinished').length, 2);
});

// ---------- the real transport class with an injected process ----------
function fakeProc() {
  const p = new EventEmitter();
  p.stdout = new EventEmitter(); p.stderr = new EventEmitter(); p.killed = false; p.kill = () => { p.killed = true; };
  return p;
}
function realNotifier(behave, extra = {}) {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'pocol-codex-'));
  const exe = path.join(dir, 'codex.exe'); writeFileSync(exe, 'MZ');
  const calls = [];
  const spawnImpl = (cmd, args, opts) => { const p = fakeProc(); calls.push({ cmd, args, opts, p }); queueMicrotask(() => behave(p)); return p; };
  return { n: new Notifier({ codexBin: exe, threadId: THREAD, ws: dir, spawnImpl, platform: 'win32', ...extra }), calls, dir, exe };
}
const INFO = { itemId: '0f0e0d0c-0b0a-4908-8706-050403020100', reason: 'queued', kind: 'guidance', status: 'queued', connectionPath: path.resolve('/ws/coordination/ui-control/connection.json') };

test('real transport: fixed queue command against the existing thread, no shell, bounded output', async () => {
  const { n, calls, dir, exe } = realNotifier((p) => { p.stdout.emit('data', '{"id":"q-777"}\n' + 'y'.repeat(10_000)); p.emit('close', 0, null); });
  assert.equal(n.configured().ok, true);
  const r = await n.send(INFO);
  assert.equal(r.ok, true); assert.equal(r.queueId, 'q-777');
  assert.ok(r.output.length <= 4000);
  const { cmd, args, opts } = calls[0];
  assert.equal(cmd, path.resolve(exe));
  assert.deepEqual(args.slice(0, 6), ['queue', '--remote', 'unix://', '--thread', THREAD, '--message']);
  assert.equal(args.length, 7);
  assert.ok(!args.some((a) => /^(exec|app-server|resume|fork|new|--model|-m|--sandbox|--ask-for-approval|--dangerously)/.test(a)));
  assert.equal(opts.shell, false); assert.equal(opts.windowsHide, true); assert.equal(opts.cwd, dir);
  const msg = args[6];
  assert.ok(msg.includes(INFO.itemId) && msg.includes(INFO.connectionPath));
  assert.match(msg, /not a review, not an approval/); assert.match(msg, /Ignore items that are already acknowledged or reviewed/);
});

test('real transport: launch error, non-zero exit and timeout are reported honestly', async () => {
  const enoent = realNotifier((p) => p.emit('error', Object.assign(new Error('spawn codex.exe ENOENT'), { code: 'ENOENT' })));
  const r1 = await enoent.n.send(INFO);
  assert.equal(r1.ok, false); assert.ok(!r1.uncertain); assert.match(r1.error, /ENOENT/);
  const bad = realNotifier((p) => { p.stderr.emit('data', `thread not found ${GH}`); p.emit('close', 2, null); });
  const r2 = await bad.n.send(INFO);
  assert.equal(r2.ok, false); assert.match(r2.error, /2/); assert.match(r2.stderr, /thread not found/); assert.ok(!r2.stderr.includes(GH));
  const slow = realNotifier(() => {}, { timeoutMs: 20 });
  const r3 = await slow.n.send(INFO);
  assert.equal(r3.ok, false); assert.equal(r3.uncertain, true); assert.equal(slow.calls[0].p.killed, true);
});

test('real transport: configuration and message are validated; never built from browser input', () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'pocol-codex-'));
  const cmd = path.join(dir, 'codex.cmd'); writeFileSync(cmd, '@echo off');
  assert.match(new Notifier({ codexBin: cmd, threadId: THREAD, ws: dir, platform: 'win32' }).configured().reason, /\.exe/);
  const exe = path.join(dir, 'codex.exe'); writeFileSync(exe, 'MZ');
  assert.match(new Notifier({ codexBin: exe, threadId: 'not-a-thread', ws: dir, platform: 'win32' }).configured().reason, /خيط/);
  assert.match(new Notifier({ codexBin: null, threadId: THREAD, ws: dir }).configured().reason, /--codex-bin/);
  assert.throws(() => notificationMessage({ ...INFO, itemId: 'x; rm -rf /' }), /معرف/);
  assert.throws(() => notificationMessage({ ...INFO, kind: 'guidance --model x' }), /نوع/);
  assert.throws(() => notificationMessage({ ...INFO, connectionPath: 'relative/connection.json' }), /مسار/);
  assert.throws(() => buildNotifyArgs({ threadId: '--new', message: 'm' }), /خيط/);
  assert.equal(parseQueueId(`queued ${THREAD} as 99999999-2222-4333-8444-555555555555`, [THREAD]), '99999999-2222-4333-8444-555555555555');
});

test('real transport through the broker: browser text and secrets never reach the command line', async () => {
  const seen = [];
  const { n } = realNotifier((p) => p.emit('close', 0, null));
  const orig = n.spawnImpl;
  n.spawnImpl = (cmd, args, opts) => { seen.push(args); return orig(cmd, args, opts); };
  const { ctl } = setup({ notifier: n });
  ctl.submitGuidance({ text: `BROWSER-TEXT-MARKER --model evil ${GH}`, idempotencyKey: 'notify-real-001' });
  await ctl.notifyIdle();
  assert.equal(seen.length, 1);
  const line = seen[0].join(' ');
  assert.ok(!line.includes('BROWSER-TEXT-MARKER') && !line.includes(GH) && !line.includes('--model'));
  assert.ok(line.includes(ctl.connectionFile));
});
