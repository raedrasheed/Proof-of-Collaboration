import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync, existsSync, readFileSync, readdirSync, unlinkSync } from 'node:fs';
import path from 'node:path';
import { Controller } from '../src/broker.mjs';
import { clock, fakeSpawner, makeWorkspace, resultLine } from './helpers.mjs';

// The host coordinator is simulated through the same reviewer API the real host uses
// (attach/heartbeat/claim/ack/review). Nothing here fabricates a review on its own.
const HOST = 'codex-host-sim';

function setup({ attach = true, ...opts } = {}) {
  const ws = makeWorkspace(opts);
  const sp = fakeSpawner();
  const c = clock();
  const alive = new Set();
  const ctl = new Controller({ workspace: ws, claudeBin: 'claude-fake', spawnImpl: sp.spawnImpl, isAlive: (pid) => alive.has(pid), now: c.now, watchMs: 10 });
  if (attach) ctl.attach({ reviewerId: HOST });
  return { ws, sp, c, alive, ctl };
}

/** The server restarts over the same ui-control directory (same clock, so the host lease is still valid). */
function restart(ws, c, isAlive = () => false, extra = {}) {
  const sp2 = fakeSpawner();
  const ctl2 = new Controller({ workspace: ws, claudeBin: 'claude-fake', spawnImpl: sp2.spawnImpl, isAlive, now: c.now, ...extra });
  return { sp2, ctl2 };
}

function finish(ctl, sp, idx, { isError = false } = {}) {
  const { child } = sp.calls[idx];
  const jobId = ctl.state.currentJob;
  writeFileSync(path.join(ctl.uiDir, 'jobs', jobId, 'receipt.jsonl'), resultLine(isError));
  child.emit('exit', isError ? 1 : 0, null);
  return jobId;
}

test('duplicate guidance submissions create one queued item', () => {
  const { ctl } = setup();
  const a = ctl.submitGuidance({ text: 'please check 0.8', idempotencyKey: 'guide-key-0001' });
  const b = ctl.submitGuidance({ text: 'please check 0.8', idempotencyKey: 'guide-key-0001' });
  assert.equal(a.duplicate, false); assert.equal(b.duplicate, true);
  assert.equal(a.item.id, b.item.id);
  assert.equal(ctl.state.order.length, 1);
});

test('author job: one spawn, no replay, next job waits for the actual review', () => {
  const { ctl, sp } = setup();
  const r1 = ctl.requestAuthorJob({ mode: 'smoke', idempotencyKey: 'job-key-00001' });
  ctl.requestAuthorJob({ mode: 'smoke', idempotencyKey: 'job-key-00001' });       // duplicate click
  assert.equal(sp.calls.length, 0, 'nothing runs before the coordinator approves');
  ctl.ack({ itemId: r1.item.id, dispatch: {} });
  assert.equal(sp.calls.length, 1);
  assert.equal(sp.calls[0].opts.shell, false);
  const args = sp.calls[0].args;
  assert.equal(args[args.indexOf('--tools') + 1], 'Read,Glob,Grep', 'smoke capability set is read-only');
  const allowed = args.slice(args.indexOf('--allowedTools') + 1, args.indexOf('--disallowedTools'));
  assert.deepEqual(allowed, ['Read', 'Glob', 'Grep'], 'smoke job is read-only');
  assert.equal(args[args.indexOf('--permission-mode') + 1], 'default');
  assert.ok(args.slice(args.indexOf('--disallowedTools')).includes('Bash') && args.includes('--resume'));
  const r2 = ctl.requestAuthorJob({ mode: 'smoke', idempotencyKey: 'job-key-00002' });
  ctl.ack({ itemId: r2.item.id, dispatch: {} });
  ctl.tryDispatch(); ctl.tryDispatch();
  assert.equal(sp.calls.length, 1, 'second job does not run concurrently');
  const jobId = finish(ctl, sp, 0);
  assert.equal(ctl.state.items[jobId].status, 'completed');
  ctl.tryDispatch();
  assert.equal(sp.calls.length, 1, 'completed job must be reviewed before another job');
  assert.equal(ctl.waitingReason(), 'waitingReview');
  ctl.review({ jobId, verdict: 'accept', summaryAr: 'مراجعة فعلية' });
  assert.equal(sp.calls.length, 2, 'review releases the next approved job');
  // The duplicate guard comes first, so a second review of the same job says "already reviewed".
  assert.throws(() => ctl.review({ jobId, verdict: 'accept', summaryAr: 'مكرر' }), /رُوجعت بالفعل/);
  assert.equal(ctl.state.reviews.length, 1);
});

test('failed author turn needs an actual review before any dispatch; retry stays available after it', () => {
  const { ctl, sp } = setup();
  const r1 = ctl.requestAuthorJob({ mode: 'smoke', idempotencyKey: 'fail-job-0001' });
  ctl.ack({ itemId: r1.item.id, dispatch: {} });
  const jobId = finish(ctl, sp, 0, { isError: true });
  assert.equal(ctl.state.items[jobId].status, 'failed');
  assert.equal(ctl.waitingReason(), 'workerFailed');
  const retry = ctl.requestAuthorJob({ mode: 'smoke', idempotencyKey: 'fail-retry-01', retryOf: jobId });
  ctl.ack({ itemId: retry.item.id, dispatch: {} });
  assert.equal(sp.calls.length, 1, 'an unreviewed failure blocks the retry');
  assert.match(ctl.state.items[retry.item.id].blockedReason, /مراجعة Codex الفعلية/);
  ctl.review({ jobId, verdict: 'revise', summaryAr: 'الفشل رُوجع فعليًا' });
  assert.equal(ctl.state.items[jobId].status, 'failed', 'a reviewed failure stays failed (retry remains possible)');
  assert.ok(ctl.state.items[jobId].reviewId);
  assert.equal(sp.calls.length, 2, 'the approved retry starts only after the review');
  // Retrying the same reviewed failure is still accepted (a new explicit request, new approval).
  const again = ctl.requestAuthorJob({ mode: 'smoke', idempotencyKey: 'fail-retry-02', retryOf: jobId });
  assert.equal(again.item.status, 'queued');
});

test('a worker start failure leaves no lease and must be reviewed', () => {
  const ws = makeWorkspace();
  const c = clock();
  const ctl = new Controller({ workspace: ws, claudeBin: 'claude-fake', spawnImpl: () => { throw new Error('spawn EACCES'); }, isAlive: () => false, now: c.now });
  ctl.attach({ reviewerId: HOST });
  const r = ctl.requestAuthorJob({ mode: 'smoke', idempotencyKey: 'start-fail-01' });
  ctl.ack({ itemId: r.item.id, dispatch: {} });
  const item = ctl.state.items[r.item.id];
  assert.equal(item.status, 'failed');
  assert.ok(item.endedAt);
  assert.equal(ctl.worker.readLease(), null, 'lease removed after the failed start');
  assert.equal(ctl.state.currentJob, null);
  assert.equal(ctl.waitingReason(), 'workerFailed');
});

test('pause drains to the job boundary, preserves state, and resume dispatches', () => {
  const { ctl, sp } = setup();
  const r1 = ctl.requestAuthorJob({ mode: 'smoke', idempotencyKey: 'pause-job-01' });
  ctl.ack({ itemId: r1.item.id, dispatch: {} });
  ctl.pause({ idempotencyKey: 'pause-key-01' });
  assert.equal(ctl.pauseState(), 'draining');
  const jobId = finish(ctl, sp, 0);
  assert.equal(ctl.pauseState(), 'paused');
  ctl.review({ jobId, verdict: 'accept', summaryAr: 'تمت' });
  const r2 = ctl.requestAuthorJob({ mode: 'smoke', idempotencyKey: 'pause-job-02' });
  ctl.ack({ itemId: r2.item.id, dispatch: {} });
  assert.equal(sp.calls.length, 1, 'no dispatch while paused');
  assert.equal(ctl.state.items[r2.item.id].blockedReason, 'متوقف مؤقتًا');
  ctl.resume({ idempotencyKey: 'resume-key-01', reason: 'test' });
  assert.equal(sp.calls.length, 2);
  assert.ok(ctl.state.events.some((e) => e.kind === 'resume'));
});

test('restart: finished child is imported without spawning', () => {
  const { ws, c, ctl, sp } = setup();
  const r = ctl.requestAuthorJob({ mode: 'smoke', idempotencyKey: 'restart-job-1' });
  ctl.ack({ itemId: r.item.id, dispatch: {} });
  writeFileSync(path.join(ctl.uiDir, 'jobs', r.item.id, 'receipt.jsonl'), resultLine(false));
  // the server dies: a new controller over the same directory, the old pid is dead
  const { ctl2, sp2 } = restart(ws, c);
  ctl2.recover();
  assert.equal(ctl2.state.items[r.item.id].status, 'completed');
  assert.equal(sp2.calls.length, 0);
  assert.equal(sp.calls.length, 1);
  assert.equal(ctl2.worker.readLease(), null);
  assert.equal(ctl2.waitingReason(), 'waitingReview');
});

test('restart: dead child without a result is interrupted, reviewed, then explicitly retried', () => {
  const { ws, c, ctl } = setup();
  const r = ctl.requestAuthorJob({ mode: 'smoke', idempotencyKey: 'interrupt-job' });
  ctl.ack({ itemId: r.item.id, dispatch: {} });
  const { ctl2, sp2 } = restart(ws, c);
  ctl2.recover();
  assert.equal(ctl2.state.items[r.item.id].status, 'interrupted');
  assert.equal(ctl2.reviewerStatus().status, 'attached', 'the host attachment survives the restart within its lease');
  ctl2.tryDispatch();
  assert.equal(sp2.calls.length, 0, 'no automatic respawn');
  assert.equal(ctl2.waitingReason(), 'workerFailed');
  ctl2.review({ jobId: r.item.id, verdict: 'revise', summaryAr: 'انقطاع رُوجع' });
  assert.equal(ctl2.state.items[r.item.id].status, 'interrupted');
  assert.equal(ctl2.waitingReason(), 'retryAvailable');
  assert.equal(sp2.calls.length, 0, 'a review never starts a follow-up by itself');
  const retry = ctl2.requestAuthorJob({ mode: 'smoke', idempotencyKey: 'retry-key-001', retryOf: r.item.id });
  assert.equal(sp2.calls.length, 0, 'retry still needs coordinator approval');
  ctl2.ack({ itemId: retry.item.id, dispatch: {} });
  assert.equal(sp2.calls.length, 1);
});

test('restart: a live child is re-attached, never duplicated', () => {
  const { ws, c, ctl, sp } = setup();
  const r = ctl.requestAuthorJob({ mode: 'smoke', idempotencyKey: 'alive-job-001' });
  ctl.ack({ itemId: r.item.id, dispatch: {} });
  const pid = sp.calls[0].child.pid;
  const { ctl2, sp2 } = restart(ws, c, (p) => p === pid, { watchMs: 60_000 });
  ctl2.recover();
  assert.equal(ctl2.state.items[r.item.id].status, 'running');
  const r2 = ctl2.requestAuthorJob({ mode: 'smoke', idempotencyKey: 'alive-job-002' });
  ctl2.ack({ itemId: r2.item.id, dispatch: {} });
  assert.equal(sp2.calls.length, 0);
  ctl2.stop();
});

// ---------- service lock (UI07) ----------
const DEAD = 999999;
const lockDir = (ws) => path.join(ws, 'coordination', 'ui-control');
const lockFile = (ws) => path.join(lockDir(ws), 'service.lock');
const readLock = (ws) => readFileSync(lockFile(ws), 'utf8');

test('stale service lock is taken over with evidence; a live one refuses', () => {
  const { ws } = setup();
  const stale = JSON.stringify({ pid: DEAD });
  writeFileSync(lockFile(ws), stale);
  const a = new Controller({ workspace: ws, isAlive: () => false });
  a.acquireService(1);
  assert.ok(a.state.events.some((e) => e.kind === 'service.staleLockRecovered'));
  assert.equal(JSON.parse(readLock(ws)).owner, a.serviceOwner);
  const evidence = readdirSync(lockDir(ws)).filter((f) => f.startsWith('service.lock.stale-'));
  assert.equal(evidence.length, 1, 'stale lock content preserved');
  assert.equal(readFileSync(path.join(lockDir(ws), evidence[0]), 'utf8'), stale);
  assert.equal(existsSync(`${lockFile(ws)}.recovery`), false, 'recovery mutex released');
  writeFileSync(lockFile(ws), JSON.stringify({ pid: 4242, owner: 'other-service' }));
  const b = new Controller({ workspace: ws, isAlive: (p) => p === 4242 });
  assert.throws(() => b.acquireService(2), /تعمل بالفعل/);
});

test('empty or malformed lock fails closed even when every pid looks dead', () => {
  const { ws } = setup();
  for (const bad of ['', '{"pid":', '{"pid":"4242"}', '{"pid":0}', '{"pid":4242,"owner":5}', 'null']) {
    writeFileSync(lockFile(ws), bad);
    const c = new Controller({ workspace: ws, isAlive: () => false });
    assert.throws(() => c.acquireService(1), /فارغ أو غير صالح/, `refuses ${JSON.stringify(bad)}`);
    assert.equal(readLock(ws), bad, 'the lock is left untouched (its writer may still be initializing)');
  }
  assert.equal(readdirSync(lockDir(ws)).filter((f) => f.startsWith('service.lock.stale-')).length, 0);
});

test('two controllers in the same process: no shared ownership; owner updates port and releases', () => {
  const { ws } = setup();
  const a = new Controller({ workspace: ws, isAlive: () => false });   // isAlive is not what protects a same-pid owner
  const b = new Controller({ workspace: ws, isAlive: () => false });
  a.acquireService(null);
  assert.throws(() => b.acquireService(null), /تعمل بالفعل/);
  b.releaseService();
  assert.equal(JSON.parse(readLock(ws)).owner, a.serviceOwner, 'a non-owner release does nothing');
  a.acquireService(4321);                                                // normal second call with the real port
  const cur = JSON.parse(readLock(ws));
  assert.equal(cur.port, 4321); assert.equal(cur.owner, a.serviceOwner);
  a.releaseService();
  assert.equal(existsSync(lockFile(ws)), false);
});

test('release never removes a successor lock; a replaced owner cannot update it', () => {
  const { ws } = setup();
  const a = new Controller({ workspace: ws, isAlive: () => false });
  a.acquireService(1);
  const successor = JSON.stringify({ pid: 4242, owner: 'successor-owner', port: 2 });
  writeFileSync(lockFile(ws), successor);
  assert.throws(() => a.acquireService(3), /لم يعد مملوكًا/);
  assert.equal(readLock(ws), successor);
  a.releaseService();
  assert.equal(readLock(ws), successor, 'foreign lock survives release');
});

test('competing stale recovery: one mutex holder at a time; a late recoverer re-reads and stops', () => {
  const { ws } = setup();
  const stale = JSON.stringify({ pid: DEAD, owner: 'dead-owner' });
  const mutex = `${lockFile(ws)}.recovery`;
  const alive = (p) => p !== DEAD;
  writeFileSync(lockFile(ws), stale);
  // (1) another live process is recovering right now
  writeFileSync(mutex, JSON.stringify({ pid: process.pid, owner: 'other-recoverer' }));
  const a = new Controller({ workspace: ws, isAlive: alive });
  assert.throws(() => a.acquireService(1), /استعادة قفل الخدمة جارية/);
  assert.equal(readLock(ws), stale); assert.ok(existsSync(mutex), 'a foreign mutex is not removed');
  // (2) an abandoned mutex fails closed
  writeFileSync(mutex, JSON.stringify({ pid: DEAD, owner: 'dead-recoverer' }));
  assert.throws(() => a.acquireService(1), /متروك/);
  assert.equal(readLock(ws), stale);
  unlinkSync(mutex);                                                     // the operator's manual step
  // (3) both judged the same stale lock; a wins, b re-reads under the mutex and stops
  const b = new Controller({ workspace: ws, isAlive: alive });
  a.acquireService(1);
  assert.equal(JSON.parse(readLock(ws)).owner, a.serviceOwner);
  b.serviceOwner = 'b-owner'; b.serviceStartedAt = 'x';
  assert.throws(() => b._takeOverStale(lockFile(ws), stale, JSON.parse(stale), 2), /تغيّر قفل الخدمة/);
  assert.equal(JSON.parse(readLock(ws)).owner, a.serviceOwner, 'the winner keeps the lock');
  assert.equal(existsSync(mutex), false, 'b removed only its own mutex');
  assert.throws(() => b.acquireService(2), /تعمل بالفعل/);
});

test('ledger with an uncheckpointed author blocks dispatch', () => {
  const { ctl, sp } = setup({ activeState: 'running' });
  const r = ctl.requestAuthorJob({ mode: 'smoke', idempotencyKey: 'ledger-block1' });
  ctl.ack({ itemId: r.item.id, dispatch: {} });
  assert.equal(sp.calls.length, 0);
  assert.match(ctl.state.items[r.item.id].blockedReason, /مؤلفًا نشطًا/);
});

test('author dispatch plan is validated; browser text never becomes CLI arguments', () => {
  const { ws, ctl, sp } = setup();
  const r = ctl.requestAuthorJob({ mode: 'author', note: '--dangerously-skip-permissions; rm -rf /', idempotencyKey: 'plan-key-0001' });
  assert.throws(() => ctl.ack({ itemId: r.item.id, dispatch: { taskFile: '../secret.md', plannedDir: 'm1-draft-0.9' } }), /ملف المهمة/);
  mkdirSync(path.join(ws, 'm1-draft-0.9'));
  assert.throws(() => ctl.ack({ itemId: r.item.id, dispatch: { taskFile: 'task-006.md', plannedDir: 'm1-draft-0.9' } }), /موجود بالفعل/);
  ctl.ack({ itemId: r.item.id, dispatch: { taskFile: 'task-006.md', plannedDir: 'm1-draft-0.10' } });
  const args = sp.calls[0].args;
  assert.ok(!args.join(' ').includes('rm -rf'));
  assert.ok(!args.includes('--dangerously-skip-permissions'));
  assert.equal(args[args.indexOf('--tools') + 1], 'Read,Glob,Grep,Write,Edit');
  assert.ok(args.includes('Write(./m1-draft-0.10/**)'));
  assert.equal(existsSync(path.join(ws, 'm1-draft-0.10')), false, 'the broker never creates the planned directory itself');
});

test('reviewer attachment expires honestly and an absent host blocks dispatch', () => {
  const { ctl, sp, c } = setup({ attach: false });
  const r = ctl.requestAuthorJob({ mode: 'smoke', idempotencyKey: 'expire-job-01' });
  ctl.ack({ itemId: r.item.id, dispatch: {} });                    // e.g. approved just before the host turn ended
  assert.equal(sp.calls.length, 0, 'no host attached: nothing starts');
  assert.match(ctl.state.items[r.item.id].blockedReason, /غير متصل/);
  assert.equal(ctl.waitingReason(), 'waitingReviewerAttach');
  ctl.attach({ reviewerId: HOST, leaseMs: 15_000 });
  assert.equal(ctl.reviewerStatus().status, 'attached');
  assert.equal(sp.calls.length, 1, 'the already-approved job starts once the host is present');
  const jobId = finish(ctl, sp, 0);
  ctl.review({ jobId, verdict: 'accept', summaryAr: 'رُوجعت' });
  const r2 = ctl.requestAuthorJob({ mode: 'smoke', idempotencyKey: 'expire-job-02' });
  ctl.ack({ itemId: r2.item.id, dispatch: {} });
  assert.equal(sp.calls.length, 2);
  finish(ctl, sp, 1);
  ctl.review({ jobId: ctl.state.order.at(-1), verdict: 'accept', summaryAr: 'رُوجعت' });
  const r3 = ctl.requestAuthorJob({ mode: 'smoke', idempotencyKey: 'expire-job-03' });
  c.advance(16_000);
  assert.equal(ctl.reviewerStatus().status, 'expired');
  assert.equal(ctl.waitingReason(), 'waitingReviewerAttach');
  ctl.ack({ itemId: r3.item.id, dispatch: {} });
  assert.equal(sp.calls.length, 2, 'expired host lease blocks dispatch');
  ctl.heartbeat();
  assert.equal(ctl.reviewerStatus().status, 'attached');
  assert.equal(sp.calls.length, 3);
  finish(ctl, sp, 2);
  ctl.detach();
  const r4 = ctl.requestAuthorJob({ mode: 'smoke', idempotencyKey: 'expire-job-04' });
  ctl.ack({ itemId: r4.item.id, dispatch: {} });
  assert.equal(sp.calls.length, 3, 'detached host: no dispatch (and the last job is still unreviewed)');
});

test('current receipts and actual reviews appear as timestamped Claude/Codex cards', () => {
  const { ctl, sp, c } = setup();
  const before = ctl.timelineCards();
  const sig0 = ctl.view().timelineSig;
  const r = ctl.requestAuthorJob({ mode: 'smoke', idempotencyKey: 'card-job-0001' });
  ctl.ack({ itemId: r.item.id, dispatch: {} });
  c.advance(5_000);
  const jobId = finish(ctl, sp, 0);
  const sig1 = ctl.view().timelineSig;
  assert.notEqual(sig1, sig0, 'a finished job changes the signature the page polls');
  c.advance(5_000);
  const review = ctl.review({ jobId, verdict: 'accept', summaryAr: 'مراجعة المضيف', text: 'checked receipt' });
  assert.notEqual(ctl.view().timelineSig, sig1);
  const cards = ctl.timelineCards();
  for (const h of before) assert.ok(cards.some((x) => x.id === h.id), 'historical cards preserved');
  const job = cards.find((x) => x.id === `job-${jobId}`);
  const rev = cards.find((x) => x.id === `review-${review.id}`);
  assert.equal(job.actor, 'Claude'); assert.equal(job.role, 'author'); assert.equal(job.current, true);
  assert.equal(job.time, ctl.state.items[jobId].endedAt);
  assert.match(job.sha256, /^[0-9a-f]{64}$/);
  assert.ok(job.source.endsWith(`jobs/${jobId}/receipt.jsonl`));
  assert.equal(job.result.text, 'status: 0.8 verified');
  assert.equal(rev.actor, 'Codex'); assert.equal(rev.role, 'reviewer');
  assert.equal(rev.time, review.at); assert.equal(rev.reviewerId, HOST); assert.equal(rev.verdict, 'accept');
  assert.ok(cards.indexOf(job) < cards.indexOf(rev), 'chronological: the job before its review');
  const times = cards.map((x) => x.time).filter(Boolean).map(Date.parse);
  assert.deepEqual(times, [...times].sort((a, b) => a - b), 'known times are in order');
  assert.ok(cards.some((x) => x.time === null && x.timeNote), 'unknown times stay unknown and are labelled');
});

test('owner answers are queued, never approved; UI-TEST is test-only', () => {
  const { ctl } = setup();
  const t = ctl.submitOwnerAnswer({ questionId: 'UI-TEST', choice: 'yes', idempotencyKey: 'owner-test-01' });
  assert.equal(t.item.payload.testOnly, true);
  const u = ctl.submitOwnerAnswer({ questionId: 'U14', choice: 'per-request', idempotencyKey: 'owner-u14-001' });
  assert.equal(ctl.state.ownerAnswers.U14.status, 'queued');
  assert.throws(() => ctl.submitOwnerAnswer({ questionId: 'U14', choice: 'approve-everything', idempotencyKey: 'owner-bad-001' }), /خيار/);
  ctl.claim({ itemId: u.item.id });
  ctl.ack({ itemId: u.item.id, note: 'received' });
  assert.equal(ctl.state.ownerAnswers.U14.status, 'acknowledged');
  assert.ok(!JSON.stringify(ctl.view()).includes('"approved"'));
});
