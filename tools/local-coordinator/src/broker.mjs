// Persisted control broker for the CURRENT host coordinator. It never reviews, never
// creates agent turns on its own, and never starts a reviewer process. Browser requests
// and the host coordinator's reviewer API go through this one persisted state.
import { existsSync, mkdirSync, openSync, closeSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { appendLog, bound, isoNow, newId, pidAlive, readJson, sha256, writeJsonAtomic } from './util.mjs';
import { redact, redactDeep } from './redact.mjs';
import { loadHistory, loadCheckResults, parseReceipt } from './history.mjs';
import { findQuestion, OWNER_QUESTIONS } from './owner.mjs';
import { PLANNED_DIR, TASK_FILE, Worker } from './worker.mjs';

const KEY_RE = /^[A-Za-z0-9_-]{8,100}$/;
const TEXT_MAX = 8000, OPEN_ITEMS_MAX = 200, EVENTS_MAX = 500;
const LEASE_MIN = 15_000, LEASE_MAX = 600_000;

export class BrokerError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}
const fail = (status, msg) => { throw new BrokerError(status, msg); };

function emptyState(now) {
  return { schema: 'pocol-local-coordinator/1', createdAt: isoNow(now), paused: false, pauseRequestedAt: null,
    items: {}, order: [], keys: {}, reviewer: null, currentJob: null, reviews: [], ownerAnswers: {}, events: [] };
}

export class Controller {
  constructor({ workspace, uiDir = path.join(workspace, 'coordination', 'ui-control'), sessionId = null, claudeBin = null,
    spawnImpl, isAlive = pidAlive, now = () => Date.now(), watchMs = 2000 }) {
    this.ws = workspace; this.uiDir = uiDir; this.now = now; this.isAlive = isAlive; this.watchMs = watchMs;
    mkdirSync(uiDir, { recursive: true });
    this.stateFile = path.join(uiDir, 'state.json');
    this.logFile = path.join(uiDir, 'server.log');
    this.cacheFile = path.join(uiDir, 'history-cache.json');
    this.state = readJson(this.stateFile, null) || emptyState(now());
    this.ledgerFile = path.join(workspace, 'coordination', 'issue-ledger.json');
    this.sessionId = sessionId || readJson(this.ledgerFile, {})?.activeAuthor?.claudeSessionId || null;
    this.worker = new Worker({ ws: workspace, uiDir, claudeBin, spawnImpl, isAlive, log: (r) => this.log(r) });
    this.watchTimer = null;
    this.historyAt = 0; this.history = null;
  }

  // ---------- persistence ----------
  save() { writeJsonAtomic(this.stateFile, this.state); }
  log(record) { appendLog(this.logFile, redactDeep(record)); }
  event(kind, detail = {}) {
    this.state.events.push({ at: isoNow(this.now()), kind, ...redactDeep(detail) });
    if (this.state.events.length > EVENTS_MAX) this.state.events.splice(0, this.state.events.length - EVENTS_MAX);
    this.log({ event: kind, ...detail });
  }

  /** Single running service per ui-control directory. A stale lock (dead pid) is taken over and recorded. */
  acquireService(port) {
    const lock = path.join(this.uiDir, 'service.lock');
    const info = { pid: process.pid, startedAt: isoNow(this.now()), port };
    try { const fd = openSync(lock, 'wx', 0o600); writeFileSync(fd, JSON.stringify(info)); closeSync(fd); }
    catch {
      const old = readJson(lock, {});
      if (old.pid && old.pid !== process.pid && this.isAlive(old.pid)) fail(409, `خدمة المنسق تعمل بالفعل (pid ${old.pid}).`);
      writeJsonAtomic(lock, info);
      if (old.pid !== process.pid) this.event('service.staleLockRecovered', { previousPid: old.pid ?? null });
    }
    this.serviceLock = lock;
  }
  releaseService() { if (this.serviceLock) try { unlinkSync(this.serviceLock); } catch { /* gone */ } }

  // ---------- restart recovery (never spawns) ----------
  recover() {
    const r = this.worker.recover();
    const jobId = r.lease?.jobId ?? this.state.currentJob;
    const item = jobId ? this.state.items[jobId] : null;
    if (r.state === 'alive') {
      this.state.currentJob = r.lease.jobId;
      if (item) item.status = 'running';
      this.event('worker.reattached', { jobId: r.lease.jobId, pid: r.lease.pid });
      this.watch();
    } else if (r.state === 'finished') {
      this.finishJob(r.lease.jobId, { code: r.result.is_error ? 1 : 0, recovered: true });
    } else if (r.state === 'interrupted') {
      if (item) { item.status = 'interrupted'; item.endedAt = isoNow(this.now()); }
      this.worker.release(r.lease.jobId); this.state.currentJob = null;
      this.event('worker.interrupted', { jobId: r.lease.jobId, pid: r.lease.pid });
    } else if (this.state.currentJob && item && item.status === 'running') {
      item.status = 'interrupted'; this.state.currentJob = null;
      this.event('worker.interrupted', { jobId: item.id, reason: 'no lease file' });
    }
    this.save();
  }

  watch() {
    if (this.watchTimer) return;
    this.watchTimer = setInterval(() => {
      const lease = this.worker.readLease();
      if (!lease || (lease.pid && this.isAlive(lease.pid))) return;
      clearInterval(this.watchTimer); this.watchTimer = null;
      const res = this.worker.receiptResult(lease.jobId);
      this.finishJob(lease.jobId, { code: res && !res.is_error ? 0 : 1, recovered: true });
      this.save();
    }, this.watchMs);
    this.watchTimer.unref?.();
  }

  stop() { if (this.watchTimer) clearInterval(this.watchTimer); this.watchTimer = null; }

  // ---------- idempotent submissions (browser) ----------
  _existing(key) {
    if (!KEY_RE.test(key || '')) fail(400, 'مفتاح الطلب (idempotencyKey) غير صالح.');
    const id = this.state.keys[key];
    return id ? this.state.items[id] : null;
  }
  _add(kind, key, payload) {
    const open = this.state.order.filter((id) => !['acknowledged', 'reviewed', 'cancelled'].includes(this.state.items[id].status)).length;
    if (open >= OPEN_ITEMS_MAX) fail(429, 'الطابور ممتلئ؛ انتظر استلام المنسق.');
    const item = { id: newId(), kind, idempotencyKey: key, createdAt: isoNow(this.now()), status: 'queued', payload };
    this.state.items[item.id] = item; this.state.order.push(item.id); this.state.keys[key] = item.id;
    this.event(`${kind}.queued`, { itemId: item.id });
    this.save();
    return item;
  }
  _text(text) {
    if (typeof text !== 'string' || !text.trim()) fail(400, 'النص فارغ.');
    if (text.length > TEXT_MAX) fail(413, 'النص أطول من الحد المسموح.');
    return text;
  }

  submitGuidance({ text, idempotencyKey }) {
    const ex = this._existing(idempotencyKey); if (ex) return { item: ex, duplicate: true };
    return { item: this._add('guidance', idempotencyKey, { text: this._text(text) }), duplicate: false };
  }

  submitOwnerAnswer({ questionId, choice, note = '', idempotencyKey }) {
    const ex = this._existing(idempotencyKey); if (ex) return { item: ex, duplicate: true };
    const q = findQuestion(questionId); if (!q) fail(400, 'سؤال غير معروف.');
    if (!q.options.some((o) => o.id === choice)) fail(400, 'خيار غير معروف.');
    if (typeof note !== 'string' || note.length > TEXT_MAX) fail(400, 'ملاحظة غير صالحة.');
    const item = this._add('ownerAnswer', idempotencyKey, { questionId, choice, note, testOnly: Boolean(q.testOnly) });
    this.state.ownerAnswers[questionId] = { itemId: item.id, choice, at: item.createdAt, status: 'queued', testOnly: Boolean(q.testOnly) };
    this.save();
    return { item, duplicate: false };
  }

  requestAuthorJob({ mode = 'smoke', note = '', idempotencyKey, retryOf = null }) {
    const ex = this._existing(idempotencyKey); if (ex) return { item: ex, duplicate: true };
    if (!['smoke', 'author'].includes(mode)) fail(400, 'نوع المهمة غير معروف.');
    if (retryOf) {
      const prev = this.state.items[retryOf];
      if (!prev || prev.kind !== 'authorJob' || !['failed', 'interrupted'].includes(prev.status)) fail(409, 'لا توجد مهمة فاشلة أو متوقفة بهذا المعرف.');
    }
    return { item: this._add('authorJob', idempotencyKey, { mode, note: note ? this._text(note) : '', retryOf }), duplicate: false };
  }

  pause({ idempotencyKey }) {
    if (!KEY_RE.test(idempotencyKey || '')) fail(400, 'مفتاح الطلب غير صالح.');
    if (!this.state.paused) { this.state.paused = true; this.state.pauseRequestedAt = isoNow(this.now()); this.event('pause.requested', { draining: Boolean(this.state.currentJob) }); this.save(); }
    return { pauseState: this.pauseState() };
  }

  resume({ idempotencyKey, reason = '' }) {
    if (!KEY_RE.test(idempotencyKey || '')) fail(400, 'مفتاح الطلب غير صالح.');
    if (this.state.paused) {
      this.state.paused = false; this.state.pauseRequestedAt = null;
      this.event('resume', { reason: bound(String(reason), 500) }); this.save();
      this.tryDispatch();
    }
    return { pauseState: this.pauseState() };
  }

  pauseState() { return this.state.paused ? (this.state.currentJob ? 'draining' : 'paused') : 'active'; }

  // ---------- reviewer (host coordinator) API ----------
  reviewerStatus() {
    const r = this.state.reviewer;
    if (!r) return { status: 'disconnected' };
    const expires = Date.parse(r.heartbeatAt) + r.leaseMs;
    return { status: this.now() <= expires ? 'attached' : 'expired', reviewerId: r.id, heartbeatAt: r.heartbeatAt, expiresAt: isoNow(expires) };
  }
  attach({ reviewerId, leaseMs = 120_000 }) {
    if (typeof reviewerId !== 'string' || !/^[A-Za-z0-9._ -]{1,60}$/.test(reviewerId)) fail(400, 'reviewerId غير صالح.');
    const ms = Math.min(LEASE_MAX, Math.max(LEASE_MIN, Number(leaseMs) || 120_000));
    const at = isoNow(this.now());
    this.state.reviewer = { id: reviewerId, attachedAt: at, heartbeatAt: at, leaseMs: ms };
    this.event('reviewer.attached', { reviewerId }); this.save();
    this.tryDispatch();                                   // only items the coordinator already approved
    return this.reviewerStatus();
  }
  heartbeat() {
    if (!this.state.reviewer) fail(409, 'لا يوجد مراجع متصل.');
    this.state.reviewer.heartbeatAt = isoNow(this.now()); this.save();
    this.tryDispatch();
    return this.reviewerStatus();
  }
  detach() { this.state.reviewer = null; this.event('reviewer.detached'); this.save(); return { status: 'disconnected' }; }

  reviewerQueue() {
    return this.state.order.map((id) => this.state.items[id])
      .filter((i) => ['queued', 'claimed'].includes(i.status) || (i.kind === 'authorJob' && ['completed', 'failed', 'interrupted'].includes(i.status) && !i.reviewId))
      .map((i) => ({ ...i, receipt: i.kind === 'authorJob' && i.status !== 'queued' ? this.jobSummary(i) : undefined }));
  }

  claim({ itemId }) {
    const i = this.state.items[itemId]; if (!i) fail(404, 'عنصر غير موجود.');
    if (i.status !== 'queued') fail(409, `لا يمكن استلام عنصر بحالة ${i.status}.`);
    i.status = 'claimed'; i.claimedAt = isoNow(this.now()); i.claimedBy = this.state.reviewer?.id ?? 'host-coordinator';
    if (i.kind === 'ownerAnswer') this.state.ownerAnswers[i.payload.questionId].status = 'claimed';
    this.event('item.claimed', { itemId }); this.save();
    return i;
  }

  /** Acknowledge an item. For an author job the coordinator supplies the dispatch plan. */
  ack({ itemId, note = '', dispatch = null }) {
    const i = this.state.items[itemId]; if (!i) fail(404, 'عنصر غير موجود.');
    if (!['queued', 'claimed'].includes(i.status)) fail(409, `لا يمكن تأكيد عنصر بحالة ${i.status}.`);
    i.ackNote = bound(String(note), 2000); i.ackAt = isoNow(this.now());
    if (i.kind === 'authorJob') {
      if (!dispatch || typeof dispatch !== 'object') fail(400, 'خطة التنفيذ مطلوبة لمهمة المؤلف.');
      const mode = i.payload.mode;
      if (mode === 'author') {
        if (!TASK_FILE.test(dispatch.taskFile || '') || !existsSync(path.join(this.ws, 'coordination', dispatch.taskFile))) fail(400, 'ملف المهمة غير موجود في coordination.');
        if (!PLANNED_DIR.test(dispatch.plannedDir || '')) fail(400, 'المجلد المخطط يجب أن يكون m1-draft-0.N.');
        if (existsSync(path.join(this.ws, dispatch.plannedDir))) fail(409, 'المجلد المخطط موجود بالفعل؛ يجب أن يكون جديدًا.');
      }
      i.dispatch = { mode, sessionId: this.sessionId, taskFile: mode === 'author' ? dispatch.taskFile : null, plannedDir: mode === 'author' ? dispatch.plannedDir : null };
      i.status = 'approved';
      this.event('authorJob.approved', { itemId, mode });
      this.save();
      this.tryDispatch();
      return this.state.items[itemId];
    }
    i.status = 'acknowledged';
    if (i.kind === 'ownerAnswer') this.state.ownerAnswers[i.payload.questionId].status = 'acknowledged';
    this.event('item.acknowledged', { itemId, kind: i.kind }); this.save();
    return i;
  }

  /**
   * Record the host coordinator's actual review. Completed, failed and interrupted jobs all
   * need one before another job may start. A failed/interrupted job keeps its status after
   * review so an explicit retry stays possible; nothing is retried automatically.
   */
  review({ jobId, verdict, summaryAr, text = '' }) {
    const i = this.state.items[jobId]; if (!i || i.kind !== 'authorJob') fail(404, 'مهمة غير موجودة.');
    if (i.reviewId) fail(409, 'هذه المهمة رُوجعت بالفعل.');
    if (!['completed', 'failed', 'interrupted'].includes(i.status)) fail(409, 'لا يمكن مراجعة مهمة لم تنته.');
    if (!['accept', 'revise', 'reject'].includes(verdict)) fail(400, 'حكم المراجعة غير صالح.');
    const review = { id: newId(), jobId, verdict, summaryAr: bound(this._text(summaryAr), 2000), text: bound(String(text), 20000),
      at: isoNow(this.now()), reviewerId: this.state.reviewer?.id ?? 'host-coordinator', jobStatus: i.status };
    this.state.reviews.push(review); i.reviewId = review.id; i.reviewedAt = review.at;
    if (i.status === 'completed') i.status = 'reviewed';
    this.event('review.recorded', { jobId, verdict }); this.save();
    this.tryDispatch();
    return review;
  }

  // ---------- dispatch: one author process, only for approved items ----------
  ledgerBlock() {
    const l = readJson(this.ledgerFile, null);
    if (!l) return 'تعذّرت قراءة سجل المنسق (issue-ledger.json).';
    const a = l.activeAuthor;
    if (a && a.state && a.state !== 'completed') return `السجل يُظهر مؤلفًا نشطًا أو غير مُثبَّت (${a.task ?? '?'}: ${a.state}).`;
    return null;
  }

  /** First finished author job (completed, failed or interrupted) without an actual review. */
  unreviewedJob() {
    return this.state.order.map((id) => this.state.items[id])
      .find((i) => i.kind === 'authorJob' && ['completed', 'failed', 'interrupted'].includes(i.status) && !i.reviewId) ?? null;
  }

  dispatchBlock() {
    if (this.state.paused) return 'متوقف مؤقتًا';
    if (this.state.currentJob) return 'مهمة مؤلف قيد التشغيل';
    if (this.worker.readLease()) return 'يوجد عقد عامل قائم';
    const awaiting = this.unreviewedJob();
    if (awaiting) return `بانتظار مراجعة Codex الفعلية للمهمة السابقة (${awaiting.id}: ${awaiting.status})`;
    if (this.reviewerStatus().status !== 'attached') return 'المنسق المضيف غير متصل أو انتهت مهلة اتصاله؛ لا تبدأ مهمة دون مراجع حاضر';
    if (!this.sessionId) return 'معرف جلسة Claude غير معروف';
    if (!this.worker.claudeBin) return 'claude.exe غير متاح لهذا الخادم (استخدم --claude-bin)';
    return this.ledgerBlock();
  }

  tryDispatch() {
    const next = this.state.order.map((id) => this.state.items[id]).find((i) => i.kind === 'authorJob' && i.status === 'approved');
    if (!next) return null;
    const block = this.dispatchBlock();
    if (block) { next.blockedReason = block; this.save(); return null; }
    if (next.dispatch.plannedDir && existsSync(path.join(this.ws, next.dispatch.plannedDir))) {
      next.status = 'failed'; next.endedAt = isoNow(this.now()); next.error = 'المجلد المخطط أصبح موجودًا قبل البدء.'; this.save(); return null;
    }
    next.dispatch.sessionId = this.sessionId;
    let lease;
    try { lease = this.worker.start(next, (r) => { this.finishJob(next.id, r); this.save(); }); }
    catch (e) {
      next.status = 'failed'; next.endedAt = isoNow(this.now()); next.error = redact(String(e.message));
      this.event('worker.startFailed', { itemId: next.id }); this.save(); return null;
    }
    next.status = 'running'; next.startedAt = lease.startedAt; next.pid = lease.pid; next.blockedReason = null;
    this.state.currentJob = next.id;
    this.event('worker.started', { itemId: next.id, pid: lease.pid, mode: next.dispatch.mode });
    this.save();
    return next;
  }

  finishJob(jobId, { code = null, error = null, recovered = false } = {}) {
    const i = this.state.items[jobId];
    const res = this.worker.receiptResult(jobId);
    if (i && i.status === 'running' || i && recovered) {
      i.status = res && !res.is_error && (code === 0 || recovered) ? 'completed' : 'failed';
      i.endedAt = isoNow(this.now()); i.exitCode = code; if (error) i.error = redact(error);
      if (!res) i.error = i.error || 'لم يكتب Claude نتيجة نهائية في الإيصال.';
    }
    this.worker.release(jobId);
    if (this.state.currentJob === jobId) this.state.currentJob = null;
    this.event('worker.finished', { jobId, status: i?.status, exitCode: code });
  }

  jobSummary(item) {
    const f = path.join(this.uiDir, 'jobs', item.id, 'receipt.jsonl');
    if (!existsSync(f)) return null;
    const p = parseReceipt(readFileSync(f).toString('utf8'));
    return { result: p.result, toolCalls: p.toolCalls, entries: p.entries.slice(-60), lastAt: p.lastAt };
  }

  // ---------- read models ----------
  historyCards() {
    if (!this.history || this.now() - this.historyAt > 30_000) {
      const cache = readJson(this.cacheFile, {});
      const h = loadHistory(this.ws, cache);
      writeJsonAtomic(this.cacheFile, h.cache);
      this.history = h; this.historyAt = this.now();
    }
    return this.history.cards;
  }

  /**
   * Cards for what happened through this broker: one Claude card per author job that was
   * started or failed to start (from its own receipt), and one Codex card per review the
   * host coordinator actually recorded. Times are the broker's own recorded times.
   */
  currentCards() {
    const rel = (f) => path.relative(this.ws, f).split(path.sep).join('/');
    const cards = [];
    for (const i of this.state.order.map((id) => this.state.items[id])) {
      if (i.kind !== 'authorJob' || !(i.startedAt || i.endedAt)) continue;
      const f = path.join(this.uiDir, 'jobs', i.id, 'receipt.jsonl');
      const raw = existsSync(f) ? readFileSync(f) : null;
      const p = raw ? parseReceipt(raw.toString('utf8')) : null;
      const r = p?.result ?? null;
      const mode = i.dispatch?.mode ?? i.payload.mode;
      const outcome = i.status === 'running' ? 'قيد التشغيل' : !r ? 'لا توجد نتيجة نهائية في الإيصال' : r.isError ? 'انتهى بخطأ' : 'اكتمل';
      cards.push({
        id: `job-${i.id}`, role: 'author', actor: 'Claude', kind: 'currentReceipt', current: true, jobId: i.id, status: i.status,
        task: i.dispatch?.taskFile ?? (mode === 'smoke' ? 'smoke (قراءة فقط)' : null), revision: i.dispatch?.plannedDir?.replace('m1-draft-', '') ?? null,
        time: i.endedAt ?? i.startedAt ?? null,
        timeNote: i.endedAt ? 'وقت انتهاء المهمة كما سجله الوسيط' : 'وقت بدء المهمة كما سجله الوسيط؛ لم تنته بعد',
        sha256: raw ? sha256(raw) : null, commit: null, source: raw ? rel(f) : `${rel(f)} (غير موجود)`,
        sessionId: r?.sessionId ?? i.dispatch?.sessionId ?? null,
        summaryAr: `دورة المؤلف الحالية (${mode}) ${i.id}: ${outcome} · ${p ? p.toolCalls : 0} استدعاء أداة · رفض أذونات: ${r ? r.permissionDenials.length : 'غير معروف'}${i.error ? ' · خطأ: ' + i.error : ''}`,
        result: r, technical: p?.entries ?? [], truncatedEntries: p?.truncatedEntries ?? 0,
      });
    }
    for (const rv of this.state.reviews) {
      const job = this.state.items[rv.jobId];
      cards.push({
        id: `review-${rv.id}`, role: 'reviewer', actor: 'Codex', kind: 'currentReview', current: true, jobId: rv.jobId, verdict: rv.verdict,
        reviewerId: rv.reviewerId, task: job?.dispatch?.taskFile ?? null, revision: job?.dispatch?.plannedDir?.replace('m1-draft-', '') ?? null,
        time: rv.at ?? null, timeNote: rv.at ? 'وقت تسجيل المراجعة عبر واجهة المراجع' : 'غير مسجل',
        sha256: rv.text ? sha256(rv.text) : null, commit: null, source: `${rel(this.stateFile)}#reviews/${rv.id}`,
        summaryAr: `مراجعة Codex الفعلية (${rv.reviewerId}) للمهمة ${rv.jobId}${rv.jobStatus ? ' [' + rv.jobStatus + ']' : ''}: ${rv.verdict} · ${rv.summaryAr}`,
        technical: [{ kind: 'text', text: rv.text || '(لم يُرسل نص تقني مع المراجعة)' }],
      });
    }
    return redactDeep(cards);
  }

  /**
   * Historical and current cards in one chronological list. A card without a recorded time
   * keeps "unavailable" as its time and is ordered right after its preceding neighbour in
   * the source sequence (never given an invented time). Stable for equal times.
   */
  timelineCards() {
    let key = -Infinity;
    const keyed = [...this.historyCards(), ...this.currentCards()].map((c, n) => {
      const t = c.time ? Date.parse(c.time) : NaN;
      if (Number.isFinite(t)) key = t;
      return { c, key, n };
    });
    keyed.sort((a, b) => (a.key === b.key ? 0 : a.key - b.key) || a.n - b.n);
    return keyed.map((k) => k.c);
  }

  /** Changes whenever a current card would change; the page refetches the timeline then. */
  timelineSig() {
    const jobs = this.state.order.map((id) => this.state.items[id]).filter((i) => i.kind === 'authorJob' && (i.startedAt || i.endedAt))
      .map((i) => `${i.id}:${i.status}:${i.endedAt ?? ''}`);
    return sha256(jobs.concat(this.state.reviews.map((r) => r.id)).join('|')).slice(0, 16);
  }

  statusPanel() {
    const ledger = readJson(this.ledgerFile, null);
    const checks = loadCheckResults(this.ws);
    const latest = checks.find((c) => c.revision === (ledger?.latestCompletedRevision || '').replace('m1-draft-', '')) || checks[0] || null;
    const running = this.state.currentJob ? this.state.items[this.state.currentJob] : null;
    return redactDeep({
      phaseAr: 'M1: مرحلة المواصفات فقط (لا تنفيذ إنتاجي، لا نشر، لا معاملات حقيقية)',
      updatedAt: isoNow(this.now()),
      ledgerStatus: ledger?.status ?? null,
      latestRevision: ledger?.latestCompletedRevision ?? null,
      latestCheck: latest,
      activeWorker: running ? { itemId: running.id, mode: running.dispatch?.mode, pid: running.pid ?? null, startedAt: running.startedAt ?? null } : null,
      ledgerActiveAuthor: ledger?.activeAuthor ?? null,
      openFindings: (ledger?.issues || []).filter((x) => !/^closed|^resolved|^documented/.test(String(x.status))).map((x) => ({ id: x.id, status: x.status, decision: x.decision })),
      noteAr: 'اتفاق الوكيلين ليس اختبارًا. النتائج أعلاه من ملفات فحص محفوظة فعلًا؛ ما لا يوجد له ملف يظهر «غير متاح».',
    });
  }

  ownerView() {
    return OWNER_QUESTIONS.map((q) => ({ ...q, answer: this.state.ownerAnswers[q.id] ?? null }));
  }

  waitingReason() {
    const items = this.state.order.map((id) => this.state.items[id]);
    if (this.state.currentJob) return 'workerRunning';
    const unreviewed = this.unreviewedJob();
    if (unreviewed) return unreviewed.status === 'completed' ? 'waitingReview' : 'workerFailed';
    const pending = items.some((i) => ['queued', 'claimed', 'approved'].includes(i.status));
    if (pending && this.reviewerStatus().status !== 'attached') return 'waitingReviewerAttach';
    if (items.some((i) => i.status === 'queued' || i.status === 'claimed')) return 'waitingCoordinator';
    if (items.some((i) => i.kind === 'authorJob' && i.status === 'approved')) return 'dispatchBlocked';
    const last = items.filter((i) => i.kind === 'authorJob').at(-1);
    if (last && ['failed', 'interrupted'].includes(last.status)) return 'retryAvailable';
    return 'idle';
  }

  /** Everything the browser may see. No tokens, no reviewer secret, redacted text. */
  view() {
    const items = this.state.order.map((id) => this.state.items[id]).slice(-100)
      .map((i) => ({ ...i, receipt: i.kind === 'authorJob' && i.status !== 'queued' && i.status !== 'approved' ? this.jobSummary(i) : undefined }));
    return redactDeep({
      status: this.statusPanel(), pauseState: this.pauseState(), reviewer: this.reviewerStatus(), waiting: this.waitingReason(),
      items, reviews: this.state.reviews.slice(-50), timelineSig: this.timelineSig(), owner: this.ownerView(), events: this.state.events.slice(-40),
    });
  }
}
