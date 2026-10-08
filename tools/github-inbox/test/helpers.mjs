// Test doubles for the GitHub inbox adapter: an in-memory GitHub issue (FakeGh), an in-memory
// local broker (FakeBroker) with the real broker's idempotency rule, and a manual clock.
import { mkdtempSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { ISSUE_API_URL, ISSUE_HTML_URL, PINNED } from '../src/constants.mjs';
import { Adapter } from '../src/adapter.mjs';
import { Journal } from '../src/journal.mjs';

export function tmpDir(t) {
  const d = mkdtempSync(path.join(os.tmpdir(), 'github-inbox-test-'));
  t?.after?.(() => rmSync(d, { recursive: true, force: true }));
  return d;
}

export const OWNER = Object.freeze({ login: PINNED.ownerLogin, id: PINNED.ownerId, type: 'User' });

export function comment(id, body, over = {}) {
  return {
    id, body, user: { ...OWNER }, issue_url: ISSUE_API_URL, html_url: `${ISSUE_HTML_URL}#issuecomment-${id}`,
    created_at: '2026-10-01T00:00:00Z', updated_at: '2026-10-01T00:00:00Z', ...over,
  };
}

export class Clock {
  constructor(t = Date.parse('2026-10-08T00:00:00Z')) { this.t = t; }
  now = () => this.t;
  advance(ms) { this.t += ms; }
}

/** In-memory issue. Posts are authored by the owner account (gh uses the owner's credentials). */
export class FakeGh {
  constructor({ pageSize = 100 } = {}) {
    this.comments = []; this.pageSize = pageSize; this.nextId = 1_000_000; this.posts = []; this.listCalls = 0;
    this.listPlan = []; this.postPlan = [];
  }
  add(c) { this.comments.push(c); return c; }
  async listPage(page) {
    this.listCalls += 1;
    const step = this.listPlan.shift();
    if (step) return { ok: false, reason: step.reason, comments: [], next: false, rate: { retryAfterS: step.retryAfterS ?? null, remaining: step.remaining ?? null, resetAt: step.resetAt ?? null } };
    const sorted = [...this.comments].sort((a, b) => a.id - b.id);
    const slice = sorted.slice((page - 1) * this.pageSize, page * this.pageSize);
    return { ok: true, comments: JSON.parse(JSON.stringify(slice)), next: page * this.pageSize < sorted.length, rate: { retryAfterS: null, remaining: 4000, resetAt: null } };
  }
  _land(body) {
    const id = this.nextId++;
    this.comments.push(comment(id, body));
    this.posts.push({ id, body });
    return id;
  }
  async postComment(body) {
    const step = this.postPlan.shift() || 'ok';
    if (step === 'ok') { const id = this._land(body); return { ok: true, comment: { id }, rate: {} }; }
    if (step === 'uncertainPosted') { this._land(body); return { ok: false, uncertain: true, reason: 'timeout', rate: {} }; }
    if (step === 'uncertainLost') return { ok: false, uncertain: true, reason: 'timeout', rate: {} };
    if (step === 'refused') return { ok: false, uncertain: false, reason: 'http422', rate: {} };
    if (step === 'rateLimited') return { ok: false, uncertain: false, reason: 'rateLimited', rate: { retryAfterS: 300, remaining: 0, resetAt: null } };
    throw new Error('unknown post step');
  }
  markerPosts(fragment) { return this.posts.filter((p) => p.body.includes(fragment)); }
}

export class FakeBroker {
  constructor() { this.items = new Map(); this.keys = new Map(); this.reviews = []; this.down = false; this.uncertainOnce = false; this.refuse = false; this.posts = 0; this.stateCalls = 0; }
  async postGuidance({ text, idempotencyKey }) {
    this.posts += 1;
    if (this.down) { const e = new Error('down'); e.kind = 'unreachable'; throw e; }
    if (this.refuse) { const e = new Error('النص أطول من الحد المسموح.'); e.kind = 'refused'; throw e; }
    if (!/^[A-Za-z0-9_-]{8,100}$/.test(idempotencyKey)) throw new Error('bad key');
    if (this.keys.has(idempotencyKey)) return { item: this.items.get(this.keys.get(idempotencyKey)), duplicate: true };
    const item = { id: randomUUID(), kind: 'guidance', idempotencyKey, status: 'queued', payload: { text } };
    this.items.set(item.id, item); this.keys.set(idempotencyKey, item.id);
    if (this.uncertainOnce) { this.uncertainOnce = false; const e = new Error('timeout'); e.kind = 'uncertain'; throw e; }
    return { item, duplicate: false };
  }
  async getState() {
    this.stateCalls += 1;
    if (this.down) { const e = new Error('down'); e.kind = 'unreachable'; throw e; }
    return JSON.parse(JSON.stringify({ items: [...this.items.values()], reviews: this.reviews }));
  }
  guidance() { return [...this.items.values()].filter((i) => i.kind === 'guidance'); }
  ack(itemId, note = '') { const i = this.items.get(itemId); i.status = 'acknowledged'; i.ackNote = note; }
  addJob(status = 'approved', extra = {}) { const j = { id: randomUUID(), kind: 'authorJob', status, ...extra }; this.items.set(j.id, j); return j; }
  review(job, verdict) { const r = { id: randomUUID(), jobId: job.id, verdict, summaryAr: 'مراجعة فعلية' }; this.reviews.push(r); job.reviewId = r.id; if (job.status === 'completed') job.status = 'reviewed'; return r; }
}

export function makeAdapter(dir, { gh, broker, clock, checkpoint = null, brokerFactory = null }) {
  const journal = new Journal(dir, { now: clock.now });
  return new Adapter({ journal, gh, brokerFactory: brokerFactory || (() => broker), readCheckpoint: () => checkpoint, now: clock.now });
}

export const LP3_CHECKPOINT = Object.freeze({
  status: 'LP3-author-dispatch-blocked-policy',
  nextPR: 'https://github.com/raedrasheed/Proof-of-Collaboration/pull/7',
  blockedStep: 'Shell command to correct the prepared task, consume the queued continuation and dispatch one LP3 Claude author, then checkpoint that author',
  exactError: 'CreateProcess rejected: blocked by policy',
  actualPendingItems: [{ id: '9027dd9a-381a-4731-9f08-7b6d2cda0864', kind: 'continuation', status: 'queued' }],
});
