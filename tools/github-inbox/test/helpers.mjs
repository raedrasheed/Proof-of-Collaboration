// Test doubles for the GitHub inbox adapter: an in-memory GitHub issue (FakeGh), an in-memory
// local broker (FakeBroker) with the real broker's idempotency rule, the browser view's limits
// (last 100 items, last 50 reviews) and the narrow item lookup, and a manual clock.
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
    this.comments = []; this.pageSize = pageSize; this.nextId = 1_000_000; this.posts = []; this.listCalls = 0; this.pagesRequested = [];
    this.listPlan = []; this.postPlan = [];
  }
  add(c) { this.comments.push(c); return c; }
  async listPage(page) {
    this.listCalls += 1;
    this.pagesRequested.push(page);
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
  /** Comments on GitHub (not only those posted in this run) carrying a marker fragment. */
  markerComments(fragment) { return this.comments.filter((c) => c.body.includes(fragment)); }
}

const err = (kind, message = kind) => Object.assign(new Error(message), { kind });

export class FakeBroker {
  constructor() {
    this.items = new Map(); this.keys = new Map(); this.reviews = []; this.down = false; this.uncertainOnce = false; this.refuse = false;
    this.postFailKind = null;                             // fail deliveries (without persisting) while reads still work
    this.posts = 0; this.stateCalls = 0; this.lookups = []; this.postedKeys = [];
  }
  async postGuidance({ text, idempotencyKey }) {
    this.posts += 1;
    this.postedKeys.push(idempotencyKey);
    if (this.down) throw err('unreachable');
    if (this.refuse) throw err('refused', 'النص أطول من الحد المسموح.');
    if (this.postFailKind) throw err(this.postFailKind);
    if (!/^[A-Za-z0-9_-]{8,100}$/.test(idempotencyKey)) throw new Error('bad key');
    if (this.keys.has(idempotencyKey)) return { item: this.items.get(this.keys.get(idempotencyKey)), duplicate: true };
    const item = { id: randomUUID(), kind: 'guidance', idempotencyKey, status: 'queued', payload: { text } };
    this.items.set(item.id, item); this.keys.set(idempotencyKey, item.id);
    if (this.uncertainOnce) { this.uncertainOnce = false; throw err('uncertain', 'timeout'); }
    return { item, duplicate: false };
  }
  /** Like Controller.view(): only the last 100 items and the last 50 reviews. */
  async getState() {
    this.stateCalls += 1;
    if (this.down) throw err('unreachable');
    return JSON.parse(JSON.stringify({ items: [...this.items.values()].slice(-100), reviews: this.reviews.slice(-50) }));
  }
  /** Like GET /api/github-item: the narrow allowlist, and only the review belonging to that item. */
  async getItem(id) {
    this.lookups.push(id);
    if (this.down) throw err('unreachable');
    const i = this.items.get(id);
    if (!i) throw err('notFound');
    const pick = (k) => (i[k] === undefined ? null : i[k]);
    const item = { id: i.id, kind: i.kind, status: i.status, idempotencyKey: pick('idempotencyKey'), ackNote: pick('ackNote'), reviewId: pick('reviewId'), error: pick('error'), blockedReason: pick('blockedReason') };
    const r = i.reviewId ? this.reviews.find((x) => x.id === i.reviewId && x.jobId === i.id) : null;
    return JSON.parse(JSON.stringify({ item, review: r ? { id: r.id, jobId: r.jobId, verdict: r.verdict, summaryAr: r.summaryAr } : null }));
  }
  guidance() { return [...this.items.values()].filter((i) => i.kind === 'guidance'); }
  ack(itemId, note = '') { const i = this.items.get(itemId); i.status = 'acknowledged'; i.ackNote = note; }
  addJob(status = 'approved', extra = {}) { const j = { id: randomUUID(), kind: 'authorJob', status, ...extra }; this.items.set(j.id, j); return j; }
  review(job, verdict) { const r = { id: randomUUID(), jobId: job.id, verdict, summaryAr: 'مراجعة فعلية' }; this.reviews.push(r); job.reviewId = r.id; if (job.status === 'completed') job.status = 'reviewed'; return r; }
  /** Push older records out of the 100-item / 50-review view. */
  flood(nItems, nReviews = 0) {
    for (let k = 0; k < nItems; k++) { const it = { id: randomUUID(), kind: 'guidance', idempotencyKey: `flood-${randomUUID()}`, status: 'acknowledged' }; this.items.set(it.id, it); }
    for (let k = 0; k < nReviews; k++) this.reviews.push({ id: randomUUID(), jobId: randomUUID(), verdict: 'revise', summaryAr: 'أخرى' });
  }
}

export function makeAdapter(dir, { gh, broker, clock, checkpoint = null, brokerFactory = null }) {
  const journal = new Journal(dir, { now: clock.now });
  return new Adapter({ journal, gh, brokerFactory: brokerFactory || (() => broker), readCheckpoint: () => checkpoint, now: clock.now });
}

/** Run cycles, advancing the clock before each, until `until()` is true or `max` cycles ran. */
export async function runCycles(adapter, clock, { stepMs, max, until = () => false }) {
  let n = 0;
  for (; n < max && !until(); n++) { clock.advance(stepMs); await adapter.cycle(); }
  return n;
}

export const LP3_CHECKPOINT = Object.freeze({
  status: 'LP3-author-dispatch-blocked-policy',
  nextPR: 'https://github.com/raedrasheed/Proof-of-Collaboration/pull/7',
  blockedStep: 'Shell command to correct the prepared task, consume the queued continuation and dispatch one LP3 Claude author, then checkpoint that author',
  exactError: 'CreateProcess rejected: blocked by policy',
  actualPendingItems: [{ id: '9027dd9a-381a-4731-9f08-7b6d2cda0864', kind: 'continuation', status: 'queued' }],
});
