// GET /api/github-item: narrow read-only projection for the GitHub issue #8 transport (0.41).
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { randomUUID } from 'node:crypto';
import { createApp } from '../src/server.mjs';
import { Controller } from '../src/broker.mjs';
import { githubItemView } from '../src/github-item.mjs';
import { fakeSpawner, makeWorkspace, SESSION } from './helpers.mjs';

async function start() {
  const ws = makeWorkspace();
  const sp = fakeSpawner();
  const controller = new Controller({ workspace: ws, claudeBin: 'claude-fake', spawnImpl: sp.spawnImpl, isAlive: () => false });
  const app = createApp({ controller });
  await new Promise((r) => app.server.listen(0, '127.0.0.1', r));
  const port = app.server.address().port;
  return { ...app, port, controller, close: () => new Promise((r) => { app.server.closeAllConnections(); app.server.close(r); }) };
}

function request(port, { method = 'GET', path = '/', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, method, path, headers: { host: `127.0.0.1:${port}`, ...headers } }, (res) => {
      const chunks = []; res.on('data', (c) => chunks.push(c));
      res.on('end', () => { const text = Buffer.concat(chunks).toString('utf8'); let json = null; try { json = JSON.parse(text); } catch { /* not json */ } resolve({ status: res.statusCode, text, json }); });
    });
    req.on('error', reject);
    if (body !== undefined) req.write(typeof body === 'string' ? body : JSON.stringify(body));
    req.end();
  });
}

const ITEM_KEYS = ['ackNote', 'blockedReason', 'error', 'id', 'idempotencyKey', 'kind', 'reviewId', 'status'];
const REVIEW_KEYS = ['id', 'jobId', 'summaryAr', 'verdict'];

test('an acknowledged item older than the 100-item view is still returned with its actual ack note', async (t) => {
  const s = await start(); t.after(s.close);
  const h = { 'x-pocol-control': s.controlToken, origin: `http://127.0.0.1:${s.port}` };
  const first = s.controller.submitGuidance({ text: 'PAYLOAD-MARKER first request', idempotencyKey: 'gh8-retention-000' }).item;
  s.controller.claim({ itemId: first.id });
  s.controller.ack({ itemId: first.id, note: 'POCOL_GITHUB_RESULT {"mode":"status","state":"completed","summary":"ok"}' });
  for (let i = 1; i <= 101; i++) s.controller.submitGuidance({ text: `later ${i}`, idempotencyKey: `gh8-retention-${String(i).padStart(3, '0')}` });
  const view = await request(s.port, { path: '/api/state', headers: h });
  assert.equal(view.json.items.length, 100, '/api/state keeps its existing 100-item limit');
  assert.ok(!view.json.items.some((i) => i.id === first.id), 'the original is outside the view');
  const r = await request(s.port, { path: `/api/github-item?itemId=${first.id}`, headers: h });
  assert.equal(r.status, 200);
  assert.deepEqual(Object.keys(r.json.item).sort(), ITEM_KEYS);
  assert.equal(r.json.item.status, 'acknowledged');
  assert.equal(r.json.item.kind, 'guidance');
  assert.equal(r.json.item.idempotencyKey, 'gh8-retention-000');
  assert.match(r.json.item.ackNote, /^POCOL_GITHUB_RESULT/);
  assert.equal(r.json.review, null);
  assert.ok(!r.text.includes('PAYLOAD-MARKER'), 'the payload is never returned');
});

test('a linked job and its actual review past the view resolve; only allowlisted fields leave the broker', async (t) => {
  const s = await start(); t.after(s.close);
  const h = { 'x-pocol-control': s.controlToken };
  const jobId = randomUUID(), reviewId = randomUUID(), otherJob = randomUUID();
  const st = s.controller.state;
  st.items[jobId] = {
    id: jobId, kind: 'authorJob', status: 'reviewed', idempotencyKey: 'job-key-0001', reviewId,
    payload: { mode: 'author', note: 'JOB-NOTE-MARKER' }, dispatch: { sessionId: SESSION, taskFile: 'task-006.md', plannedDir: 'm1-draft-0.9' },
    pid: 4242, ackNote: 'approved plan', error: null,
  };
  st.order.unshift(jobId);
  // A second job that wrongly points at the first job's review must not receive it.
  st.items[otherJob] = { id: otherJob, kind: 'authorJob', status: 'reviewed', idempotencyKey: 'job-key-0002', reviewId };
  st.order.unshift(otherJob);
  st.reviews.push({ id: reviewId, jobId, verdict: 'accept', summaryAr: 'قبول فعلي', text: 'REVIEW-TEXT-MARKER', reviewerId: 'host', continuation: { status: 'queued' } });
  for (let i = 1; i <= 101; i++) s.controller.submitGuidance({ text: `later ${i}`, idempotencyKey: `gh8-job-later-${String(i).padStart(3, '0')}` });
  const before = JSON.stringify(s.controller.state);
  const r = await request(s.port, { path: `/api/github-item?itemId=${jobId}`, headers: h });
  assert.equal(r.status, 200);
  assert.deepEqual(Object.keys(r.json.item).sort(), ITEM_KEYS);
  assert.deepEqual(Object.keys(r.json.review).sort(), REVIEW_KEYS);
  assert.deepEqual(r.json.review, { id: reviewId, jobId, verdict: 'accept', summaryAr: 'قبول فعلي' });
  for (const leak of ['JOB-NOTE-MARKER', 'REVIEW-TEXT-MARKER', SESSION, 'task-006.md', 'm1-draft-0.9', '"pid"', '"dispatch"', '"payload"', s.controlToken, s.reviewerToken]) {
    assert.ok(!r.text.includes(leak), `leaked ${leak}`);
  }
  const other = await request(s.port, { path: `/api/github-item?itemId=${otherJob}`, headers: h });
  assert.equal(other.json.review, null, 'a review is returned only for the job it belongs to');
  assert.equal(JSON.stringify(s.controller.state), before, 'lookups change nothing');
});

test('authentication, Host, Origin, Sec-Fetch-Site, method and query are enforced; missing is 404', async (t) => {
  const s = await start(); t.after(s.close);
  const id = s.controller.submitGuidance({ text: 'x', idempotencyKey: 'gh8-auth-0001' }).item.id;
  const ok = { 'x-pocol-control': s.controlToken };
  const p = `/api/github-item?itemId=${id}`;
  assert.equal((await request(s.port, { path: p })).status, 403, 'no capability');
  assert.equal((await request(s.port, { path: p, headers: { 'x-pocol-control': 'f'.repeat(64) } })).status, 403, 'wrong capability');
  assert.equal((await request(s.port, { path: p, headers: { 'x-pocol-reviewer': s.reviewerToken } })).status, 403, 'the reviewer capability is not accepted here');
  assert.equal((await request(s.port, { path: p, headers: { ...ok, host: `localhost:${s.port}` } })).status, 403, 'wrong Host');
  assert.equal((await request(s.port, { path: p, headers: { ...ok, origin: 'http://evil.example' } })).status, 403, 'foreign Origin');
  assert.equal((await request(s.port, { path: p, headers: { ...ok, 'sec-fetch-site': 'cross-site' } })).status, 403, 'cross-site fetch');
  assert.equal((await request(s.port, { path: p, headers: { ...ok, origin: `http://127.0.0.1:${s.port}` } })).status, 200, 'exact Origin is fine');
  const post = await request(s.port, { method: 'POST', path: p, headers: { ...ok, origin: `http://127.0.0.1:${s.port}`, 'content-type': 'application/json' }, body: {} });
  assert.equal(post.status, 404, 'no write method exists on this path');
  for (const bad of ['/api/github-item', '/api/github-item?itemId=not-a-uuid', `/api/github-item?itemId=${id}&itemId=${id}`, `/api/github-item?itemId=${id}&x=1`, '/api/github-item?id=1']) {
    assert.equal((await request(s.port, { path: bad, headers: ok })).status, 400, bad);
  }
  const missing = await request(s.port, { path: `/api/github-item?itemId=${randomUUID()}`, headers: ok });
  assert.equal(missing.status, 404);
  assert.equal(missing.json.missing, 'item');
});

test('projection unit: allowlist, bounds, redaction', () => {
  const idA = randomUUID();
  const state = { items: { [idA]: { id: idA, kind: 'guidance', status: 'acknowledged', idempotencyKey: 'gh8-unit-0001', ackNote: 'token: ghp_' + 'Q'.repeat(36), payload: { text: 'secret' }, extra: 1 } }, reviews: [] };
  const v = githubItemView(state, idA);
  assert.deepEqual(Object.keys(v.item).sort(), ITEM_KEYS);
  assert.ok(!JSON.stringify(v).includes('ghp_QQQQ'));
  assert.equal(githubItemView(state, randomUUID()), null);
  assert.equal(githubItemView({ items: Object.create(null) }, '__proto__'), null);
});
