import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { writeFileSync } from 'node:fs';
import path from 'node:path';
import { createApp } from '../src/server.mjs';
import { Controller } from '../src/broker.mjs';
import { fakeSpawner, makeWorkspace, resultLine } from './helpers.mjs';

async function start() {
  const ws = makeWorkspace();
  const sp = fakeSpawner();
  const controller = new Controller({ workspace: ws, claudeBin: 'claude-fake', spawnImpl: sp.spawnImpl, isAlive: () => false });
  const app = createApp({ controller });
  await new Promise((r) => app.server.listen(0, '127.0.0.1', r));
  const port = app.server.address().port;
  return { ...app, port, controller, sp, close: () => new Promise((r) => { app.server.closeAllConnections(); app.server.close(r); }) };
}

function request(port, { method = 'GET', path = '/', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, method, path, headers: { host: `127.0.0.1:${port}`, ...headers } }, (res) => {
      const chunks = []; res.on('data', (c) => chunks.push(c));
      res.on('end', () => { const text = Buffer.concat(chunks).toString('utf8'); let json = null; try { json = JSON.parse(text); } catch { /* html or css */ } resolve({ status: res.statusCode, text, json, headers: res.headers }); });
    });
    req.on('error', reject);
    if (body !== undefined) req.write(typeof body === 'string' ? body : JSON.stringify(body));
    req.end();
  });
}

test('static page served with CSP; API requires the control token', async (t) => {
  const s = await start(); t.after(s.close);
  const page = await request(s.port);
  assert.equal(page.status, 200);
  assert.match(page.headers['content-security-policy'], /default-src 'none'/);
  assert.equal((await request(s.port, { path: '/api/state' })).status, 403);
  const ok = await request(s.port, { path: '/api/state', headers: { 'x-pocol-control': s.controlToken } });
  assert.equal(ok.status, 200);
  assert.ok(!ok.text.includes(s.reviewerToken), 'reviewer capability never reaches the browser');
  assert.ok(!ok.text.includes(s.controlToken));
});

test('wrong Host and cross-origin writes are refused', async (t) => {
  const s = await start(); t.after(s.close);
  assert.equal((await request(s.port, { path: '/api/state', headers: { host: `localhost:${s.port}`, 'x-pocol-control': s.controlToken } })).status, 403);
  const cross = await request(s.port, { method: 'POST', path: '/api/guidance', body: { text: 'x', idempotencyKey: 'cross-origin-1' },
    headers: { 'x-pocol-control': s.controlToken, 'content-type': 'application/json', origin: 'http://evil.example' } });
  assert.equal(cross.status, 403);
  const noOrigin = await request(s.port, { method: 'POST', path: '/api/guidance', body: { text: 'x', idempotencyKey: 'no-origin-001' },
    headers: { 'x-pocol-control': s.controlToken, 'content-type': 'application/json' } });
  assert.equal(noOrigin.status, 403);
  const site = await request(s.port, { path: '/api/state', headers: { 'x-pocol-control': s.controlToken, 'sec-fetch-site': 'cross-site' } });
  assert.equal(site.status, 403);
  assert.equal(s.controller.state.order.length, 0, 'nothing was queued');
});

test('content type, body size and unknown paths', async (t) => {
  const s = await start(); t.after(s.close);
  const origin = `http://127.0.0.1:${s.port}`;
  const h = { 'x-pocol-control': s.controlToken, origin };
  assert.equal((await request(s.port, { method: 'POST', path: '/api/guidance', body: 'text=x', headers: { ...h, 'content-type': 'text/plain' } })).status, 415);
  assert.equal((await request(s.port, { method: 'POST', path: '/api/guidance', body: { text: 'a'.repeat(70_000), idempotencyKey: 'big-body-0001' }, headers: { ...h, 'content-type': 'application/json' } })).status, 413);
  const trav = await request(s.port, { path: '/%2e%2e/src/server.mjs', headers: h });
  assert.equal(trav.status, 404);
  assert.ok(!trav.text.includes('createServer'));
  assert.equal((await request(s.port, { path: '/../package.json', headers: h })).status, 404);
});

test('duplicate POST with the same idempotency key returns the same item', async (t) => {
  const s = await start(); t.after(s.close);
  const h = { 'x-pocol-control': s.controlToken, origin: `http://127.0.0.1:${s.port}`, 'content-type': 'application/json' };
  const body = { text: 'تحقق من 0.8', idempotencyKey: 'dup-http-key-1' };
  const a = await request(s.port, { method: 'POST', path: '/api/guidance', body, headers: h });
  const b = await request(s.port, { method: 'POST', path: '/api/guidance', body, headers: h });
  assert.equal(a.status, 200); assert.equal(b.json.duplicate, true);
  assert.equal(a.json.item.id, b.json.item.id);
});

test('reviewer API: separate token, no browser origin, then claim and ack', async (t) => {
  const s = await start(); t.after(s.close);
  const json = { 'content-type': 'application/json' };
  assert.equal((await request(s.port, { method: 'POST', path: '/api/reviewer/attach', body: { reviewerId: 'codex' }, headers: { ...json, 'x-pocol-reviewer': s.controlToken } })).status, 403);
  assert.equal((await request(s.port, { method: 'POST', path: '/api/reviewer/attach', body: { reviewerId: 'codex' },
    headers: { ...json, 'x-pocol-reviewer': s.reviewerToken, origin: `http://127.0.0.1:${s.port}` } })).status, 403);
  const att = await request(s.port, { method: 'POST', path: '/api/reviewer/attach', body: { reviewerId: 'codex-host' }, headers: { ...json, 'x-pocol-reviewer': s.reviewerToken } });
  assert.equal(att.status, 200); assert.equal(att.json.status, 'attached');
  const g = s.controller.submitGuidance({ text: 'hello', idempotencyKey: 'rev-flow-0001' });
  const q = await request(s.port, { path: '/api/reviewer/queue', headers: { 'x-pocol-reviewer': s.reviewerToken } });
  assert.equal(q.json.items.length, 1);
  const ack = await request(s.port, { method: 'POST', path: '/api/reviewer/ack', body: { itemId: g.item.id, note: 'received' }, headers: { ...json, 'x-pocol-reviewer': s.reviewerToken } });
  assert.equal(ack.json.status, 'acknowledged');
  assert.equal((await request(s.port, { path: '/api/reviewer/queue', headers: { 'x-pocol-control': s.controlToken } })).status, 403);
});

test('a review recorded through the reviewer API reaches the browser timeline on the next poll', async (t) => {
  const s = await start(); t.after(s.close);
  const rev = { 'content-type': 'application/json', 'x-pocol-reviewer': s.reviewerToken };
  const ctl = { 'x-pocol-control': s.controlToken };
  await request(s.port, { method: 'POST', path: '/api/reviewer/attach', body: { reviewerId: 'codex-host' }, headers: rev });
  const job = s.controller.requestAuthorJob({ mode: 'smoke', idempotencyKey: 'http-card-job1' });
  await request(s.port, { method: 'POST', path: '/api/reviewer/ack', body: { itemId: job.item.id, dispatch: {} }, headers: rev });
  assert.equal(s.sp.calls.length, 1);
  writeFileSync(path.join(s.controller.uiDir, 'jobs', job.item.id, 'receipt.jsonl'), resultLine(false));
  s.sp.calls[0].child.emit('exit', 0, null);
  const sigBefore = (await request(s.port, { path: '/api/state', headers: ctl })).json.timelineSig;
  const r = await request(s.port, { method: 'POST', path: '/api/reviewer/review', body: { jobId: job.item.id, verdict: 'accept', summaryAr: 'مراجعة فعلية' }, headers: rev });
  assert.equal(r.status, 200);
  const state = await request(s.port, { path: '/api/state', headers: ctl });
  assert.notEqual(state.json.timelineSig, sigBefore, 'the ordinary poll sees the change');
  const h = await request(s.port, { path: '/api/history', headers: ctl });
  const cards = h.json.cards;
  const jobCard = cards.find((c) => c.id === `job-${job.item.id}`);
  const reviewCard = cards.find((c) => c.id === `review-${r.json.id}`);
  assert.equal(jobCard.actor, 'Claude'); assert.equal(reviewCard.actor, 'Codex');
  assert.ok(cards.indexOf(jobCard) < cards.indexOf(reviewCard));
  assert.ok(cards.some((c) => c.source?.endsWith('claude-006.jsonl')), 'historical cards still served');
  assert.ok(!h.text.includes(s.reviewerToken));
});
