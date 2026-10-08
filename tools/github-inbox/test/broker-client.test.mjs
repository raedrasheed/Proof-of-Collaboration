import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { randomUUID } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { Clock, comment, FakeGh, tmpDir } from './helpers.mjs';
import { ALLOWED_PATHS, BrokerClient, BrokerError, loadConnection } from '../src/broker-client.mjs';
import { Adapter } from '../src/adapter.mjs';
import { Journal } from '../src/journal.mjs';
import { brokerKey } from '../src/protocol.mjs';
import { MASK, redact } from '../src/sanitize.mjs';

const CONTROL = 'a1'.repeat(32), REVIEWER = 'b2'.repeat(32);

function workspace(t, conn) {
  const ws = tmpDir(t);
  mkdirSync(path.join(ws, 'coordination', 'ui-control'), { recursive: true });
  writeFileSync(path.join(ws, 'coordination', 'issue-ledger.json'), '{}');
  const file = path.join(ws, 'coordination', 'ui-control', 'connection.json');
  if (conn) writeFileSync(file, JSON.stringify(typeof conn === 'function' ? conn(ws) : conn));
  return { ws, file };
}

const connFor = (port, control = CONTROL, reviewer = REVIEWER) => (ws) => ({
  url: `http://127.0.0.1:${port}/#${control}`, port, workspace: ws,
  reviewerApi: `http://127.0.0.1:${port}/api/reviewer/`, reviewerHeader: 'X-PoCol-Reviewer', reviewerToken: reviewer,
});

test('connection.json is accepted only through the coordinator validator; both capabilities become redacted', (t) => {
  const { ws, file } = workspace(t, connFor(43210));
  const c = loadConnection(file, ws);
  assert.equal(c.port, 43210);
  assert.equal(c.controlToken, CONTROL);
  assert.equal(Object.hasOwn(c, 'reviewerToken'), false, 'the reviewer capability is not kept');
  assert.equal(redact(`x ${CONTROL} y ${REVIEWER}`), `x ${MASK} y ${MASK}`);
  const reject = (conn) => {
    const w = workspace(t, conn);
    assert.throws(() => loadConnection(w.file, w.ws), (e) => e instanceof BrokerError && e.kind === 'connection');
  };
  reject((ws2) => ({ ...connFor(43210)(ws2), url: `http://example.com:43210/#${CONTROL}` }));
  reject((ws2) => ({ ...connFor(43210)(ws2), url: `http://127.0.0.1:43210/../x#${CONTROL}` }));
  reject((ws2) => ({ ...connFor(43210)(ws2), workspace: path.join(ws2, 'other') }));
  reject((ws2) => ({ ...connFor(43210)(ws2), reviewerToken: CONTROL }));
  reject(null);
});

/** A minimal stand-in for the coordinator control API (fixed paths, idempotent guidance, item lookup). */
async function fakeCoordinator(t, { control = CONTROL, onRequest = null } = {}) {
  const seen = [], items = new Map(), keys = new Map();
  let mode = 'ok';
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      seen.push({ method: req.method, url: req.url, headers: req.headers, body });
      const send = (s, v) => { res.writeHead(s, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(v)); };
      if (onRequest && onRequest(req, send) === true) return;
      if (req.headers['x-pocol-control'] !== control) return send(403, { error: 'رمز غير صالح' });
      if (mode === 'refuse') return send(400, { error: 'النص فارغ.' });
      if (mode === 'busy') return send(429, { error: 'full' });
      const u = new URL(req.url, 'http://127.0.0.1');
      if (req.method === 'POST' && u.pathname === '/api/guidance') {
        const b = JSON.parse(body);
        if (keys.has(b.idempotencyKey)) return send(200, { item: items.get(keys.get(b.idempotencyKey)), duplicate: true });
        const it = { id: randomUUID(), kind: 'guidance', status: 'queued', idempotencyKey: b.idempotencyKey };
        items.set(it.id, it); keys.set(b.idempotencyKey, it.id);
        return send(200, { item: it, duplicate: false });
      }
      if (req.method === 'GET' && u.pathname === '/api/state') return send(200, { items: [...items.values()], reviews: [] });
      if (req.method === 'GET' && u.pathname === '/api/github-item') {
        const it = items.get(u.searchParams.get('itemId'));
        return it ? send(200, { item: { ...it, ackNote: null, reviewId: null, error: null, blockedReason: null }, review: null }) : send(404, { error: 'عنصر غير موجود.', missing: 'item' });
      }
      return send(404, { error: 'المسار غير موجود.' });
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  t.after(() => new Promise((r) => { server.closeAllConnections?.(); server.close(() => r()); }));
  return { server, port: server.address().port, seen, items, keys, setMode: (m) => { mode = m; } };
}

test('requests: fixed loopback paths, exact Host/Origin, control capability; error kinds', async (t) => {
  const co = await fakeCoordinator(t);
  const client = new BrokerClient({ port: co.port, controlToken: CONTROL });
  const r = await client.postGuidance({ text: 'hello', idempotencyKey: 'gh8-abcdef0123' });
  const v = await client.getState();
  assert.equal(v.items.length, 1);
  const got = await client.getItem(r.item.id);
  assert.equal(got.item.id, r.item.id);
  assert.equal(got.review, null);
  await assert.rejects(client.getItem(randomUUID()), (e) => e.kind === 'notFound');
  await assert.rejects(client.getItem('not-a-uuid'), (e) => e.kind === 'internal');
  for (const s of co.seen) {
    assert.equal(s.headers.host, `127.0.0.1:${co.port}`);
    assert.equal(s.headers.origin, `http://127.0.0.1:${co.port}`);
    assert.equal(s.headers['x-pocol-control'], CONTROL);
    assert.equal(s.headers['x-pocol-reviewer'], undefined);
    assert.ok(Object.values(ALLOWED_PATHS).includes(new URL(s.url, 'http://x').pathname));
  }
  assert.match(co.seen[2].url, /^\/api\/github-item\?itemId=[0-9a-f-]{36}$/);
  co.setMode('refuse');
  await assert.rejects(client.postGuidance({ text: '', idempotencyKey: 'gh8-abcdef0123' }), (e) => e.kind === 'refused' && e.status === 400);
  co.setMode('busy');
  await assert.rejects(client.postGuidance({ text: 'x', idempotencyKey: 'gh8-abcdef0123' }), (e) => e.kind === 'busy');
  co.setMode('ok');
  const stale = new BrokerClient({ port: co.port, controlToken: 'c3'.repeat(32) });
  await assert.rejects(stale.getState(), (e) => e.kind === 'stale' && e.status === 403);
  await assert.rejects(client._request('POST', '/api/reviewer/ack', {}), (e) => e.kind === 'internal');
  await assert.rejects(client._request('POST', '/api/pause', {}), (e) => e.kind === 'internal');
  await assert.rejects(client._request('GET', '/api/state', undefined, { itemId: randomUUID() }), (e) => e.kind === 'internal');
});

test('an older coordinator without the lookup endpoint is reported as unsupported, not as a missing item', async (t) => {
  const co = await fakeCoordinator(t, { onRequest: (req, send) => (req.url.startsWith('/api/github-item') ? (send(404, { error: 'المسار غير موجود.' }), true) : false) });
  const client = new BrokerClient({ port: co.port, controlToken: CONTROL });
  await assert.rejects(client.getItem(randomUUID()), (e) => e.kind === 'unsupported');
});

test('nothing listening: unreachable, never an external fallback', async () => {
  const s = http.createServer();
  await new Promise((r) => s.listen(0, '127.0.0.1', r));
  const port = s.address().port;
  await new Promise((r) => s.close(r));
  const client = new BrokerClient({ port, controlToken: CONTROL, timeoutMs: 2000 });
  await assert.rejects(client.getState(), (e) => e instanceof BrokerError && ['unreachable', 'uncertain'].includes(e.kind));
});

test('I8-05 (real HTTP): the coordinator restarts on a new port and capability; the adapter reloads connection.json and keeps the key', async (t) => {
  const CONTROL2 = 'd4'.repeat(32), REVIEWER2 = 'e5'.repeat(32);
  const co2 = await fakeCoordinator(t, { control: CONTROL2 });
  let file = null, ws = null;
  // The first coordinator rejects the guidance POST as if its capability had been rotated, and at
  // that moment the saved connection.json is rewritten to point to the second coordinator.
  const co1 = await fakeCoordinator(t, {
    onRequest: (req, send) => {
      if (req.method === 'POST') { writeFileSync(file, JSON.stringify(connFor(co2.port, CONTROL2, REVIEWER2)(ws))); send(403, { error: 'رمز غير صالح' }); return true; }
      return false;
    },
  });
  const w = workspace(t, connFor(co1.port));
  file = w.file; ws = w.ws;
  const stateDir = path.join(ws, 'coordination', 'ui-control', 'github-inbox');
  const clock = new Clock();
  const gh = new FakeGh();
  gh.add(comment(500, '/pocol guidance rotate-1'));
  let factoryCalls = 0;
  const brokerFactory = () => { factoryCalls += 1; const c = loadConnection(file, ws); return new BrokerClient({ port: c.port, controlToken: c.controlToken }); };
  const adapter = new Adapter({ journal: new Journal(stateDir, { now: clock.now }), gh, brokerFactory, now: clock.now });
  const s1 = await adapter.cycle();
  assert.deepEqual(s1.deliveryIssues, ['stale']);
  assert.equal(adapter.state.records['500'].status, 'delivering');
  const s2 = await adapter.cycle();
  assert.equal(s2.delivered, 1);
  assert.equal(factoryCalls, 2);
  assert.equal(co2.keys.size, 1);
  assert.ok(co2.keys.has(brokerKey(500)), 'the same idempotency key was delivered to the restarted coordinator');
  const first = co1.seen.find((s) => s.method === 'POST');
  assert.equal(JSON.parse(first.body).idempotencyKey, brokerKey(500));
  assert.equal(gh.posts.length, 1);
});
