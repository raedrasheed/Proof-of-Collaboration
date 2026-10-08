import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { tmpDir } from './helpers.mjs';
import { ALLOWED_PATHS, BrokerClient, BrokerError, loadConnection } from '../src/broker-client.mjs';
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

const validConn = (port) => (ws) => ({
  url: `http://127.0.0.1:${port}/#${CONTROL}`, port, workspace: ws,
  reviewerApi: `http://127.0.0.1:${port}/api/reviewer/`, reviewerHeader: 'X-PoCol-Reviewer', reviewerToken: REVIEWER,
});

test('connection.json is accepted only through the coordinator validator; both capabilities become redacted', (t) => {
  const { ws, file } = workspace(t, validConn(43210));
  const c = loadConnection(file, ws);
  assert.equal(c.port, 43210);
  assert.equal(c.controlToken, CONTROL);
  assert.equal(Object.hasOwn(c, 'reviewerToken'), false, 'the reviewer capability is not kept');
  assert.equal(redact(`x ${CONTROL} y ${REVIEWER}`), `x ${MASK} y ${MASK}`);
  const reject = (conn) => {
    const w = workspace(t, conn);
    assert.throws(() => loadConnection(w.file, w.ws), (e) => e instanceof BrokerError && e.kind === 'connection');
  };
  reject((ws2) => ({ ...validConn(43210)(ws2), url: `http://example.com:43210/#${CONTROL}` }));
  reject((ws2) => ({ ...validConn(43210)(ws2), url: `http://127.0.0.1:43210/../x#${CONTROL}` }));
  reject((ws2) => ({ ...validConn(43210)(ws2), workspace: path.join(ws2, 'other') }));
  reject((ws2) => ({ ...validConn(43210)(ws2), reviewerToken: CONTROL }));
  reject(null);
});

test('requests: fixed loopback paths, exact Host/Origin, control capability; refusals and busy are classified', async (t) => {
  const seen = [];
  let mode = 'ok';
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      seen.push({ method: req.method, url: req.url, headers: req.headers, body });
      const send = (s, v) => { res.writeHead(s, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(v)); };
      if (mode === 'refuse') return send(400, { error: 'النص فارغ.' });
      if (mode === 'busy') return send(429, { error: 'full' });
      if (req.url === '/api/guidance') { const b = JSON.parse(body); return send(200, { item: { id: 'i-1', idempotencyKey: b.idempotencyKey, status: 'queued' }, duplicate: false }); }
      if (req.url === '/api/state') return send(200, { items: [], reviews: [] });
      return send(404, { error: 'no' });
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  t.after(() => server.close());
  const port = server.address().port;
  const client = new BrokerClient({ port, controlToken: CONTROL });
  const r = await client.postGuidance({ text: 'hello', idempotencyKey: 'gh8-abcdef0123' });
  assert.equal(r.item.id, 'i-1');
  const v = await client.getState();
  assert.deepEqual(v, { items: [], reviews: [] });
  for (const s of seen) {
    assert.equal(s.headers.host, `127.0.0.1:${port}`);
    assert.equal(s.headers.origin, `http://127.0.0.1:${port}`);
    assert.equal(s.headers['x-pocol-control'], CONTROL);
    assert.equal(s.headers['x-pocol-reviewer'], undefined);
    assert.ok(Object.values(ALLOWED_PATHS).includes(s.url));
  }
  assert.equal(seen[0].method, 'POST');
  assert.match(seen[0].headers['content-type'], /^application\/json/);
  assert.deepEqual(JSON.parse(seen[0].body), { text: 'hello', idempotencyKey: 'gh8-abcdef0123' });
  assert.equal(seen[1].method, 'GET');
  mode = 'refuse';
  await assert.rejects(client.postGuidance({ text: '', idempotencyKey: 'gh8-abcdef0123' }), (e) => e.kind === 'refused' && e.status === 400);
  mode = 'busy';
  await assert.rejects(client.postGuidance({ text: 'x', idempotencyKey: 'gh8-abcdef0123' }), (e) => e.kind === 'busy');
  await assert.rejects(client._request('POST', '/api/reviewer/ack', {}), (e) => e.kind === 'internal');
  await assert.rejects(client._request('POST', '/api/pause', {}), (e) => e.kind === 'internal');
});

test('nothing listening: unreachable, never an external fallback', async () => {
  const s = http.createServer();
  await new Promise((r) => s.listen(0, '127.0.0.1', r));
  const port = s.address().port;
  await new Promise((r) => s.close(r));
  const client = new BrokerClient({ port, controlToken: CONTROL, timeoutMs: 2000 });
  await assert.rejects(client.getState(), (e) => e instanceof BrokerError && ['unreachable', 'uncertain'].includes(e.kind));
});
