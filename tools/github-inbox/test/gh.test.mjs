import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { childEnv, GhClient, listArgs, parseIncluded, postArgs, rateInfo } from '../src/gh.mjs';

/** A fake child with NO event-loop handle of its own: settling relies on the client's timer. */
class FakeChild extends EventEmitter {
  constructor({ closeOnKill = true } = {}) {
    super();
    this.stdout = new EventEmitter(); this.stderr = new EventEmitter(); this.stdinData = ''; this.stdinEnded = false; this.killed = false; this.closeOnKill = closeOnKill;
    this.stdin = { on: () => {}, end: (d) => { if (d !== undefined) this.stdinData += d; this.stdinEnded = true; } };
  }
  kill() { this.killed = true; if (this.closeOnKill) setImmediate(() => this.emit('close', null)); }
}

function fakeSpawn(script, childOpts) {
  const calls = [];
  const spawnImpl = (bin, args, opts) => {
    const child = new FakeChild(childOpts);
    calls.push({ bin, args: [...args], opts, child });
    setImmediate(() => script(child, args));
    return child;
  };
  return { calls, spawnImpl };
}

const OK_LIST = 'HTTP/2.0 200 OK\r\nContent-Type: application/json\r\nLink: <https://api.github.com/x?page=2>; rel="next"\r\nX-RateLimit-Remaining: 4999\r\nX-RateLimit-Reset: 1900000000\r\n\r\n[{"id":1,"body":"x"}]';

test('fixed argument vectors with a forced hostname; shell:false; windowsHide; the body only on stdin', async () => {
  assert.deepEqual(listArgs(3), ['api', '--hostname', 'github.com', '--method', 'GET', '--include', 'repos/raedrasheed/Proof-of-Collaboration/issues/8/comments?per_page=100&page=3']);
  assert.deepEqual(postArgs(), ['api', '--hostname', 'github.com', '--method', 'POST', '--include', 'repos/raedrasheed/Proof-of-Collaboration/issues/8/comments', '--input', '-']);
  assert.throws(() => listArgs('1; rm -rf /'));
  assert.throws(() => listArgs(0));
  const { calls, spawnImpl } = fakeSpawn((ch) => {
    ch.stdout.emit('data', Buffer.from('HTTP/2.0 201 Created\r\n\r\n{"id":555,"html_url":"https://github.com/raedrasheed/Proof-of-Collaboration/issues/8#issuecomment-555"}'));
    ch.emit('close', 0);
  });
  const gh = new GhClient({ ghBin: 'C:\\gh\\gh.exe', cwd: 'C:\\ws', spawnImpl, env: { PATH: 'x', GH_HOST: 'evil.example', gh_repo: 'other/repo' } });
  const evil = '"; Remove-Item -Recurse C:\\ ; $(whoami) `calc` & del /q * --hostname evil.example';
  const r = await gh.postComment(evil);
  assert.equal(r.ok, true);
  assert.equal(r.comment.id, 555);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].bin, 'C:\\gh\\gh.exe');
  assert.deepEqual(calls[0].args, postArgs());
  assert.equal(calls[0].opts.shell, false);
  assert.equal(calls[0].opts.windowsHide, true);
  assert.deepEqual(JSON.parse(calls[0].child.stdinData), { body: evil });
  assert.equal(calls[0].opts.env.GH_PROMPT_DISABLED, '1');
  assert.equal(calls[0].opts.env.PATH, 'x');
  assert.equal(calls[0].opts.env.GH_HOST, undefined, 'GH_HOST cannot redirect requests');
  assert.equal(calls[0].opts.env.gh_repo, undefined);
  assert.equal(childEnv({ Gh_Host: 'x' }).Gh_Host, undefined);
});

test('list parsing: headers, next page, rate information', async () => {
  const { calls, spawnImpl } = fakeSpawn((ch) => { ch.stdout.emit('data', OK_LIST); ch.emit('close', 0); });
  const gh = new GhClient({ ghBin: 'gh', cwd: '.', spawnImpl });
  const r = await gh.listPage(1);
  assert.equal(r.ok, true);
  assert.equal(r.next, true);
  assert.deepEqual(r.comments, [{ id: 1, body: 'x' }]);
  assert.equal(r.rate.remaining, 4999);
  assert.equal(r.rate.resetAt, 1900000000 * 1000);
  assert.deepEqual(calls[0].args, listArgs(1));
  assert.deepEqual(rateInfo({ 'retry-after': 'abc' }), { retryAfterS: null, remaining: null, resetAt: null });
  assert.equal(parseIncluded('not http').status, null);
});

// Arabic letters and an emoji built from code points (no escapes or raw characters in this source).
const ARABIC_EMOJI = String.fromCodePoint(0x645, 0x631, 0x62d, 0x628, 0x627, 0x20, 0x1f600, 0x20, 0x634, 0x643, 0x631, 0x627);

test('I8-03: UTF-8 split across chunks at every byte position is decoded exactly', async () => {
  const expected = 'HTTP/2.0 200 OK\r\n\r\n' + JSON.stringify([{ id: 7, body: ARABIC_EMOJI }]);
  const bytes = Buffer.from(expected, 'utf8');
  const start = bytes.indexOf(Buffer.from(ARABIC_EMOJI, 'utf8'));
  const end = start + Buffer.byteLength(ARABIC_EMOJI, 'utf8');
  for (let split = start + 1; split < end; split++) {
    const { spawnImpl } = fakeSpawn((ch) => { ch.stdout.emit('data', bytes.subarray(0, split)); ch.stdout.emit('data', bytes.subarray(split)); ch.emit('close', 0); });
    const r = await new GhClient({ ghBin: 'gh', cwd: '.', spawnImpl }).listPage(1);
    assert.equal(r.ok, true, `split ${split}`);
    assert.equal(r.comments[0].body, ARABIC_EMOJI, `split ${split}`);
    assert.ok(!JSON.stringify(r.comments).includes(String.fromCodePoint(0xfffd)));
  }
  // One byte per chunk.
  const { spawnImpl } = fakeSpawn((ch) => { for (const b of bytes) ch.stdout.emit('data', Buffer.from([b])); ch.emit('close', 0); });
  const r = await new GhClient({ ghBin: 'gh', cwd: '.', spawnImpl }).run(['x']);
  assert.equal(r.stdout, expected);
});

test('I8-03: the stdout cap counts bytes, not characters', async () => {
  const six = String.fromCodePoint(0x645, 0x631, 0x62d, 0x628, 0x627, 0x645);    // 6 characters, 12 bytes
  const { calls, spawnImpl } = fakeSpawn((ch) => { ch.stdout.emit('data', Buffer.from(six, 'utf8')); ch.emit('close', 0); });
  const r = await new GhClient({ ghBin: 'gh', cwd: '.', spawnImpl, maxStdout: 10 }).run(['x']);
  assert.equal(r.overflow, true);
  assert.equal(r.stdout, '');
  assert.equal(calls[0].child.killed, true);
});

test('rate limiting is classified; stderr text (even split UTF-8) is never returned', async () => {
  const secret = 'ghp_' + 'Z'.repeat(36);
  const errBytes = Buffer.from(`gh: API rate limit exceeded (HTTP 403) ${ARABIC_EMOJI} token=${secret}`, 'utf8');
  const { spawnImpl } = fakeSpawn((ch) => {
    ch.stdout.emit('data', 'HTTP/2.0 403 Forbidden\r\nRetry-After: 60\r\nX-RateLimit-Remaining: 0\r\n\r\n{"message":"API rate limit exceeded"}');
    ch.stderr.emit('data', errBytes.subarray(0, 50)); ch.stderr.emit('data', errBytes.subarray(50));
    ch.emit('close', 1);
  });
  const gh = new GhClient({ ghBin: 'gh', cwd: '.', spawnImpl });
  const r = await gh.listPage(1);
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'rateLimited');
  assert.equal(r.rate.retryAfterS, 60);
  assert.ok(!JSON.stringify(r).includes(secret));
});

test('I8-01: a silent child settles by timeout although nothing else keeps the event loop alive', async () => {
  const { calls, spawnImpl } = fakeSpawn(() => { /* never answers */ });
  const gh = new GhClient({ ghBin: 'gh', cwd: '.', spawnImpl, timeoutMs: 30 });
  const t0 = Date.now();
  const r = await gh.postComment('hello');
  assert.ok(Date.now() - t0 < 5000);
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'timeout');
  assert.equal(r.uncertain, true);
  assert.equal(calls[0].child.killed, true);
});

test('I8-01: a child that ignores kill still settles once, by timeout', async () => {
  const { calls, spawnImpl } = fakeSpawn(() => { /* never answers */ }, { closeOnKill: false });
  const r = await new GhClient({ ghBin: 'gh', cwd: '.', spawnImpl, timeoutMs: 20 }).listPage(2);
  assert.equal(r.reason, 'timeout');
  assert.equal(calls[0].child.killed, true);
  calls[0].child.emit('close', 0);                            // a late close changes nothing
});

test('stdout beyond the bound is discarded and the process killed', async () => {
  const { calls, spawnImpl } = fakeSpawn((ch) => { ch.stdout.emit('data', 'x'.repeat(2000)); });
  const gh = new GhClient({ ghBin: 'gh', cwd: '.', spawnImpl, maxStdout: 1000 });
  const r = await gh.listPage(1);
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'outputTooLarge');
  assert.equal(calls[0].child.killed, true);
});

test('a definite 4xx on post is not uncertain; a 5xx is', async () => {
  for (const [status, uncertain] of [[422, false], [502, true]]) {
    const { spawnImpl } = fakeSpawn((ch) => { ch.stdout.emit('data', `HTTP/2.0 ${status} X\r\n\r\n{}`); ch.stderr.emit('data', `gh: failed (HTTP ${status})`); ch.emit('close', 1); });
    const r = await new GhClient({ ghBin: 'gh', cwd: '.', spawnImpl }).postComment('b');
    assert.equal(r.ok, false);
    assert.equal(r.uncertain, uncertain, String(status));
  }
});

test('a launch failure means not posted', async () => {
  const spawnImpl = () => { const e = new Error('nope'); e.code = 'ENOENT'; throw e; };
  const r = await new GhClient({ ghBin: 'missing.exe', cwd: '.', spawnImpl }).postComment('b');
  assert.deepEqual([r.ok, r.reason, r.uncertain], [false, 'launchFailed', false]);
});
