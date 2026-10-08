import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { GhClient, listArgs, parseIncluded, postArgs, rateInfo } from '../src/gh.mjs';

class FakeChild extends EventEmitter {
  constructor() {
    super();
    this.stdout = new EventEmitter(); this.stderr = new EventEmitter(); this.stdinData = ''; this.stdinEnded = false; this.killed = false;
    this.stdin = { on: () => {}, end: (d) => { if (d !== undefined) this.stdinData += d; this.stdinEnded = true; } };
  }
  kill() { this.killed = true; setImmediate(() => this.emit('close', null)); }
}

function fakeSpawn(script) {
  const calls = [];
  const spawnImpl = (bin, args, opts) => {
    const child = new FakeChild();
    calls.push({ bin, args: [...args], opts, child });
    setImmediate(() => script(child, args));
    return child;
  };
  return { calls, spawnImpl };
}

const OK_LIST = 'HTTP/2.0 200 OK\r\nContent-Type: application/json\r\nLink: <https://api.github.com/x?page=2>; rel="next"\r\nX-RateLimit-Remaining: 4999\r\nX-RateLimit-Reset: 1900000000\r\n\r\n[{"id":1,"body":"x"}]';

test('fixed argument vectors; shell:false; windowsHide; the comment body only on stdin', async () => {
  assert.deepEqual(listArgs(3), ['api', '--method', 'GET', '--include', 'repos/raedrasheed/Proof-of-Collaboration/issues/8/comments?per_page=100&page=3']);
  assert.deepEqual(postArgs(), ['api', '--method', 'POST', '--include', 'repos/raedrasheed/Proof-of-Collaboration/issues/8/comments', '--input', '-']);
  assert.throws(() => listArgs('1; rm -rf /'));
  assert.throws(() => listArgs(0));
  const { calls, spawnImpl } = fakeSpawn((ch) => {
    ch.stdout.emit('data', 'HTTP/2.0 201 Created\r\n\r\n{"id":555,"html_url":"https://github.com/raedrasheed/Proof-of-Collaboration/issues/8#issuecomment-555"}');
    ch.emit('close', 0);
  });
  const gh = new GhClient({ ghBin: 'C:\\gh\\gh.exe', cwd: 'C:\\ws', spawnImpl, env: { PATH: 'x' } });
  const evil = '"; Remove-Item -Recurse C:\\ ; $(whoami) `calc` & del /q *';
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
});

test('list parsing: headers, next page, rate information', async () => {
  const { spawnImpl } = fakeSpawn((ch) => { ch.stdout.emit('data', OK_LIST); ch.emit('close', 0); });
  const gh = new GhClient({ ghBin: 'gh', cwd: '.', spawnImpl });
  const r = await gh.listPage(1);
  assert.equal(r.ok, true);
  assert.equal(r.next, true);
  assert.deepEqual(r.comments, [{ id: 1, body: 'x' }]);
  assert.equal(r.rate.remaining, 4999);
  assert.equal(r.rate.resetAt, 1900000000 * 1000);
  assert.deepEqual(rateInfo({ 'retry-after': 'abc' }), { retryAfterS: null, remaining: null, resetAt: null });
  assert.equal(parseIncluded('not http').status, null);
});

test('rate limiting is classified; stderr text is never returned', async () => {
  const secret = 'ghp_' + 'Z'.repeat(36);
  const { spawnImpl } = fakeSpawn((ch) => {
    ch.stdout.emit('data', 'HTTP/2.0 403 Forbidden\r\nRetry-After: 60\r\nX-RateLimit-Remaining: 0\r\n\r\n{"message":"API rate limit exceeded"}');
    ch.stderr.emit('data', `gh: API rate limit exceeded (HTTP 403) token=${secret}`);
    ch.emit('close', 1);
  });
  const gh = new GhClient({ ghBin: 'gh', cwd: '.', spawnImpl });
  const r = await gh.listPage(1);
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'rateLimited');
  assert.equal(r.rate.retryAfterS, 60);
  assert.ok(!JSON.stringify(r).includes(secret));
});

test('timeout kills gh; a post with an unknown outcome is reported as uncertain', async () => {
  const { calls, spawnImpl } = fakeSpawn(() => { /* never answers */ });
  const gh = new GhClient({ ghBin: 'gh', cwd: '.', spawnImpl, timeoutMs: 30 });
  const r = await gh.postComment('hello');
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'timeout');
  assert.equal(r.uncertain, true);
  assert.equal(calls[0].child.killed, true);
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
