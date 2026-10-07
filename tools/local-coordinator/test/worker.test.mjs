import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { buildCommand, findClaude, Worker } from '../src/worker.mjs';
import { SESSION, fakeSpawner } from './helpers.mjs';

function makeWorker() {
  const root = mkdtempSync(path.join(os.tmpdir(), 'pocol-worker-'));
  const uiDir = path.join(root, 'ui-control');
  const sp = fakeSpawner();
  const ctx = { impl: sp.spawnImpl };
  const w = new Worker({ ws: root, uiDir, claudeBin: 'claude-fake', spawnImpl: (...a) => ctx.impl(...a), isAlive: () => false });
  return { root, uiDir, w, sp, ctx };
}
const smoke = (id) => ({ id, dispatch: { mode: 'smoke', sessionId: SESSION } });

test('capability set (--tools) is explicit; scoped allow/deny and default permissions kept', () => {
  const s = buildCommand({ mode: 'smoke', sessionId: SESSION }).args;
  assert.equal(s[s.indexOf('--tools') + 1], 'Read,Glob,Grep');
  assert.ok(s.indexOf('--tools') < s.indexOf('--allowedTools'), '--tools is not swallowed by a variadic list');
  assert.deepEqual(s.slice(s.indexOf('--allowedTools') + 1, s.indexOf('--disallowedTools')), ['Read', 'Glob', 'Grep']);
  assert.equal(s[s.indexOf('--permission-mode') + 1], 'default');
  const a = buildCommand({ mode: 'author', sessionId: SESSION, taskFile: 'task-007.md', plannedDir: 'm1-draft-0.9' }).args;
  assert.equal(a[a.indexOf('--tools') + 1], 'Read,Glob,Grep,Write,Edit');
  assert.deepEqual(a.slice(a.indexOf('--allowedTools') + 1, a.indexOf('--disallowedTools')),
    ['Read', 'Glob', 'Grep', 'Write(./m1-draft-0.9/**)', 'Edit(./m1-draft-0.9/**)']);
  for (const denied of ['Bash', 'PowerShell', 'Agent', 'WebFetch']) assert.ok(a.slice(a.indexOf('--disallowedTools')).includes(denied));
  assert.ok(!a.includes('--dangerously-skip-permissions') && !a.includes('bypassPermissions'));
});

test('invalid plan or session fails before any lease or spawn', () => {
  const { w, sp } = makeWorker();
  assert.throws(() => w.start({ id: 'job-bad-1', dispatch: { mode: 'author', sessionId: SESSION, taskFile: '../x.md', plannedDir: 'm1-draft-0.9' } }), /ملف المهمة/);
  assert.throws(() => w.start({ id: 'job-bad-2', dispatch: { mode: 'smoke', sessionId: 'not-a-session' } }), /جلسة/);
  assert.equal(existsSync(w.leaseFile), false);
  assert.equal(sp.calls.length, 0);
});

test('job directory failure happens before the lease', () => {
  const { w, uiDir, sp } = makeWorker();
  mkdirSync(uiDir, { recursive: true });
  writeFileSync(path.join(uiDir, 'jobs'), 'a file where the jobs directory should be');
  assert.throws(() => w.start(smoke('job-mkdir-1')));
  assert.equal(existsSync(w.leaseFile), false);
  assert.equal(sp.calls.length, 0);
});

test('spawn throwing after the lease: lease removed, no completion, next start works', () => {
  const { w, sp, ctx } = makeWorker();
  const good = ctx.impl;
  let exits = 0;
  ctx.impl = () => { throw new Error('spawn EACCES'); };
  assert.throws(() => w.start(smoke('job-throw-1'), () => exits++), /EACCES/);
  assert.equal(existsSync(w.leaseFile), false, 'lease not stranded');
  ctx.impl = () => null;
  assert.throws(() => w.start(smoke('job-null-01'), () => exits++), /عملية صالحة/);
  assert.equal(existsSync(w.leaseFile), false);
  ctx.impl = good;
  const lease = w.start(smoke('job-after-1'), () => exits++);
  assert.equal(lease.jobId, 'job-after-1');
  assert.equal(sp.calls.length, 1);
  assert.equal(exits, 0, 'failed starts never report a completion');
});

test('failure after spawn stops the child and releases the lease', () => {
  const { w, ctx } = makeWorker();
  let killed = false;
  ctx.impl = () => ({ pid: 4711, on() { throw new Error('listener failure'); }, kill() { killed = true; } });
  assert.throws(() => w.start(smoke('job-post-01')), /listener failure/);
  assert.equal(killed, true);
  assert.equal(existsSync(w.leaseFile), false);
});

test('exit and error both firing complete the job exactly once', () => {
  const { w, sp } = makeWorker();
  const seen = [];
  const lease = w.start(smoke('job-once-01'), (r) => seen.push(r));
  assert.equal(JSON.parse(readFileSync(w.leaseFile, 'utf8')).pid, lease.pid);
  const child = sp.calls[0].child;
  child.emit('error', new Error('spawn ENOENT'));
  child.emit('exit', 1, null);
  child.emit('exit', 1, null);
  assert.equal(seen.length, 1);
  assert.match(seen[0].error, /ENOENT/);
  assert.equal(w.child, null);
});

test('one lease at a time; release only removes the matching job lease', () => {
  const { w, sp } = makeWorker();
  w.start(smoke('job-lease-01'));
  assert.throws(() => w.start(smoke('job-lease-02')), /عقد عامل قائم/);
  assert.equal(sp.calls.length, 1);
  w.release('job-lease-02');
  assert.equal(existsSync(w.leaseFile), true, 'another job cannot release this lease');
  w.release('job-lease-01');
  assert.equal(existsSync(w.leaseFile), false);
});

test('explicit claude path must be a real executable file (.exe on Windows, never .cmd)', () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'pocol-claude-'));
  const cmd = path.join(dir, 'claude.cmd'); writeFileSync(cmd, '@echo off');
  const exe = path.join(dir, 'claude.exe'); writeFileSync(exe, 'MZ');
  const folder = path.join(dir, 'folder.exe'); mkdirSync(folder);
  assert.throws(() => findClaude(cmd, { platform: 'win32' }), /\.exe/);
  assert.throws(() => findClaude(folder, { platform: 'win32' }), /ليس ملفًا/);
  assert.throws(() => findClaude(path.join(dir, 'missing.exe'), { platform: 'win32' }), /غير موجود/);
  assert.equal(findClaude(exe, { platform: 'win32' }), path.resolve(exe));
  const unix = path.join(dir, 'claude'); writeFileSync(unix, '#!/bin/sh');
  assert.equal(findClaude(unix, { platform: 'linux' }), path.resolve(unix));
});
