import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { tmpDir } from './helpers.mjs';
import { acquireLease, ACTIVATION_FILE, BACKUP_FILE, freshState, Journal, JournalError, LeaseError, STATE_FILE } from '../src/journal.mjs';

test('atomic save and load round trip; the previous state is kept as backup', (t) => {
  const dir = tmpDir(t);
  const j = new Journal(dir);
  const s = j.load();
  assert.deepEqual(Object.keys(s.records), []);
  s.records['1'] = { commentId: 1, status: 'accepted' };
  j.save(s);
  s.records['1'].status = 'delivered';
  j.save(s);
  assert.equal(new Journal(dir).load().records['1'].status, 'delivered');
  assert.ok(existsSync(path.join(dir, BACKUP_FILE)));
});

test('corrupt or torn main file falls back to the valid backup', (t) => {
  const dir = tmpDir(t);
  const j = new Journal(dir);
  const s = freshState();
  s.records['7'] = { commentId: 7, status: 'delivered' };
  j.save(s);
  s.records['8'] = { commentId: 8, status: 'accepted' };
  j.save(s);
  const main = path.join(dir, STATE_FILE);
  writeFileSync(main, readFileSync(main, 'utf8').slice(0, 40));
  const j2 = new Journal(dir);
  const loaded = j2.load();
  assert.equal(j2.recoveredFromBackup, true);
  assert.deepEqual(Object.keys(loaded.records), ['7']);
  // Crash between the two renames: only the backup exists.
  renameSync(main, path.join(dir, 'gone'));
  assert.deepEqual(Object.keys(new Journal(dir).load().records), ['7']);
});

test('state files that exist but are all invalid never become an empty state', (t) => {
  const dir = tmpDir(t);
  writeFileSync(path.join(dir, STATE_FILE), '{"format":"pocol-github-inbox-state/1","body":"{}","digest":"x"}');
  writeFileSync(path.join(dir, BACKUP_FILE), 'garbage');
  assert.throws(() => new Journal(dir).load(), JournalError);
});

test('activation is false unless root recorded complete end-to-end evidence', (t) => {
  const dir = tmpDir(t);
  const j = new Journal(dir);
  assert.equal(j.activation().connectionVerified, false);
  writeFileSync(path.join(dir, ACTIVATION_FILE), JSON.stringify({ connectionVerified: true, evidence: { roundtripCommentUrl: 'x' } }));
  assert.equal(j.activation().connectionVerified, false);
  writeFileSync(path.join(dir, ACTIVATION_FILE), JSON.stringify({
    connectionVerified: true, recordedBy: 'root', recordedAt: '2026-10-08T00:00:00Z',
    evidence: { roundtripCommentUrl: 'https://github.com/raedrasheed/Proof-of-Collaboration/issues/8#issuecomment-1', duplicateCheck: 'passed', restartCheck: 'passed' },
  }));
  assert.equal(j.activation().connectionVerified, true);
});

test('the lease is exclusive and released without deleting anything', async (t) => {
  const dir = tmpDir(t);
  const a = await acquireLease(dir);
  await assert.rejects(acquireLease(dir), LeaseError);
  await a.release();
  const b = await acquireLease(dir);
  await b.release();
});
