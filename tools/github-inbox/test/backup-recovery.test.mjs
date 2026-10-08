// I8-08: journal backup recovery. The backup can predate a saved 'posting' flag, so after any
// fallback a persisted barrier walks the whole issue from page 1 (bounded pages per cycle, progress
// kept across restarts and interruptions) and nothing is posted until coverage is complete and settled.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { Clock, comment, FakeBroker, FakeGh, makeAdapter, runCycles, tmpDir } from './helpers.mjs';
import { RECONCILE_MIN_AGE_MS } from '../src/constants.mjs';
import { resetJournal } from '../src/adapter.mjs';
import { BACKUP_FILE, Journal, STATE_FILE } from '../src/journal.mjs';
import { publicationKey } from '../src/protocol.mjs';

const NOTES = 2400;                                         // 24 full pages before the request
const CMD = NOTES + 1;                                      // the request is on page 25

/**
 * Real flow up to a posted "completed" status reply, then the exact failure from the review: main
 * file torn, backup = the state saved BEFORE the completed publication (no 'posting' flag in it).
 */
async function scenario(t) {
  const dir = tmpDir(t), gh = new FakeGh(), broker = new FakeBroker(), clock = new Clock();
  const mk = () => makeAdapter(dir, { gh, broker, clock });
  for (let i = 1; i <= NOTES; i++) gh.add(comment(i, `ordinary comment ${i}`));
  gh.add(comment(CMD, '/pocol status replay-proof'));
  const a = mk();
  await runCycles(a, clock, { stepMs: 61_000, max: 6, until: () => a.state.records[String(CMD)]?.publications.received?.status === 'posted' });
  assert.equal(a.state.records[String(CMD)].publications.received.status, 'posted');
  broker.ack(broker.guidance()[0].id, 'POCOL_GITHUB_RESULT {"mode":"status","state":"completed","summary":"actual acknowledged status"}');
  const main = path.join(dir, STATE_FILE), bak = path.join(dir, BACKUP_FILE);
  const beforeCompleted = readFileSync(main, 'utf8');      // state without any 'completed' publication
  clock.advance(61_000);
  await a.cycle();
  const completedKey = publicationKey(CMD, 'completed');
  assert.equal(gh.markerPosts(completedKey).length, 1, 'the original completed reply exists on GitHub');
  writeFileSync(bak, beforeCompleted);
  writeFileSync(main, 'torn');
  return { dir, gh, broker, clock, mk, completedKey, main, bak };
}

test('backup recovery: the existing marker beyond the page budget is reconciled; no duplicate POST', async (t) => {
  const { dir, gh, clock, mk, completedKey } = await scenario(t);
  const postsBefore = gh.posts.length;
  const b = mk();
  assert.ok(b.state.reconcileBarrier, 'a persisted barrier is set at once');
  assert.equal(b.state.records[String(CMD)].publications.completed, undefined, 'the restored state lacks the completed publication');
  assert.ok(readdirSync(dir).some((f) => f.startsWith(`${STATE_FILE}.corrupt-`)), 'the corrupt main file is kept as evidence');
  gh.pagesRequested.length = 0;
  clock.advance(61_000);
  const c1 = await b.cycle();
  assert.deepEqual(gh.pagesRequested, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 'the walk starts at page 1, not at the saved cursor');
  assert.ok(c1.publishIssues.includes('reconcileBarrier'));
  assert.equal(gh.posts.length, postsBefore, 'no POST during the walk');
  clock.advance(61_000);
  await b.cycle();                                          // pages 11..20
  // Restart during reconciliation: the barrier and its progress survive (main file is valid now).
  const c = mk();
  assert.equal(c.state.reconcileBarrier.nextPage, 21);
  gh.pagesRequested.length = 0;
  clock.advance(RECONCILE_MIN_AGE_MS);
  const c3 = await c.cycle();
  assert.deepEqual(gh.pagesRequested, [21, 22, 23, 24, 25]);
  assert.equal(c3.barrierCleared, true);
  assert.equal(c.state.reconcileBarrier, null);
  assert.equal(gh.markerComments(completedKey).length, 1, 'still exactly one completed reply on GitHub');
  assert.equal(gh.posts.length, postsBefore, 'reconciled, not reposted');
  assert.equal(c.state.records[String(CMD)].publications.completed.status, 'posted');
  assert.equal(c.state.records[String(CMD)].publications.completed.reconciled, true);
  await runCycles(c, clock, { stepMs: 61_000, max: 3 });
  assert.equal(gh.posts.length, postsBefore);
});

test('backup recovery: an absent marker is posted exactly once, only after full coverage and settling', async (t) => {
  const { gh, clock, mk, completedKey } = await scenario(t);
  gh.comments = gh.comments.filter((x) => !x.body.includes(completedKey));   // the earlier reply never landed
  const postsBefore = gh.posts.length;
  const b = mk();
  // Walk the whole issue quickly (less than the settling age): coverage complete, still no POST.
  await b.cycle(); await b.cycle(); await b.cycle();
  assert.equal(b.state.reconcileBarrier.phase, 'settle');
  assert.equal(gh.posts.length, postsBefore, 'no POST before the barrier settles');
  clock.advance(RECONCILE_MIN_AGE_MS);
  gh.pagesRequested.length = 0;
  const s = await b.cycle();
  assert.equal(s.barrierCleared, true);
  assert.ok(gh.pagesRequested[0] >= 23, 'the settling scan re-reads the tail, not the whole issue');
  assert.equal(gh.markerComments(completedKey).length, 1);
  assert.equal(gh.posts.length, postsBefore + 1);
  await runCycles(b, clock, { stepMs: 61_000, max: 3 });
  assert.equal(gh.markerComments(completedKey).length, 1, 'exactly once');
});

test('backup recovery: rate limits interrupt the walk without losing its progress', async (t) => {
  const { gh, clock, mk, completedKey } = await scenario(t);
  const postsBefore = gh.posts.length;
  const b = mk();
  clock.advance(61_000);
  await b.cycle();                                          // pages 1..10
  gh.listPlan.push({ reason: 'rateLimited', retryAfterS: 120 });
  clock.advance(61_000);
  const s = await b.cycle();
  assert.equal(s.error, 'scan:rateLimited');
  assert.equal(b.state.reconcileBarrier.nextPage, 11);
  clock.advance(121_000);
  await runCycles(b, clock, { stepMs: 61_000, max: 4, until: () => b.state.reconcileBarrier === null });
  assert.equal(b.state.reconcileBarrier, null);
  assert.equal(gh.markerComments(completedKey).length, 1);
  assert.equal(gh.posts.length, postsBefore);
});

test('operator reset archives the journal and reconciles existing replies instead of reposting them', async (t) => {
  const { dir, gh, broker, clock, mk } = await scenario(t);
  writeFileSync(path.join(dir, STATE_FILE), readFileSync(path.join(dir, BACKUP_FILE), 'utf8'));   // a valid journal again
  const postsBefore = gh.posts.length;
  const archived = resetJournal(new Journal(dir, { now: clock.now }), clock.now);
  assert.equal(archived.length, 2);
  assert.ok(archived.every((f) => f.includes('.reset-')));
  const r = mk();
  assert.equal(r.state.reconcileBarrier.reason, 'operatorReset');
  assert.deepEqual(Object.keys(r.state.records), []);
  await runCycles(r, clock, { stepMs: 61_000, max: 6, until: () => r.state.reconcileBarrier === null });
  await runCycles(r, clock, { stepMs: 61_000, max: 2 });
  assert.equal(r.state.records[String(CMD)].duplicateAtBroker, true, 'the same coordinator item, no new one');
  assert.equal(broker.guidance().length, 1);
  assert.equal(gh.posts.length, postsBefore, 'received and completed were reconciled from their markers');
  assert.equal(r.state.records[String(CMD)].publications.completed.reconciled, true);
});

test('a second backup recovery during the walk restarts the walk at page 1', async (t) => {
  const { dir, clock, mk, main, bak } = await scenario(t);
  const b = mk();
  clock.advance(61_000);
  await b.cycle();
  assert.equal(b.state.reconcileBarrier.nextPage, 11);
  writeFileSync(bak, readFileSync(main, 'utf8'));
  writeFileSync(main, 'torn again');
  const c = mk();
  assert.equal(c.state.reconcileBarrier.nextPage, 1);
  assert.equal(c.state.reconcileBarrier.phase, 'walk');
  assert.ok(readdirSync(dir).filter((f) => f.startsWith(`${STATE_FILE}.corrupt-`)).length >= 2, 'every corrupt file is kept');
});
