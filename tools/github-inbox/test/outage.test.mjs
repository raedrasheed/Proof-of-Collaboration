// I8-07: delivery outages. Bounded per-request state, a truthful temporary transport notice, and
// idempotent recovery with the SAME broker key after an observed healthy coordinator.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Clock, comment, FakeBroker, FakeGh, makeAdapter, runCycles, tmpDir } from './helpers.mjs';
import { DELIVERY_BACKOFF_MAX_S, MAX_DELIVERY_ATTEMPTS, MAX_RECOVERY_EPOCHS, RECOVERY_EPOCH_ATTEMPTS } from '../src/constants.mjs';
import { publicStatus } from '../src/adapter.mjs';
import { brokerKey, publicationKey } from '../src/protocol.mjs';

const STEP = (DELIVERY_BACKOFF_MAX_S + 1) * 1000;           // longer than any per-request backoff and the health interval

function setup(t) {
  const dir = tmpDir(t), gh = new FakeGh(), broker = new FakeBroker(), clock = new Clock();
  const mk = () => makeAdapter(dir, { gh, broker, clock });
  return { dir, gh, broker, clock, mk, adapter: mk() };
}

test('offline until the budget is exhausted, then healthy: one temporary notice, then recovery with the same key', async (t) => {
  const { gh, broker, clock, adapter } = setup(t);
  gh.add(comment(300, '/pocol guidance out-long\nplease'));
  broker.down = true;
  const rec = () => adapter.state.records['300'];
  await adapter.cycle();
  await runCycles(adapter, clock, { stepMs: STEP, max: 60, until: () => rec().status === 'deliveryStalled' });
  assert.equal(rec().status, 'deliveryStalled', 'stalled, not failed');
  assert.equal(broker.posts, MAX_DELIVERY_ATTEMPTS);
  const notice = gh.markerPosts(publicationKey(300, 'transportBlocked'));
  assert.equal(notice.length, 1, 'exactly one temporary transport notice');
  assert.match(notice[0].body, /Temporarily blocked \(transport only\)/);
  assert.match(notice[0].body, /NOT known whether the request already reached/);
  assert.ok(!/not delivered|author did not run|no author/i.test(notice[0].body.replace(/NOT known whether/, '')), 'never concludes non-delivery');
  // Still offline: health reads fail, nothing is delivered, no loop of POSTs.
  await runCycles(adapter, clock, { stepMs: STEP, max: 3 });
  assert.equal(broker.posts, MAX_DELIVERY_ATTEMPTS);
  assert.equal(rec().status, 'deliveryStalled');
  // Healthy again: one recovery epoch, the same key, one broker item, one "received".
  broker.down = false;
  clock.advance(STEP);
  const s = await adapter.cycle();
  assert.equal(s.health, 'ok');
  assert.equal(s.recoveryEpochs, 1);
  assert.equal(rec().status, 'delivered');
  assert.equal(broker.guidance().length, 1);
  assert.ok(broker.postedKeys.every((k) => k === brokerKey(300)), 'every attempt used the same key');
  assert.equal(gh.markerPosts(publicationKey(300, 'received')).length, 1);
  assert.equal(gh.markerPosts(publicationKey(300, 'transportBlocked')).length, 1, 'the notice is not repeated');
  // The temporary notice never suppresses later actual states.
  broker.ack(broker.guidance()[0].id, 'thanks');
  await runCycles(adapter, clock, { stepMs: STEP, max: 2 });
  assert.equal(gh.markerPosts(publicationKey(300, 'acknowledged')).length, 1);
});

test('response lost before exhaustion: the coordinator already persisted it; recovery returns the same item', async (t) => {
  const { gh, broker, clock, adapter } = setup(t);
  gh.add(comment(301, '/pocol status lost-1'));
  broker.uncertainOnce = true;                                // persisted, but the reply is lost
  await adapter.cycle();
  const rec = adapter.state.records['301'];
  assert.equal(rec.status, 'delivering');
  assert.equal(rec.delivery.maybeDelivered, true);
  broker.down = true;
  await runCycles(adapter, clock, { stepMs: STEP, max: 60, until: () => adapter.state.records['301'].status === 'deliveryStalled' });
  const notice = gh.markerPosts(publicationKey(301, 'transportBlocked'));
  assert.equal(notice.length, 1);
  assert.match(notice[0].body, /NOT known whether/);
  broker.down = false;
  await runCycles(adapter, clock, { stepMs: STEP, max: 3, until: () => adapter.state.records['301'].status === 'delivered' });
  assert.equal(adapter.state.records['301'].status, 'delivered');
  assert.equal(adapter.state.records['301'].duplicateAtBroker, true, 'the earlier persisted item was returned');
  assert.equal(broker.guidance().length, 1, 'no second local item');
});

test('a definite refusal is final: blocked once, no retry loop, no health reads', async (t) => {
  const { gh, broker, clock, adapter } = setup(t);
  gh.add(comment(302, '/pocol guidance refused-1'));
  broker.refuse = true;
  await adapter.cycle();
  await runCycles(adapter, clock, { stepMs: STEP, max: 10 });
  assert.equal(adapter.state.records['302'].status, 'deliveryRefused');
  assert.equal(broker.posts, 1);
  assert.equal(broker.stateCalls, 0);
  assert.equal(gh.markerPosts(publicationKey(302, 'blocked')).length, 1);
  assert.equal(gh.markerPosts(publicationKey(302, 'transportBlocked')).length, 0);
});

test('restart keeps budgets, epochs and keys', async (t) => {
  const { gh, broker, clock, mk, adapter } = setup(t);
  gh.add(comment(303, '/pocol guidance restart-1'));
  broker.down = true;
  await adapter.cycle();
  await runCycles(adapter, clock, { stepMs: STEP, max: 4 });
  assert.equal(adapter.state.records['303'].delivery.epochAttempts, 5);
  const again = mk();
  assert.equal(again.state.records['303'].delivery.epochAttempts, 5);
  assert.equal(again.state.records['303'].brokerKey, brokerKey(303));
  await runCycles(again, clock, { stepMs: STEP, max: 60, until: () => again.state.records['303'].status === 'deliveryStalled' });
  assert.equal(broker.posts, MAX_DELIVERY_ATTEMPTS, 'the restart did not reset the budget');
});

test('recovery epochs are bounded; afterwards only an explicit operator retry re-enables delivery (same IDs)', async (t) => {
  const { gh, broker, clock, adapter } = setup(t);
  gh.add(comment(304, '/pocol guidance epochs-1'));
  broker.postFailKind = 'uncertain';                          // reads work, deliveries keep failing
  await adapter.cycle();
  await runCycles(adapter, clock, { stepMs: STEP, max: 400, until: () => adapter.state.records['304'].status === 'deliveryFailed' });
  const rec = adapter.state.records['304'];
  assert.equal(rec.status, 'deliveryFailed');
  assert.equal(rec.lastError, 'recoveryEpochsExhausted');
  assert.equal(broker.posts, MAX_DELIVERY_ATTEMPTS + MAX_RECOVERY_EPOCHS * RECOVERY_EPOCH_ATTEMPTS);
  await runCycles(adapter, clock, { stepMs: STEP, max: 5 });
  assert.equal(broker.posts, MAX_DELIVERY_ATTEMPTS + MAX_RECOVERY_EPOCHS * RECOVERY_EPOCH_ATTEMPTS, 'no endless loop');
  assert.equal(adapter.operatorRetry('nope-1').ok, false);
  const r = adapter.operatorRetry('epochs-1');
  assert.equal(r.ok, true);
  broker.postFailKind = null;
  clock.advance(STEP);
  await adapter.cycle();
  assert.equal(adapter.state.records['304'].status, 'delivered');
  assert.equal(adapter.state.records['304'].commentId, 304);
  assert.equal(adapter.state.requestIds['epochs-1'], 304);
  assert.ok(broker.postedKeys.every((k) => k === brokerKey(304)));
  assert.equal(broker.guidance().length, 1);
  assert.equal(adapter.operatorRetry('epochs-1').ok, false, 'a delivered request is not retryable');
});

test('an actual blocked result stays final; a temporary notice before it does not hide it', async (t) => {
  const { gh, broker, clock, adapter } = setup(t);
  gh.add(comment(305, '/pocol status final-1'));
  broker.down = true;
  await adapter.cycle();
  await runCycles(adapter, clock, { stepMs: STEP, max: 3 });   // > 10 minutes of outage
  assert.equal(gh.markerPosts(publicationKey(305, 'transportBlocked')).length, 1);
  broker.down = false;
  await runCycles(adapter, clock, { stepMs: STEP, max: 2 });
  broker.ack(broker.guidance()[0].id, 'POCOL_GITHUB_RESULT {"mode":"status","state":"blocked","summary":"policy blocker remains"}');
  await runCycles(adapter, clock, { stepMs: STEP, max: 3 });
  assert.equal(gh.markerPosts(publicationKey(305, 'received')).length, 1);
  assert.equal(gh.markerPosts(publicationKey(305, 'blocked')).length, 1);
  const before = gh.posts.length;
  await runCycles(adapter, clock, { stepMs: STEP, max: 3 });
  assert.equal(gh.posts.length, before, 'final: nothing after the actual blocked result');
  const ps = publicStatus(adapter.state, null);
  assert.deepEqual(ps.requests[0].published.sort(), ['blocked', 'received', 'transportBlocked']);
});

test('a short outage recovers automatically without any notice', async (t) => {
  const { gh, broker, clock, adapter } = setup(t);
  gh.add(comment(306, '/pocol status short-1'));
  broker.down = true;
  await adapter.cycle();
  clock.advance(60_000);
  await adapter.cycle();
  broker.down = false;
  clock.advance(60_000);
  await adapter.cycle();
  await runCycles(adapter, clock, { stepMs: 60_000, max: 3, until: () => adapter.state.records['306'].status === 'delivered' });
  assert.equal(adapter.state.records['306'].status, 'delivered');
  assert.equal(gh.markerPosts(publicationKey(306, 'transportBlocked')).length, 0);
  assert.equal(gh.markerPosts(publicationKey(306, 'received')).length, 1);
});
