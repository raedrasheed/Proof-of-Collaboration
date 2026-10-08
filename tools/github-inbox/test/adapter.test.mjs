import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Clock, comment, FakeBroker, FakeGh, LP3_CHECKPOINT, makeAdapter, OWNER, tmpDir } from './helpers.mjs';
import { FULL_RESCAN_EVERY, ISSUE_API_URL, MAX_LOOKUPS_PER_CYCLE, RECONCILE_MIN_AGE_MS } from '../src/constants.mjs';
import { publicStatus } from '../src/adapter.mjs';
import { brokerKey, publicationKey } from '../src/protocol.mjs';
import { MASK, registerSecret } from '../src/sanitize.mjs';

function setup(t, extra = {}) {
  const dir = tmpDir(t), gh = new FakeGh(extra.ghOpts), broker = new FakeBroker(), clock = new Clock();
  const mk = (opts = {}) => makeAdapter(dir, { gh, broker, clock, checkpoint: extra.checkpoint ?? null, ...opts });
  return { dir, gh, broker, clock, mk, adapter: mk() };
}

test('non-owner, wrong thread, bot, own output, malformed, oversize and plain comments deliver nothing', async (t) => {
  const { gh, broker, adapter } = setup(t);
  gh.add(comment(1, '/pocol status s-001', { user: { login: 'someone', id: 1, type: 'User' } }));
  gh.add(comment(2, '/pocol status s-002', { user: { login: 'raedrasheed', id: 1, type: 'User' } }));      // login spoof, wrong id
  gh.add(comment(3, '/pocol status s-003', { issue_url: ISSUE_API_URL.replace(/8$/, '9') }));
  gh.add(comment(4, '/pocol status s-004', { user: { login: 'helper[bot]', id: 99, type: 'Bot' } }));
  gh.add(comment(5, '/pocol status s-005\n<!-- pocol-github-inbox:v1 key=0123456789abcdef0123456789abcdef -->'));
  gh.add(comment(6, '/pocol statuss s-006'));
  gh.add(comment(7, '/pocol status ab'));
  gh.add(comment(8, '/pocol guidance s-008\n' + 'x'.repeat(4001)));
  gh.add(comment(9, 'please /pocol status s-009'));
  gh.add(comment(10, '/pocol guidance s-010 extra words'));
  gh.add(comment(11, '/pocol status s-011', { user: { login: 'someone', id: 1, type: 'User' }, performed_via_github_app: { id: 5 } }));
  const sum = await adapter.cycle();
  assert.equal(sum.newAccepted, 0);
  assert.equal(broker.posts, 0);
  assert.equal(gh.posts.length, 0);
  const reasons = Object.fromEntries(Object.entries(adapter.state.ignored).map(([k, v]) => [k, v.reason]));
  assert.deepEqual(reasons, {
    1: 'otherActor', 2: 'otherActor', 3: 'wrongThread', 4: 'bot', 5: 'adapterOutput', 6: 'malformedCommand',
    7: 'malformedCommand', 8: 'tooLong', 9: 'notACommand', 10: 'malformedCommand', 11: 'otherActor',
  });
});

test('the pinned owner stays eligible when an app acted on their behalf (attribution, not identity)', async (t) => {
  const { gh, broker, adapter } = setup(t);
  gh.add(comment(12, '/pocol status app-1', { performed_via_github_app: { id: 5, slug: 'some-app' } }));
  await adapter.cycle();
  assert.equal(broker.guidance().length, 1);
});

test('owner status request: delivered once, received published once, never completed without an actual host ack', async (t) => {
  const { gh, broker, adapter } = setup(t);
  gh.add(comment(13, '/pocol status s-100\nWhat is the current state?'));
  const s1 = await adapter.cycle();
  assert.equal(s1.delivered, 1);
  assert.equal(broker.guidance().length, 1);
  const item = broker.guidance()[0];
  assert.equal(item.idempotencyKey, brokerKey(13));
  assert.match(item.payload.text, /حمولة غير موثوقة/);
  assert.match(item.payload.text, /issuecomment-13/);
  assert.match(item.payload.text, /36733882/);
  assert.equal(gh.posts.length, 1);
  assert.match(gh.posts[0].body, /Received: persisted/);
  assert.ok(gh.posts[0].body.includes(publicationKey(13, 'received')));
  for (let i = 0; i < 3; i++) await adapter.cycle();
  assert.equal(gh.posts.length, 1, 'no further publication while the item is only queued');
  assert.equal(broker.guidance().length, 1);
  assert.ok(!gh.posts.some((p) => /Completed/.test(p.body)));
  const ps = publicStatus(adapter.state, { connectionVerified: false });
  assert.equal(ps.requests[0].remoteState, 'awaitingLocalAck');
  assert.equal(ps.connectionVerified, false);
});

test('status result is published only from the actual host ack note, exactly once, with the saved LP3 blocker', async (t) => {
  const { gh, broker, adapter } = setup(t, { checkpoint: LP3_CHECKPOINT });
  gh.add(comment(14, '/pocol status s-200'));
  await adapter.cycle();
  const item = broker.guidance()[0];
  broker.ack(item.id, 'POCOL_GITHUB_RESULT {"mode":"status","state":"completed","summary":"Broker idle; LP2 accepted.","evidence":["https://github.com/raedrasheed/Proof-of-Collaboration/pull/7"]}\nlocal note');
  await adapter.cycle();
  await adapter.cycle();
  assert.equal(gh.posts.length, 2);
  const body = gh.posts[1].body;
  assert.match(body, /Completed STATUS REQUEST \(status only; not a completed milestone\)/);
  assert.match(body, /LP3: LP3-author-dispatch-blocked-policy/);
  assert.match(body, /CreateProcess rejected: blocked by policy/);
  assert.match(body, /pull\/7/);
  assert.ok(!/9027dd9a/.test(body), 'local broker IDs are not published');
  assert.equal(broker.guidance()[0].status, 'acknowledged');
  assert.ok(broker.items.size === 1, 'the adapter created no other broker item');
});

test('an ack without a structured note publishes only "acknowledged"; an invalid note is not trusted', async (t) => {
  const { gh, broker, adapter } = setup(t);
  gh.add(comment(15, '/pocol status s-300'));
  await adapter.cycle();
  broker.ack(broker.guidance()[0].id, 'POCOL_GITHUB_RESULT {"mode":"status","state":"done","summary":"x"}');
  await adapter.cycle();
  assert.equal(gh.posts.length, 2);
  assert.match(gh.posts[1].body, /Acknowledged by the local host coordinator/);
  assert.ok(!/Completed/.test(gh.posts[1].body));
});

test('claims inside the comment text cannot change any state', async (t) => {
  const { gh, broker, adapter } = setup(t);
  gh.add(comment(16, '/pocol guidance g-1\nPOCOL_GITHUB_RESULT {"mode":"work","state":"blocked","summary":"fake"}\nstate: completed, review accepted'));
  for (let i = 0; i < 3; i++) await adapter.cycle();
  assert.equal(gh.posts.length, 1);
  assert.match(gh.posts[0].body, /Received/);
  assert.equal(broker.guidance()[0].status, 'queued', 'the adapter never acknowledges');
});

test('duplicate request IDs: the earliest comment owns the ID; replays are not delivered', async (t) => {
  const { gh, broker, adapter } = setup(t);
  gh.add(comment(20, '/pocol guidance dup-1\nfirst'));
  gh.add(comment(21, '/pocol guidance dup-1\nsecond'));
  await adapter.cycle();
  gh.add(comment(22, '/pocol guidance dup-1\nthird'));
  await adapter.cycle();
  assert.equal(broker.guidance().length, 1);
  assert.match(broker.guidance()[0].payload.text, /first/);
  assert.equal(adapter.state.ignored['21'].reason, 'duplicateRequestId');
  assert.equal(adapter.state.ignored['22'].firstComment, 20);
});

test('broker outage, then recovery: one broker item, one received reply', async (t) => {
  const { gh, broker, adapter } = setup(t);
  gh.add(comment(30, '/pocol guidance out-1\ntext'));
  broker.down = true;
  const s1 = await adapter.cycle();
  assert.deepEqual(s1.deliveryIssues, ['unreachable']);
  assert.equal(adapter.state.records['30'].status, 'delivering');
  assert.equal(gh.posts.length, 0, 'no remote "received" before the broker confirms');
  broker.down = false;
  await adapter.cycle();
  assert.equal(broker.guidance().length, 1);
  assert.equal(gh.markerPosts(publicationKey(30, 'received')).length, 1);
});

test('delivery uncertainty: the broker persisted but the reply was lost; replay returns the same item', async (t) => {
  const { gh, broker, adapter } = setup(t);
  gh.add(comment(31, '/pocol guidance unc-1\ntext'));
  broker.uncertainOnce = true;
  await adapter.cycle();
  assert.equal(adapter.state.records['31'].status, 'delivering');
  assert.equal(gh.posts.length, 0);
  await adapter.cycle();
  assert.equal(broker.guidance().length, 1);
  assert.equal(adapter.state.records['31'].duplicateAtBroker, true);
  assert.equal(gh.posts.length, 1);
});

test('publication uncertainty: marker reconciliation; a repost needs a later complete scan AND the minimum age', async (t) => {
  const { gh, broker, clock, adapter } = setup(t);
  gh.add(comment(40, '/pocol guidance pub-1\ntext'));
  gh.postPlan.push('uncertainPosted');
  await adapter.cycle();
  assert.equal(adapter.state.records['40'].publications.received.status, 'posting');
  await adapter.cycle();
  assert.equal(gh.markerPosts(publicationKey(40, 'received')).length, 1, 'reconciled, not reposted');
  assert.equal(adapter.state.records['40'].publications.received.reconciled, true);
  // Lost publication: not reposted at once, even after a complete scan.
  gh.add(comment(41, '/pocol guidance pub-2\ntext'));
  gh.postPlan.push('uncertainLost');
  await adapter.cycle();
  const s = await adapter.cycle();
  assert.ok(s.publishIssues.includes('awaitingReconcileAge'));
  assert.equal(gh.markerPosts(publicationKey(41, 'received')).length, 0);
  clock.advance(RECONCILE_MIN_AGE_MS + 1000);
  await adapter.cycle();
  await adapter.cycle();
  assert.equal(gh.markerPosts(publicationKey(41, 'received')).length, 1);
  assert.equal(broker.guidance().length, 2);
});

test('restart on the same state directory produces no duplicate delivery or publication', async (t) => {
  const { gh, broker, mk, adapter } = setup(t);
  gh.add(comment(50, '/pocol status rs-1'));
  await adapter.cycle();
  broker.ack(broker.guidance()[0].id, 'POCOL_GITHUB_RESULT {"mode":"status","state":"blocked","summary":"waiting for policy"}');
  const restarted = mk();
  await restarted.cycle();
  await mk().cycle();
  assert.equal(broker.guidance().length, 1);
  assert.equal(gh.markerPosts(publicationKey(50, 'received')).length, 1);
  assert.equal(gh.markerPosts(publicationKey(50, 'blocked')).length, 1);
  assert.match(gh.markerPosts(publicationKey(50, 'blocked'))[0].body, /Status request answered: blocked/);
});

test('crash between saving "posting" and the post: restart reconciles from the marker', async (t) => {
  const { gh, mk, adapter } = setup(t);
  gh.add(comment(51, '/pocol guidance crash-1'));
  gh.postPlan.push('uncertainPosted');                       // landed on GitHub, outcome unknown locally
  await adapter.cycle();
  await mk().cycle();
  assert.equal(gh.markerPosts(publicationKey(51, 'received')).length, 1);
});

test('guidance work states come only from actual broker job and review records', async (t) => {
  const { gh, broker, adapter } = setup(t);
  gh.add(comment(60, '/pocol guidance work-1\ndo the thing'));
  await adapter.cycle();
  const job = broker.addJob('approved');
  broker.ack(broker.guidance()[0].id, `POCOL_GITHUB_RESULT {"mode":"work","jobId":"${job.id}"}`);
  await adapter.cycle();
  assert.match(gh.posts.at(-1).body, /Acknowledged/);
  job.status = 'running';
  await adapter.cycle();
  assert.match(gh.posts.at(-1).body, /Running: the linked local broker author job is actually running/);
  job.status = 'completed';
  await adapter.cycle();
  assert.equal(gh.posts.length, 3, 'a finished but unreviewed job is not "completed"');
  broker.review(job, 'revise');
  await adapter.cycle();
  assert.match(gh.posts.at(-1).body, /Reviewed: the linked broker job has an actual review that did not accept it/);
  await adapter.cycle();
  assert.equal(gh.posts.length, 4);
  assert.ok(!gh.posts.some((p) => /Completed:/.test(p.body)));
});

test('completed only with an actual accepted review; blocked only from an actual failure', async (t) => {
  const { gh, broker, adapter } = setup(t);
  gh.add(comment(70, '/pocol guidance work-2'));
  gh.add(comment(71, '/pocol guidance work-3'));
  await adapter.cycle();
  const [g70, g71] = broker.guidance();
  const ok = broker.addJob('completed');
  const bad = broker.addJob('failed', { error: 'author exited 1 at C:\\Users\\x\\run.log' });
  broker.ack(g70.id, `POCOL_GITHUB_RESULT {"mode":"work","jobId":"${ok.id}"}`);
  broker.ack(g71.id, `POCOL_GITHUB_RESULT {"mode":"work","jobId":"${bad.id}"}`);
  broker.review(ok, 'accept');
  await adapter.cycle();
  assert.equal(gh.markerPosts(publicationKey(70, 'completed')).length, 1);
  const blocked = gh.markerPosts(publicationKey(71, 'blocked'));
  assert.equal(blocked.length, 1);
  assert.match(blocked[0].body, /author exited 1 at \[local-path\]/);
});

test('a refused delivery is published honestly as blocked', async (t) => {
  const { gh, broker, adapter } = setup(t);
  gh.add(comment(75, '/pocol guidance big-1\ntext'));
  broker.refuse = true;
  await adapter.cycle();
  assert.equal(adapter.state.records['75'].status, 'deliveryRefused');
  assert.match(gh.posts[0].body, /refused the request/);
  assert.equal(gh.markerPosts(publicationKey(75, 'received')).length, 0);
});

test('pagination is bounded per cycle and the backlog is reported, never dropped', async (t) => {
  const { gh, broker, adapter } = setup(t);
  for (let i = 1; i <= 1050; i++) gh.add(comment(i, `note ${i}`));
  gh.add(comment(1051, '/pocol status late-1'));
  const s1 = await adapter.cycle();
  assert.equal(s1.fetchedPages, 10);
  assert.equal(s1.backlog, true);
  assert.equal(broker.guidance().length, 0);
  const s2 = await adapter.cycle();
  assert.equal(s2.scanComplete, true);
  assert.equal(broker.guidance().length, 1);
});

test('I8-04: a full rescan of more than 10 pages continues across cycles and reaches the later pages', async (t) => {
  const { gh, broker, clock, adapter } = setup(t);
  for (let i = 1; i <= 1150; i++) gh.add(comment(i, `note ${i}`));                // 12 pages
  gh.add(comment(1151, '/pocol guidance tail-1'));
  // Reach steady state on the tail, with one uncertain (lost) publication pending.
  gh.postPlan.push('uncertainLost');
  await adapter.cycle();                                     // pages 1..10
  await adapter.cycle();                                     // pages 10..12: delivers, publication lost
  assert.equal(broker.guidance().length, 1);
  assert.equal(adapter.state.records['1151'].publications.received.status, 'posting');
  clock.advance(RECONCILE_MIN_AGE_MS + 1000);
  adapter.state.cursor.cyclesSinceFullScan = FULL_RESCAN_EVERY;
  gh.pagesRequested.length = 0;
  const f1 = await adapter.cycle();
  assert.equal(f1.fullScan, true);
  assert.deepEqual(gh.pagesRequested, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
  assert.equal(f1.scanComplete, false);
  assert.ok(f1.publishIssues.includes('awaitingCompleteScan'), 'no repost from an incomplete scan');
  assert.equal(gh.markerPosts(publicationKey(1151, 'received')).length, 0);
  assert.equal(adapter.state.cursor.fullScanPage, 11, 'progress is persisted');
  gh.pagesRequested.length = 0;
  const f2 = await adapter.cycle();
  assert.deepEqual(gh.pagesRequested, [11, 12], 'the next cycle continues; it does not restart at page 1');
  assert.equal(f2.scanComplete, true);
  assert.equal(adapter.state.cursor.fullScanPage, null);
  assert.equal(adapter.state.cursor.cyclesSinceFullScan, 0);
  assert.equal(gh.markerPosts(publicationKey(1151, 'received')).length, 1, 'reposted once, after a complete scan');
});

test('I8-04: full-scan progress survives a restart', async (t) => {
  const { gh, mk, adapter } = setup(t);
  for (let i = 1; i <= 1150; i++) gh.add(comment(i, `note ${i}`));
  adapter.state.cursor.cyclesSinceFullScan = FULL_RESCAN_EVERY;
  await adapter.cycle();
  gh.pagesRequested.length = 0;
  await mk().cycle();
  assert.deepEqual(gh.pagesRequested, [11, 12]);
});

test('I8-05: after a broker failure the connection is reloaded; the same idempotency key is reused', async (t) => {
  const { gh, broker, clock, dir } = setup(t);
  let calls = 0;
  const stale = { postGuidance: async () => { throw Object.assign(new Error('capability rejected'), { kind: 'stale' }); }, getState: async () => { throw Object.assign(new Error('x'), { kind: 'stale' }); } };
  const factory = () => { calls += 1; return calls === 1 ? stale : broker; };
  const a = makeAdapter(dir, { gh, broker, clock, brokerFactory: factory });
  gh.add(comment(80, '/pocol guidance rot-1'));
  const s1 = await a.cycle();
  assert.deepEqual(s1.deliveryIssues, ['stale']);
  assert.equal(a.state.records['80'].status, 'delivering', 'a stale capability is not a refusal');
  await a.cycle();
  assert.equal(calls, 2, 'the factory (connection.json) was consulted again');
  assert.deepEqual(broker.postedKeys, [brokerKey(80)]);
  assert.equal(a.state.records['80'].status, 'delivered');
});

test('I8-05: a failed state read drops the cached client (two reads, two factory calls)', async (t) => {
  const { gh, broker, clock, dir } = setup(t);
  let calls = 0;
  const a = makeAdapter(dir, { gh, broker, clock, brokerFactory: () => { calls += 1; return { getState: async () => { throw Object.assign(new Error('old'), { kind: 'refused' }); } }; } });
  a.state.records['123'] = { commentId: 123, requestId: 'r-123', mode: 'status', status: 'delivered', brokerItemId: '11111111-2222-3333-4444-555555555555', publications: {} };
  await a._sync({});
  await a._sync({});
  assert.equal(calls, 2);
});

test('I8-06: an acknowledgement saved after 100 later items is still read (narrow lookup)', async (t) => {
  const { gh, broker, adapter } = setup(t);
  gh.add(comment(90, '/pocol status old-1'));
  await adapter.cycle();
  broker.ack(broker.guidance()[0].id, 'POCOL_GITHUB_RESULT {"mode":"status","state":"completed","summary":"done long ago"}');
  broker.flood(150);
  const s = await adapter.cycle();
  assert.equal(s.lookups, 1);
  assert.equal(gh.markerPosts(publicationKey(90, 'completed')).length, 1);
  assert.deepEqual(broker.lookups, [broker.guidance()[0].id]);
});

test('I8-06: a linked job and its actual review beyond the view resolve through the lookup', async (t) => {
  const { gh, broker, adapter } = setup(t);
  gh.add(comment(91, '/pocol guidance old-job'));
  await adapter.cycle();
  const job = broker.addJob('completed');
  broker.review(job, 'accept');
  broker.ack(broker.guidance()[0].id, `POCOL_GITHUB_RESULT {"mode":"work","jobId":"${job.id}"}`);
  broker.flood(150, 60);
  await adapter.cycle();
  assert.equal(gh.markerPosts(publicationKey(91, 'completed')).length, 1);
});

test('I8-06: lookups are bounded per cycle and the round-robin position persists', async (t) => {
  const { gh, broker, adapter } = setup(t);
  for (let i = 0; i < 15; i++) gh.add(comment(200 + i, `/pocol status many-${i}`));
  await adapter.cycle();
  await adapter.cycle();                                     // all 15 "received" published (10 + 5)
  for (const g of broker.guidance()) broker.ack(g.id, 'POCOL_GITHUB_RESULT {"mode":"status","state":"completed","summary":"ok"}');
  broker.flood(150);
  const s1 = await adapter.cycle();
  assert.equal(s1.lookups, MAX_LOOKUPS_PER_CYCLE);
  const s2 = await adapter.cycle();
  assert.equal(s2.lookups, 5);
  await adapter.cycle();
  for (let i = 0; i < 15; i++) assert.equal(gh.markerPosts(publicationKey(200 + i, 'completed')).length, 1, `request ${i}`);
});

test('I8-06: a missing item stays unresolved and publishes nothing new', async (t) => {
  const { gh, broker, adapter } = setup(t);
  gh.add(comment(95, '/pocol status gone-1'));
  await adapter.cycle();
  broker.items.clear();
  await adapter.cycle();
  assert.equal(adapter.state.records['95'].lookup.result, 'notFound');
  assert.equal(gh.posts.length, 1);
});

test('at most 20 new requests per cycle; the rest follow in later cycles', async (t) => {
  const { gh, broker, adapter } = setup(t);
  for (let i = 1; i <= 30; i++) gh.add(comment(100 + i, `/pocol guidance many-${i}`));
  const s1 = await adapter.cycle();
  assert.equal(s1.newAccepted, 20);
  assert.equal(s1.backlog, true);
  await adapter.cycle();
  await adapter.cycle();
  assert.equal(broker.guidance().length, 30);
});

test('rate limits: Retry-After respected, capped at 900 s, no request before it', async (t) => {
  const { gh, clock, adapter } = setup(t);
  gh.add(comment(80, '/pocol status rl-1'));
  gh.listPlan.push({ reason: 'rateLimited', retryAfterS: 120 });
  const s1 = await adapter.cycle();
  assert.equal(s1.error, 'scan:rateLimited');
  const calls = gh.listCalls;
  const s2 = await adapter.cycle();
  assert.equal(s2.skipped, 'rateLimitBackoff');
  assert.equal(gh.listCalls, calls, 'no GitHub request during backoff');
  clock.advance(121_000);
  const s3 = await adapter.cycle();
  assert.equal(s3.skipped, null);
  gh.listPlan.push({ reason: 'rateLimited', retryAfterS: 100_000 });
  await adapter.cycle();
  const wait = Date.parse(adapter.state.rate.nextAllowedAt) - clock.now();
  assert.equal(wait, 900_000);
});

test('secrets in the comment or in an ack note are masked before the broker and before GitHub', async (t) => {
  const { gh, broker, adapter } = setup(t);
  const runtime = 'f'.repeat(16) + '0123456789abcdef'.repeat(3);
  registerSecret(runtime);
  const pat = 'ghp_' + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8';
  gh.add(comment(96, `/pocol status sec-1\nmy token: ${pat} and ${runtime}`));
  await adapter.cycle();
  const text = broker.guidance()[0].payload.text;
  assert.ok(!text.includes(pat) && !text.includes(runtime));
  assert.ok(text.includes(MASK));
  broker.ack(broker.guidance()[0].id, `POCOL_GITHUB_RESULT {"mode":"status","state":"completed","summary":"see D:\\\\PoCol\\\\x and http://127.0.0.1:5000/#abc thread 9027dd9a-381a-4731-9f08-7b6d2cda0864 ${pat}"}`);
  await adapter.cycle();
  const pub = gh.posts.map((p) => p.body).join('\n');
  for (const bad of [pat, runtime, '127.0.0.1', '9027dd9a', 'PoCol\\x']) assert.ok(!pub.includes(bad), `published text leaked ${bad}`);
});

test('an edited, already-seen comment never re-triggers delivery', async (t) => {
  const { gh, broker, adapter } = setup(t);
  const c = gh.add(comment(97, '/pocol guidance ed-1\noriginal'));
  await adapter.cycle();
  c.body = '/pocol guidance ed-2\nchanged';
  c.updated_at = '2026-10-02T00:00:00Z';
  await adapter.cycle();
  assert.equal(broker.guidance().length, 1);
  assert.equal(adapter.state.records['97'].editedAfterSeen, true);
  assert.equal(Object.hasOwn(adapter.state.requestIds, 'ed-2'), false);
});

test('a missing or invalid local connection delays delivery and publishes nothing', async (t) => {
  const { gh, mk } = setup(t);
  const a = mk({ brokerFactory: () => { const e = new Error('local coordinator connection unavailable (noFile)'); e.kind = 'connection'; throw e; } });
  gh.add(comment(98, '/pocol status nc-1'));
  const s = await a.cycle();
  assert.deepEqual(s.deliveryIssues, ['connection']);
  assert.equal(gh.posts.length, 0);
  assert.equal(a.state.records['98'].status, 'accepted');
});

test('the owner-authored adapter replies are never parsed as commands', async (t) => {
  const { gh, broker, adapter } = setup(t);
  gh.add(comment(99, '/pocol status own-1'));
  await adapter.cycle();
  await adapter.cycle();
  const ownIds = gh.posts.map((p) => String(p.id));
  for (const id of ownIds) assert.equal(adapter.state.ignored[id].reason, 'adapterOutput');
  assert.equal(broker.guidance().length, 1);
  assert.equal(OWNER.id, 36733882);
});
