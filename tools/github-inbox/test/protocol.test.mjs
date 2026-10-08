import { test } from 'node:test';
import assert from 'node:assert/strict';
import { comment, LP3_CHECKPOINT } from './helpers.mjs';
import { brokerKey, classifyComment, deriveState, guidanceText, lp3Summary, marker, markerKeyOf, parseCommand, parseResultNote, publicationKey, renderReply } from '../src/protocol.mjs';
import { validateConfig, ConfigError } from '../src/config.mjs';

test('command parsing: first line only, exact syntax, bounded request ID', () => {
  assert.deepEqual(parseCommand('/pocol status abc-1'), { mode: 'status', requestId: 'abc-1', payload: '' });
  assert.deepEqual(parseCommand('/pocol guidance R.2_x\r\nline one\r\nline two  '), { mode: 'guidance', requestId: 'R.2_x', payload: 'line one\nline two' });
  assert.equal(parseCommand('/pocol status abc-1   ').requestId, 'abc-1');
  for (const bad of ['/pocol', '/pocol status', '/pocol run abc', '/pocol status ab', '/pocol status -abc', '/pocol status a'.padEnd(80, 'b'), '/pocol  status abc', '/POCOL status abc', '/pocol status abc def', '/pocol status ab$c']) {
    assert.ok(parseCommand(bad).reason, bad);
  }
  assert.equal(parseCommand('hello\n/pocol status abc').reason, 'notACommand');
});

test('classification of comments', () => {
  assert.equal(classifyComment(comment(1, '/pocol status abc')).accept, true);
  assert.equal(classifyComment({}).reason, 'malformedComment');
  assert.equal(classifyComment(comment(1, '/pocol status abc', { html_url: 'https://github.com/raedrasheed/Proof-of-Collaboration/issues/8#issuecomment-2' })).reason, 'wrongThread');
  assert.equal(classifyComment(comment(1, '/pocol status abc', { performed_via_github_app: { id: 1 } })).reason, 'bot');
  assert.equal(classifyComment(comment(1, '/pocol status abc', { user: { login: 'raedrasheed', id: 36733882, type: 'Bot' } })).reason, 'bot');
  assert.equal(classifyComment(comment(1, '/pocol status abc', { user: { login: 'RaedRasheed', id: 36733882, type: 'User' } })).reason, 'otherActor');
  assert.equal(classifyComment(comment(1, 'x' + marker('0'.repeat(32)))).reason, 'adapterOutput');
});

test('deterministic keys and markers', () => {
  const k = brokerKey(123);
  assert.equal(k, brokerKey(123));
  assert.notEqual(k, brokerKey(124));
  assert.match(k, /^[A-Za-z0-9_-]{8,100}$/);
  assert.notEqual(publicationKey(1, 'received'), publicationKey(1, 'completed'));
  assert.equal(markerKeyOf('a\n' + marker(publicationKey(1, 'received'))), publicationKey(1, 'received'));
  assert.equal(markerKeyOf('no marker'), null);
});

test('guidance text: Arabic transport label, untrusted payload, owner identity, bounded', () => {
  const t = guidanceText({ mode: 'guidance', requestId: 'g-1', commentId: 77, payload: 'please look at https://evil.example/x' });
  assert.match(t, /نقل GitHub/);
  assert.match(t, /not an owner approval/);
  assert.match(t, /issuecomment-77/);
  assert.match(t, /36733882/);
  assert.match(t, /links are not fetched/);
  assert.ok(guidanceText({ mode: 'status', requestId: 's-1', commentId: 1, payload: 'y'.repeat(20000) }).length <= 7900);
});

test('structured result notes: strict validation', () => {
  assert.equal(parseResultNote('plain ack'), null);
  assert.deepEqual(parseResultNote('POCOL_GITHUB_RESULT {"mode":"status","state":"completed","summary":"ok"}'), { mode: 'status', state: 'completed', summary: 'ok', evidence: [] });
  assert.equal(parseResultNote('POCOL_GITHUB_RESULT {"mode":"status","state":"completed","summary":"ok","evidence":["https://example.com/x"]}').invalid, 'evidence');
  assert.equal(parseResultNote('POCOL_GITHUB_RESULT {"mode":"status","state":"completed"}').invalid, 'summary');
  assert.equal(parseResultNote('POCOL_GITHUB_RESULT {"mode":"status","state":"completed","summary":"ok","approved":true}').invalid, 'unknownField');
  assert.equal(parseResultNote('POCOL_GITHUB_RESULT {"mode":"work","jobId":"not-a-uuid"}').invalid, 'jobId');
  assert.equal(parseResultNote('POCOL_GITHUB_RESULT {"mode":"milestone","state":"completed","summary":"x"}').invalid, 'mode');
  assert.equal(parseResultNote('POCOL_GITHUB_RESULT {broken').invalid, 'json');
  assert.equal(parseResultNote('note\nPOCOL_GITHUB_RESULT {"mode":"status","state":"completed","summary":"ok"}'), null, 'only the first line counts');
});

const J = '11111111-2222-3333-4444-555555555555';
const view = (items, reviews = []) => ({ items, reviews });
const rec = (mode) => ({ mode, brokerItemId: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee' });
const g = (status, ackNote) => ({ id: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee', kind: 'guidance', status, ackNote });

test('state mapping is derived only from actual broker records', () => {
  assert.equal(deriveState(rec('status'), view([])).state, null);
  assert.equal(deriveState(rec('status'), view([g('queued')])).state, 'awaitingLocalAck');
  assert.equal(deriveState(rec('status'), view([g('claimed')])).state, 'awaitingLocalAck');
  assert.equal(deriveState(rec('status'), view([g('acknowledged', 'thanks')])).state, 'acknowledged');
  assert.equal(deriveState(rec('status'), view([g('acknowledged', 'POCOL_GITHUB_RESULT {"mode":"status","state":"blocked","summary":"policy"}')])).state, 'blocked');
  const note = `POCOL_GITHUB_RESULT {"mode":"work","jobId":"${J}"}`;
  assert.equal(deriveState(rec('guidance'), view([g('acknowledged', note)])).detail, 'linkedJobNotVisible');
  const job = (status, extra = {}) => ({ id: J, kind: 'authorJob', status, ...extra });
  assert.equal(deriveState(rec('guidance'), view([g('acknowledged', note), job('running')])).state, 'running');
  assert.equal(deriveState(rec('guidance'), view([g('acknowledged', note), job('completed')])).state, 'acknowledged');
  assert.equal(deriveState(rec('guidance'), view([g('acknowledged', note), job('reviewed', { reviewId: 'r1' })], [{ id: 'r1', jobId: J, verdict: 'accept' }])).state, 'completed');
  assert.equal(deriveState(rec('guidance'), view([g('acknowledged', note), job('reviewed', { reviewId: 'r1' })], [{ id: 'r1', jobId: 'other', verdict: 'accept' }])).detail, 'reviewNotVisible');
  assert.equal(deriveState(rec('guidance'), view([g('acknowledged', note), job('failed', { reviewId: 'r1' })], [{ id: 'r1', jobId: J, verdict: 'accept' }])).state, 'reviewed', 'accept on a failed job is not completion');
  assert.equal(deriveState(rec('guidance'), view([g('acknowledged', note), job('interrupted')])).state, 'blocked');
  assert.equal(deriveState(rec('guidance'), view([g('acknowledged', 'POCOL_GITHUB_RESULT {"mode":"work","state":"blocked","summary":"needs policy"}')])).state, 'blocked');
  // The linked job must be an author job: a guidance item ID cannot be passed off as one.
  assert.equal(deriveState(rec('guidance'), view([g('acknowledged', note), { id: J, kind: 'guidance', status: 'acknowledged' }])).detail, 'linkedJobNotVisible');
});

test('LP3 checkpoint summary is sanitized and never includes local IDs', () => {
  const s = lp3Summary(LP3_CHECKPOINT);
  assert.equal(s.pr, 'https://github.com/raedrasheed/Proof-of-Collaboration/pull/7');
  assert.equal(s.exactError, 'CreateProcess rejected: blocked by policy');
  assert.ok(!JSON.stringify(s).includes('9027dd9a'));
  assert.equal(lp3Summary({ ...LP3_CHECKPOINT, nextPR: 'https://evil.example/pull/7' }).pr, null);
  assert.equal(lp3Summary({ status: 'LP2-accepted' }), null);
  const body = renderReply({ rec: { requestId: 's-1', mode: 'status', commentId: 5 }, state: 'completed', derived: { summary: 'idle' }, lp3: s });
  assert.match(body, /Completed STATUS REQUEST \(status only; not a completed milestone\)/);
  assert.match(body, /nothing was run/);
});

test('config: pinned scope, derived paths, strict keys', () => {
  const ws = process.platform === 'win32' ? 'D:\\ws' : '/srv/ws';
  const join = (...p) => [ws, ...p].join(process.platform === 'win32' ? '\\' : '/');
  const good = {
    workspaceRoot: ws, connectionPath: join('coordination', 'ui-control', 'connection.json'), stateDir: join('coordination', 'ui-control', 'github-inbox'),
    ghBin: process.platform === 'win32' ? 'C:\\gh\\gh.exe' : '/usr/bin/gh', owner: 'raedrasheed', repo: 'Proof-of-Collaboration', issue: 8, ownerLogin: 'raedrasheed', ownerId: 36733882,
  };
  const c = validateConfig(good, { fsCheck: false });
  assert.equal(c.pollSeconds, 60);
  assert.ok(Object.isFrozen(c));
  const bad = (patch) => assert.throws(() => validateConfig({ ...good, ...patch }, { fsCheck: false }), ConfigError);
  bad({ issue: 9 });
  bad({ ownerId: 1 });
  bad({ repo: 'other' });
  bad({ stateDir: join('elsewhere') });
  bad({ connectionPath: join('coordination', 'ui-control', '..', '..', 'x.json') });
  bad({ pollSeconds: 10 });
  bad({ extra: true });
  bad({ ghBin: 'gh' });
});
