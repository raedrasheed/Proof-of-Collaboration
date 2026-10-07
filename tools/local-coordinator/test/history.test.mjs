import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadHistory, loadCheckResults, parseReceipt } from '../src/history.mjs';
import { redact, registerSecret, MASK } from '../src/redact.mjs';
import { decodeText } from '../src/util.mjs';
import { Controller } from '../src/broker.mjs';
import { FAKE_PRIV, fakeSpawner, makeWorkspace } from './helpers.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));

test('UTF-16 receipt: allowlist keeps visible text, drops hidden reasoning and raw payloads', () => {
  const ws = makeWorkspace();
  const parsed = parseReceipt(decodeText(readFileSync(path.join(ws, 'coordination', 'claude-006.jsonl'))));
  const json = JSON.stringify(parsed);
  assert.ok(json.includes('Reading the task now.'));
  assert.ok(!json.includes('HIDDEN-REASONING-MARKER'), 'thinking text must not appear');
  assert.ok(!json.includes('thinking_tokens') && !json.includes('estimated_tokens'));
  assert.ok(!json.includes('RAW-PAYLOAD-MARKER'), 'tool_use_result payload is never read');
  assert.ok(!json.includes('C:/secret/memory'), 'init details beyond model/version are dropped');
  assert.equal(parsed.toolCalls, 1);
  assert.equal(parsed.result.isError, false);
});

test('secrets are masked: private key in tool input, mnemonic in result, registered tokens', () => {
  const ws = makeWorkspace();
  const json = JSON.stringify(parseReceipt(decodeText(readFileSync(path.join(ws, 'coordination', 'claude-006.jsonl')))));
  assert.ok(!json.includes(FAKE_PRIV.slice(2)), 'private key hex masked');
  assert.ok(!json.includes('test test test test'), 'mnemonic masked');
  assert.ok(json.includes(MASK));
  registerSecret('runtime-control-token-abcdef0123456789');
  assert.equal(redact('x runtime-control-token-abcdef0123456789 y'), `x ${MASK} y`);
  assert.equal(redact('ghp_' + 'a'.repeat(30)), MASK);
  assert.ok(redact('sha256 of the file 2fdc37b7cb1bc0c7d76531ac9fe8a3209d061deb25645d3b0c82c117af54b88b').includes('2fdc37b7'), 'plain hashes stay visible');
});

// Executable HTML/code sinks: property assignment or call syntax, not mere mentions in comments.
const SINK = /\.\s*(?:innerHTML|outerHTML)\s*\+?=|\binsertAdjacentHTML\s*\(|\bdocument\s*\.\s*write(?:ln)?\s*\(|\beval\s*\(|\bnew\s+Function\s*\(|\bset(?:Timeout|Interval)\s*\(\s*['"`]|\bcreateContextualFragment\s*\(|\bparseFromString\s*\(|\.srcdoc\s*=/;

test('sink detector catches real sinks and ignores comments that name them', () => {
  for (const bad of ['n.innerHTML = x', 'n.outerHTML += x', "n.insertAdjacentHTML('beforeend', x)", 'document.write(x)', 'eval(x)',
    'new Function(x)', "setTimeout('alert(1)', 0)", 'r.createContextualFragment(x)', "new DOMParser().parseFromString(x, 'text/html')", 'f.srcdoc = x']) {
    assert.ok(SINK.test(bad), `detects: ${bad}`);
  }
  for (const ok of ['// no innerHTML, no Markdown rendering', 'n.textContent = String(text)', 'setTimeout(poll, 2500)']) assert.ok(!SINK.test(ok), `ignores: ${ok}`);
});

test('tool text is kept as inert data and the frontend has no executable HTML sink', () => {
  const ws = makeWorkspace();
  const parsed = parseReceipt(decodeText(readFileSync(path.join(ws, 'coordination', 'claude-006.jsonl'))));
  const result = parsed.entries.find((e) => e.kind === 'tool_result');
  assert.equal(result.text, '<script>alert(1)</script><img src=x onerror=alert(2)>', 'markup is kept verbatim as data, not stripped or rendered');
  const app = readFileSync(path.join(here, '..', 'public', 'app.js'), 'utf8');
  const hit = app.split('\n').findIndex((line) => SINK.test(line));
  assert.equal(hit, -1, `executable sink in app.js line ${hit + 1}`);
  // Every text node goes through el(), which assigns textContent: the browser shows tool text as inert characters.
  assert.match(app, /function el\(tag, text, cls\) \{[^}]*n\.textContent = String\(text\)/);
  assert.ok(!/\.\s*(?:innerHTML|outerHTML)\b/.test(app.replace(/\/\/[^\n]*/g, '')), 'no innerHTML/outerHTML property use (read or write) outside comments');
});

test('RTL layout: technical fragments are isolated LTR <bdi> text nodes, Arabic prose stays text', () => {
  const app = readFileSync(path.join(here, '..', 'public', 'app.js'), 'utf8');
  // The isolation helper builds a bdi with dir=ltr and sets only textContent.
  assert.match(app, /function ltr\(text\) \{ const b = document\.createElement\('bdi'\); b\.dir = 'ltr'; b\.textContent = String\(text\); return b; \}/);
  assert.match(app, /document\.createTextNode\(String\(p\)\)/, 'Arabic prose parts are plain text nodes');
  // Status timestamps, source paths, the CLI command and IDs go through the LTR wrapper.
  for (const frag of ['L(s.updatedAt)', 'L(c.executedAtUtc)', 'L(c.source)', 'L(c.revision)', 'L(`codex queue --remote ${nt.remote}`)',
    'L(w.startedAt)', 'L(v.reviewer.heartbeatAt)', 'L(i.id)', 'L(i.createdAt)', 'L(i.dispatch.plannedDir)', 'L(n.queueId)',
    'L(`source: ${c.source}`)', 'L(`time: ${c.time ?? \'unavailable\'}`)', 'L(q.answer.at)']) {
    assert.ok(app.includes(frag), `isolated: ${frag}`);
  }
  // The mixed status lines are no longer assigned as one bidi-unsafe string.
  assert.ok(!/\$\('(latestCheck|activeWorker|reviewer|notifier|updatedAt)'\)\.textContent\s*=/.test(app));
  // Still no executable HTML sink anywhere (comments excluded).
  assert.ok(!SINK.test(app.replace(/\/\/[^\n]*/g, '')));
});

test('history cards: roles, missing timestamps marked, hashes and commit attached', () => {
  const ws = makeWorkspace();
  const { cards } = loadHistory(ws);
  const author = cards.find((c) => c.role === 'author' && c.source.endsWith('claude-006.jsonl'));
  const old = cards.find((c) => c.source.endsWith('claude-001.json'));
  const task = cards.find((c) => c.kind === 'task');
  const review = cards.find((c) => c.role === 'reviewer');
  assert.equal(author.actor, 'Claude'); assert.equal(review.actor, 'Codex');
  assert.equal(author.revision, '0.8');
  assert.equal(author.time, '2026-10-07T10:23:01.000Z');
  assert.equal(old.time, null); assert.ok(old.timeNote);
  assert.equal(task.time, null);
  assert.equal(author.commit, '24aec0066ad7b39e3a423bd45f8952d75ea2b6c4');
  assert.match(author.sha256, /^[0-9a-f]{64}$/);
  assert.ok(review.summaryAr.includes('261 pass'));
});

test('source history reload uses the cache and never invokes an agent', () => {
  const ws = makeWorkspace();
  const sp = fakeSpawner();
  const a = new Controller({ workspace: ws, claudeBin: 'claude-fake', spawnImpl: sp.spawnImpl, isAlive: () => false });
  const first = a.historyCards();
  const b = new Controller({ workspace: ws, claudeBin: 'claude-fake', spawnImpl: sp.spawnImpl, isAlive: () => false });
  b.recover();
  const second = b.historyCards();
  assert.deepEqual(second.map((c) => c.id), first.map((c) => c.id), 'stable ids');
  assert.equal(sp.calls.length, 0);
});

test('saved check results and the fixed status panel come from files', () => {
  const ws = makeWorkspace();
  const checks = loadCheckResults(ws);
  assert.deepEqual(checks[0].summary, { checks: 264, passed: 261, recorded: 3, failed: 0 });
  const ctl = new Controller({ workspace: ws, isAlive: () => false });
  const s = ctl.statusPanel();
  assert.equal(s.latestCheck.summary.passed, 261);
  assert.deepEqual(s.openFindings.map((f) => f.id), ['C01']);
  assert.match(s.noteAr, /ليس اختبارًا/);
});
