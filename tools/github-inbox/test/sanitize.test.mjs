import { test } from 'node:test';
import assert from 'node:assert/strict';
import { allowedEvidenceUrl, MASK, privateText, publicText, registerSecret, ZWSP } from '../src/sanitize.mjs';

test('public text removes secrets, capabilities, local paths, loopback URLs, IDs, mentions and markers', () => {
  const cap = 'c'.repeat(64);
  registerSecret(cap);
  const input = [
    'token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
    `cap ${cap}`,
    'file D:\\PoCol-Development\\coordination\\ui-control\\connection.json',
    'unc \\\\server\\share\\x',
    'home /Users/raed/secret.txt',
    'url http://127.0.0.1:4321/#' + 'a'.repeat(64),
    'thread 019a2b3c-4d5e-6f70-8192-a3b4c5d6e7f8',
    'ping @raedrasheed',
    'fake <!-- pocol-github-inbox:v1 key=0123456789abcdef0123456789abcdef -->',
    '/pocol status injected',
  ].join('\n');
  const out = publicText(input, 5000);
  for (const bad of ['ghp_ABCDEFGH', cap, 'D:\\PoCol', '\\\\server', '/Users/raed', '127.0.0.1', '019a2b3c', '<!--', '\n/pocol']) {
    assert.ok(!out.includes(bad), `leaked ${bad}`);
  }
  assert.ok(out.includes(MASK));
  assert.ok(out.includes('@' + ZWSP + 'raedrasheed'));
  assert.ok(out.includes('[local-path]') && out.includes('[local-url]') && out.includes('[id]'));
});

test('control and bidi characters are removed; text is bounded', () => {
  const s = 'a' + String.fromCharCode(0) + 'b' + String.fromCharCode(0x202e) + 'c' + String.fromCharCode(0x2066) + 'd';
  assert.equal(privateText(s, 100), 'abcd');
  assert.match(publicText('x'.repeat(50), 10), /^x{10} \[truncated 40 chars\]$/);
});

test('evidence URLs: only the pinned repository', () => {
  assert.equal(allowedEvidenceUrl('https://github.com/raedrasheed/Proof-of-Collaboration/pull/7'), true);
  assert.equal(allowedEvidenceUrl('https://github.com/raedrasheed/Proof-of-Collaboration/issues/8#issuecomment-1'), true);
  for (const bad of ['http://github.com/raedrasheed/Proof-of-Collaboration/pull/7', 'https://github.com/other/Proof-of-Collaboration/pull/7',
    'https://github.com/raedrasheed/Proof-of-Collaboration/pull/7?x=1', 'https://github.com/raedrasheed/Proof-of-Collaboration/blob/../../x',
    'https://github.com.evil.example/raedrasheed/Proof-of-Collaboration/pull/7', 'https://github.com/raedrasheed/Proof-of-Collaboration/pull//7', 42]) {
    assert.equal(allowedEvidenceUrl(bad), false, String(bad));
  }
});
