// Static boundary checks on the adapter source: one child process (gh, in gh.mjs only), two
// broker endpoints, no reviewer/author/pause/resume calls, no external fetch, no shell.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const src = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'src');
const files = readdirSync(src).filter((f) => f.endsWith('.mjs'));
const text = Object.fromEntries(files.map((f) => [f, readFileSync(path.join(src, f), 'utf8')]));

test('only gh.mjs starts a child process, always without a shell', () => {
  for (const [f, s] of Object.entries(text)) {
    if (f === 'gh.mjs') continue;
    assert.ok(!/child_process/.test(s), `${f} imports child_process`);
  }
  for (const [f, s] of Object.entries(text)) {
    assert.ok(!/\bexec(Sync|File|FileSync)?\s*\(/.test(s), `${f} uses exec`);
    assert.ok(!/shell:\s*true/.test(s), `${f} enables a shell`);
    assert.ok(!/\bfetch\s*\(/.test(s), `${f} uses fetch`);
  }
  assert.match(text['gh.mjs'], /shell: false/);
});

test('only /api/guidance and /api/state are used; no reviewer, author-job, pause or resume calls', () => {
  const all = Object.values(text).join('\n');
  const apis = new Set([...all.matchAll(/['"`](\/api\/[A-Za-z/-]*)/g)].map((m) => m[1]));
  assert.deepEqual([...apis].sort(), ['/api/guidance', '/api/state']);
  for (const name of ['claim', 'ack', 'review', 'attach', 'heartbeat', 'requestAuthorJob', 'pause', 'resume', 'retryNotification', 'submitOwnerAnswer']) {
    assert.ok(!new RegExp(`\\.${name}\\(`).test(all), `calls .${name}(`);
  }
  assert.ok(!/reviewerToken\s*[:,]/.test(text['broker-client.mjs'].replace(/registerSecret\(c\.reviewerToken\)/, '')), 'the reviewer capability is not stored');
});

test('no command interpolation: gh arguments are built from constants and an integer page only', () => {
  const s = text['gh.mjs'];
  assert.match(s, /\['api', '--method', 'GET', '--include', `\$\{COMMENTS_PATH\}\?per_page=\$\{PAGE_SIZE\}&page=\$\{page\}`\]/);
  assert.match(s, /\['api', '--method', 'POST', '--include', COMMENTS_PATH, '--input', '-'\]/);
});
