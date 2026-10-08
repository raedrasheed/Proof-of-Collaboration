// Static boundary checks on the adapter source: one child process (gh, in gh.mjs only, imported as
// exactly `import { spawn } from 'node:child_process'`), no exec/fork/spawnSync calls, no shell,
// no fetch, and only the three allowed coordinator control-API paths.
//
// 0.41 (I8-02): the checker distinguishes a bare function call `exec(...)` (a child_process call)
// from a method call `/re/.exec(...)` or `obj.exec(...)` (RegExp and friends). Synthetic positive and
// negative control cases prove the checker still catches unsafe imports and calls.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const src = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'src');
const files = readdirSync(src).filter((f) => f.endsWith('.mjs'));
const text = Object.fromEntries(files.map((f) => [f, readFileSync(path.join(src, f), 'utf8')]));

const CP_MODULE = String.raw`['"](?:node:)?child_process['"]`;
const IMPORT_RES = [
  new RegExp(String.raw`\bfrom\s+${CP_MODULE}`, 'g'),
  new RegExp(String.raw`\bimport\s*\(\s*${CP_MODULE}\s*\)`, 'g'),
  new RegExp(String.raw`\brequire\s*\(\s*${CP_MODULE}\s*\)`, 'g'),
  new RegExp(String.raw`\bimport\s+${CP_MODULE}`, 'g'),
];
const ALLOWED_GH_IMPORT = "import { spawn } from 'node:child_process';";
// A bare call: not preceded by an identifier character, '.', '$' or '#'.
const UNSAFE_CALL_RE = /(?<![\w.$#])(exec|execSync|execFile|execFileSync|fork|spawnSync)\s*\(/g;
const SHELL_RE = /\bshell\s*:\s*(?!false\b)[^,}\s]/g;
const FETCH_RE = /(?<![\w.$#])fetch\s*\(/g;

/** Findings for one source file. */
export function childProcessFindings(source, fileName) {
  const out = [];
  const lines = source.split(/\r?\n/);
  const importLines = lines.filter((l) => IMPORT_RES.some((re) => { re.lastIndex = 0; return re.test(l); }));
  if (fileName !== 'gh.mjs' && importLines.length) out.push('childProcessImportOutsideGh');
  if (fileName === 'gh.mjs' && importLines.some((l) => l.trim() !== ALLOWED_GH_IMPORT)) out.push('childProcessImportNotExactlySpawn');
  for (const m of source.matchAll(UNSAFE_CALL_RE)) out.push(`unsafeCall:${m[1]}`);
  for (const m of source.matchAll(SHELL_RE)) out.push(`shell:${m[0].trim()}`);
  if ([...source.matchAll(FETCH_RE)].length) out.push('fetch');
  return out;
}

test('control cases: the checker flags unsafe forms and accepts safe ones', () => {
  const flagged = (s, f = 'adapter.mjs') => childProcessFindings(s, f).length > 0;
  // Unsafe: must be flagged.
  assert.ok(flagged("import { exec } from 'node:child_process';"));
  assert.ok(flagged("import { spawn } from 'child_process';"), 'outside gh.mjs any child_process import is refused');
  assert.ok(flagged("import * as cp from 'node:child_process'; cp.spawn('x');", 'gh.mjs'));
  assert.ok(flagged("import cp from 'node:child_process';", 'gh.mjs'));
  assert.ok(flagged("import { spawn, exec } from 'node:child_process';", 'gh.mjs'));
  assert.ok(flagged("const { execSync } = require('child_process'); execSync('dir');"));
  assert.ok(flagged("const cp = await import('node:child_process');"));
  assert.ok(flagged("exec('calc');", 'gh.mjs'));
  assert.ok(flagged("execFile(bin, args);", 'gh.mjs'));
  assert.ok(flagged("spawnSync('gh', []);", 'gh.mjs'));
  assert.ok(flagged("fork('./x.mjs');", 'gh.mjs'));
  assert.ok(flagged("spawn(bin, args, { shell: true });", 'gh.mjs'));
  assert.ok(flagged("spawn(bin, args, { shell: process.env.COMSPEC });", 'gh.mjs'));
  assert.ok(flagged("await fetch('https://example.com');"));
  // Safe: must NOT be flagged.
  assert.deepEqual(childProcessFindings("import { spawn } from 'node:child_process';\nspawn(bin, args, { shell: false });", 'gh.mjs'), []);
  assert.deepEqual(childProcessFindings('const m = /HTTP (\\d{3})/.exec(s);', 'gh.mjs'), []);
  assert.deepEqual(childProcessFindings('const r = RE.exec(x); obj.fork(); this.exec(1); a.fetch(2);', 'adapter.mjs'), []);
  assert.deepEqual(childProcessFindings('// execution is not a call; prefetch(x) is a different identifier', 'adapter.mjs'), []);
});

test('the real adapter sources pass the checker: one child process, in gh.mjs, without a shell', () => {
  for (const [f, s] of Object.entries(text)) assert.deepEqual(childProcessFindings(s, f), [], f);
  assert.ok(text['gh.mjs'].includes("import { spawn } from 'node:child_process';"));
  assert.match(text['gh.mjs'], /shell: false/);
});

test('only /api/guidance, /api/state and /api/github-item; no reviewer, author-job, pause or resume calls', () => {
  const all = Object.values(text).join('\n');
  const apis = new Set([...all.matchAll(/['"`](\/api\/[A-Za-z/-]*)/g)].map((m) => m[1]));
  assert.deepEqual([...apis].sort(), ['/api/github-item', '/api/guidance', '/api/state']);
  for (const name of ['claim', 'ack', 'review', 'attach', 'heartbeat', 'requestAuthorJob', 'pause', 'resume', 'retryNotification', 'submitOwnerAnswer']) {
    assert.ok(!new RegExp(`\\.${name}\\(`).test(all), `calls .${name}(`);
  }
  assert.ok(!/reviewerToken\s*[:,]/.test(text['broker-client.mjs'].replace(/registerSecret\(c\.reviewerToken\)/, '')), 'the reviewer capability is not stored');
});

test('no command interpolation: gh arguments are built from constants and an integer page only', () => {
  const s = text['gh.mjs'];
  assert.match(s, /\['api', '--hostname', GH_HOSTNAME, '--method', 'GET', '--include', `\$\{COMMENTS_PATH\}\?per_page=\$\{PAGE_SIZE\}&page=\$\{page\}`\]/);
  assert.match(s, /\['api', '--hostname', GH_HOSTNAME, '--method', 'POST', '--include', COMMENTS_PATH, '--input', '-'\]/);
  assert.match(text['constants.mjs'], /GH_HOSTNAME = 'github\.com'/);
});
