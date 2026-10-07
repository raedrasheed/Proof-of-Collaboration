import { EventEmitter } from 'node:events';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export const SESSION = '83a06b92-c5ea-45e3-852e-b5b5f28a3eea';
export const FAKE_PRIV = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';

export function utf16(text) {
  return Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(text, 'utf16le')]);
}

/** A temporary workspace shaped like D:/PoCol-Development (only what the coordinator reads). */
export function makeWorkspace({ activeState = 'completed' } = {}) {
  const ws = mkdtempSync(path.join(os.tmpdir(), 'pocol-coord-'));
  const coord = path.join(ws, 'coordination');
  mkdirSync(path.join(coord, 'review-001', 'm1-draft-0.8', 'results'), { recursive: true });
  writeFileSync(path.join(coord, 'issue-ledger.json'), '\uFEFF' + JSON.stringify({
    status: '0.8-verified', latestCompletedRevision: 'm1-draft-0.8',
    issues: [{ id: 'C01', status: 'open', decision: 'Full gate' }, { id: 'C23', status: 'closed-spec-tooling', decision: 'fixed' }],
    history: [{ revision: '0.8', result: '261 pass, 3 recorded, 0 fail' }],
    activeAuthor: { task: 'task-006.md', claudeSessionId: SESSION, state: activeState },
    githubHandoff: { commit: '24aec0066ad7b39e3a423bd45f8952d75ea2b6c4' },
  }));
  writeFileSync(path.join(coord, 'task-006.md'), '# Claude author turn 006\n\nWrite ONLY new m1-draft-0.8 files.\n');
  const lines = [
    { type: 'system', subtype: 'init', session_id: SESSION, model: 'claude-x', claude_code_version: '9.9', permissionMode: 'default', memory_paths: { auto: 'C:/secret/memory' } },
    { type: 'assistant', timestamp: '2026-10-07T10:23:00.432Z', message: { content: [
      { type: 'thinking', thinking: 'HIDDEN-REASONING-MARKER should never appear' },
      { type: 'text', text: 'Reading the task now.' },
      { type: 'tool_use', name: 'Write', input: { file_path: 'm1-draft-0.8/x.json', content: `{"privateKey": "${FAKE_PRIV}"}` } } ] } },
    { type: 'system', subtype: 'thinking_tokens', estimated_tokens: 50 },
    { type: 'user', timestamp: '2026-10-07T10:23:01.000Z', message: { content: [{ type: 'tool_result', content: '<script>alert(1)</script><img src=x onerror=alert(2)>' }] },
      tool_use_result: { file: { content: 'RAW-PAYLOAD-MARKER' } } },
    { type: 'rate_limit_event', rate_limit_info: { status: 'allowed' } },
    { type: 'result', subtype: 'success', is_error: false, result: 'Done. mnemonic: test test test test test test test test test test test junk', duration_ms: 1000, num_turns: 3, permission_denials: [], session_id: SESSION },
  ];
  writeFileSync(path.join(coord, 'claude-006.jsonl'), utf16(lines.map((l) => JSON.stringify(l)).join('\n') + '\n'));
  writeFileSync(path.join(coord, 'claude-001.json'), JSON.stringify({ type: 'result', is_error: true, result: 'API Error', terminal_reason: 'api_error', session_id: SESSION }));
  writeFileSync(path.join(coord, 'review-001', 'REVIEW-0.8.md'), '# Codex review of 0.8\n\n261 pass, 3 recorded, 0 fail.\n');
  writeFileSync(path.join(coord, 'review-001', 'm1-draft-0.8', 'results', 'run-results-0.8.json'),
    JSON.stringify({ executedAtUtc: '2026-10-07T11:00:00+00:00', summary: { checks: 264, passed: 261, recorded: 3, failed: 0 } }));
  return ws;
}

/** Fake spawner: records calls; the test decides when the child "exits". */
export function fakeSpawner() {
  const calls = [];
  let nextPid = 40000;
  const spawnImpl = (cmd, args, opts) => {
    const child = new EventEmitter();
    child.pid = nextPid++;
    child.unref = () => {};
    calls.push({ cmd, args, opts, child });
    return child;
  };
  return { spawnImpl, calls };
}

export const resultLine = (isError = false) => JSON.stringify({ type: 'result', is_error: isError, result: isError ? 'failed' : 'status: 0.8 verified', session_id: SESSION }) + '\n';

/** Deterministic clock. */
export function clock(start = Date.parse('2026-10-08T09:00:00Z')) {
  let t = start;
  return { now: () => t, advance: (ms) => { t += ms; } };
}
