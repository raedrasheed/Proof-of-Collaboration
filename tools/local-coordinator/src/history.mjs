// Read-only import of the existing coordination record into display cards.
// Allowlist only: final result text, assistant text blocks, tool calls (name and
// selected input fields), bounded tool results, and result metadata. Everything
// else is dropped: thinking/redacted_thinking blocks, system events (including
// thinking_tokens), rate-limit events, raw tool_use_result payloads, init details.
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { bound, decodeText, readJson, sha256 } from './util.mjs';
import { redact, redactDeep } from './redact.mjs';

const TEXT_MAX = 6000, TOOL_RESULT_MAX = 1500, INPUT_PREVIEW_MAX = 400, ENTRIES_MAX = 400;
const INPUT_KEYS = ['file_path', 'path', 'pattern', 'glob', 'output_mode', 'offset', 'limit', 'head_limit', 'type', 'multiline'];
const UNAVAILABLE = null;

const cardId = (source, n) => sha256(`${source}#${n}`).slice(0, 16);
const rel = (ws, file) => path.relative(ws, file).split(path.sep).join('/');

function toolInput(name, input) {
  const out = {};
  if (!input || typeof input !== 'object') return out;
  for (const k of INPUT_KEYS) if (k in input && typeof input[k] !== 'object') out[k] = String(input[k]);
  if (typeof input.content === 'string') { out.contentChars = String(input.content.length); out.contentPreview = bound(input.content, INPUT_PREVIEW_MAX); }
  if (typeof input.old_string === 'string') out.oldPreview = bound(input.old_string, INPUT_PREVIEW_MAX);
  if (typeof input.new_string === 'string') out.newPreview = bound(input.new_string, INPUT_PREVIEW_MAX);
  if (typeof input.command === 'string') out.command = bound(input.command, INPUT_PREVIEW_MAX);
  return out;
}

function toolResultText(content) {
  if (typeof content === 'string') return content;
  if (Array.isArray(content)) return content.filter((c) => c && c.type === 'text' && typeof c.text === 'string').map((c) => c.text).join('\n');
  return '';
}

/** Parse one CLI receipt (stream-json lines or a single result object) through the allowlist. */
export function parseReceipt(text) {
  const entries = [];
  let result = null, init = null, firstAt = UNAVAILABLE, lastAt = UNAVAILABLE, toolCalls = 0;
  const lines = text.trim().startsWith('{') && !text.includes('\n{') ? [text] : text.split(/\r?\n/);
  for (const line of lines) {
    if (!line.trim()) continue;
    let ev;
    try { ev = JSON.parse(line); } catch { continue; }
    if (!ev || typeof ev !== 'object') continue;
    const at = typeof ev.timestamp === 'string' ? ev.timestamp : UNAVAILABLE;
    if (at) { firstAt ??= at; lastAt = at; }
    if (ev.type === 'system') {
      if (ev.subtype === 'init') init = { model: ev.model ?? UNAVAILABLE, version: ev.claude_code_version ?? UNAVAILABLE, permissionMode: ev.permissionMode ?? UNAVAILABLE, sessionId: ev.session_id ?? UNAVAILABLE };
      continue;                                                         // thinking_tokens and every other system event are dropped
    }
    if (ev.type === 'assistant' && ev.message && Array.isArray(ev.message.content)) {
      for (const c of ev.message.content) {
        if (!c || typeof c !== 'object') continue;
        if (c.type === 'text' && typeof c.text === 'string') entries.push({ kind: 'text', at, text: bound(c.text, TEXT_MAX) });
        else if (c.type === 'tool_use') { toolCalls++; entries.push({ kind: 'tool_use', at, name: String(c.name || ''), input: toolInput(c.name, c.input) }); }
        // 'thinking', 'redacted_thinking' and unknown block types are intentionally ignored
      }
      continue;
    }
    if (ev.type === 'user' && ev.message) {
      const content = ev.message.content;
      if (typeof content === 'string') { entries.push({ kind: 'prompt', at, text: bound(content, TEXT_MAX) }); continue; }
      if (Array.isArray(content)) {
        for (const c of content) {
          if (c && c.type === 'tool_result') entries.push({ kind: 'tool_result', at, isError: Boolean(c.is_error), text: bound(toolResultText(c.content), TOOL_RESULT_MAX) });
        }
      }
      continue;                                                         // ev.tool_use_result (raw payload) is never read
    }
    if (ev.type === 'result') {
      result = {
        text: bound(typeof ev.result === 'string' ? ev.result : '', TEXT_MAX * 4),
        isError: Boolean(ev.is_error), subtype: ev.subtype ?? UNAVAILABLE, terminalReason: ev.terminal_reason ?? UNAVAILABLE,
        durationMs: Number.isFinite(ev.duration_ms) ? ev.duration_ms : UNAVAILABLE, numTurns: Number.isFinite(ev.num_turns) ? ev.num_turns : UNAVAILABLE,
        permissionDenials: Array.isArray(ev.permission_denials) ? ev.permission_denials.map((d) => String(d?.tool_name || 'unknown')) : [],
        sessionId: ev.session_id ?? UNAVAILABLE,
      };
    }
  }
  return redactDeep({ entries: entries.slice(-ENTRIES_MAX), truncatedEntries: Math.max(0, entries.length - ENTRIES_MAX), result, init, firstAt, lastAt, toolCalls });
}

function listFiles(dir, re) {
  if (!existsSync(dir)) return [];
  return readdirSync(dir).filter((n) => re.test(n)).sort().map((n) => path.join(dir, n));
}

function maxRevision(text) {
  let best = null;
  for (const m of text.matchAll(/m1-draft-(0\.\d+)/g)) if (!best || Number(m[1].slice(2)) > Number(best.slice(2))) best = m[1];
  return best;
}

/** Load (or reuse from cache) every historical card. `cache` maps file hash -> parsed receipt. */
export function loadHistory(ws, cache = {}) {
  const coord = path.join(ws, 'coordination');
  const ledger = readJson(path.join(coord, 'issue-ledger.json'), null);
  const commit = ledger?.githubHandoff?.commit ?? UNAVAILABLE;
  const cards = [];
  const newCache = {};
  const taskRevision = {};

  for (const file of listFiles(coord, /^task-\d{3}\.md$/)) {
    const raw = readFileSync(file);
    const text = decodeText(raw);
    const n = path.basename(file).match(/\d{3}/)[0];
    const revision = maxRevision(text);
    taskRevision[n] = revision;
    cards.push({
      id: cardId(rel(ws, file), 0), role: 'coordinator', actor: 'Codex', kind: 'task', task: n, revision,
      time: UNAVAILABLE, timeNote: 'غير مسجل في الملف', sha256: sha256(raw), commit, source: rel(ws, file),
      summaryAr: `مهمة المؤلف ${n} التي كتبها المنسق${revision ? ` · المسودة المستهدفة ${revision}` : ''}`,
      technical: [{ kind: 'text', text: redact(bound(text, TEXT_MAX)) }],
    });
  }

  for (const file of listFiles(coord, /^claude-\d{3}[^/\\]*\.jsonl?$/)) {
    const raw = readFileSync(file);
    const hash = sha256(raw);
    const parsed = cache[hash] ?? parseReceipt(decodeText(raw));
    newCache[hash] = parsed;
    const n = path.basename(file).match(/\d{3}/)[0];
    const r = parsed.result;
    const outcome = !r ? 'لا توجد نتيجة نهائية في الملف' : r.isError ? `انتهى بخطأ (${r.terminalReason ?? 'سبب غير مسجل'})` : 'اكتمل';
    cards.push({
      id: cardId(rel(ws, file), 0), role: 'author', actor: 'Claude', kind: 'receipt', task: n, revision: taskRevision[n] ?? UNAVAILABLE,
      time: parsed.lastAt ?? UNAVAILABLE, timeNote: parsed.lastAt ? null : 'الطابع الزمني غير متاح في هذا الملف',
      sha256: hash, commit, source: rel(ws, file), sessionId: r?.sessionId ?? parsed.init?.sessionId ?? UNAVAILABLE,
      summaryAr: `ردّ Claude (المؤلف) على المهمة ${n}: ${outcome} · ${parsed.toolCalls} استدعاء أداة · رفض أذونات: ${r ? r.permissionDenials.length : 'غير معروف'}`,
      result: r, technical: parsed.entries, truncatedEntries: parsed.truncatedEntries,
    });
  }

  const reviewDir = path.join(coord, 'review-001');
  for (const file of listFiles(reviewDir, /^REVIEW(-0\.\d+)?\.md$/)) {
    const raw = readFileSync(file);
    const m = path.basename(file).match(/REVIEW-(0\.\d+)/);
    const revision = m ? m[1] : '0.2';
    const hist = (ledger?.history || []).find((h) => h.revision === revision);
    cards.push({
      id: cardId(rel(ws, file), 0), role: 'reviewer', actor: 'Codex', kind: 'review', revision, task: UNAVAILABLE,
      time: UNAVAILABLE, timeNote: 'غير مسجل في الملف', sha256: sha256(raw), commit, source: rel(ws, file),
      summaryAr: `مراجعة Codex المستقلة للمسودة ${revision}${hist ? ' · نتيجة السجل: ' + redact(String(hist.result)) : ''}`,
      technical: [{ kind: 'text', text: redact(bound(decodeText(raw), TEXT_MAX * 2)) }],
    });
  }
  return { cards, cache: newCache, ledger };
}

/** Saved check results: summaries only, newest revision first. */
export function loadCheckResults(ws) {
  const out = [];
  const roots = [path.join(ws, 'coordination', 'review-001'), ws];
  for (const root of roots) {
    if (!existsSync(root)) continue;
    for (const d of readdirSync(root).filter((n) => /^m1-draft-0\.\d+$/.test(n))) {
      const resDir = path.join(root, d, 'results');
      for (const f of listFiles(resDir, /^run-results(-0\.\d+)?\.json$/)) {
        const j = readJson(f, null);
        if (!j?.summary) continue;
        out.push({ revision: d.replace('m1-draft-', ''), source: rel(ws, f), executedAtUtc: j.executedAtUtc ?? UNAVAILABLE,
          summary: { checks: j.summary.checks, passed: j.summary.passed, recorded: j.summary.recorded ?? 0, failed: j.summary.failed },
          sha256: sha256(readFileSync(f)), mtime: statSync(f).mtime.toISOString() });
      }
    }
  }
  out.sort((a, b) => Number(b.revision.slice(2)) - Number(a.revision.slice(2)) || (a.source.includes('review-001') ? -1 : 1));
  return out;
}
