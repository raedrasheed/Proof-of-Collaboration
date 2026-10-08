// The ONLY child process the adapter ever starts: the operator's existing, already authenticated
// GitHub CLI, with one of two fixed argument vectors. Nothing from a GitHub comment can reach an
// argument: comment text is only ever sent as JSON on stdin (`--input -`). spawn uses shell:false and
// windowsHide; output is bounded and the process is killed on timeout. gh's own credential storage is
// used as is; the adapter never reads, prints or passes a token. stderr is never logged or returned:
// it is reduced to a fixed classification.
import { spawn } from 'node:child_process';
import { COMMENTS_PATH, MAX_PAGES_PER_CYCLE, PAGE_SIZE } from './constants.mjs';

const STDERR_SCAN_MAX = 8 * 1024;
const RATE_HEADERS = ['retry-after', 'x-ratelimit-remaining', 'x-ratelimit-reset'];

/** The fixed argument vectors. Exported for tests. */
export function listArgs(page) {
  if (!Number.isInteger(page) || page < 1 || page > 100000) throw new Error('invalid page');
  return ['api', '--method', 'GET', '--include', `${COMMENTS_PATH}?per_page=${PAGE_SIZE}&page=${page}`];
}
export function postArgs() {
  return ['api', '--method', 'POST', '--include', COMMENTS_PATH, '--input', '-'];
}

/** Fixed classification of gh's stderr; the text itself is discarded. */
export function classifyStderr(text) {
  const s = String(text || '').slice(0, STDERR_SCAN_MAX);
  if (/rate limit|secondary rate/i.test(s)) return 'rateLimited';
  if (/auth login|not logged in|authentication|bad credentials|HTTP 401/i.test(s)) return 'authRequired';
  const m = /HTTP (\d{3})/.exec(s);
  if (m) return `http${m[1]}`;
  if (/timeout|timed out|connection|network|dial tcp|EOF/i.test(s)) return 'network';
  return s.trim() ? 'error' : 'none';
}

/** Split `gh api --include` output into { status, headers, body }. */
export function parseIncluded(stdout) {
  const text = String(stdout || '');
  const m = /\r?\n\r?\n/.exec(text);
  if (!/^HTTP\/[0-9.]+ \d{3}/.test(text) || !m) return { status: null, headers: {}, body: text };
  const head = text.slice(0, m.index).split(/\r?\n/);
  const status = Number(/^HTTP\/[0-9.]+ (\d{3})/.exec(head[0])[1]);
  const headers = {};
  for (const line of head.slice(1)) {
    const i = line.indexOf(':');
    if (i > 0) headers[line.slice(0, i).trim().toLowerCase()] = line.slice(i + 1).trim();
  }
  return { status, headers, body: text.slice(m.index + m[0].length) };
}

export function hasNextPage(headers) {
  return typeof headers.link === 'string' && /rel="next"/.test(headers.link);
}

/** Rate information from headers: { retryAfterS, remaining, resetAt } (numbers or null). */
export function rateInfo(headers) {
  const out = { retryAfterS: null, remaining: null, resetAt: null };
  for (const h of RATE_HEADERS) if (headers[h] !== undefined && !/^\d{1,12}$/.test(headers[h])) return out;
  if (headers['retry-after'] !== undefined) out.retryAfterS = Number(headers['retry-after']);
  if (headers['x-ratelimit-remaining'] !== undefined) out.remaining = Number(headers['x-ratelimit-remaining']);
  if (headers['x-ratelimit-reset'] !== undefined) out.resetAt = Number(headers['x-ratelimit-reset']) * 1000;
  return out;
}

export class GhClient {
  constructor({ ghBin, cwd, spawnImpl = spawn, timeoutMs = 30_000, maxStdout = 4 * 1024 * 1024, env = process.env }) {
    Object.assign(this, { ghBin, cwd, spawnImpl, timeoutMs, maxStdout });
    // Inherit the environment (gh finds its own stored credentials); only disable prompts, pager,
    // colour and update checks. Nothing is added from configuration or comments.
    this.env = { ...env, GH_PROMPT_DISABLED: '1', GH_NO_UPDATE_NOTIFIER: '1', NO_COLOR: '1', GH_PAGER: 'cat', PAGER: 'cat' };
  }

  /**
   * One gh invocation. Resolves (never rejects) with
   * { code, stdout, stderrClass, timedOut, overflow, launchError }.
   */
  run(args, stdinText = null) {
    return new Promise((resolve) => {
      let out = '', errScan = '', settled = false, timer = null, child = null, overflow = false;
      const finish = (r) => {
        if (settled) return;
        settled = true;
        if (timer) clearTimeout(timer);
        resolve({ code: null, stdout: overflow ? '' : out, stderrClass: classifyStderr(errScan), timedOut: false, overflow, launchError: null, ...r });
      };
      try {
        child = this.spawnImpl(this.ghBin, args, { cwd: this.cwd, env: this.env, shell: false, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
      } catch (e) { finish({ launchError: e?.code || 'spawnFailed' }); return; }
      child.stdout?.on('data', (c) => {
        if (overflow) return;
        out += String(c);
        if (out.length > this.maxStdout) { overflow = true; out = ''; try { child.kill(); } catch { /* gone */ } }
      });
      child.stderr?.on('data', (c) => { if (errScan.length < STDERR_SCAN_MAX) errScan += String(c).slice(0, STDERR_SCAN_MAX - errScan.length); });
      child.on('error', (e) => finish({ launchError: e?.code || 'spawnFailed' }));
      child.on('close', (code) => finish({ code }));
      timer = setTimeout(() => { try { child.kill(); } catch { /* gone */ } finish({ timedOut: true }); }, this.timeoutMs);
      timer.unref?.();
      try {
        if (child.stdin) {
          child.stdin.on('error', () => { /* child exited early; reported via close */ });
          if (stdinText !== null) child.stdin.end(stdinText); else child.stdin.end();
        }
      } catch { /* reported via close/error */ }
    });
  }

  /**
   * One page of issue comments. Resolves { ok, comments, next, rate, httpStatus, reason }.
   * `ok:false` never throws; `reason` is a fixed word.
   */
  async listPage(page) {
    if (page > MAX_PAGES_PER_CYCLE * 1000) return { ok: false, reason: 'pageBound', comments: [], next: false, rate: rateInfo({}) };
    const r = await this.run(listArgs(page));
    return this._parse(r, (body) => Array.isArray(body) ? body : null, 'comments');
  }

  /** Post one comment. Resolves { ok, comment, rate, httpStatus, reason, uncertain }. */
  async postComment(body) {
    if (typeof body !== 'string' || !body || body.length > 60_000) return { ok: false, reason: 'invalidBody', uncertain: false };
    const r = await this.run(postArgs(), JSON.stringify({ body }));
    const p = this._parse(r, (b) => (b && typeof b === 'object' && Number.isInteger(b.id) ? b : null), 'comment');
    // A timeout, overflow or unparseable success means the comment may or may not exist.
    // A 5xx may still have created the comment. Only a definite 4xx/launch failure is "not posted".
    p.uncertain = !p.ok && (r.timedOut || r.overflow || r.code === 0 || r.stderrClass === 'network' || (p.httpStatus !== null && p.httpStatus >= 500) || p.reason === 'unparseable');
    return p;
  }

  _parse(r, pick, field) {
    const base = { ok: false, rate: rateInfo({}), httpStatus: null, reason: null, next: false, [field]: field === 'comments' ? [] : null };
    if (r.launchError) return { ...base, reason: 'launchFailed' };
    if (r.timedOut) return { ...base, reason: 'timeout' };
    if (r.overflow) return { ...base, reason: 'outputTooLarge' };
    const inc = parseIncluded(r.stdout);
    const rate = rateInfo(inc.headers);
    const httpStatus = inc.status;
    if (r.code !== 0 || (httpStatus !== null && httpStatus >= 400)) {
      const limited = httpStatus === 429 || r.stderrClass === 'rateLimited' || (httpStatus === 403 && (rate.remaining === 0 || rate.retryAfterS !== null));
      return { ...base, rate, httpStatus, reason: limited ? 'rateLimited' : (r.stderrClass !== 'none' ? r.stderrClass : `exit${r.code}`) };
    }
    let parsed = null;
    try { parsed = pick(JSON.parse(inc.body)); } catch { parsed = null; }
    if (parsed === null) return { ...base, rate, httpStatus, reason: 'unparseable' };
    return { ...base, ok: true, rate, httpStatus, next: hasNextPage(inc.headers), [field]: parsed };
  }
}
