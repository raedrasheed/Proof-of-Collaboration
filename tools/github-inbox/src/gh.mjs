// The ONLY child process the adapter ever starts: the operator's existing, already authenticated
// GitHub CLI, with one of two fixed argument vectors. Nothing from a GitHub comment can reach an
// argument: comment text is only ever sent as JSON on stdin (`--input -`). spawn uses shell:false and
// windowsHide; output is bounded in BYTES and decoded with a streaming UTF-8 decoder (multibyte
// characters split across chunks stay intact); the process is killed on timeout. The destination
// host is forced with `--hostname github.com`, and GH_HOST / GH_REPO are removed from the child
// environment, so neither configuration nor the environment can redirect requests. gh's own
// credential storage is used as is; the adapter never reads, prints or passes a token. stderr is
// never logged or returned: it is reduced to a fixed classification.
//
// 0.41: the timeout timer is referenced (not unref'd) and always cleared on settle, so a run settles
// within timeoutMs even when nothing else keeps the event loop alive (I8-01).
import { spawn } from 'node:child_process';
import { StringDecoder } from 'node:string_decoder';
import { COMMENTS_PATH, GH_HOSTNAME, MAX_PAGES_PER_CYCLE, PAGE_SIZE } from './constants.mjs';

const STDERR_SCAN_MAX = 8 * 1024;
const RATE_HEADERS = ['retry-after', 'x-ratelimit-remaining', 'x-ratelimit-reset'];
const ENV_REMOVED = ['GH_HOST', 'GH_REPO'];

/** The fixed argument vectors. Exported for tests. */
export function listArgs(page) {
  if (!Number.isInteger(page) || page < 1 || page > 100000) throw new Error('invalid page');
  return ['api', '--hostname', GH_HOSTNAME, '--method', 'GET', '--include', `${COMMENTS_PATH}?per_page=${PAGE_SIZE}&page=${page}`];
}
export function postArgs() {
  return ['api', '--hostname', GH_HOSTNAME, '--method', 'POST', '--include', COMMENTS_PATH, '--input', '-'];
}

/** The child environment: inherited, minus host/repo selection, plus non-interactive settings. */
export function childEnv(env) {
  const out = { ...env };
  for (const k of Object.keys(out)) if (ENV_REMOVED.includes(k.toUpperCase())) delete out[k];
  return { ...out, GH_PROMPT_DISABLED: '1', GH_NO_UPDATE_NOTIFIER: '1', NO_COLOR: '1', GH_PAGER: 'cat', PAGER: 'cat' };
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

const asBuffer = (c) => (Buffer.isBuffer(c) ? c : Buffer.from(String(c), 'utf8'));

export class GhClient {
  constructor({ ghBin, cwd, spawnImpl = spawn, timeoutMs = 30_000, maxStdout = 4 * 1024 * 1024, env = process.env }) {
    Object.assign(this, { ghBin, cwd, spawnImpl, timeoutMs, maxStdout });
    this.env = childEnv(env);
  }

  /**
   * One gh invocation. Resolves (never rejects) within timeoutMs with
   * { code, stdout, stderrClass, timedOut, overflow, launchError }. maxStdout counts bytes.
   */
  run(args, stdinText = null) {
    return new Promise((resolve) => {
      const outDec = new StringDecoder('utf8'), errDec = new StringDecoder('utf8');
      let out = '', outBytes = 0, errScan = '', settled = false, timer = null, child = null, overflow = false;
      const finish = (r) => {
        if (settled) return;
        settled = true;
        if (timer) { clearTimeout(timer); timer = null; }
        if (!overflow) out += outDec.end();
        resolve({ code: null, stdout: overflow ? '' : out, stderrClass: classifyStderr(errScan), timedOut: false, overflow, launchError: null, ...r });
      };
      try {
        child = this.spawnImpl(this.ghBin, args, { cwd: this.cwd, env: this.env, shell: false, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
      } catch (e) { finish({ launchError: e?.code || 'spawnFailed' }); return; }
      // Referenced on purpose: the run must settle even if the child never closes (I8-01).
      timer = setTimeout(() => { try { child.kill(); } catch { /* gone */ } finish({ timedOut: true }); }, this.timeoutMs);
      child.stdout?.on('data', (c) => {
        if (overflow || settled) return;
        const b = asBuffer(c);
        outBytes += b.length;
        if (outBytes > this.maxStdout) { overflow = true; out = ''; try { child.kill(); } catch { /* gone */ } return; }
        out += outDec.write(b);
      });
      child.stderr?.on('data', (c) => {
        if (errScan.length < STDERR_SCAN_MAX) errScan += errDec.write(asBuffer(c)).slice(0, STDERR_SCAN_MAX - errScan.length);
      });
      child.on('error', (e) => finish({ launchError: e?.code || 'spawnFailed' }));
      child.on('close', (code) => finish({ code }));
      try {
        if (child.stdin) {
          child.stdin.on?.('error', () => { /* child exited early; reported via close */ });
          if (stdinText !== null) child.stdin.end(stdinText); else child.stdin.end();
        }
      } catch { /* reported via close/error */ }
    });
  }

  /** One page of issue comments. Resolves { ok, comments, next, rate, httpStatus, reason }; never throws. */
  async listPage(page) {
    if (page > MAX_PAGES_PER_CYCLE * 1000) return { ok: false, reason: 'pageBound', comments: [], next: false, rate: rateInfo({}) };
    const r = await this.run(listArgs(page));
    return this._parse(r, (body) => (Array.isArray(body) ? body : null), 'comments');
  }

  /** Post one comment. Resolves { ok, comment, rate, httpStatus, reason, uncertain }. */
  async postComment(body) {
    if (typeof body !== 'string' || !body || body.length > 60_000) return { ok: false, reason: 'invalidBody', uncertain: false };
    const r = await this.run(postArgs(), JSON.stringify({ body }));
    const p = this._parse(r, (b) => (b && typeof b === 'object' && Number.isInteger(b.id) ? b : null), 'comment');
    // A timeout, overflow, unparseable success or 5xx means the comment may or may not exist.
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
