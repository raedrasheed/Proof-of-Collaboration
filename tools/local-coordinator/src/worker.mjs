// Author-job worker: builds a FIXED claude command line (never from browser strings),
// starts exactly one detached process with shell:false, and records a durable lease.
import { spawn } from 'node:child_process';
import { closeSync, existsSync, mkdirSync, openSync, readFileSync, statSync, unlinkSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { decodeText, isoNow, pidAlive } from './util.mjs';

export const PLANNED_DIR = /^m1-draft-0\.\d{1,3}$/;
export const TASK_FILE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,80}\.md$/;
const DENIED = ['Bash', 'PowerShell', 'Agent', 'Task', 'WebFetch', 'WebSearch', 'NotebookEdit', 'KillShell', 'BashOutput'];

/** Prompt and arguments for one job. mode: 'smoke' (read-only) or 'author'. */
export function buildCommand({ mode, sessionId, taskFile, plannedDir }) {
  if (!/^[0-9a-f-]{36}$/.test(sessionId || '')) throw new Error('معرف جلسة Claude غير صالح.');
  // `tools` is the capability set (what exists in the session at all); `allowed` only
  // pre-approves calls inside it. Both are fixed here; the deny list stays as a backstop.
  let prompt, tools, allowed;
  if (mode === 'smoke') {
    prompt = 'Read-only status check requested through the local coordinator. Read coordination/issue-ledger.json and coordination/review-001/m1-draft-0.8/results/run-results-0.8.json, then report the latest verified revision and its pass/recorded/fail counts in two sentences. Do not write or edit any file.';
    tools = ['Read', 'Glob', 'Grep'];
    allowed = ['Read', 'Glob', 'Grep'];
  } else if (mode === 'author') {
    if (!TASK_FILE.test(taskFile || '')) throw new Error('اسم ملف المهمة غير صالح.');
    if (!PLANNED_DIR.test(plannedDir || '')) throw new Error('المجلد المخطط يجب أن يكون m1-draft-0.N جديدًا.');
    prompt = `Read coordination/${taskFile} and perform the queued author turn. Write only new files under ${plannedDir}. Preserve all earlier work. No production implementation, installs, deployments, transactions, subagents or memory notes.`;
    tools = ['Read', 'Glob', 'Grep', 'Write', 'Edit'];
    allowed = ['Read', 'Glob', 'Grep', `Write(./${plannedDir}/**)`, `Edit(./${plannedDir}/**)`];
  } else throw new Error('نوع المهمة غير معروف.');
  const args = ['-p', prompt, '--resume', sessionId, '--permission-mode', 'default', '--output-format', 'stream-json', '--verbose',
    '--tools', tools.join(','), '--allowedTools', ...allowed, '--disallowedTools', ...DENIED];
  return { args, prompt, tools, allowed };
}

/**
 * Locate the claude executable without a shell. An explicit path must be an existing
 * regular file and, on Windows, a real .exe: .cmd/.bat/.ps1 shims need a shell, which
 * the worker never uses.
 */
export function findClaude(explicit, { platform = process.platform } = {}) {
  if (explicit) {
    const p = path.resolve(explicit);
    let st = null;
    try { st = statSync(p); } catch { /* missing */ }
    if (!st) throw new Error('مسار claude المحدد غير موجود.');
    if (!st.isFile()) throw new Error('مسار claude المحدد ليس ملفًا تنفيذيًا.');
    if (platform === 'win32' && path.extname(p).toLowerCase() !== '.exe') throw new Error('على Windows يجب أن يكون --claude-bin ملف claude.exe؛ ملفات .cmd و.bat و.ps1 غير مدعومة لأن التشغيل دون shell.');
    return p;
  }
  const names = platform === 'win32' ? ['claude.exe'] : ['claude'];
  for (const dir of (process.env.PATH || '').split(path.delimiter)) {
    for (const n of names) { const p = path.join(dir, n); if (dir && existsSync(p) && statSync(p).isFile()) return p; }
  }
  throw new Error('لم يُعثر على claude.exe في PATH. شغّل الخادم مع --claude-bin بالمسار الكامل.');
}

export class Worker {
  constructor({ ws, uiDir, claudeBin, spawnImpl = spawn, isAlive = pidAlive, log = () => {} }) {
    Object.assign(this, { ws, uiDir, claudeBin, spawnImpl, isAlive, log });
    this.leaseFile = path.join(uiDir, 'worker.lease');
    this.child = null;
  }

  jobDir(jobId) { return path.join(this.uiDir, 'jobs', jobId); }
  readLease() { try { return JSON.parse(readFileSync(this.leaseFile, 'utf8')); } catch { return null; } }

  /**
   * Exclusive start: the lease file is created with 'wx'; a second start fails instead of spawning.
   * Everything that can be validated is validated before the lease exists. After the lease is
   * taken, any synchronous failure closes every descriptor, removes the lease (and stops a child
   * that was already spawned) before rethrowing. onExit is called at most once ('exit' and
   * 'error' may both fire), and never for a start that threw.
   */
  start(job, onExit) {
    if (!this.claudeBin) throw new Error('claude.exe غير متاح لهذا الخادم.');
    const { args } = buildCommand(job.dispatch);
    const dir = this.jobDir(job.id);
    mkdirSync(dir, { recursive: true });
    const receipt = path.join(dir, 'receipt.jsonl');
    const errLog = path.join(dir, 'stderr.log');
    let fd;
    try { fd = openSync(this.leaseFile, 'wx', 0o600); }
    catch (e) { throw new Error(e.code === 'EEXIST' ? 'يوجد عقد عامل قائم؛ لن يبدأ مؤلف ثانٍ.' : `تعذر إنشاء عقد العامل (${e.code || 'خطأ غير معروف'}).`); }
    const fds = [fd];
    const closeAll = () => { for (const f of fds.splice(0)) { try { closeSync(f); } catch { /* already closed */ } } };
    let child = null, done = false;
    const complete = (r) => {
      if (done) return;
      done = true;
      if (this.child === child) this.child = null;
      onExit?.(r);
    };
    try {
      const out = openSync(receipt, 'a', 0o600); fds.push(out);
      const err = openSync(errLog, 'a', 0o600); fds.push(err);
      child = this.spawnImpl(this.claudeBin, args, { cwd: this.ws, shell: false, detached: true, windowsHide: true, stdio: ['ignore', out, err] });
      if (!child || typeof child.on !== 'function') { child = null; throw new Error('لم يُرجع التشغيل عملية صالحة.'); }
      child.on('exit', (code, signal) => complete({ code, signal }));
      child.on('error', (e) => complete({ code: null, signal: null, error: String(e?.message || e) }));
      const lease = { jobId: job.id, pid: child.pid ?? null, startedAt: isoNow(), receipt: path.relative(this.uiDir, receipt) };
      writeFileSync(fd, JSON.stringify(lease));
      closeAll();
      this.child = child;
      child.unref?.();
      this.log({ event: 'worker.start', jobId: job.id, pid: lease.pid });
      return lease;
    } catch (e) {
      done = true;                                        // a failed start never reports a completion
      if (child) { try { child.kill?.(); } catch { /* already gone */ } }
      closeAll();
      try { unlinkSync(this.leaseFile); } catch { /* already gone */ }
      this.log({ event: 'worker.startAborted', jobId: job.id, message: String(e?.message || e) });
      throw e;
    }
  }

  /** Remove the lease; with a jobId, only if the lease belongs to that job. */
  release(jobId) {
    if (jobId) { const l = this.readLease(); if (l && l.jobId !== jobId) return; }
    try { unlinkSync(this.leaseFile); } catch { /* already gone */ }
  }

  /** Final 'result' event of a receipt, if the CLI wrote one. */
  receiptResult(jobId) {
    const f = path.join(this.jobDir(jobId), 'receipt.jsonl');
    if (!existsSync(f)) return null;
    let res = null;
    for (const line of decodeText(readFileSync(f)).split(/\r?\n/)) {
      if (!line.startsWith('{')) continue;
      try { const ev = JSON.parse(line); if (ev.type === 'result') res = ev; } catch { /* partial line */ }
    }
    return res;
  }

  /** Classify an existing lease after a restart without spawning anything. */
  recover() {
    const lease = this.readLease();
    if (!lease) return { state: 'none' };
    if (lease.pid && this.isAlive(lease.pid)) return { state: 'alive', lease };
    const result = this.receiptResult(lease.jobId);
    return result ? { state: 'finished', lease, result } : { state: 'interrupted', lease };
  }
}
