// Small shared helpers. Node built-ins only.
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync, appendFileSync } from 'node:fs';
import path from 'node:path';

export const sha256 = (data) => createHash('sha256').update(data).digest('hex');
export const newToken = () => randomBytes(32).toString('hex');
export const newId = () => randomUUID();
export const isoNow = (now = Date.now()) => new Date(now).toISOString();

/** Decode a text file written as UTF-8 (optional BOM) or UTF-16LE/BE with BOM (PowerShell redirection). */
export function decodeText(buf) {
  if (buf.length >= 2 && buf[0] === 0xff && buf[1] === 0xfe) return new TextDecoder('utf-16le').decode(buf.subarray(2));
  if (buf.length >= 2 && buf[0] === 0xfe && buf[1] === 0xff) return new TextDecoder('utf-16be').decode(buf.subarray(2));
  const text = new TextDecoder('utf-8').decode(buf);
  return text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
}

export function readText(file) {
  return decodeText(readFileSync(file));
}

export function readJson(file, fallback = undefined) {
  if (!existsSync(file)) return fallback;
  try { return JSON.parse(readText(file)); } catch { return fallback; }
}

/** Atomic replace: write a sibling temp file, then rename over the target. */
export function writeJsonAtomic(file, value) {
  mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.${randomBytes(4).toString('hex')}.tmp`;
  writeFileSync(tmp, JSON.stringify(value, null, 2) + '\n', { encoding: 'utf8', mode: 0o600 });
  renameSync(tmp, file);
}

export function appendLog(file, record) {
  mkdirSync(path.dirname(file), { recursive: true });
  appendFileSync(file, JSON.stringify({ at: isoNow(), ...record }) + '\n', { encoding: 'utf8', mode: 0o600 });
}

/** True if a process with this pid exists (EPERM still means it exists). */
export function pidAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try { process.kill(pid, 0); return true; } catch (e) { return e.code === 'EPERM'; }
}

/** Bound a string to max characters, marking the cut. */
export function bound(text, max) {
  if (typeof text !== 'string') return '';
  return text.length <= max ? text : text.slice(0, max) + `\n… [قُصّ: ${text.length - max} حرفًا إضافيًا]`;
}
