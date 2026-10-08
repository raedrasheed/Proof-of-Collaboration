// Text sanitizing for the GitHub inbox adapter. Reuses the coordinator's redactor (secret
// keywords, token shapes, every registered runtime capability) and adds an allowlist pass for
// anything published on GitHub: no local paths, loopback URLs, capabilities, UUIDs (thread, broker
// and session IDs), mentions, HTML comments or control characters leave this machine.
import { redact, registerSecret, MASK } from '../../local-coordinator/src/redact.mjs';
import { REPO_FULL } from './constants.mjs';

export { redact, registerSecret, MASK };

const UUID_RE = /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi;
const HEX64_RE = /\b[0-9a-fA-F]{64}\b/g;
const LOOPBACK_RE = /\b(?:https?|wss?):\/\/(?:127\.\d{1,3}\.\d{1,3}\.\d{1,3}|localhost|\[::1\]|0\.0\.0\.0)(?::\d+)?[^\s)>\]]*/gi;
const WIN_PATH_RE = /(?:\b[A-Za-z]:[\\/]|\\\\)[^\s"'`<>|]*/g;
const POSIX_PATH_RE = /(?:^|[\s("'`])((?:\/(?:Users|home|root|tmp|var|etc|opt|mnt|private)\/)[^\s"'`<>|]*)/g;
// Built from code points (no escape sequences in this source): C0 controls except tab/LF/CR, DEL,
// and the bidirectional override/isolate characters U+202A-U+202E and U+2066-U+2069.
const CONTROL_RANGES = [[0x00, 0x08], [0x0b, 0x0c], [0x0e, 0x1f], [0x7f, 0x7f], [0x202a, 0x202e], [0x2066, 0x2069]];
const CONTROL_RE = new RegExp('[' + CONTROL_RANGES.map(([a, b]) => String.fromCharCode(a) + '-' + String.fromCharCode(b)).join('') + ']', 'g');
/** Zero-width space, used to defuse mentions and command prefixes in published text. */
export const ZWSP = String.fromCharCode(0x200b);

/** Bound to `max` characters, marking the cut in English (public text is English plus fixed Arabic labels). */
export function boundText(s, max) {
  const t = typeof s === 'string' ? s : '';
  return t.length <= max ? t : t.slice(0, max) + ` [truncated ${t.length - max} chars]`;
}

/** For the private broker payload: secrets masked, control characters removed, length bounded. */
export function privateText(s, max) {
  return boundText(redact(String(s ?? '')).replace(CONTROL_RE, ''), max);
}

/** For anything posted to GitHub. Allowlist-style: removes every class of local identifier. */
export function publicText(s, max) {
  let t = redact(String(s ?? ''));
  t = t.replace(CONTROL_RE, '');
  t = t.replace(LOOPBACK_RE, '[local-url]');
  t = t.replace(WIN_PATH_RE, '[local-path]');
  t = t.replace(POSIX_PATH_RE, (whole, p) => whole.slice(0, whole.length - p.length) + '[local-path]');
  t = t.replace(UUID_RE, '[id]');
  t = t.replace(HEX64_RE, MASK);
  t = t.replace(/<!--/g, '&lt;!--').replace(/-->/g, '--&gt;');
  t = t.replace(/@(?=[A-Za-z0-9-])/g, '@' + ZWSP);
  t = t.replace(/^\s*\/pocol\b/gim, (m) => m.replace('/pocol', '/' + ZWSP + 'pocol'));
  return boundText(t, max);
}

const EVIDENCE_RE = new RegExp(`^https://github\\.com/${REPO_FULL.replace(/[.\-/]/g, (c) => '\\' + c)}/(?:pull|issues|commit|blob|tree|actions/runs)/[A-Za-z0-9._/#=-]{1,200}$`);

/** Only links into the pinned repository; no query strings, no traversal, no other hosts. */
export function allowedEvidenceUrl(u) {
  return typeof u === 'string' && u.length <= 300 && EVIDENCE_RE.test(u) && !u.includes('..') && !u.includes('//', 'https://'.length);
}
