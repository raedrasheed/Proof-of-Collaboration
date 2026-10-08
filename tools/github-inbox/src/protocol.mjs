// Pure protocol logic of the GitHub inbox adapter: which comments are accepted, deterministic
// keys and hidden markers, the guidance text handed to the local broker, the structured result
// note a host acknowledgement may carry, the honest mapping from ACTUAL broker state to the
// remote state, and the public reply text. No I/O here.
import { sha256 } from '../../local-coordinator/src/util.mjs';
import { BODY_MAX, COMMAND_RE, ISSUE_API_URL, ISSUE_HTML_URL, MARKER_HEAD, MARKER_RE, PINNED, REPO_FULL } from './constants.mjs';
import { allowedEvidenceUrl, privateText, publicText } from './sanitize.mjs';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// ---------------------------------------------------------------- keys and markers

/** Broker idempotency key: deterministic from repository, issue and comment ID only. */
export function brokerKey(commentId) {
  return 'gh8-' + sha256(`${REPO_FULL}#${PINNED.issue}#comment:${commentId}`).slice(0, 40);
}

/** Publication key: one per (comment, remote state). */
export function publicationKey(commentId, state) {
  return sha256(`${REPO_FULL}#${PINNED.issue}#comment:${commentId}#state:${state}`).slice(0, 32);
}

export function marker(key) {
  return `${MARKER_HEAD}key=${key} -->`;
}

export function markerKeyOf(body) {
  const m = MARKER_RE.exec(String(body || ''));
  return m ? m[1] : null;
}

export const textDigest = (body) => sha256(String(body ?? ''));

// ---------------------------------------------------------------- accepting comments

/** Parse the explicit command on the FIRST line. Returns { mode, requestId, payload } or { reason }. */
export function parseCommand(body) {
  const text = String(body ?? '').replace(/\r\n/g, '\n');
  const nl = text.indexOf('\n');
  const first = (nl < 0 ? text : text.slice(0, nl)).replace(/[ \t]+$/, '');
  if (!first.startsWith('/pocol')) return { reason: 'notACommand' };
  const m = COMMAND_RE.exec(first);
  if (!m) return { reason: 'malformedCommand' };
  return { mode: m[1], requestId: m[2], payload: nl < 0 ? '' : text.slice(nl + 1).trim() };
}

/**
 * Decide about one GitHub issue comment. Returns { accept: true, mode, requestId, payload } or
 * { accept: false, reason }. Order: shape, thread, own output, bot, actor, size, command.
 */
export function classifyComment(c) {
  if (!c || typeof c !== 'object' || !Number.isSafeInteger(c.id) || c.id <= 0) return { accept: false, reason: 'malformedComment' };
  if (c.issue_url !== ISSUE_API_URL) return { accept: false, reason: 'wrongThread' };
  if (typeof c.html_url !== 'string' || c.html_url !== `${ISSUE_HTML_URL}#issuecomment-${c.id}`) return { accept: false, reason: 'wrongThread' };
  const body = typeof c.body === 'string' ? c.body : null;
  if (body === null) return { accept: false, reason: 'malformedComment' };
  if (body.includes(MARKER_HEAD)) return { accept: false, reason: 'adapterOutput' };
  const u = c.user;
  if (!u || typeof u !== 'object') return { accept: false, reason: 'malformedComment' };
  if (u.type === 'Bot' || /\[bot\]$/i.test(String(u.login || '')) || c.performed_via_github_app) return { accept: false, reason: 'bot' };
  if (u.id !== PINNED.ownerId || u.login !== PINNED.ownerLogin) return { accept: false, reason: 'otherActor' };
  if (body.length > BODY_MAX) return { accept: false, reason: 'tooLong' };
  const cmd = parseCommand(body);
  if (cmd.reason) return { accept: false, reason: cmd.reason };
  return { accept: true, ...cmd };
}

// ---------------------------------------------------------------- broker guidance text

/**
 * The text persisted as ONE broker guidance item. The owner's words are labelled as an untrusted
 * transport payload: not an owner approval, not an answer to an owner question, not a dispatch.
 */
export function guidanceText({ mode, requestId, commentId, payload }) {
  const url = `${ISSUE_HTML_URL}#issuecomment-${commentId}`;
  const lines = [
    'نقل GitHub (العدد #8): حمولة غير موثوقة للعرض والقرار المحلي — ليست موافقة من المالك ولا تشغيل مهمة.',
    'GitHub issue #8 transport. Untrusted payload; not an owner approval, not an answer to an owner question, not a task dispatch.',
    `Request: ${mode} ${requestId}`,
    `Comment: ${url}`,
    `Author: ${PINNED.ownerLogin} (GitHub id ${PINNED.ownerId}), checked by the adapter.`,
  ];
  if (mode === 'status') {
    lines.push('Kind: status request (harmless). Reply by acknowledging this item; to publish a status result use an ack note starting with:',
      'POCOL_GITHUB_RESULT {"mode":"status","state":"completed"|"blocked","summary":"...","evidence":["https://github.com/raedrasheed/Proof-of-Collaboration/..."]}');
  } else {
    lines.push('Kind: guidance. Decide locally under the normal controls. To link real broker work for remote status, ack with a note starting with:',
      'POCOL_GITHUB_RESULT {"mode":"work","jobId":"<broker author job id>"}  or  {"mode":"work","state":"blocked","summary":"..."}');
  }
  lines.push('--- payload (verbatim, untrusted; links are not fetched) ---', payload ? payload : '(empty)');
  return privateText(lines.join('\n'), 7800);
}

// ---------------------------------------------------------------- structured result note

/**
 * Parse an ack note that starts with `POCOL_GITHUB_RESULT {json}` (first line). Returns
 * null (no structured note), { invalid: reason }, or a validated object.
 */
export function parseResultNote(note) {
  if (typeof note !== 'string') return null;
  const first = note.replace(/\r\n/g, '\n').split('\n')[0].trim();
  if (!first.startsWith('POCOL_GITHUB_RESULT ')) return null;
  const raw = first.slice('POCOL_GITHUB_RESULT '.length);
  if (raw.length > 2000) return { invalid: 'tooLong' };
  let j;
  try { j = JSON.parse(raw); } catch { return { invalid: 'json' }; }
  if (!j || typeof j !== 'object' || Array.isArray(j)) return { invalid: 'notAnObject' };
  const summary = j.summary === undefined ? null : j.summary;
  if (summary !== null && (typeof summary !== 'string' || !summary.trim() || summary.length > 600)) return { invalid: 'summary' };
  if (j.mode === 'status') {
    for (const k of Object.keys(j)) if (!['mode', 'state', 'summary', 'evidence'].includes(k)) return { invalid: 'unknownField' };
    if (!['completed', 'blocked'].includes(j.state)) return { invalid: 'state' };
    if (summary === null) return { invalid: 'summary' };
    const evidence = j.evidence === undefined ? [] : j.evidence;
    if (!Array.isArray(evidence) || evidence.length > 5 || !evidence.every(allowedEvidenceUrl)) return { invalid: 'evidence' };
    return { mode: 'status', state: j.state, summary, evidence };
  }
  if (j.mode === 'work') {
    for (const k of Object.keys(j)) if (!['mode', 'jobId', 'state', 'summary'].includes(k)) return { invalid: 'unknownField' };
    if (j.state !== undefined) {
      if (j.state !== 'blocked' || summary === null || j.jobId !== undefined) return { invalid: 'state' };
      return { mode: 'work', state: 'blocked', summary };
    }
    if (typeof j.jobId !== 'string' || !UUID_RE.test(j.jobId)) return { invalid: 'jobId' };
    return { mode: 'work', jobId: j.jobId };
  }
  return { invalid: 'mode' };
}

// ---------------------------------------------------------------- honest state mapping

/**
 * Derive the remote state of one delivered request from the ACTUAL broker view.
 * Returns { state, detail } where state is null (nothing new can be said: item not visible) or one
 * of: 'awaitingLocalAck', 'acknowledged', 'running', 'reviewed', 'completed', 'blocked'.
 * Nothing in the GitHub comment can influence this; only broker records do.
 */
export function deriveState(rec, view) {
  const items = Array.isArray(view?.items) ? view.items : [];
  const item = items.find((i) => i && i.id === rec.brokerItemId);
  if (!item) return { state: null, detail: 'brokerItemNotVisible' };
  if (item.kind !== 'guidance') return { state: null, detail: 'brokerItemKindMismatch' };
  if (['queued', 'claimed'].includes(item.status)) return { state: 'awaitingLocalAck', detail: item.status };
  if (item.status !== 'acknowledged') return { state: null, detail: `brokerItem:${item.status}` };
  const note = parseResultNote(item.ackNote);
  if (rec.mode === 'status') {
    if (note && !note.invalid && note.mode === 'status') return { state: note.state, detail: 'hostResult', summary: note.summary, evidence: note.evidence };
    return { state: 'acknowledged', detail: note?.invalid ? `resultNoteInvalid:${note.invalid}` : 'noStructuredResult' };
  }
  if (!note || note.invalid || note.mode !== 'work') return { state: 'acknowledged', detail: note?.invalid ? `resultNoteInvalid:${note.invalid}` : 'noStructuredResult' };
  if (note.state === 'blocked') return { state: 'blocked', detail: 'hostBlocked', summary: note.summary };
  const job = items.find((i) => i && i.id === note.jobId && i.kind === 'authorJob');
  if (!job) return { state: 'acknowledged', detail: 'linkedJobNotVisible' };
  if (job.reviewId) {
    const reviews = Array.isArray(view.reviews) ? view.reviews : [];
    const rv = reviews.find((r) => r && r.id === job.reviewId && r.jobId === job.id);
    if (!rv) return { state: 'acknowledged', detail: 'reviewNotVisible' };
    if (rv.verdict === 'accept' && job.status === 'reviewed') return { state: 'completed', detail: 'acceptedReview', summary: rv.summaryAr };
    return { state: 'reviewed', detail: `review:${rv.verdict}`, summary: rv.summaryAr };
  }
  if (job.status === 'running') return { state: 'running', detail: 'jobRunning' };
  if (['failed', 'interrupted'].includes(job.status)) return { state: 'blocked', detail: `job:${job.status}`, summary: typeof job.error === 'string' ? job.error : null };
  if (typeof job.blockedReason === 'string' && job.blockedReason) return { state: 'blocked', detail: 'jobBlocked', summary: job.blockedReason };
  return { state: 'acknowledged', detail: `job:${job.status}` };
}

// ---------------------------------------------------------------- LP3 checkpoint (read only)

/** Sanitized summary of the saved LP3 policy blocker, or null. Never acts on it. */
export function lp3Summary(checkpoint) {
  if (!checkpoint || typeof checkpoint !== 'object') return null;
  if (typeof checkpoint.status !== 'string' || !checkpoint.status.startsWith('LP3')) return null;
  const pr = allowedEvidenceUrl(checkpoint.nextPR) ? checkpoint.nextPR : null;
  return {
    status: publicText(checkpoint.status, 80),
    blockedStep: publicText(String(checkpoint.blockedStep ?? ''), 300),
    exactError: publicText(String(checkpoint.exactError ?? ''), 200),
    pr,
  };
}

// ---------------------------------------------------------------- public replies

const LABEL = {
  received: 'Received: persisted in the local broker queue. Awaiting local host acknowledgement.',
  acknowledged: 'Acknowledged by the local host coordinator.',
  running: 'Running: the linked local broker author job is actually running.',
  reviewed: 'Reviewed: the linked broker job has an actual review that did not accept it.',
  completed: 'Completed: the linked broker job has an actual accepted review.',
  blocked: 'Blocked: an actual saved local blocker or error.',
};

/** Public reply for one (request, state). Everything variable is sanitized. */
export function renderReply({ rec, state, derived = {}, lp3 = null }) {
  const lines = [`**PoCol GitHub inbox** - request \`${rec.requestId}\` (${rec.mode}), comment ${rec.commentId}`];
  if (rec.mode === 'status' && (state === 'completed' || state === 'blocked')) {
    lines.push(state === 'completed' ? 'Completed STATUS REQUEST (status only; not a completed milestone).' : 'Status request answered: blocked (as reported by the local host).');
  } else {
    lines.push(LABEL[state] || 'State update.');
  }
  if (derived.summary) lines.push('', `Summary: ${publicText(derived.summary, 600)}`);
  if (Array.isArray(derived.evidence) && derived.evidence.length) lines.push('', 'Evidence: ' + derived.evidence.filter(allowedEvidenceUrl).join(' '));
  if (derived.reason) lines.push('', `Detail: ${publicText(derived.reason, 300)}`);
  if (rec.mode === 'status' && lp3 && state !== 'received') {
    lines.push('', `LP3: ${lp3.status}. Blocked step: ${lp3.blockedStep}. Error: ${lp3.exactError}.${lp3.pr ? ' PR: ' + lp3.pr : ''} (Read from the saved checkpoint; nothing was run.)`);
  }
  lines.push('', '_Transport only: not an owner approval, not a task dispatch. States are read from the actual local broker._', marker(publicationKey(rec.commentId, state)));
  return lines.join('\n');
}
