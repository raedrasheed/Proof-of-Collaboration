// Client for the EXISTING local coordinator control API. Exactly two endpoints are used:
//   POST /api/guidance  (persist one guidance item; the broker deduplicates by idempotencyKey)
//   GET  /api/state     (the sanitized browser view: item status, ack notes, jobs, reviews)
// Never the reviewer API (attach/claim/ack/review), author jobs, retry, pause or resume.
// The connection is read from the private connection.json and accepted only through the
// coordinator's own validator (loopback 127.0.0.1 URL of THIS workspace, 64-hex capabilities).
// Both capabilities are registered with the redactor; only the control capability is kept.
// Requests go to 127.0.0.1:<port> with fixed paths and the exact Host/Origin the server checks;
// there is no external fetch and no fallback.
import http from 'node:http';
import { savedConnection } from '../../local-coordinator/src/server.mjs';
import { registerSecret, redact } from './sanitize.mjs';

export const ALLOWED_PATHS = Object.freeze({ guidance: '/api/guidance', state: '/api/state' });
const RESPONSE_MAX = 8 * 1024 * 1024;

export class BrokerError extends Error {
  constructor(kind, message, status = null) { super(message); this.kind = kind; this.status = status; }
}

/** Load and validate connection.json. Returns { port, controlToken } or throws BrokerError('connection'). */
export function loadConnection(connectionPath, workspaceRoot, { platform = process.platform } = {}) {
  const c = savedConnection(connectionPath, workspaceRoot, { platform });
  if (c.status !== 'valid') throw new BrokerError('connection', `local coordinator connection unavailable (${c.reason})`);
  registerSecret(c.controlToken);
  registerSecret(c.reviewerToken);
  return { port: c.port, controlToken: c.controlToken };
}

export class BrokerClient {
  constructor({ port, controlToken, requestImpl = http.request, timeoutMs = 15_000 }) {
    if (!Number.isInteger(port) || port < 1024 || port > 65535) throw new BrokerError('connection', 'invalid port');
    if (!/^[0-9a-f]{64}$/.test(controlToken || '')) throw new BrokerError('connection', 'invalid control capability');
    registerSecret(controlToken);
    Object.assign(this, { port, controlToken, requestImpl, timeoutMs });
    this.origin = `http://127.0.0.1:${port}`;
  }

  _request(method, pathName, body) {
    if (!Object.values(ALLOWED_PATHS).includes(pathName)) return Promise.reject(new BrokerError('internal', 'path not allowed'));
    const payload = body === undefined ? null : JSON.stringify(body);
    const headers = { Host: `127.0.0.1:${this.port}`, Origin: this.origin, 'X-PoCol-Control': this.controlToken, Accept: 'application/json' };
    if (payload !== null) { headers['Content-Type'] = 'application/json; charset=utf-8'; headers['Content-Length'] = Buffer.byteLength(payload); }
    return new Promise((resolve, reject) => {
      let done = false;
      const fail = (e) => { if (!done) { done = true; reject(e); } };
      let req;
      try {
        req = this.requestImpl({ host: '127.0.0.1', port: this.port, method, path: pathName, headers, timeout: this.timeoutMs, agent: false }, (res) => {
          const chunks = []; let size = 0;
          res.on('data', (c) => { size += c.length; if (size > RESPONSE_MAX) { res.destroy(); fail(new BrokerError('uncertain', 'response too large')); } else chunks.push(c); });
          res.on('end', () => {
            if (done) return;
            let json = null;
            try { json = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { /* not JSON */ }
            if (res.statusCode === 200 && json && typeof json === 'object') { done = true; resolve(json); return; }
            const msg = redact(String(json?.error ?? `HTTP ${res.statusCode}`)).slice(0, 300);
            // 4xx from the broker is a definite refusal (nothing persisted), except 429 (queue full: retry later).
            const kind = res.statusCode === 429 ? 'busy' : res.statusCode >= 400 && res.statusCode < 500 ? 'refused' : 'uncertain';
            fail(new BrokerError(kind, msg, res.statusCode));
          });
          res.on('error', () => fail(new BrokerError('uncertain', 'response error')));
        });
      } catch (e) { fail(new BrokerError('unreachable', 'request could not be created')); return; }
      req.on('timeout', () => { req.destroy(); fail(new BrokerError('uncertain', 'request timed out')); });
      // A connection refused before sending means nothing was delivered; anything later is uncertain.
      req.on('error', (e) => fail(new BrokerError(e?.code === 'ECONNREFUSED' ? 'unreachable' : 'uncertain', `request failed (${e?.code || 'error'})`)));
      if (payload !== null) req.end(payload); else req.end();
    });
  }

  /** Persist one guidance item. Resolves { item, duplicate } as returned by the broker. */
  async postGuidance({ text, idempotencyKey }) {
    const r = await this._request('POST', ALLOWED_PATHS.guidance, { text, idempotencyKey });
    if (!r.item || typeof r.item.id !== 'string' || r.item.idempotencyKey !== idempotencyKey) throw new BrokerError('uncertain', 'unexpected guidance response');
    return { item: r.item, duplicate: Boolean(r.duplicate) };
  }

  /** The sanitized browser view (items, reviews, status). */
  async getState() {
    const v = await this._request('GET', ALLOWED_PATHS.state);
    if (!Array.isArray(v.items) || !Array.isArray(v.reviews)) throw new BrokerError('uncertain', 'unexpected state response');
    return v;
  }
}
