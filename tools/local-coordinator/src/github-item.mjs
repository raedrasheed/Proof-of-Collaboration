// Narrow, read-only projection of ONE broker item for the GitHub issue #8 transport adapter
// (tools/github-inbox). Served as GET /api/github-item?itemId=<UUID> behind the SAME browser
// control checks as /api/state (exact Host, Origin if present, Sec-Fetch-Site, X-PoCol-Control).
//
// Why: the browser view (/api/state) keeps its existing limit of the last 100 items and 50 reviews.
// A transport request acknowledged long ago must still be resolvable, so the adapter may look up a
// single item by ID. The response is an allowlist:
//   item:   { id, kind, status, idempotencyKey, ackNote, reviewId, error, blockedReason }
//   review: { id, jobId, verdict, summaryAr } only for the review the item itself references AND
//           whose jobId is that item; otherwise null.
// Never returned: payloads, dispatch plans, session IDs, receipts, review texts, notifications,
// capabilities, thread IDs or paths. Strings are bounded and redacted. Read-only: it grants no write,
// approval, author, pause or resume capability, and it reads the controller's in-memory state (not
// the state file on disk).
import { BrokerError } from './broker.mjs';
import { redactDeep } from './redact.mjs';
import { bound } from './util.mjs';

export const ITEM_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const WORD_RE = /^[A-Za-z]{1,40}$/;
const KEY_RE = /^[A-Za-z0-9_-]{8,100}$/;

const text = (v, max) => (typeof v === 'string' ? bound(v, max) : null);
const word = (v) => (typeof v === 'string' && WORD_RE.test(v) ? v : null);
const id = (v) => (typeof v === 'string' && ITEM_ID_RE.test(v) ? v : null);

/** Validate the query of GET /api/github-item: exactly one parameter, itemId, a UUID. */
export function parseItemQuery(searchParams) {
  const keys = [...searchParams.keys()];
  if (keys.length !== 1 || keys[0] !== 'itemId') throw new BrokerError(400, 'المطلوب معامل واحد فقط: itemId.');
  const itemId = searchParams.get('itemId');
  if (!ITEM_ID_RE.test(itemId || '')) throw new BrokerError(400, 'معرف العنصر يجب أن يكون UUID.');
  return itemId;
}

/** The allowlisted projection, or null when the item does not exist. */
export function githubItemView(state, itemId) {
  const items = state && state.items && typeof state.items === 'object' ? state.items : {};
  const i = Object.hasOwn(items, itemId) ? items[itemId] : undefined;
  if (!i || typeof i !== 'object') return null;
  const item = {
    id: id(i.id),
    kind: word(i.kind),
    status: word(i.status),
    idempotencyKey: typeof i.idempotencyKey === 'string' && KEY_RE.test(i.idempotencyKey) ? i.idempotencyKey : null,
    ackNote: text(i.ackNote, 2000),
    reviewId: id(i.reviewId),
    error: text(i.error, 2000),
    blockedReason: text(i.blockedReason, 1000),
  };
  let review = null;
  if (item.reviewId && Array.isArray(state.reviews)) {
    const r = state.reviews.find((x) => x && x.id === item.reviewId && x.jobId === i.id);
    if (r) review = { id: id(r.id), jobId: id(r.jobId), verdict: word(r.verdict), summaryAr: text(r.summaryAr, 2000) };
  }
  return redactDeep({ item, review });
}
