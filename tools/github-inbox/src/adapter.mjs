// One adapter cycle: read the pinned issue's comments (bounded pages), accept explicit owner
// commands, persist them, deliver each as ONE local broker guidance item (idempotent key), read the
// actual broker state, and publish deterministic, marked replies on the issue.
//
// Delivery is not execution: the adapter never acknowledges, claims, reviews, dispatches, pauses or
// resumes anything. Remote "received" is published only after the broker returned the persisted
// item; later states come only from actual broker records (see protocol.deriveState).
//
// Crash safety: every outward action is bracketed by saves. A delivery is saved as 'delivering'
// before the POST; replaying it reuses the same broker idempotency key, so the broker returns the
// same item. A publication is saved as 'posting' before gh runs; an uncertain outcome is reconciled
// by finding the publication's hidden marker on GitHub (complete scan required) before any repost.
import { isoNow } from '../../local-coordinator/src/util.mjs';
import { BACKOFF_MAX_S, FINAL_STATES, FULL_RESCAN_EVERY, MAX_DELIVERY_ATTEMPTS, MAX_NEW_PER_CYCLE, MAX_PAGES_PER_CYCLE, MAX_PUBLISH_PER_CYCLE, MAX_TRACKED_COMMENTS, PINNED, STATES } from './constants.mjs';
import { brokerKey, classifyComment, deriveState, guidanceText, lp3Summary, markerKeyOf, publicationKey, renderReply, textDigest } from './protocol.mjs';
import { privateText, publicText } from './sanitize.mjs';

const RANK = Object.fromEntries(STATES.map((s, i) => [s, i]));
RANK.completed = RANK.blocked = 4;

export class Adapter {
  /**
   * deps: { journal, gh, brokerFactory() -> { postGuidance, getState }, readCheckpoint() -> object|null,
   *         now() -> ms, log(record) }
   */
  constructor({ journal, gh, brokerFactory, readCheckpoint = () => null, now = Date.now, log = () => {} }) {
    Object.assign(this, { journal, gh, brokerFactory, readCheckpoint, now, log });
    this.state = journal.load();
    this.broker = null;
  }

  save() { this.journal.save(this.state); }

  _setRateLimit(seconds, reason) {
    const s = Math.min(BACKOFF_MAX_S, Math.max(1, Math.ceil(Number.isFinite(seconds) ? seconds : BACKOFF_MAX_S)));
    this.state.rate.nextAllowedAt = isoNow(this.now() + s * 1000);
    this.state.rate.lastReason = reason;
  }

  _rateFrom(rate, reason) {
    const now = this.now();
    if (rate.retryAfterS !== null) return this._setRateLimit(rate.retryAfterS, reason);
    if (rate.resetAt !== null && rate.resetAt > now) return this._setRateLimit((rate.resetAt - now) / 1000, reason);
    return this._setRateLimit(60 * 2 ** Math.min(4, this.state.rate.consecutiveFailures), reason);
  }

  _getBroker() {
    if (!this.broker) this.broker = this.brokerFactory();
    return this.broker;
  }

  /** Run one cycle. Resolves a sanitized summary (counts and fixed words only). */
  async cycle() {
    const st = this.state;
    const sum = { at: isoNow(this.now()), skipped: null, fetchedPages: 0, comments: 0, newAccepted: 0, newIgnored: 0, backlog: false,
      delivered: 0, deliveryIssues: [], brokerState: null, published: 0, reconciled: 0, publishIssues: [], scanComplete: false, error: null };
    this.broker = null;                                   // connection.json is re-read every cycle
    if (st.rate.nextAllowedAt && Date.parse(st.rate.nextAllowedAt) > this.now()) {
      sum.skipped = 'rateLimitBackoff';
      return this._finish(sum);
    }
    const scan = await this._scan(sum);
    if (!scan) return this._finish(sum);
    this._classify(scan, sum);
    this.save();
    await this._deliver(sum);
    await this._sync(sum);
    await this._publish(scan, sum);
    return this._finish(sum);
  }

  _finish(sum) {
    this.state.lastCycle = { at: sum.at, skipped: sum.skipped, error: sum.error, backlog: sum.backlog, scanComplete: sum.scanComplete };
    this.save();
    this.log({ event: 'cycle', ...sum });
    return sum;
  }

  // ---------------------------------------------------------------- scan (bounded pagination)
  async _scan(sum) {
    const st = this.state;
    const full = st.cursor.cyclesSinceFullScan >= FULL_RESCAN_EVERY;
    const start = full ? 1 : Math.max(1, st.cursor.page - 1);
    const comments = new Map();
    let page = start, complete = false, lastPage = start;
    for (let n = 0; n < MAX_PAGES_PER_CYCLE; n++, page++) {
      const r = await this.gh.listPage(page);
      if (!r.ok) {
        if (r.reason === 'rateLimited') this._rateFrom(r.rate, 'rateLimited');
        else { st.rate.consecutiveFailures += 1; st.rate.lastReason = r.reason; }
        sum.error = `scan:${r.reason}`;
        return null;
      }
      sum.fetchedPages += 1;
      lastPage = page;
      for (const c of r.comments) if (c && Number.isSafeInteger(c.id) && !comments.has(c.id)) comments.set(c.id, { c, page });
      if (r.rate.remaining === 0) this._rateFrom({ retryAfterS: null, resetAt: r.rate.resetAt }, 'quotaExhausted');
      if (!r.next) { complete = true; break; }
    }
    st.rate.consecutiveFailures = 0;
    sum.scanComplete = complete;
    if (!complete) sum.backlog = true;                    // more pages remain: reported, continued next cycle
    st.cursor.page = complete ? lastPage : lastPage + 1;
    st.cursor.cyclesSinceFullScan = full && complete ? 0 : st.cursor.cyclesSinceFullScan + 1;
    const list = [...comments.values()].sort((a, b) => a.c.id - b.c.id);
    sum.comments = list.length;
    // Own publications (marked, by the owner account the gh CLI uses) prove what was posted.
    for (const { c } of list) {
      const key = markerKeyOf(c.body);
      if (key && c.user && c.user.id === PINNED.ownerId) this.state.markers[key] = c.id;
    }
    return { list, complete };
  }

  // ---------------------------------------------------------------- accept / ignore
  _classify(scan, sum) {
    const st = this.state;
    let accepted = 0;
    for (const { c, page } of scan.list) {
      const id = String(c.id);
      const rec = st.records[id];
      if (rec) {
        if (rec.digest !== textDigest(c.body) && !rec.editedAfterSeen) rec.editedAfterSeen = true;   // edits never re-trigger
        continue;
      }
      if (st.ignored[id]) continue;
      if (Object.keys(st.records).length + Object.keys(st.ignored).length >= MAX_TRACKED_COMMENTS) { sum.error = 'stateFull'; sum.backlog = true; break; }
      const cls = classifyComment(c);
      if (!cls.accept) { st.ignored[id] = { reason: cls.reason, at: sum.at }; sum.newIgnored += 1; continue; }
      if (accepted >= MAX_NEW_PER_CYCLE) {
        // Not dropped: left unrecorded, the cursor moves back to this page for the next cycle.
        sum.backlog = true;
        st.cursor.page = Math.min(st.cursor.page, page);
        break;
      }
      if (Object.hasOwn(st.requestIds, cls.requestId)) {
        // Deterministic contract: the earliest accepted comment owns a request ID; later ones are ignored.
        st.ignored[id] = { reason: 'duplicateRequestId', requestId: cls.requestId, firstComment: st.requestIds[cls.requestId], at: sum.at };
        sum.newIgnored += 1;
        continue;
      }
      st.records[id] = {
        commentId: c.id, requestId: cls.requestId, mode: cls.mode, digest: textDigest(c.body),
        payload: privateText(cls.payload, 4000), brokerKey: brokerKey(c.id), status: 'accepted', attempts: 0,
        acceptedAt: sum.at, deliveredAt: null, brokerItemId: null, duplicateAtBroker: null, lastError: null,
        derived: null, publications: {}, editedAfterSeen: false,
      };
      st.requestIds[cls.requestId] = c.id;
      accepted += 1;
      sum.newAccepted += 1;
    }
  }

  _recordsInOrder() {
    return Object.values(this.state.records).sort((a, b) => a.commentId - b.commentId);
  }

  // ---------------------------------------------------------------- delivery (no execution)
  async _deliver(sum) {
    const pending = this._recordsInOrder().filter((r) => r.status === 'accepted' || r.status === 'delivering');
    if (!pending.length) return;
    let broker;
    try { broker = this._getBroker(); } catch (e) { sum.deliveryIssues.push(e?.kind || 'connection'); return; }
    for (const rec of pending) {
      if (rec.attempts >= MAX_DELIVERY_ATTEMPTS) { rec.status = 'deliveryFailed'; rec.lastError = 'attemptsExhausted'; this.save(); continue; }
      rec.status = 'delivering'; rec.attempts += 1;
      this.save();
      try {
        const r = await broker.postGuidance({ text: guidanceText(rec), idempotencyKey: rec.brokerKey });
        rec.status = 'delivered'; rec.brokerItemId = r.item.id; rec.duplicateAtBroker = r.duplicate; rec.deliveredAt = isoNow(this.now()); rec.lastError = null;
        sum.delivered += 1;
        this.save();
      } catch (e) {
        const kind = e?.kind || 'uncertain';
        if (kind === 'refused') { rec.status = 'deliveryRefused'; rec.lastError = publicText(e.message, 200); }
        else rec.lastError = kind;                         // stays 'delivering': retried with the same key
        sum.deliveryIssues.push(kind);
        this.save();
        if (kind !== 'refused') return;                    // broker unavailable or uncertain: stop for this cycle
      }
    }
  }

  // ---------------------------------------------------------------- actual broker state
  async _sync(sum) {
    const open = this._recordsInOrder().filter((r) => r.status === 'delivered' && !this._finalPublished(r));
    if (!open.length) return;
    let view;
    try { view = await this._getBroker().getState(); } catch (e) { sum.brokerState = e?.kind || 'unavailable'; return; }
    sum.brokerState = 'read';
    for (const rec of open) {
      const d = deriveState(rec, view);
      if (d.state && d.state !== 'awaitingLocalAck') rec.derived = { state: d.state, detail: d.detail, summary: d.summary ?? null, evidence: d.evidence ?? [] };
      else rec.derived = rec.derived && rec.derived.state ? rec.derived : null;   // never regress to "nothing"
    }
    this.save();
  }

  _finalPublished(rec) {
    return Object.entries(rec.publications).some(([s, p]) => p.status === 'posted' && (FINAL_STATES.includes(s) || (rec.mode === 'status' && s === 'acknowledged')));
  }

  /** States this record should have published, in order. */
  _desired(rec) {
    if (rec.status === 'deliveryRefused') return [{ state: 'blocked', derived: { reason: `the local broker refused the request: ${rec.lastError || 'refused'}` } }];
    if (rec.status !== 'delivered') return [];
    const out = [{ state: 'received', derived: {} }];
    const d = rec.derived;
    if (d && d.state && d.state !== 'received') out.push({ state: d.state, derived: d });
    return out;
  }

  // ---------------------------------------------------------------- publication (marked, reconciled)
  async _publish(scan, sum) {
    let budget = MAX_PUBLISH_PER_CYCLE;
    let lp3 = undefined;
    for (const rec of this._recordsInOrder()) {
      for (const { state, derived } of this._desired(rec)) {
        const posted = Object.entries(rec.publications).filter(([, p]) => p.status === 'posted').map(([s]) => s);
        if (posted.includes(state)) continue;
        if (this._finalPublished(rec)) break;
        const maxRank = Math.max(-1, ...posted.map((s) => RANK[s]));
        if (RANK[state] <= maxRank) continue;              // never publish an earlier state after a later one
        const pub = rec.publications[state] ??= { status: 'pending', key: publicationKey(rec.commentId, state), commentId: null, attempts: 0 };
        if (Object.hasOwn(this.state.markers, pub.key)) {
          pub.status = 'posted'; pub.commentId = this.state.markers[pub.key]; pub.reconciled = true;
          sum.reconciled += 1; this.save();
          continue;
        }
        if (pub.status === 'posting' && !scan.complete) { sum.publishIssues.push('uncertainNeedsCompleteScan'); break; }
        if (budget <= 0) { sum.backlog = true; return; }
        if (rec.mode === 'status' && state !== 'received' && lp3 === undefined) {
          try { lp3 = lp3Summary(this.readCheckpoint()); } catch { lp3 = null; }
        }
        const body = renderReply({ rec, state, derived, lp3: lp3 ?? null });
        pub.status = 'posting'; pub.attempts += 1;
        this.save();
        budget -= 1;
        const r = await this.gh.postComment(body);
        if (r.ok) {
          pub.status = 'posted'; pub.commentId = r.comment.id; this.state.markers[pub.key] = r.comment.id;
          sum.published += 1; this.save();
          continue;
        }
        if (!r.uncertain) pub.status = 'pending';          // definitely not posted
        sum.publishIssues.push(r.reason || 'failed');
        if (r.reason === 'rateLimited') this._rateFrom(r.rate || { retryAfterS: null, resetAt: null }, 'rateLimited');
        this.save();
        if (r.reason === 'rateLimited') return;
        break;                                             // keep per-request order: later states wait
      }
    }
  }
}

/** Sanitized public status: counts, request IDs and states only. No paths, tokens or local IDs. */
export function publicStatus(state, activation) {
  const recs = Object.values(state.records).sort((a, b) => a.commentId - b.commentId);
  const counts = {};
  for (const r of recs) counts[r.status] = (counts[r.status] || 0) + 1;
  const ignored = {};
  for (const v of Object.values(state.ignored)) ignored[v.reason] = (ignored[v.reason] || 0) + 1;
  return {
    adapter: 'pocol-github-inbox',
    scope: { repository: `${PINNED.owner}/${PINNED.repo}`, issue: PINNED.issue, ownerLogin: PINNED.ownerLogin },
    connectionVerified: Boolean(activation?.connectionVerified),
    activationNote: activation?.connectionVerified ? 'recorded by root' : 'NOT ACTIVE: no root-recorded end-to-end evidence',
    lastCycle: state.lastCycle,
    nextAllowedAt: state.rate.nextAllowedAt,
    deliveries: counts,
    ignored,
    requests: recs.slice(-50).map((r) => ({
      requestId: r.requestId, mode: r.mode, comment: r.commentId, delivery: r.status,
      remoteState: r.derived?.state ?? (r.status === 'delivered' ? 'awaitingLocalAck' : null),
      published: Object.entries(r.publications).filter(([, p]) => p.status === 'posted').map(([s]) => s),
      editedAfterSeen: r.editedAfterSeen,
    })),
  };
}
