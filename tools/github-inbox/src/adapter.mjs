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
// by finding the publication's hidden marker on GitHub. A repost happens only after a LATER cycle's
// complete scan (through the last page) shows no marker AND at least RECONCILE_MIN_AGE_MS passed.
//
// 0.41 corrections:
//  * I8-04 a full rescan is a persisted multi-cycle walk (cursor.fullScanPage): each cycle continues
//    where the previous one stopped until the last page is reached; it never restarts at page 1.
//  * I8-05 the broker client is created per cycle and DROPPED after any failure, so the next call
//    re-reads and re-validates connection.json (new port/capability after a coordinator restart);
//    broker idempotency keys are unchanged. A config reload is not a permission or policy change.
//  * I8-06 requests (or linked jobs/reviews) no longer in the coordinator's 100-item view are read
//    through GET /api/github-item, at most MAX_LOOKUPS_PER_CYCLE per cycle, round-robin with the
//    position persisted (lookupCursor), so every open request is eventually resolved.
import { isoNow } from '../../local-coordinator/src/util.mjs';
import { BACKOFF_MAX_S, FINAL_STATES, FULL_RESCAN_EVERY, MAX_DELIVERY_ATTEMPTS, MAX_LOOKUPS_PER_CYCLE, MAX_NEW_PER_CYCLE, MAX_PAGES_PER_CYCLE, MAX_PUBLISH_PER_CYCLE, MAX_TRACKED_COMMENTS, PINNED, RECONCILE_MIN_AGE_MS, STATES } from './constants.mjs';
import { brokerKey, classifyComment, deriveState, guidanceText, lp3Summary, markerKeyOf, publicationKey, renderReply, textDigest } from './protocol.mjs';
import { privateText, publicText } from './sanitize.mjs';

const RANK = Object.fromEntries(STATES.map((s, i) => [s, i]));
RANK.completed = RANK.blocked = 4;

export class Adapter {
  /**
   * deps: { journal, gh, brokerFactory() -> { postGuidance, getState, getItem }, readCheckpoint() -> object|null,
   *         now() -> ms, log(record) }
   */
  constructor({ journal, gh, brokerFactory, readCheckpoint = () => null, now = Date.now, log = () => {} }) {
    Object.assign(this, { journal, gh, brokerFactory, readCheckpoint, now, log });
    this.state = journal.load();
    const c = this.state.cursor;
    if (c.fullScanPage === undefined) c.fullScanPage = null;   // states saved by 0.40
    this.state.lookupCursor ??= 0;
    this.state.cycleSeq ??= 0;
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
    if (rate.retryAfterS !== null && rate.retryAfterS !== undefined) return this._setRateLimit(rate.retryAfterS, reason);
    if (rate.resetAt !== null && rate.resetAt !== undefined && rate.resetAt > now) return this._setRateLimit((rate.resetAt - now) / 1000, reason);
    return this._setRateLimit(60 * 2 ** Math.min(4, this.state.rate.consecutiveFailures), reason);
  }

  /** The cached client, or a new one from a freshly validated connection.json. */
  _getBroker() {
    if (!this.broker) this.broker = this.brokerFactory();
    return this.broker;
  }

  /** Run one broker call; on ANY failure drop the cached client so the next call reloads the connection. */
  async _brokerCall(fn) {
    let b;
    try { b = this._getBroker(); } catch (e) { this.broker = null; throw e; }
    try { return await fn(b); } catch (e) { this.broker = null; throw e; }
  }

  /** Run one cycle. Resolves a sanitized summary (counts and fixed words only). */
  async cycle() {
    const st = this.state;
    const sum = { at: isoNow(this.now()), skipped: null, fetchedPages: 0, comments: 0, newAccepted: 0, newIgnored: 0, backlog: false, fullScan: false,
      delivered: 0, deliveryIssues: [], brokerState: null, lookups: 0, published: 0, reconciled: 0, publishIssues: [], scanComplete: false, error: null };
    this.broker = null;                                   // connection.json is re-read every cycle
    if (st.rate.nextAllowedAt && Date.parse(st.rate.nextAllowedAt) > this.now()) {
      sum.skipped = 'rateLimitBackoff';
      return this._finish(sum);
    }
    st.cycleSeq += 1;
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
    this.state.lastCycle = { at: sum.at, skipped: sum.skipped, error: sum.error, backlog: sum.backlog, scanComplete: sum.scanComplete, fullScan: sum.fullScan };
    this.save();
    this.log({ event: 'cycle', ...sum });
    return sum;
  }

  // ---------------------------------------------------------------- scan (bounded pagination)
  async _scan(sum) {
    const st = this.state, cur = st.cursor;
    if (cur.fullScanPage === null && cur.cyclesSinceFullScan >= FULL_RESCAN_EVERY) cur.fullScanPage = 1;
    const inFull = cur.fullScanPage !== null;
    sum.fullScan = inFull;
    const start = inFull ? cur.fullScanPage : Math.max(1, cur.page - 1);
    const comments = new Map();
    let page = start, complete = false, lastPage = start;
    for (let n = 0; n < MAX_PAGES_PER_CYCLE; n++, page++) {
      const r = await this.gh.listPage(page);
      if (!r.ok) {
        if (r.reason === 'rateLimited') this._rateFrom(r.rate || {}, 'rateLimited');
        else { st.rate.consecutiveFailures += 1; st.rate.lastReason = r.reason; }
        sum.error = `scan:${r.reason}`;
        if (sum.fetchedPages > 0) { if (inFull) cur.fullScanPage = lastPage; }   // keep progress of a partial full scan
        return null;
      }
      sum.fetchedPages += 1;
      lastPage = page;
      for (const c of r.comments || []) if (c && Number.isSafeInteger(c.id) && !comments.has(c.id)) comments.set(c.id, { c, page });
      if (r.rate && r.rate.remaining === 0) this._rateFrom({ retryAfterS: null, resetAt: r.rate.resetAt }, 'quotaExhausted');
      if (!r.next) { complete = true; break; }
    }
    st.rate.consecutiveFailures = 0;
    sum.scanComplete = complete;
    if (!complete) sum.backlog = true;                    // more pages remain: reported, continued next cycle
    if (inFull) {
      if (complete) { cur.fullScanPage = null; cur.cyclesSinceFullScan = 0; cur.page = lastPage; }
      else cur.fullScanPage = lastPage + 1;               // persisted progress: the next cycle continues here
    } else {
      cur.page = complete ? lastPage : lastPage + 1;
      cur.cyclesSinceFullScan += 1;
    }
    const list = [...comments.values()].sort((a, b) => a.c.id - b.c.id);
    sum.comments = list.length;
    // Own publications (marked, by the owner account the gh CLI uses) prove what was posted.
    for (const { c } of list) {
      const key = markerKeyOf(c.body);
      if (key && c.user && c.user.id === PINNED.ownerId) this.state.markers[key] = c.id;
    }
    return { list, complete, inFull, cycle: st.cycleSeq };
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
        // Not dropped: left unrecorded; the cursor moves back to this page for the next cycle.
        sum.backlog = true;
        if (scan.inFull && st.cursor.fullScanPage !== null) st.cursor.fullScanPage = Math.min(st.cursor.fullScanPage, page);
        else if (scan.inFull) { st.cursor.fullScanPage = page; }
        else st.cursor.page = Math.min(st.cursor.page, page);
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
        derived: null, publications: {}, editedAfterSeen: false, lookup: null,
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
    for (const rec of pending) {
      if (rec.attempts >= MAX_DELIVERY_ATTEMPTS) { rec.status = 'deliveryFailed'; rec.lastError = 'attemptsExhausted'; this.save(); continue; }
      let r;
      try {
        r = await this._brokerCall(async (broker) => {
          rec.status = 'delivering'; rec.attempts += 1;
          this.save();
          return broker.postGuidance({ text: guidanceText(rec), idempotencyKey: rec.brokerKey });
        });
      } catch (e) {
        const kind = e?.kind || 'uncertain';
        if (kind === 'refused') { rec.status = 'deliveryRefused'; rec.lastError = publicText(e.message, 200); }
        else rec.lastError = kind;                         // stays accepted/delivering: retried with the same key
        sum.deliveryIssues.push(kind);
        this.save();
        if (kind !== 'refused') return;                    // broker unavailable, stale or uncertain: stop for this cycle
        continue;
      }
      rec.status = 'delivered'; rec.brokerItemId = r.item.id; rec.duplicateAtBroker = r.duplicate; rec.deliveredAt = isoNow(this.now()); rec.lastError = null;
      sum.delivered += 1;
      this.save();
    }
  }

  // ---------------------------------------------------------------- actual broker state
  async _sync(sum) {
    const open = this._recordsInOrder().filter((r) => r.status === 'delivered' && !this._finalPublished(r));
    if (!open.length) return;
    let view;
    try { view = await this._brokerCall((b) => b.getState()); } catch (e) { sum.brokerState = e?.kind || 'unavailable'; return; }
    sum.brokerState = 'read';
    const items = new Map((view.items || []).map((i) => [i.id, i]));
    const reviews = new Map((view.reviews || []).map((r) => [r.id, r]));
    const aug = () => ({ items: [...items.values()], reviews: [...reviews.values()] });
    // Round-robin from the persisted position, so records beyond the per-cycle bound are reached later.
    const start = open.findIndex((r) => r.commentId > this.state.lookupCursor);
    const ordered = start < 0 ? open : open.slice(start).concat(open.slice(0, start));
    let lookups = 0, lookupsStopped = false;
    const lookup = async (rec, id) => {
      if (lookupsStopped || lookups >= MAX_LOOKUPS_PER_CYCLE || !id) return;
      lookups += 1; sum.lookups = (sum.lookups || 0) + 1;
      this.state.lookupCursor = rec.commentId;
      try {
        const r = await this._brokerCall((b) => b.getItem(id));
        items.set(r.item.id, r.item);
        if (r.review) reviews.set(r.review.id, r.review);
        rec.lookup = { at: isoNow(this.now()), id, result: 'found' };
      } catch (e) {
        rec.lookup = { at: isoNow(this.now()), id, result: e?.kind || 'error' };
        if (e?.kind !== 'notFound') lookupsStopped = true;  // broker trouble: stop lookups this cycle
      }
    };
    for (const rec of ordered) {
      let d = deriveState(rec, aug());
      if (d.detail === 'brokerItemNotVisible') { await lookup(rec, rec.brokerItemId); d = deriveState(rec, aug()); }
      if (d.detail === 'linkedJobNotVisible' || d.detail === 'reviewNotVisible') { await lookup(rec, d.jobId); d = deriveState(rec, aug()); }
      if (d.state && d.state !== 'awaitingLocalAck') rec.derived = { state: d.state, detail: d.detail, summary: d.summary ?? null, evidence: d.evidence ?? [] };
      else if (!(rec.derived && rec.derived.state)) rec.derived = null;   // never regress to "nothing"
    }
    if (lookups < MAX_LOOKUPS_PER_CYCLE && !lookupsStopped) this.state.lookupCursor = 0;   // a full pass finished
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

  /** May an uncertain ('posting') publication without a marker be posted again now? Conservative. */
  _mayRepost(pub, scan) {
    if (!scan.complete) return 'awaitingCompleteScan';
    const cycle = Number.isInteger(pub.postingCycle) ? pub.postingCycle : -1;   // 0.40 records: treated as earlier
    if (cycle >= scan.cycle) return 'awaitingLaterScan';
    const at = Date.parse(pub.postingAt || '');
    if (!Number.isFinite(at)) {
      // A 0.40 record has no attempt time: start the age window now rather than reposting at once.
      pub.postingAt = isoNow(this.now());
      this.save();
      return 'awaitingReconcileAge';
    }
    if (this.now() - at < RECONCILE_MIN_AGE_MS) return 'awaitingReconcileAge';
    return null;
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
        if (pub.status === 'posting') {
          const wait = this._mayRepost(pub, scan);
          if (wait) { sum.publishIssues.push(wait); break; }
        }
        if (budget <= 0) { sum.backlog = true; return; }
        if (rec.mode === 'status' && state !== 'received' && lp3 === undefined) {
          try { lp3 = lp3Summary(this.readCheckpoint()); } catch { lp3 = null; }
        }
        const body = renderReply({ rec, state, derived, lp3: lp3 ?? null });
        pub.status = 'posting'; pub.attempts += 1; pub.postingAt = isoNow(this.now()); pub.postingCycle = this.state.cycleSeq;
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
        if (r.reason === 'rateLimited') this._rateFrom(r.rate || {}, 'rateLimited');
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
    fullScanInProgress: state.cursor.fullScanPage !== null && state.cursor.fullScanPage !== undefined,
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
