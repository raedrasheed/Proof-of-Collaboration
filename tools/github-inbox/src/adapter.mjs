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
// 0.41: persisted multi-cycle full rescans (I8-04); the broker client is dropped after any failure so
// connection.json is re-read (I8-05); bounded narrow item lookups beyond the 100-item view (I8-06).
//
// 0.42 corrections:
//  * I8-07 delivery outages. Each request carries a bounded outage state (record.delivery): attempts
//    per epoch, per-request backoff, outage start, whether an earlier attempt may have reached the
//    coordinator. After the first-epoch budget the request is 'deliveryStalled' (NOT failed). While
//    stalled, a lightweight authenticated health read (GET /api/state) runs at most every
//    HEALTH_INTERVAL_MS; when it succeeds, each stalled request gets ONE bounded recovery epoch that
//    replays the SAME broker key (no new item, no new IDs). Epochs are capped; after the cap only an
//    explicit operator retry (`--retry-delivery <requestId>`, same IDs) re-enables delivery. A
//    definite refusal (4xx other than 401/403/429) is final and never retried. A request undelivered
//    for OUTAGE_NOTICE_MS gets ONE temporary 'transportBlocked' reply, which says the outcome is
//    unknown; it is never final and never ranks above later received/ack/result replies.
//  * I8-08 backup recovery. When the journal had to fall back to its backup, the backup may predate a
//    saved 'posting' flag, so ANY publication could be a replay. A persisted reconciliation barrier
//    (state.reconcileBarrier) is set before anything else: the issue is walked from page 1 across
//    bounded cycles (progress survives restarts and failures), every marker found reconciles its
//    publication, and NO comment is posted until the walk reached the last page and the barrier is
//    at least RECONCILE_MIN_AGE_MS old (later tail scans settle it). A new backup recovery restarts
//    the walk at page 1.
import { isoNow } from '../../local-coordinator/src/util.mjs';
import {
  BACKOFF_MAX_S, DELIVERY_BACKOFF_BASE_S, DELIVERY_BACKOFF_MAX_S, FINAL_STATES, FULL_RESCAN_EVERY, HEALTH_INTERVAL_MS, MAX_DELIVERY_ATTEMPTS,
  MAX_LOOKUPS_PER_CYCLE, MAX_NEW_PER_CYCLE, MAX_PAGES_PER_CYCLE, MAX_PUBLISH_PER_CYCLE, MAX_RECOVERY_EPOCHS, MAX_TRACKED_COMMENTS, OUTAGE_NOTICE_MS,
  PINNED, RECONCILE_MIN_AGE_MS, RECOVERY_EPOCH_ATTEMPTS, STATES, TEMPORARY_KEYS,
} from './constants.mjs';
import { freshState } from './journal.mjs';
import { brokerKey, classifyComment, deriveState, guidanceText, lp3Summary, markerKeyOf, publicationKey, renderReply, textDigest } from './protocol.mjs';
import { privateText, publicText } from './sanitize.mjs';

/**
 * Operator reset: archive (rename) the journal and start a fresh one that carries a reconciliation
 * barrier, because an empty journal knows no markers and must not repost existing replies.
 */
export function resetJournal(journal, now = Date.now) {
  const st = freshState(now());
  st.reconcileBarrier = { reason: 'operatorReset', since: isoNow(now()), nextPage: 1, phase: 'walk', walkCompletedAt: null };
  return journal.archiveAndReset(st);
}

const RANK = Object.fromEntries(STATES.map((s, i) => [s, i]));
RANK.completed = RANK.blocked = 4;
const UNDELIVERED = ['accepted', 'delivering', 'deliveryStalled', 'deliveryFailed'];

function freshDelivery(attempts = 0) {
  return { epoch: 0, epochAttempts: attempts, nextAttemptAt: null, outageSince: null, lastKind: null, maybeDelivered: false, stalledAt: null };
}

export class Adapter {
  /**
   * deps: { journal, gh, brokerFactory() -> { postGuidance, getState, getItem }, readCheckpoint() -> object|null,
   *         now() -> ms, log(record) }
   */
  constructor({ journal, gh, brokerFactory, readCheckpoint = () => null, now = Date.now, log = () => {} }) {
    Object.assign(this, { journal, gh, brokerFactory, readCheckpoint, now, log });
    this.state = journal.load();
    const st = this.state;
    // Defaults for states saved by 0.40/0.41.
    if (st.cursor.fullScanPage === undefined) st.cursor.fullScanPage = null;
    st.lookupCursor ??= 0;
    st.cycleSeq ??= 0;
    st.health ??= { nextCheckAt: null, lastOkAt: null, lastFailAt: null };
    if (st.reconcileBarrier === undefined) st.reconcileBarrier = null;
    for (const rec of Object.values(st.records)) {
      if (!rec.delivery) rec.delivery = freshDelivery(['accepted', 'delivering'].includes(rec.status) ? rec.attempts || 0 : 0);
      if (rec.status === 'deliveryFailed' && rec.lastError === 'attemptsExhausted') {
        // 0.41 made exhaustion terminal; it is a stall now, recoverable when the coordinator is healthy.
        rec.status = 'deliveryStalled';
        rec.delivery.stalledAt = isoNow(this.now());
        rec.delivery.outageSince ??= rec.delivery.stalledAt;
      }
    }
    this.broker = null;
    if (journal.recoveredFromBackup) {
      // Persisted before anything else: survives the next save and the next restart.
      st.reconcileBarrier = { reason: 'backupRecovery', since: isoNow(this.now()), nextPage: 1, phase: 'walk', walkCompletedAt: null };
      this.save();
    }
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
      barrier: Boolean(st.reconcileBarrier), barrierCleared: false, delivered: 0, deliveryIssues: [], health: null, recoveryEpochs: 0,
      brokerState: null, lookups: 0, published: 0, reconciled: 0, publishIssues: [], scanComplete: false, error: null };
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
    this.state.lastCycle = { at: sum.at, skipped: sum.skipped, error: sum.error, backlog: sum.backlog, scanComplete: sum.scanComplete, fullScan: sum.fullScan, barrier: Boolean(this.state.reconcileBarrier) };
    this.save();
    this.log({ event: 'cycle', ...sum });
    return sum;
  }

  // ---------------------------------------------------------------- scan (bounded pagination)
  async _scan(sum) {
    const st = this.state, cur = st.cursor, bar = st.reconcileBarrier;
    if (!bar && cur.fullScanPage === null && cur.cyclesSinceFullScan >= FULL_RESCAN_EVERY) cur.fullScanPage = 1;
    const inFull = !bar && cur.fullScanPage !== null;
    sum.fullScan = inFull;
    const start = bar ? bar.nextPage : inFull ? cur.fullScanPage : Math.max(1, cur.page - 1);
    const comments = new Map();
    let page = start, complete = false, lastPage = start;
    for (let n = 0; n < MAX_PAGES_PER_CYCLE; n++, page++) {
      const r = await this.gh.listPage(page);
      if (!r.ok) {
        if (r.reason === 'rateLimited') this._rateFrom(r.rate || {}, 'rateLimited');
        else { st.rate.consecutiveFailures += 1; st.rate.lastReason = r.reason; }
        sum.error = `scan:${r.reason}`;
        if (sum.fetchedPages > 0) {                       // keep the progress already made
          if (bar) bar.nextPage = lastPage + 1;
          else if (inFull) cur.fullScanPage = lastPage;
        }
        for (const { c } of comments.values()) this._noteMarker(c);
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
    if (bar) {
      if (!complete) bar.nextPage = lastPage + 1;
      else {
        if (bar.phase === 'walk') { bar.phase = 'settle'; bar.walkCompletedAt = isoNow(this.now()); }
        if (this.now() - Date.parse(bar.since) >= RECONCILE_MIN_AGE_MS) {
          st.reconcileBarrier = null;                     // full coverage after recovery, settled
          sum.barrierCleared = true;
          cur.page = lastPage;
        } else bar.nextPage = Math.max(1, lastPage - 1);  // settle: re-scan the tail in a later cycle
      }
    } else if (inFull) {
      if (complete) { cur.fullScanPage = null; cur.cyclesSinceFullScan = 0; cur.page = lastPage; }
      else cur.fullScanPage = lastPage + 1;               // persisted progress: the next cycle continues here
    } else {
      cur.page = complete ? lastPage : lastPage + 1;
      cur.cyclesSinceFullScan += 1;
    }
    const list = [...comments.values()].sort((a, b) => a.c.id - b.c.id);
    sum.comments = list.length;
    for (const { c } of list) this._noteMarker(c);
    return { list, complete: complete && !st.reconcileBarrier, inFull, inBarrier: Boolean(bar), cycle: st.cycleSeq };
  }

  /** Own publications (marked, by the owner account the gh CLI uses) prove what was posted. */
  _noteMarker(c) {
    const key = markerKeyOf(c.body);
    if (key && c.user && c.user.id === PINNED.ownerId) this.state.markers[key] = c.id;
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
        if (st.reconcileBarrier) st.reconcileBarrier.nextPage = Math.min(st.reconcileBarrier.nextPage, page);
        else if (scan.inFull) st.cursor.fullScanPage = st.cursor.fullScanPage === null ? page : Math.min(st.cursor.fullScanPage, page);
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
        derived: null, publications: {}, editedAfterSeen: false, lookup: null, delivery: freshDelivery(),
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
  _budget(d) { return d.epoch === 0 ? MAX_DELIVERY_ATTEMPTS : RECOVERY_EPOCH_ATTEMPTS; }

  _stall(rec) {
    rec.status = 'deliveryStalled';
    rec.delivery.stalledAt = isoNow(this.now());
    rec.delivery.nextAttemptAt = null;
  }

  /**
   * While requests are stalled: at most one health read per HEALTH_INTERVAL_MS. A successful read is
   * an observed healthy coordinator: each stalled request gets one bounded recovery epoch (same key).
   */
  async _healthRecovery(sum) {
    const st = this.state, now = this.now();
    const stalled = this._recordsInOrder().filter((r) => r.status === 'deliveryStalled');
    if (!stalled.length) return;
    if (st.health.nextCheckAt && Date.parse(st.health.nextCheckAt) > now) return;
    st.health.nextCheckAt = isoNow(now + HEALTH_INTERVAL_MS);
    try {
      await this._brokerCall((b) => b.getState());
      st.health.lastOkAt = isoNow(now);
      sum.health = 'ok';
    } catch (e) {
      st.health.lastFailAt = isoNow(now);
      sum.health = e?.kind || 'unavailable';
      this.save();
      return;
    }
    for (const rec of stalled) {
      const d = rec.delivery;
      if (d.epoch >= MAX_RECOVERY_EPOCHS) { rec.status = 'deliveryFailed'; rec.lastError = 'recoveryEpochsExhausted'; continue; }
      d.epoch += 1; d.epochAttempts = 0; d.nextAttemptAt = null; d.stalledAt = null;
      rec.status = 'delivering';                          // the outcome of earlier attempts stays unknown
      sum.recoveryEpochs += 1;
    }
    this.save();
  }

  async _deliver(sum) {
    await this._healthRecovery(sum);
    const now = this.now();
    const pending = this._recordsInOrder().filter((r) => r.status === 'accepted' || r.status === 'delivering');
    for (const rec of pending) {
      const d = rec.delivery;
      if (d.nextAttemptAt && Date.parse(d.nextAttemptAt) > now) continue;       // per-request backoff
      if (d.epochAttempts >= this._budget(d)) { this._stall(rec); this.save(); continue; }
      let attempted = false, r;
      try {
        r = await this._brokerCall(async (broker) => {
          attempted = true;
          rec.status = 'delivering'; rec.attempts += 1; d.epochAttempts += 1;
          this.save();
          return broker.postGuidance({ text: guidanceText(rec), idempotencyKey: rec.brokerKey });
        });
      } catch (e) {
        const kind = e?.kind || 'uncertain';
        sum.deliveryIssues.push(kind);
        if (kind === 'refused') {                         // definite refusal of this request: final, never retried
          rec.status = 'deliveryRefused'; rec.lastError = publicText(e.message, 200);
          this.save();
          continue;
        }
        rec.lastError = kind;
        d.lastKind = kind;
        d.outageSince ??= isoNow(now);
        if (attempted && kind === 'uncertain') d.maybeDelivered = true;
        if (attempted) {
          if (d.epochAttempts >= 2) d.nextAttemptAt = isoNow(now + Math.min(DELIVERY_BACKOFF_MAX_S, DELIVERY_BACKOFF_BASE_S * 2 ** (d.epochAttempts - 2)) * 1000);
          if (d.epochAttempts >= this._budget(d)) this._stall(rec);
        }
        this.save();
        return;                                           // coordinator unavailable, stale or uncertain: stop for this cycle
      }
      rec.status = 'delivered'; rec.brokerItemId = r.item.id; rec.duplicateAtBroker = r.duplicate; rec.deliveredAt = isoNow(this.now()); rec.lastError = null;
      d.outageSince = null; d.nextAttemptAt = null; d.stalledAt = null; d.lastKind = null;
      this.state.health.lastOkAt = isoNow(this.now());
      sum.delivered += 1;
      this.save();
    }
  }

  /**
   * Explicit operator retry for a stalled or failed request: one more epoch with the SAME broker key,
   * comment ID and request ID. Never creates a new item or request.
   */
  operatorRetry(requestId) {
    const st = this.state;
    const cid = Object.hasOwn(st.requestIds, requestId) ? st.requestIds[requestId] : undefined;
    const rec = cid === undefined ? null : st.records[String(cid)];
    if (!rec) return { ok: false, reason: 'unknownRequest' };
    if (!['deliveryStalled', 'deliveryFailed'].includes(rec.status)) return { ok: false, reason: `notRetryable:${rec.status}` };
    const d = rec.delivery;
    d.epoch += 1; d.epochAttempts = 0; d.nextAttemptAt = null; d.stalledAt = null;
    rec.status = 'delivering';
    rec.operatorRetries = (rec.operatorRetries || 0) + 1;
    this.save();
    return { ok: true, requestId: rec.requestId, comment: rec.commentId, epoch: d.epoch };
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

  /** A FINAL publication exists. Temporary transport notices never count. */
  _finalPublished(rec) {
    return Object.entries(rec.publications).some(([s, p]) => p.status === 'posted' && !TEMPORARY_KEYS.includes(s)
      && (FINAL_STATES.includes(s) || (rec.mode === 'status' && s === 'acknowledged')));
  }

  /**
   * Publications this record should have, in order: { key, state, temporary, derived }. `key` names the
   * publication (marker); `state` is the remote meaning. A temporary transport notice has
   * state 'blocked' but key 'transportBlocked': it is never final and never ranked.
   */
  _desired(rec) {
    if (rec.status === 'deliveryRefused') return [{ key: 'blocked', state: 'blocked', temporary: false, derived: { reason: `the local broker refused the request: ${rec.lastError || 'refused'}` } }];
    if (UNDELIVERED.includes(rec.status)) {
      const d = rec.delivery || {};
      const since = Date.parse(d.outageSince || '');
      const longOutage = Number.isFinite(since) && this.now() - since >= OUTAGE_NOTICE_MS;
      if (longOutage || rec.status === 'deliveryStalled' || rec.status === 'deliveryFailed') {
        return [{ key: 'transportBlocked', state: 'blocked', temporary: true, derived: {} }];
      }
      return [];
    }
    if (rec.status !== 'delivered') return [];
    const out = [{ key: 'received', state: 'received', temporary: false, derived: {} }];
    const d = rec.derived;
    if (d && d.state && d.state !== 'received') out.push({ key: d.state, state: d.state, temporary: false, derived: d });
    return out;
  }

  /** May an uncertain ('posting') publication without a marker be posted again now? Conservative. */
  _mayRepost(pub, scan) {
    if (!scan.complete) return 'awaitingCompleteScan';
    const cycle = Number.isInteger(pub.postingCycle) ? pub.postingCycle : -1;   // 0.40 records: treated as earlier
    if (cycle >= scan.cycle) return 'awaitingLaterScan';
    const at = Date.parse(pub.postingAt || '');
    if (!Number.isFinite(at)) {
      // A record without an attempt time: start the age window now rather than reposting at once.
      pub.postingAt = isoNow(this.now());
      this.save();
      return 'awaitingReconcileAge';
    }
    if (this.now() - at < RECONCILE_MIN_AGE_MS) return 'awaitingReconcileAge';
    return null;
  }

  // ---------------------------------------------------------------- publication (marked, reconciled)
  async _publish(scan, sum) {
    if (this.state.reconcileBarrier) { sum.publishIssues.push('reconcileBarrier'); return; }   // I8-08: no POST before full coverage
    let budget = MAX_PUBLISH_PER_CYCLE;
    let lp3 = undefined;
    for (const rec of this._recordsInOrder()) {
      for (const { key, temporary, derived } of this._desired(rec)) {
        const posted = Object.entries(rec.publications).filter(([, p]) => p.status === 'posted').map(([s]) => s);
        if (posted.includes(key)) continue;
        if (this._finalPublished(rec)) break;
        if (!temporary) {
          const ranked = posted.filter((s) => !TEMPORARY_KEYS.includes(s) && Object.hasOwn(RANK, s));
          const maxRank = Math.max(-1, ...ranked.map((s) => RANK[s]));
          if (RANK[key] <= maxRank) continue;              // never publish an earlier state after a later one
        }
        const pub = rec.publications[key] ??= { status: 'pending', key: publicationKey(rec.commentId, key), commentId: null, attempts: 0 };
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
        if (rec.mode === 'status' && key !== 'received' && !temporary && lp3 === undefined) {
          try { lp3 = lp3Summary(this.readCheckpoint()); } catch { lp3 = null; }
        }
        const body = renderReply({ rec, state: key, derived, lp3: lp3 ?? null });
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
  const bar = state.reconcileBarrier;
  return {
    adapter: 'pocol-github-inbox',
    scope: { repository: `${PINNED.owner}/${PINNED.repo}`, issue: PINNED.issue, ownerLogin: PINNED.ownerLogin },
    connectionVerified: Boolean(activation?.connectionVerified),
    activationNote: activation?.connectionVerified ? 'recorded by root' : 'NOT ACTIVE: no root-recorded end-to-end evidence',
    lastCycle: state.lastCycle,
    nextAllowedAt: state.rate.nextAllowedAt,
    fullScanInProgress: state.cursor.fullScanPage !== null && state.cursor.fullScanPage !== undefined,
    reconcileBarrier: bar ? { reason: bar.reason, phase: bar.phase, nextPage: bar.nextPage, since: bar.since } : null,
    health: state.health ? { lastOkAt: state.health.lastOkAt, lastFailAt: state.health.lastFailAt } : null,
    deliveries: counts,
    ignored,
    requests: recs.slice(-50).map((r) => ({
      requestId: r.requestId, mode: r.mode, comment: r.commentId, delivery: r.status,
      deliveryEpoch: r.delivery?.epoch ?? 0, epochAttempts: r.delivery?.epochAttempts ?? 0, outageSince: r.delivery?.outageSince ?? null,
      remoteState: r.derived?.state ?? (r.status === 'delivered' ? 'awaitingLocalAck' : null),
      published: Object.entries(r.publications).filter(([, p]) => p.status === 'posted').map(([s]) => s),
      editedAfterSeen: r.editedAfterSeen,
    })),
  };
}
