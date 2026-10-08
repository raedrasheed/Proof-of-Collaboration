# PoCol GitHub inbox adapter (issue #8 transport)

**Status: NOT ACTIVE.** This is a separate transport task. It is not LP3, and it does not retry or
bypass the blocked LP3 author dispatch (task 037).

The author has executed nothing for revision 0.42: no unit tests, no HTTP tests, no live connection,
and no comment delivered. `connectionVerified` stays `false` until root records real end-to-end
evidence (see "Activation").

## What it does

An outbound-only polling adapter (Node 22, standard library only) between one GitHub issue and the
existing local coordinator. It is a small poller, not an agent loop.

**Scope:** it is pinned to `raedrasheed/Proof-of-Collaboration`, issue **#8**, owner login
`raedrasheed`, owner ID **36733882**.

**GitHub calls:** every `gh` call carries `--hostname github.com`, and `GH_HOST`/`GH_REPO` are removed
from the child environment.

**Accepted comments:** only those where all of the following hold:

- the user is of type `User`, with the pinned id and login;
- the comment is in issue #8;
- the comment does not contain the adapter's own marker;
- the body is at most 4000 characters;
- the first line is exactly `/pocol status <request-id>` or `/pocol guidance <request-id>`.

App attribution (`performed_via_github_app`) does not refuse the pinned user. Bots, organizations and
other actors are refused.

**Delivery:** each accepted comment becomes one coordinator guidance item (`POST /api/guidance`). It is
labelled as an untrusted transport payload: not an owner approval, not an answer to an owner question,
not a dispatch.

**Publication:** replies are published from actual coordinator records only, each with a
deterministic hidden marker.

**Never:** the adapter never uses the reviewer API, never requests author jobs, retries, pauses or
resumes, never acknowledges anything, never dispatches an agent, never runs any process other than
`gh`, and never touches the LP3 blocker.

## Revision history of corrections

**0.41 (I8-01 to I8-06):**

| Finding | Correction |
|---|---|
| I8-01 | The `gh` timeout always settles. |
| I8-02 | Precise process-boundary checks, with control cases. |
| I8-03 | Streaming UTF-8 decoding with a byte cap. |
| I8-04 | Full rescans continue across cycles. |
| I8-05 | `connection.json` is reloaded after any coordinator failure, with the same keys. |
| I8-06 | The narrow `GET /api/github-item` lookup for items beyond the 100-item view. |

**0.42:**

| Finding | Correction |
|---|---|
| I8-07 | Delivery outages: see "Delivery outages" below. |
| I8-08 | Journal backup recovery: see "Backup recovery" below. |

## Delivery outages (I8-07)

**Outage state:** every request carries a bounded, persisted outage state:

- delivery epoch;
- attempts in the epoch;
- per-request backoff;
- outage start;
- whether an earlier attempt may already have reached the coordinator.

**First epoch:** up to 20 attempts. Backoff starts at the second consecutive failure (30 s, doubling,
capped at 300 s), so a single failure is retried on the next cycle. A short outage therefore recovers
automatically and publishes nothing extra.

**Stall:** after the first-epoch budget the request becomes **`deliveryStalled`, not failed**. While
any request is stalled, the adapter reads `GET /api/state` (an authenticated, supported, read-only
call) at most every 5 minutes. When that read succeeds, each stalled request gets one recovery epoch
of 5 attempts, replaying the **same broker key, comment ID and request ID**. The coordinator's
deduplication returns the existing item if an earlier attempt had in fact been persisted. Nothing new
is created locally, and no author is started.

**Bounds:** at most 5 recovery epochs per request. After that the request is `deliveryFailed`, and only
an explicit operator retry re-enables it:

```
node tools\github-inbox\src\cli.mjs --config <config> --retry-delivery <request-id>
```

That command uses the same IDs and adds one epoch. The next cycle delivers.

**Definite refusal:** a 4xx other than 401/403/429 is final. It is published once as `blocked`, and is
never retried and never revived by a health read. A 401/403 means a stale capability: the connection
is reloaded and the request retried.

**Temporary transport notice:** a request not delivered for 10 minutes, or stalled, gets **one**
`transportBlocked` reply. It says the coordinator could not be reached or has not confirmed the
request, and that it is **not known** whether the request already arrived. It concludes nothing about
delivery, authors or work, and says delivery is retried with the same request.

That notice is temporary. It is never final and never ranked, so it never suppresses the later
`received`, `acknowledged`, status-result or work replies. An actual `blocked` (a work or status
blocker, or a definite refusal) remains final, and transport recovery never clears it.

## Backup recovery (I8-08)

**Why a barrier is needed:** the journal's backup is one save older than its main file, so it can
predate a saved `posting` flag. Any publication restored from it could be a replay.

**What the barrier does:** whenever the journal falls back to the backup (`Journal.recoveredFromBackup`),
the adapter immediately persists `state.reconcileBarrier`. While it is present:

- the issue is walked from **page 1**, up to 10 pages per cycle;
- progress (`nextPage`) is saved, so it survives restarts, rate limits and other interruptions;
- every marker found reconciles its publication to `posted`;
- **no comment is posted at all.**

**Clearing it:** the barrier clears only when the walk has reached the last page **and** the barrier is
at least 120 s old. Until then, settling scans re-read the tail. After that, publications whose
markers exist are reconciled without a POST, and genuinely absent ones are posted once. The existing
uncertainty rules (marker reconciliation, a later complete scan, the 120 s age) still apply.

A second backup recovery restarts the walk at page 1.

**No deletion:** the corrupt main file is kept as `inbox-journal.json.corrupt-<time>` and the good
backup is left in place. Nothing is deleted.

## Coordinator read API (unchanged in 0.42)

`GET /api/github-item?itemId=<UUID>`, added in 0.41:

- the same control checks as `/api/state`;
- returns the item allowlist `{ id, kind, status, idempotencyKey, ackNote, reviewId, error, blockedReason }`, plus only the item's own review `{ id, jobId, verdict, summaryAr }`;
- read-only, and grants nothing.

## Remote states (only from actual coordinator records)

| Publication | Meaning |
|---|---|
| `received` | POST guidance returned the persisted item |
| `acknowledged` | actual host ack |
| `completed` / `blocked` (status) | host ack note `POCOL_GITHUB_RESULT {"mode":"status",...}`; "Completed STATUS REQUEST", never a milestone |
| `running` / `reviewed` / `completed` / `blocked` (work) | linked actual job and review records only |
| `blocked` (refusal) | definite coordinator refusal; final |
| `transportBlocked` | temporary transport notice; not final, not ranked, outcome unknown |

## Limits

| Limit | Value |
|---|---|
| Pages per cycle | 10 |
| New requests per cycle | 20 |
| Publications per cycle | 10 |
| Item lookups per cycle | 10 |
| First delivery epoch | 20 attempts |
| Recovery epochs | 5, with 5 attempts each |
| Delivery backoff | 30 s doubling, capped at 300 s |
| Health reads while stalled | at most every 5 min |
| Transport notice | after 10 min undelivered or when stalled; once per request |
| Body | 4000 characters |
| `gh` stdout | 4 MiB (bytes) |
| `gh` timeout | 30 s |
| Rate-limit wait | capped at 900 s |
| Poll interval | at least 30 s (default 60 s); failures back off, capped at 900 s |
| Full rescan | every 30 cycles, continued across cycles |
| Uncertain repost | only after a later complete scan and 120 s |
| Recovery barrier | full walk from page 1, then at least 120 s settling |

## Local procedures (root)

All paths are relative to `D:\PoCol-Development`. The config is
`coordination\ui-control\github-inbox\config.json`.

**Tests**

From `tools\github-inbox`:

```
node --test test/protocol.test.mjs test/sanitize.test.mjs test/gh.test.mjs test/broker-client.test.mjs test/journal.test.mjs test/adapter.test.mjs test/boundaries.test.mjs test/outage.test.mjs test/backup-recovery.test.mjs
```

From `tools\local-coordinator` (unchanged in 0.42):

```
node --test test/broker.test.mjs test/history.test.mjs test/server.test.mjs test/worker.test.mjs test/notifier.test.mjs test/continuation.test.mjs test/connection.test.mjs test/github-item.test.mjs
```

**Adapter commands**

| Action | Command |
|---|---|
| Status (no network, no lease) | `node tools\github-inbox\src\cli.mjs --config <config> --status` |
| One cycle | `node tools\github-inbox\src\cli.mjs --config <config> --once` |
| Polling | `node tools\github-inbox\src\cli.mjs --config <config> --poll` |
| Stop polling | Ctrl+C in the adapter's own window. This never touches the coordinator. |
| Operator retry of a stalled or failed request (same IDs) | `node tools\github-inbox\src\cli.mjs --config <config> --retry-delivery <request-id>` |
| Reset | `node tools\github-inbox\src\cli.mjs --config <config> --reset-journal` |

**Reset** (stop the adapter first): `--reset-journal` renames the journal files to dated `.reset-<time>`
evidence names (never deletes them) and starts a fresh journal with a reconciliation barrier. Existing
replies are then reconciled from their markers, not reposted, and coordinator items are found again by
their keys.

**Coordinator update (only after review and tests):** stop it with Ctrl+C in its window, then start the
reviewed source in the same workspace with no `--fresh-connection`. It reuses the saved connection,
state and single-service lock. Pause, policy, LP3 and the single-writer rule are untouched.

**Activation (root only, after all tests pass)**

1. The owner posts a harmless `/pocol status <id>` on issue #8.
2. `received` appears on the issue.
3. The host acknowledges the item normally, with a `POCOL_GITHUB_RESULT` status note.
4. The status reply appears.
5. A duplicate of the request is ignored.
6. After restarting the adapter, nothing is delivered or published twice.

Then write `coordination\ui-control\github-inbox\activation.json` by hand:

```json
{ "connectionVerified": true, "recordedBy": "root", "recordedAt": "<ISO time>",
  "evidence": { "roundtripCommentUrl": "<issue comment URL>", "duplicateCheck": "passed", "restartCheck": "passed" } }
```

Test counts and mocks are not activation evidence.

---

## إعداد سريع (عربي)

**الحالة: غير مفعّل.** هذه مهمة نقل منفصلة عن LP3 المحجوب. لم يشغّل المؤلف أي اختبار أو اتصال.

**تصحيحات 0.42:**

- **I8-07 — انقطاع التسليم:**
  - لكل طلب حالة انقطاع محدودة ومحفوظة: 20 محاولة أولى بتأخير متزايد، ثم حالة «متوقف مؤقتًا» لا «فاشل».
  - تُقرأ صحة المنسق كل 5 دقائق على الأكثر. عند نجاح القراءة تُفتح جولة استرداد محدودة تعيد الإرسال بالمفتاح نفسه، دون عنصر جديد ودون تشغيل أي مؤلف.
  - الجولات محدودة بخمس. بعدها لا يعيد التفعيل إلا أمر المشغّل `--retry-delivery` بالمعرفات نفسها.
  - الرفض الصريح نهائي ولا يُعاد.
  - يُنشر إشعار نقل مؤقت واحد يقول إنه لا يُعرف هل وصل الطلب، وهو ليس نهائيًا ولا يحجب الردود اللاحقة.
- **I8-08 — الاسترداد من النسخة الاحتياطية:**
  - عند الرجوع إلى النسخة الاحتياطية يُحفظ «حاجز مطابقة» يمسح العدد كاملًا من الصفحة الأولى عبر دورات محدودة، مع حفظ التقدم عبر إعادة التشغيل.
  - لا يُنشر أي تعليق حتى اكتمال التغطية ومرور 120 ثانية.
  - تُطابق العلامات الموجودة دون إعادة نشر، ويُنشر الغائب مرة واحدة فقط.
  - يُحفظ الملف التالف دليلًا ولا يُحذف شيء.

**أوامر المحوّل:**

| الأمر | الغرض |
|---|---|
| `--status` | الحالة |
| `--once` | دورة واحدة |
| `--poll` | استطلاع مستمر |
| `--retry-delivery <معرف>` | إعادة محاولة تسليم طلب متوقف |
| `--reset-journal` | إعادة الضبط: أرشفة دون حذف، مع حاجز مطابقة |

الإيقاف بـ Ctrl+C في نافذة المحوّل فقط.
