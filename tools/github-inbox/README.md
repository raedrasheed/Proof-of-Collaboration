# PoCol GitHub inbox adapter (issue #8 transport)

**Status: NOT ACTIVE.** This is a separate transport task. It is not LP3, and it does not retry or
bypass the blocked LP3 author dispatch (task 037).

The author has executed nothing for revision 0.41: no unit tests, no HTTP tests, no live connection,
and no comment delivered successfully. `connectionVerified` stays `false` until root records real
end-to-end evidence (see "Activation").

## What it does

An outbound-only polling adapter (Node 22, standard library only) between one GitHub issue and the
existing local coordinator. It is a small poller, not an agent loop.

**Scope:** it is pinned to `raedrasheed/Proof-of-Collaboration`, issue **#8**, owner login
`raedrasheed`, owner ID **36733882**. A config file must repeat these values exactly.

**GitHub calls:** every `gh` call carries `--hostname github.com`. `GH_HOST` and `GH_REPO` are removed
from the child environment, so neither config nor environment can redirect requests.

**Accepted comments:** only those where all of the following hold:

- the user is of type `User`, with id 36733882 and login `raedrasheed`;
- the comment is in issue #8;
- the comment does not contain the adapter's own marker;
- the body is at most 4000 characters;
- the first line is exactly `/pocol status <request-id>` or `/pocol guidance <request-id>`.

**Identity:**

- `performed_via_github_app` is attribution, not identity. The pinned user stays eligible when an app acted on their behalf.
- Bots (`type: Bot` or a `[bot]` login), organizations and every other actor are refused.

**Delivery:** each accepted comment becomes one coordinator guidance item (`POST /api/guidance`). It is
labelled in Arabic and English as an untrusted transport payload: not an owner approval, not an
answer to an owner question, and not a dispatch.

**Publication:** replies on issue #8 are published from actual coordinator records only, each with a
deterministic hidden marker.

### Never

The adapter never:

- uses the reviewer API (attach, claim, ack, review);
- requests author jobs, retries, pauses or resumes;
- acknowledges anything;
- dispatches or runs an agent;
- runs any process other than the configured `gh`;
- touches the live coordinator process or the LP3 policy blocker.

## Revision 0.41 corrections

| Finding | Correction |
|---|---|
| I8-01 | The `gh` timeout timer is referenced and always cleared on settle, so every run settles within `timeoutMs` even when nothing else keeps the event loop alive. Tests cover a silent child and a child that ignores kill. |
| I8-02 | The process-boundary test now distinguishes a bare call `exec(...)` from a method call such as `RegExp.prototype.exec`. It requires the single import `import { spawn } from 'node:child_process'` in `gh.mjs` and none elsewhere. Synthetic positive and negative control cases prove that unsafe imports, calls, shells and `fetch` are still caught. |
| I8-03 | `gh` stdout and stderr are decoded with a streaming UTF-8 decoder: Arabic and emoji split across chunks stay exact (tested at every byte position). The stdout cap counts bytes. Timeout, cap and stderr classification are unchanged. |
| I8-04 | A full rescan (every 30 cycles) is a persisted walk (`cursor.fullScanPage`). Each cycle continues where the previous one stopped, up to 10 pages, until the last page is reached. It survives restarts. An uncertain publication is reposted only after a later cycle's complete scan through the last page shows no marker, and only once at least 120 s have passed since the attempt. |
| I8-05 | The coordinator client is created per cycle and dropped after any failure (refused, stale capability, unreachable, uncertain, busy). The next call re-reads and re-validates `connection.json`. Broker idempotency keys are unchanged. A 401/403 is "stale" (retried after reload), never a permanent refusal. A reload is not a permission or policy change. |
| I8-06 | Requests and linked jobs or reviews beyond the coordinator's 100-item / 50-review browser view are read through the new narrow `GET /api/github-item` (below). At most 10 lookups run per cycle, round-robin with a persisted position, so an acknowledgement saved long ago is still published. |

## Coordinator extension: `GET /api/github-item?itemId=<UUID>` (history fix)

This is a new file, `tools/local-coordinator/src/github-item.mjs`, with one route added to
`tools/local-coordinator/src/server.mjs`. `broker.mjs` is unchanged.

**Checks:** the route uses the same control checks as `/api/state`:

- exact `Host`;
- `Origin`, if present, must be exactly the local origin;
- no cross-site `Sec-Fetch-Site`;
- the `X-PoCol-Control` capability.

**Query:** exactly one query parameter, `itemId`, which must be a UUID. Anything else is 400. An
unknown item is 404 with `{"missing":"item"}`. Any method other than GET falls through to 404.

**Response** (read-only, from the controller's in-memory state, never from the state file on disk):

| Field | Content |
|---|---|
| `item` | `{ id, kind, status, idempotencyKey, ackNote, reviewId, error, blockedReason }` |
| `review` | `{ id, jobId, verdict, summaryAr }` only for the review referenced by that item whose `jobId` is the item itself; otherwise `null` |

**Never returned:** payloads, dispatch plans, session IDs, receipts, review texts, notifications,
capabilities, thread IDs or paths. Strings are bounded and redacted.

**Grants nothing:** no write, approval, author, pause or resume. `/api/state` keeps its existing
100-item limit.

The adapter's `test/broker-client.test.mjs` checks that an older coordinator without this route
answers 404 without `missing`, which the client reports as `unsupported`.

## Identity, idempotency and markers

| Item | Rule |
|---|---|
| Broker key | `gh8-` + first 40 hex characters of SHA-256(`raedrasheed/Proof-of-Collaboration#8#comment:<id>`) |
| Duplicate request IDs | The earliest accepted comment owns a request ID. Later ones are recorded as `duplicateRequestId`, not delivered and not answered. |
| Edits | A comment is judged once. Later edits only set `editedAfterSeen`. |
| Marker | `<!-- pocol-github-inbox:v1 key=<32 hex> -->` per (comment, state). Marked comments are never parsed as input. |

## Remote states (only from actual coordinator records)

| State | Published when |
|---|---|
| `received` | POST guidance returned the persisted item |
| `acknowledged` | an actual host ack |
| `completed` / `blocked` (status requests) | the host ack note starts with `POCOL_GITHUB_RESULT {"mode":"status",...}`. Reported as "Completed STATUS REQUEST", never as a milestone. |
| `running` | the job linked by the ack note (`{"mode":"work","jobId":...}`) is actually running |
| `reviewed` | the linked job has an actual review that did not accept it |
| `completed` (work) | the linked job is `reviewed` and its matching review's verdict is `accept` |
| `blocked` (work) | the linked job actually failed or was interrupted, has a saved `blockedReason`, the host note says `{"mode":"work","state":"blocked",...}`, or the coordinator refused a delivery |

Status replies include a sanitized summary of the saved LP3 blocker checkpoint. It is read only;
nothing is run.

## Limits

| Limit | Value |
|---|---|
| Comment pages per cycle | 10 (100 comments each) |
| New requests per cycle | 20 |
| Publications per cycle | 10 |
| Item lookups per cycle | 10 |
| Delivery attempts per request | 20 |
| Comment body | 4000 characters |
| `gh` stdout | 4 MiB (bytes) |
| `gh` timeout | 30 s |
| Rate-limit wait | Retry-After or reset, capped at 900 s |
| Poll interval | at least 30 s (default 60 s); failures back off exponentially, capped at 900 s |
| Full rescan | every 30 completed cycles, continued across cycles |
| Uncertain publication | reposted only after a later complete scan and at least 120 s |

Anything beyond a per-cycle limit is reported as `backlog` and continued; nothing is dropped.

**Known limits:**

- Deleted comments can shift pages between rescans.
- Replies run as the owner's `gh` account; only the marker keeps them from being read as input.

## Local procedures (root)

All paths are relative to `D:\PoCol-Development`. The config lives at
`coordination\ui-control\github-inbox\config.json`; copy it from `config.example.json` and set `ghBin`.

**Tests**

From `tools\github-inbox`:

```
node --test test/protocol.test.mjs test/sanitize.test.mjs test/gh.test.mjs test/broker-client.test.mjs test/journal.test.mjs test/adapter.test.mjs test/boundaries.test.mjs
```

From `tools\local-coordinator`:

```
node --test test/broker.test.mjs test/history.test.mjs test/server.test.mjs test/worker.test.mjs test/notifier.test.mjs test/continuation.test.mjs test/connection.test.mjs test/github-item.test.mjs
```

**Coordinator update (only after review and tests)**

1. Stop the running coordinator with Ctrl+C in its own window.
2. Start the reviewed source in the same workspace, with no new flags: `node tools\local-coordinator\src\server.mjs`. It reuses the saved `connection.json` (same port and capabilities), the saved state and the single-service lock.

Do not use `--fresh-connection`. Pause, policy, LP3 and the single-writer rule are untouched.

**Adapter: start, run once, status, stop**

| Action | Command or method |
|---|---|
| Status (no network, no lease) | `node tools\github-inbox\src\cli.mjs --config coordination\ui-control\github-inbox\config.json --status` |
| One cycle | `node tools\github-inbox\src\cli.mjs --config coordination\ui-control\github-inbox\config.json --once` |
| Polling | `node tools\github-inbox\src\cli.mjs --config coordination\ui-control\github-inbox\config.json --poll` |
| Stop | Ctrl+C in the adapter's own window. This never pauses the coordinator or touches any item or author. |

**Reset (adapter only)**

1. Stop the adapter.
2. Move, do not delete, `coordination\ui-control\github-inbox\inbox-journal.json` and its `.bak` into a dated evidence folder.

After a reset, the adapter starts from an empty journal. Coordinator items keep their keys, so a
re-delivery returns the same items. Publications are reconciled by marker before any repost.

**Activation (root only, after unit and HTTP tests pass)**

1. The owner posts `/pocol status act-1` on issue #8.
2. `received` appears on the issue.
3. The host acknowledges the item normally, with a `POCOL_GITHUB_RESULT` status note.
4. The `completed` status reply appears.
5. A duplicate `/pocol status act-1` is ignored.
6. After restarting the adapter, nothing is delivered or published twice.

Then write `coordination\ui-control\github-inbox\activation.json` by hand:

```json
{ "connectionVerified": true, "recordedBy": "root", "recordedAt": "<ISO time>",
  "evidence": { "roundtripCommentUrl": "<issue comment URL>", "duplicateCheck": "passed", "restartCheck": "passed" } }
```

Test counts, mocks and a single posted comment are not activation evidence.

---

## إعداد سريع (عربي)

**الحالة: غير مفعّل.** هذه مهمة نقل منفصلة عن LP3، ولا تعيد محاولة إطلاق مؤلف LP3 المحجوب ولا تتجاوزه. لم يشغّل المؤلف أي اختبار أو اتصال.

**تصحيحات 0.41:**

| البند | التصحيح |
|---|---|
| I8-01 | مهلة `gh` تنتهي دائمًا حتى دون مقابض أخرى |
| I8-02 | فحص الحدود يميز `exec` الدالة من `RegExp.exec`، مع حالات تحكم إيجابية وسلبية |
| I8-03 | فك ترميز UTF-8 متدفق، فلا تتلف العربية والرموز التعبيرية عند تقسيمها |
| I8-04 | تقدم إعادة المسح الكامل محفوظ عبر الدورات، ولا يُعاد النشر إلا بعد مسح كامل لاحق ومرور 120 ثانية |
| I8-05 | يُعاد تحميل `connection.json` بعد أي فشل، بالمفاتيح نفسها |
| I8-06 | قراءة ضيقة جديدة `GET /api/github-item` لعنصر واحد، للعناصر الأقدم من آخر 100 عنصر |

ويبقى المالك المثبت مقبولًا حتى لو نشر تطبيق نيابة عنه، أما البوتات والفاعلون الآخرون فمرفوضون.

**التشغيل:**

- **التحديث:** بعد المراجعة والاختبار، أوقف المنسق بـ Ctrl+C في نافذته، ثم شغّل المصدر المراجَع في المساحة نفسها دون `--fresh-connection`، فيُعاد استخدام الاتصال والحالة المحفوظين.
- **المحوّل:**
  - الحالة: `--status`
  - دورة واحدة: `--once`
  - استطلاع: `--poll`
  - الإيقاف: Ctrl+C في نافذته فقط، ولا يوقف المنسق.
- **إعادة الضبط:** أوقف المحوّل وانقل ملف `inbox-journal.json` ونسخته الاحتياطية إلى مجلد أدلة، ولا تحذفهما.
- **التفعيل:** لا يكون إلا بعد رحلة حقيقية كاملة مع فحص التكرار وإعادة التشغيل، ثم يكتب الجذر `activation.json` يدويًا.
