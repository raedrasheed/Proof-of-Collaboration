# PoCol GitHub inbox adapter (issue #8 transport)

**Status: NOT ACTIVE.** This adapter was written as a separate transport task. It is not part of LP3,
and it is not a retry of the blocked LP3 author dispatch. The author has not run it, and none of its
tests has been executed. `connectionVerified` stays `false` until root records real end-to-end
evidence (see "Activation" below).

## What it does

An outbound-only polling adapter (Node 22, standard library only) between one GitHub issue and the
existing local coordinator.

**Scope:** it is pinned to `raedrasheed/Proof-of-Collaboration`, issue **#8**, owner login
`raedrasheed`, owner ID **36733882**. A config file must repeat these values exactly; they cannot be
changed.

**Reading:** it reads the issue's comments with the operator's existing GitHub CLI (`gh api`, two
fixed argument vectors). Pages are bounded, and Retry-After and rate-limit headers are respected.

**Accepted comments:** only those where all of the following hold:

- the author is user ID 36733882 with login `raedrasheed`;
- the author is not a bot or a GitHub App;
- the comment does not contain the adapter's own marker;
- the comment is in issue #8;
- the body is at most 4000 characters;
- the **first line** is exactly `/pocol status <request-id>` or `/pocol guidance <request-id>`, where the request ID is 3–64 characters `[A-Za-z0-9._-]` starting alphanumeric.

Everything else is recorded as ignored, with a reason. Links and text in comments are untrusted data:
they are never fetched, executed, or interpolated into a command.

**Delivery:** each accepted comment becomes **one** guidance item in the local broker, through the
existing control API (`POST /api/guidance`). The item is labelled as an untrusted transport payload
(Arabic and English): it is not an owner approval, not an answer to an owner question, and not a task
dispatch.

**Publication:** the adapter publishes replies on issue #8 from **actual broker records only**. Each
reply carries a deterministic hidden marker.

### Never

The adapter never:

- uses the reviewer API (attach, claim, ack, review);
- requests author jobs, retries, pauses or resumes;
- acknowledges anything itself;
- dispatches or runs an agent;
- runs any process other than the configured `gh`;
- touches the live coordinator process.

## Identity, idempotency and markers

| Item | Rule |
|---|---|
| Broker idempotency key | `gh8-` + first 40 hex characters of SHA-256(`raedrasheed/Proof-of-Collaboration#8#comment:<id>`) |
| Duplicate request IDs | The earliest accepted comment (lowest ID) owns a request ID. Later comments with the same ID are recorded as `duplicateRequestId` and are neither delivered nor answered. |
| Edits | A comment is judged once, when first seen. Later edits never re-trigger delivery; they are flagged as `editedAfterSeen`. |
| Publication marker | `<!-- pocol-github-inbox:v1 key=<32 hex> -->`, with key = SHA-256(repository, issue, comment ID, state). Each (comment, state) is published at most once. Marked comments are never parsed as input. |

**Restart and uncertainty:**

- A delivery is saved as `delivering` before the POST, so replay returns the same broker item (broker deduplication).
- A publication is saved as `posting` before `gh` runs. After an uncertain outcome (timeout, 5xx, crash), the adapter first looks for its marker on GitHub. It reposts only after a complete scan shows the marker is absent.

## Remote states (honest mapping)

| State | Published only when |
|---|---|
| `received` | the broker's `POST /api/guidance` returned the persisted item |
| awaiting local ack | (not published separately) the broker item is `queued` or `claimed` |
| `acknowledged` | the broker item is actually `acknowledged` by the host |
| `completed` / `blocked` (status requests) | the host's ack note starts with `POCOL_GITHUB_RESULT {"mode":"status","state":"completed"\|"blocked","summary":"...","evidence":[...]}`. Reported as **"Completed STATUS REQUEST"**, never as a completed milestone. Evidence must be links into the pinned repository. |
| `running` | the ack note links a job (`{"mode":"work","jobId":"<broker author job id>"}`) and that broker job is actually `running` |
| `reviewed` | the linked job has an actual review that is not an accepted completion |
| `completed` (work) | the linked job is `reviewed` and its matching review's verdict is `accept` |
| `blocked` (work) | the linked job actually `failed` or was `interrupted`, has a saved `blockedReason`, or the host's ack note says `{"mode":"work","state":"blocked","summary":"..."}`. Also used when the broker refused a delivery (4xx). |

Text in a GitHub comment can never set a state. Only the broker records above can.

Status replies also include a sanitized summary of the saved LP3 blocker, read from
`coordination/checkpoints/devnet-policy-blocker.json`: status, blocked step, exact error and the PR #7
link. Nothing in that checkpoint is ever run.

## Privacy and redaction

**Redaction:** the coordinator's own redactor is reused (`local-coordinator/src/redact.mjs`). Both
capabilities from `connection.json` are registered with it, and only the control capability is used.

**Published text** additionally goes through an allowlist pass that removes:

- local paths;
- loopback URLs;
- 64-hex values;
- UUIDs (thread, session and broker IDs);
- control and bidi characters;
- mentions;
- HTML comments;
- `/pocol` line starts.

**Never printed or logged:** tokens, the environment, or `gh` stderr. `gh` stderr is reduced to a fixed
classification. `gh` uses its own stored credentials; the adapter never reads them.

**Private state** lives only in `coordination/ui-control/github-inbox/`:

- `inbox-journal.json` (with `.bak`)
- `adapter.log`
- `activation.json` (written by root, never by the adapter)

**`--status`** prints only counts, request IDs, public comment IDs and states.

## Safety of the process

- **Lease:**
  - Windows: a named pipe derived from the state directory. A second adapter gets "already running", and the OS releases the pipe when the process ends or is killed. No lock files exist.
  - Other platforms: a socket file. A leftover socket after a crash is reported, never deleted automatically.
- **Atomic state:** the state is written to a temp file, fsynced, and renamed into place, with a `.bak` of the previous state. A corrupt main file falls back to a valid backup. If no valid file remains, the adapter refuses to start rather than starting empty.
- **Bounds per cycle:**

  | Limit | Value |
  |---|---|
  | comment pages | 10 (of 100 comments) |
  | new requests | 20 |
  | publications | 10 |

  The rest is reported as `backlog` and continued next cycle; nothing is dropped.
- **Rate limits:** Retry-After and rate-limit reset are honoured, capped at 900 s. Delivery attempts are capped at 20 per request.
- **Polling:** `--poll` waits `pollSeconds` (minimum 30, default 60). Consecutive failures back off exponentially, capped at 900 s.

## Files

`tools/github-inbox/`:

| Path | Content |
|---|---|
| `src/constants.mjs` | pinned scope, bounds |
| `src/config.mjs` | strict config |
| `src/sanitize.mjs` | redaction and allowlist |
| `src/gh.mjs` | the only child process |
| `src/broker-client.mjs` | two broker endpoints |
| `src/journal.mjs` | state and lease |
| `src/protocol.mjs` | rules, mapping, replies |
| `src/adapter.mjs` | one cycle |
| `src/cli.mjs` | command line |
| `test/*.test.mjs` | `node:test` suites with injected fakes and a real loopback server for the broker client |
| `config.example.json` | example config |

## Commands (root runs these; the author ran nothing)

```
cd tools\github-inbox
node --test test/protocol.test.mjs test/sanitize.test.mjs test/gh.test.mjs test/broker-client.test.mjs test/journal.test.mjs test/adapter.test.mjs test/boundaries.test.mjs
copy config.example.json D:\PoCol-Development\coordination\ui-control\github-inbox\config.json
node src\cli.mjs --config D:\PoCol-Development\coordination\ui-control\github-inbox\config.json --status
node src\cli.mjs --config D:\PoCol-Development\coordination\ui-control\github-inbox\config.json --once
node src\cli.mjs --config D:\PoCol-Development\coordination\ui-control\github-inbox\config.json --poll
```

Before running, edit `ghBin` in the copied config to the real absolute path of `gh.exe`.

**Exit codes:**

| Code | Meaning |
|---|---|
| 0 | ok |
| 1 | the cycle reported an error (see the JSON summary) |
| 2 | usage, config or lease problem |

**Stop:** stop `--poll` with Ctrl+C in its own window, or by ending that process. This never pauses
the coordinator, changes any broker item or stops any author.

## Activation (root only)

The connection becomes active only after a real, harmless round trip:

1. The owner posts `/pocol status act-1` on issue #8.
2. The adapter delivers it, and `received` appears on the issue.
3. The host acknowledges the broker item through the normal controls, with a `POCOL_GITHUB_RESULT` status note.
4. The `completed` status reply appears on the issue.
5. A duplicate comment with the same request ID is ignored.
6. After restarting the adapter, nothing is delivered or published twice.

Then root writes `coordination/ui-control/github-inbox/activation.json` by hand:

```json
{ "connectionVerified": true, "recordedBy": "root", "recordedAt": "<ISO time>",
  "evidence": { "roundtripCommentUrl": "<issue comment URL>", "duplicateCheck": "passed", "restartCheck": "passed" } }
```

Test counts, mocks or a single posted comment are not activation evidence.

---

## إعداد سريع (عربي)

**الحالة: غير مفعّل.** هذا محوّل نقل منفصل عن LP3، ولا يعيد محاولة إطلاق مؤلف LP3 المحجوب. لم يشغّل المؤلف أي أمر ولا أي اختبار.

**ما يفعله:**

- يقرأ تعليقات العدد #8 في `raedrasheed/Proof-of-Collaboration` عبر `gh` المثبت لديك.
- يقبل فقط تعليقات المالك `raedrasheed` (المعرف 36733882) التي يبدأ سطرها الأول بـ `/pocol status <معرف>` أو `/pocol guidance <معرف>`.
- يحفظ كل طلب في الوسيط المحلي عنصرَ توجيه واحدًا، موسومًا بأنه حمولة نقل غير موثوقة، لا موافقة من المالك ولا تشغيل مهمة.
- ينشر الردود على العدد بعلامة مخفية ثابتة، اعتمادًا على سجلات الوسيط الفعلية وحدها.

**ما لا يفعله أبدًا:**

- لا يستخدم واجهة المراجع.
- لا يؤكد أي عنصر ولا يراجعه.
- لا يطلق مؤلفًا.
- لا يوقف المنسق ولا يستأنفه.
- لا يشغّل أي برنامج سوى `gh`.

**الخطوات:**

1. انسخ `config.example.json` إلى `coordination\ui-control\github-inbox\config.json`، ثم عدّل `ghBin` إلى المسار الكامل لـ `gh.exe`.
2. من مجلد `tools\github-inbox` شغّل الاختبارات:
   `node --test test/protocol.test.mjs test/sanitize.test.mjs test/gh.test.mjs test/broker-client.test.mjs test/journal.test.mjs test/adapter.test.mjs test/boundaries.test.mjs`
3. تحقق من الحالة: `node src\cli.mjs --config <ملف الإعداد> --status`
4. دورة واحدة: `node src\cli.mjs --config <ملف الإعداد> --once`
5. استطلاع مستمر: `node src\cli.mjs --config <ملف الإعداد> --poll`. أوقفه بـ Ctrl+C في نافذته فقط؛ هذا لا يوقف المنسق.

**التفعيل:** يبقى `connectionVerified` بقيمة false حتى يجري الجذر رحلة كاملة حقيقية: تعليق المالك ← وصوله إلى الوسيط ← تأكيد المضيف ← رد على GitHub، ثم فحص التكرار وإعادة التشغيل. بعد ذلك يكتب الجذر الملف `activation.json` يدويًا. عدد الاختبارات أو المحاكاة ليس دليل تفعيل.
