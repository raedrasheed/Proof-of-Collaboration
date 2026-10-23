# RpcGuard in pocold: spec item, mechanism, status, test and mutant

**Scope.** This file covers `development/m1/reference/network.md:182–330`, the RpcGuard section
(D87, D88, D90, D92, D93, D94, D95). RpcGuard is a local service policy, not a validity rule
(D87, consensus.md §13). Changing it never changes consensus and needs no fork.

**Architecture.** The spec assumes an async server with a 20-thread compute pool and HTTP/1.1
keep-alive. pocold differs:

- it runs **one consensus thread plus a light lane**;
- HTTP/1.1 carries **one request per connection**, and the connection closes after its response.

**Statuses.** Each mechanism has one of these statuses:

- **ENFORCED**: implemented as specified.
- **EQUIVALENT**: a different mechanism gives the same bound or a stronger one; the proof is stated.
- **PARTIAL**: enforced for part of what the spec covers. The part that is not enforced is named.
  It is reported absent in admission.
- **NOT ENFORCED**: the reason is given, with what stays open.

**Where things are.**

- Code: `prototypes/pocold/src/rpc.rs`; `prototypes/pocold/src/lib.rs` (`RPC_ENFORCED`, `rpc_facts`);
  `prototypes/lp4-execution/src/native.rs` (`simulate_for_profile` stop hook).
- Tests: `prototypes/pocold/tests/net.rs` (loopback sockets on 127.0.0.1, and in-process `rpc::answer`);
  `tests/consensus.rs`; the rpc unit tests; `prototypes/lp4-execution/tests/simulate_stop.rs`.
- Running values: `pocol_getParams.rpcLimits`. A limit pocold does not enforce is `null` there,
  never a nominal value.

**History.** This file was revised on wf/rpcguard-r2, after the independent review of wf/rpcguard
(stage A, 87367fe). The review refuted several of stage A's ENFORCED and EQUIVALENT statuses.
§9 lists every finding and how it was resolved. The statuses below are the current ones.

## 1. Transport and the S1 invariant (أ)

| spec item | pocold mechanism | status | test | mutant |
|---|---|---|---|---|
| HTTP/1.1 on 127.0.0.1, no HTTP/2, no pipelining | `serve` binds loopback only, otherwise it refuses. `respond`/`pace_write` write HTTP/1.1 with `Connection: close` | ENFORCED | existing `rpc_*` tests | — |
| One request at a time; the next is not read before sendDone | The connection closes after one response, so it never has a next request | EQUIVALENT (stronger) | every `rpc_*` test | — |
| S1: at most 1 reservation and 1 waiting request per connection | One `conn` thread handles one request, with one `Reply` reservation | ENFORCED | `an_answer_is_reserved_until_its_connection_has_written_it` | — |
| SO_SNDBUF = 32 KiB per connection (network.md:190) | Not set. `std::net` has no portable `setsockopt`, and adding a dependency (libc, windows-sys or socket2) was not done in this round. Consequence: the kernel sizes the send buffer itself (Linux autotunes up to `net.ipv4.tcp_wmem` max). A (the bytes the socket accepted) can therefore run that far ahead of the client's reads. The SendPacer still bounds how long an answer holds its reservation, because it counts accepted bytes, but its slack against the client is the kernel buffer, not 32 KiB. The kernel also holds that much per connection, outside the process heap and the A13 model. (Correcting stage A: D93's "enters no criterion" refers to the accept/read gap, not to SO_SNDBUF; R26 has `sendSockBuf<=64KiB`, now waived.) | NOT ENFORCED (`send_sock_buf` absent; rpcLimits.sendSockBuf = null) | — | — |

## 2. Classification (ب) and response limits (ج)

| spec item | pocold mechanism | status | test | mutant |
|---|---|---|---|---|
| Light table (LIGHT_RESP_MAX 512 KiB) | `LIGHT_METHODS` + `is_light`. A light answer over LIGHT_RESP_MAX is −32008 | ENFORCED | `a_max_size_transaction_is_answered_in_the_light_lane`, rpc unit tests | — |
| Heavy table (RESP_MAX 8 MiB) | Heavy by default. `capped` returns −32008 over RESP_MAX | ENFORCED | `responses_above_resp_max_become_an_error` | — |
| RPC_CONN_MAX = 32; the excess is closed unread | `conn_max`; the acceptor answers 503 and closes without reading | ENFORCED | `rpc_connection_cap_refuses_excess_unread_and_keeps_serving` | — |
| HEAVY_ACTIVE = 4 | One consensus thread, so active heavy work ≤ 1 ≤ 4 (`heavyActive` gauge) | EQUIVALENT (stronger); reported as 1 | `queued_requests_are_busy_at_queue_wait` (holder detected by the gauge) | — |
| LIGHT_ACTIVE = 16 | The one consensus thread drains the light lane, so active light work ≤ 1 ≤ 16 (`lightActive` gauge) | EQUIVALENT (stronger); reported as 1 | `get_params_and_rpc_stats_report_the_limits` (lightActive = 1 while it runs) | — |
| HEAVY_QUEUE = 16 | `reserve_heavy`: at most `heavy_queue` places, waited for until QUEUE_WAIT. An abandoned body keeps its place until the node reaches it | ENFORCED | `abandoned_queued_bodies_are_capped_and_released` | RGM3 |
| LIGHT_QUEUE = 32 | The light lane's capacity. A full lane is −32021 {busy} (HTTP 200) | ENFORCED | `a_full_light_lane_answers_busy` | V3 |
| QUEUE_WAIT = 2 s: admitted within it, otherwise −32021 {busy, retryAfterMs ∈ [250, 2000]} (network.md:234) | **Round 2.** QUEUE_WAIT runs from the end of parsing, across the wait for a place (or a full main queue) and the wait in the queue. A shared admission state (`Request::state`: QUEUED, ADMITTED or GONE) makes it atomic. At QUEUE_WAIT the connection marks the request gone and answers busy itself. The consensus thread admits a request only while it is QUEUED and younger than QUEUE_WAIT. So a request answered busy never runs, and an admitted one is always answered. Applies to heavy and light requests | ENFORCED | `queued_requests_are_busy_at_queue_wait` (sockets: a heavy and a light request behind a 0.5 s precompile run are busy at QUEUE_WAIT, about 83 ms), `compute_deadline_runs_from_admission_and_queue_wait_bounds_admission` (in process: one queued past QUEUE_WAIT is busy and its transaction is not pooled), `heavy_queue_overflow_answers_busy_with_retry_after` | V1a, V1b |
| FIFO queues; an honest request waits behind ≤ 31 requests | Heavy requests are FIFO in the main event queue. The light lane is drained before every main event and between batch members. Light requests therefore overtake heavy ones; heavy requests do not interleave between a batch's members (each member does not re-queue). Every wait is bounded by QUEUE_WAIT | EQUIVALENT for the wait bound (QUEUE_WAIT); the ordering differs (documented) | `a_light_turn_runs_at_most_light_turn_requests_then_wakes_the_node`, `legitimate_requests_progress_under_bounded_heavy_load` | — |
| Token bucket per connection, 20/s, capacity 20; k tokens at parse; shortfall −32021 {rate, retryAfterMs} (network.md:215–218) | **Round 2.** Stage A's per-source-IP bucket is removed: it was not the spec's mechanism, it was evadable through 127/8 addresses, it grouped honest tools, and its refill was truncated below 1 ms. The bucket now applies exactly as specified per connection, to the connection's one request (`rate_refused`): a full bucket of `bucket_cap`, k tokens taken after the BATCH_MAX check. At the spec values (20/s, capacity 20 = BATCH_MAX) no request within BATCH_MAX is refused; that is the per-connection bound, met because each connection carries one request. Neither the spec nor pocold bounds the aggregate rate across reconnects (see proposals/RPCGUARD-R2-PROPOSALS.md P1) | EQUIVALENT (per connection, as specified, on its one request); aggregate bound open (P1, proposed) | `the_per_connection_bucket_charges_k_tokens_per_request` (capacity 5: 6 members are 6 rate items with retryAfterMs = 50, 5 members run, 21 members are −32600), rpc unit test `the_per_connection_bucket_refuses_only_more_tokens_than_its_capacity` | RGM2, V6 |
| HEAVY_RESP_MEM = 48 MiB | `HEAVY_RESP_POOL` = 48 MiB. A full pool is −32021 busy before anything runs | ENFORCED | `a_full_heavy_pool_answers_busy_before_anything_runs` | existing M4-BUSY |
| LIGHT_RESP_MEM = 16 MiB | Light pool = (conn_max+1)·512 KiB = 16.5 MiB ≥ 16 MiB, so a light reservation never fails (S1) | ENFORCED (≥ spec) | `response_pools_reserve_shrink_and_release` | — |
| SCRATCH ≤ 16 MiB per heavy permit, −32020 {scratch} | eth_getLogs and pocol_getLogs charge the bytes they materialize against `scratch_heavy`. An overflow is −32020 {scratch} with resume data, and the partial result is dropped. No other handler is charged: not eth_call/eth_estimateGas EVM memory and state copy (bounded by gas through the A13 execution model, not by 16 MiB), and not the JSON trees of the other heavy methods | PARTIAL (log handlers only): `scratch_heavy` absent; rpcLimits.scratchHeavy = null, rpcLimits.logsScratch = 16 MiB | `get_logs_scratch_limit_is_32020_scratch_with_resume_data` | RGM6 |
| SCRATCH ≤ 1 MiB per light permit | No light handler is charged. `scratchLightMax` is null in pocol_getRpcStats | NOT ENFORCED (`scratch_light` absent) | — | — |
| REQ_BUF = 1 MiB | Request line + headers + body ≤ REQ_BUF | ENFORCED | `rpc_request_buffer_covers_headers_and_body` | — |
| CONN_BUF = 64 KiB (the per-connection buffer a batch's k error items are written from) | A busy or rate answer is at most BATCH_MAX error items of ≤ ERR_ITEM_MAX each: ≤ SMALL_REPLY_MAX = 5184 B. Connection threads build it by scanning the ids (`scan_ids`), never by parsing a tree. Reported as conn_buf = 5184, the structural bound, not a configured value | EQUIVALENT (stronger: 5184 B ≤ 64 KiB) | rpc unit tests `error_items_fit_err_item_max_and_a_batch_of_them_small_reply_max`, `a_busy_answer_allocates_no_parse_tree`, `busy_answers_scan_the_ids_a_parse_would_echo` | RGM11 |
| RPC_MEM_TOTAL = 178 MiB ≤ 192 MiB | pocold bounds RPC memory inside its own A13 budget (rpc term 204.6 MiB, below) | NOT ENFORCED as the field (`mem_total` absent) | `a13_boot_refuses_a_bound_above_the_memory_budget` | — |
| Encoding into 64 KiB segments inside the reservation | The answer String is built within the reservation and shrunk to fit; it is not chunked | EQUIVALENT for memory (≤ reservation); the chunked form is not enforced | `an_answer_is_reserved_until_its_connection_has_written_it` | — |
| Snapshots ≤ 20 (one per permit) | Handlers read the chain on the one consensus thread. eth_call/estimateGas take one state copy at a time (the A13 transient working-copy term). `snapshotsOpen` is null | EQUIVALENT (≤ 1 working copy at a time) | A13 tests | — |

## 3. Request ownership, COMPUTE_DEADLINE and cancellation (د, و)

| spec item | pocold mechanism | status | test | mutant |
|---|---|---|---|---|
| REQ_READ_DEADLINE = 10 s | `read_deadline` over the whole request | ENFORCED | `rpc_connection_cap_…` | — |
| IDLE = 30 s | The connection closes after one response, so there is no idle period | EQUIVALENT | — | — |
| Stage 2 order: F0, origin deny, classification, rate, numeric log range, within REQ_BUF | The rate check runs on the connection thread, after the BATCH_MAX check and before ORIGIN_DENY (which is applied per member on the consensus thread). The order is observable only for a batch of k > bucket_cap, unreachable at the spec values. The numeric log range (≤ 1024) is checked in the handler, after admission | PARTIAL (order; documented) | — | — |
| Atomic admission: permit and the class's reservation together, for the head of the queue; a waiting request holds nothing | The consensus thread admits (`Request::admit`) and reserves (`RespPools::take`) in one step at dequeue. A waiting request holds only its body (the A13 queued-body terms) | EQUIVALENT | `compute_deadline_runs_from_admission_…` | V1b |
| COMPUTE_DEADLINE 5 s heavy / 500 ms light, **from admission**, including encoding; expiry is −32020 {deadline} (network.md:235) | **Round 2.** `Budget.compute_by` = admission instant + the class's deadline; time spent queued never counts (stage A measured from arrival, review B1). Checked: at handler entry (except the log handlers, which check at their first block so the error carries resume data); inside long loops (eth_getLogs every 16 blocks; eth_call/estimateGas before every simulation and through the stop hook); and once the answer is encoded. A read-only result completed after the deadline is replaced by −32020 {deadline}, never a late success (review B3). Methods whose effect already happened (eth_sendRawTransaction, pocol_submitShare) are checked only before they run: a late −32020 would hide an accepted transaction. This keeps the pre-existing behaviour for them; the reading is recorded in proposals/RPCGUARD-R2-PROPOSALS.md P3. Batch members get their own class's deadline from when they start | ENFORCED (the answer); the cancellation latency is below | `compute_deadline_runs_from_admission_and_queue_wait_bounds_admission`, `light_requests_behind_long_heavy_work_are_answered_never_deadline` (default limits: a light request behind a 1.2 s holder gets its result), `light_compute_deadline_fires`, `a_request_reaching_its_handler_past_the_deadline_never_runs`, `heavy_compute_deadline_cancels_eth_call`, `a_precompile_call_past_its_deadline_is_32020_not_a_late_success`, `estimate_gas_stops_its_search_at_the_deadline` | RGM9, RGM4, RGM5, RGM8, V7 |
| Cancellation checks every 16 blocks scanned, every 1 MiB encoded, every 10^6 gas; release within CANCEL_MAX = 100 ms (network.md:286) | 16 blocks: eth_getLogs, from its first block. 10^6 gas: `native::STOP_GAS`; the stop hook is polled at the first JUMP/JUMPI or data-sized instruction (KECCAK256, *COPY, LOG) once a frame has spent 10^6 gas since the last poll, at every 64th JUMP/JUMPI, and before every CALL/CREATE-family instruction. Not enforced: 1 MiB encoded (encoding is not chunked; it is checked once, after) and precompiles. A precompile call is not interpreted, so it runs to its end: a 29.9M-round BLAKE2F (30M gas) took about 0.5 s, and its −32020 came 480–569 ms after a 20 ms deadline. `cancelMaxMs` reports the largest observed lateness | PARTIAL: the 16-block and 10^6-gas checks are enforced; CANCEL_MAX itself is NOT ENFORCED (`cancel_max_ms` absent; proposals P2) | lp4 `the_stop_hook_is_polled_at_least_every_stop_gas` (29 polls for 30M gas), `a_stop_ends_the_simulation`, `a_precompile_call_is_never_polled`; consensus `get_logs_scratch_…` (deadline part: the scan stops at its first block) | RGM10, V5 |
| End of compute: release snapshot, SCRATCH and permit; shrink the reservation | The `Budget`, the state copy and the `Active` gauge drop at return; the reservation shrinks to the answer | ENFORCED | `a_full_heavy_pool_…` | — |

## 4. SendPacer (د.6, D90/D92/D93/D94)

| spec item | pocold mechanism | status | test | mutant |
|---|---|---|---|---|
| Binding rule: close if sendTime > GRACE and A < R·sendTime (R = 65536 B/s, GRACE = 2 s) | `pace_write`: **round 2, a non-blocking socket** (review M5). A write that would block sends nothing on every platform; there is no SO_SNDTIMEO, so there is no indeterminate Windows state. The rule is evaluated with the exact values after every write attempt. A response of `size` bytes holds its reservation at most SEND_MAX(size) | ENFORCED | `send_pacer_closes_a_slow_reader_after_grace` (a slow reader is closed after GRACE; an honest reader gets every byte, Content-Length checked and the JSON complete) | RGM1 |
| Timer at s_v + TIMER_EPS (1 ms), re-armed on every change of A, backstop check every 50 ms, exact re-check when it fires | A blocked write is retried after `pacer_poll` (1 ms, a backstop stronger than 50 ms) or at s_v + TIMER_EPS (s_v = max(GRACE, A/R)) when that is sooner, and the rule is re-checked with the exact values | ENFORCED (`timer_eps_ms` = 1 now present) | `send_pacer_…` | V2 |
| lateness ≤ ENFORCE_SLACK = 200 ms, recorded in pacerLateMaxMs | Recorded at every pacer close. The test asserts ≤ 200 ms; measured 0 ms here | ENFORCED (as a measured, asserted bound) | `send_pacer_…` | V2 |
| CloseOK record (sendTime, A) in RpcStats | `lastPacerClose {sendTime (s), accepted}` | ENFORCED | `send_pacer_…` (sendTime > GRACE, A < R·sendTime) | — |
| sendDone releases the reservation; sendOverrunMaxMs | `pace_write` returns at A = size. The `Reply` reservation drops; `sendDoneCount` and `sendOverrunMaxMs` (sendTime − (GRACE + size/R)) are recorded | ENFORCED | `send_pacer_…`, `an_answer_is_reserved_…` | existing M13-RESV |
| PacerTrace (D93): 4 MiB ring of produce/accept/pend/close/sendDone events; traceDropped | Not kept. Only close accounting is kept. `traceDropped` is null | NOT ENFORCED | — | — |

## 5. Batches (هـ)

| spec item | pocold mechanism | status | test | mutant |
|---|---|---|---|---|
| ≤ BATCH_MAX = 20 members | A larger batch is −32600 (before the bucket) | ENFORCED | `rpc_batches_…`, `the_per_connection_bucket_…` | — |
| Streamed with chunked encoding; member k+1 admitted once member k is accepted | The batch answer is built within BATCH_BYTES_HARD, then written under one pacer. Members run one at a time on the one consensus thread, each with its own class's COMPUTE_DEADLINE | EQUIVALENT for memory and per-member deadlines; streaming NOT ENFORCED | `an_answer_is_reserved_…`, `rpc_work_deadline_…` | — |
| One SendPacer per batch, GRACE once, the rule on the cumulative A | One `pace_write` per batch answer | ENFORCED | `send_pacer_…` (a 10-member batch) | RGM1 |
| BATCH_RESP_MAX = 16 MiB; the member crossing it and every later one are −32020 {batchBytes} | `batch` | ENFORCED | `batch_members_beyond_the_byte_limit_are_not_run` | — |
| BATCH_WALL = 420 s from read-end to sendDone; reaching it closes, releases and counts batchWallHits; any nonzero value in a release run is a defect | **Round 2** (review m5). Measured from the read-end through compute and send: between members (the batch stops and the connection closes without an answer) and in `pace_write` (the send is cut). Derivation at the defaults: read-end to sendDone ≤ QUEUE_WAIT 2 s + work deadline 30 s (after which the connection answers 504 and no batch answer is sent) + SEND_MAX(BATCH_BYTES_HARD) 258.3 s = 290.3 s < 420 s, so a release run never reaches it | ENFORCED (backstop, with the derivation) | `batch_wall_closes_the_batch` (compute phase and send phase) | V4a, V4b |
| busy/rate items written; order kept; ids copied | Per-member items. Ids are echoed when their encoding is ≤ 128 B | ENFORCED | `a_full_heavy_pool_…`, `the_per_connection_bucket_…` | — |

## 6. eth_getLogs and pocol_getLogs (ز, ح)

| spec item | pocold mechanism | status | test | mutant |
|---|---|---|---|---|
| P1 per-block limits with resume data | `logs` `stop` (existing) | ENFORCED | `get_logs_limits_answer_32020_with_resume_data` | — |
| Deadline / SCRATCH: −32020 {deadline\|scratch, fromBlock, lastCompleteBlock ≥ fromBlock−1, nextFromBlock}; the partial buffer dropped | **Round 2** (review M3). The log handlers check the deadline at their first block, not at a generic entry check, so a deadline at entry carries resume data. An answer completed but late carries the resume data of no progress. lastCompleteBlock = fromBlock−1 is encoded null, as for a limit at fromBlock | ENFORCED | `get_logs_scratch_…` (eth_getLogs, pocol_getLogs numeric and blockHash) | V5, RGM6 |
| Numeric range ≤ 1024 before admission, −32020 {range, maxRange} | Checked in the handler after admission; the error carries no data | NOT ENFORCED as specified (pre-existing; open) | — | — |
| pocol_getLogs(filter, anchorHash): −32022 {anchorNotCanonical, head} / {beyondAnchor} | pocold's pocol_getLogs takes no anchorHash. `anchorRejects` is null | NOT IMPLEMENTED (open; out of this round) | — | — |
| ORIGIN_DENY (ح2) | Existing, per member. `originDenied` is counted | ENFORCED | `a10_origin_deny_applies_to_every_batch_member` | — |
| (ط) RPC separated from consensus (its own runtime) | RPC runs on the consensus thread. This is why active ≤ 1 and why light requests wait behind consensus work; the wait is bounded by QUEUE_WAIT | NOT ENFORCED (architecture) | — | — |

## 7. Stats and parameters

| spec item | pocold mechanism | status | test | mutant |
|---|---|---|---|---|
| pocol_getParams → {profileKind, nodeKind, nonceMode, chainId, genesisHash, genesisPre, netKey, forkSchedule, activeVersion, rpcLimits} (network.md:336) | Every field (round 2 adds `netKey` = keccak256(RLP(['PoCol-net-v1', chainId, genesisHash])), checked against the extension's derivation, and `forkSchedule`). rpcLimits holds the running values, and null for SEND_SOCK_BUF, SCRATCH, CANCEL_MAX and RPC_MEM_TOTAL | ENFORCED | `get_params_and_rpc_stats_report_the_limits`, rpc unit test `net_key_matches_the_extension` | RGM7 |
| pocol_getRpcStats → the 27-field record (network.md:347) | Every field. Null for the mechanisms pocold does not have: scratchLightMax, snapshotsOpen, anchorRejects, traceDropped. sendOverrunMaxMs is null until the first sendDone | ENFORCED (the record; the four null fields are not tracked) | `get_params_and_rpc_stats_report_the_limits` | — |

## 8. Admission (R26) and the A13 RPC memory term

`pocold::RPC_ENFORCED` names 24 fields, at their running values:

- conn_max, req_buf, conn_buf (5184), heavy_active (1), light_active (1), light_queue;
- heavy_resp_mem, light_resp_mem, resp_max, light_resp_max, batch_resp_max, batch_max, err_item_max;
- logs_count_max, logs_scan_bytes, rate (20), bucket_cap (20), queue_wait_ms (2000), compute_heavy_ms (5000);
- grace_ms, min_send_rate, batch_wall_ms, enforce_slack_ms, timer_eps_ms (1).

Five fields are absent, never nominal:

- `send_sock_buf`;
- `scratch_heavy` and `scratch_light` (only the log handlers are charged);
- `mem_total`;
- `cancel_max_ms` (precompile runs are uninterruptible).

Under the experimental-devnet scope, 14 of the 18 R26 predicates read only present fields; they are
checked and all pass. Four are waived and reported:

- `derive` (reads scratch and cancel_max);
- `memoryRequired<=memTotal`;
- `batchWallMin<=batchWallMs` (derive);
- `sendSockBuf<=64KiB`.

The specification scope refuses (`specification:rpc-absent`). Test:
`pocold_admission_is_an_experimental_devnet_with_absent_rpc_mechanisms`.

Stage A's 26 facts carried `scratch_heavy`, `scratch_light`, `cancel_max_ms` and a nominal
`conn_buf`; those were not truly enforced (review B4/M4). It omitted `timer_eps_ms`, which is now
implemented.

A13 (`pocold::resources::derive`, rpc term), at the round-2 code:

- the per-source bucket map term is removed (−233,472 B);
- busy and rate answers built on connection threads no longer parse the request into a tree. Stage
  A had added that parse on up to conn_max threads, which the model did not count;
- a queued body is shared with its connection through an `Arc` (never copied); the Arc header and
  the admission state fit the +256 B per queued body.

| quantity | value |
|---|---|
| total | 5,577,343,580 B (5.194 GiB) |
| required budget with the 1/8 reserve | 6,374,106,949 B ≤ 6 GiB |
| rpc term | 204.6 MiB |

Tests: `a13_boot_refuses_a_bound_above_the_memory_budget`, `a13_bound_breakdown`.

## 9. Review findings (round 2) and their resolution

| finding | resolution |
|---|---|
| B1 deadline from arrival (regression) | FIXED: from admission; regression tests in process and over sockets at the default limits; mutant RGM9 |
| B2 QUEUE_WAIT not bounding queued requests | FIXED: the shared admission state; busy at QUEUE_WAIT from the connection; the node never runs a request it did not admit in time; mutants V1a, V1b |
| B3 late precompile success; CANCEL_MAX | FIXED for the answer (post-encoding check, per-simulation check; mutant RGM8). The stop hook polls per 10^6 gas (RGM10). CANCEL_MAX: `cancel_max_ms` now absent (NOT ENFORCED; proposals P2) |
| B4 SCRATCH outside getLogs | DOWNGRADED: `scratch_heavy` PARTIAL and absent, `scratch_light` NOT ENFORCED and absent; rpcLimits null; `scratchLightMax` null |
| B5 flaky work-deadline test | FIXED: snapshot after the heavy call and the lane have drained (gauges). 3 consecutive runs, plus 21 runs under load (three test processes at once): 21/21 ok, `skipped` = `late` every time (evidence/rpcguard-r2-b5-stress-dc4e3d1.log) |
| M1 refill truncation | RESOLVED BY REMOVAL: no per-source bucket; the per-connection bucket keeps no time state |
| M2 per-IP not equivalent | FIXED: per-connection bucket as specified; the aggregate rate is proposed (P1), not implemented |
| M3 getLogs deadline without resume data | FIXED: first-block check in the handler; post-encoding resume data; mutant V5 |
| M4 nominal conn_buf / sendSockBuf | FIXED: conn_buf = SMALL_REPLY_MAX (structural, tested); sendSockBuf null; the unused Limits fields removed |
| M5 Windows SO_SNDTIMEO | FIXED: non-blocking writes; the honest-reader test compares the length and parses the JSON. Not run on Windows here |
| M6 survivors V1–V8 | Tests added. V1a/V1b/V2/V3/V4a/V4b/V5/V6/V7 caught; V8 equivalent (below) |
| m1 A13 doc numbers | Corrected in the proposed A13 text (doc_updates) |
| m2 bucket map undercount | RESOLVED BY REMOVAL |
| m3 SO_SNDBUF rationale | CORRECTED (§1) |
| m4 stats and params fields | FIXED: every field present (null where pocold has no such mechanism) |
| m5 BATCH_WALL semantics | FIXED: from read-end through the send, closes; derivation in §5 |
| m6 rate edge cases | FIXED: batch-size check before the bucket (21 members are −32600); no overflow (no time state). The order versus ORIGIN_DENY is documented (§3) |
| m7 verification gaps | The lp4-execution release suite runs at the end. e2e and Windows: see the evidence index |

**V8, an equivalent mutant (entry check limited to light methods).** The answer is the same
without the heavy entry check:

- every heavy handler that does work checks the deadline again before doing it: eth_call and
  eth_estimateGas before each simulation, the log handlers at their first block;
- every other heavy handler is a bounded read-only one, whose late result `member` replaces with
  −32020;
- no heavy method is effectful.

The mutant only lets a bounded read-only heavy handler run once past its deadline before its answer
is replaced.

## 10. Mutation controls

Runner: scratch `run_mutations_rpcguard_r2.py`, on an exported copy of the committed tree
(dc4e3d1). Results: `evidence/MUTATIONS-RPCGUARD-R2.md` and `evidence/mutations-rpcguard-r2.json`.
Each mutant disables one mechanism, and its named tests must then FAIL. A timeout is incomplete,
never caught.

21 mutants, no timeouts: 20 CAUGHT, each on the assertion written for its mechanism, and 1
equivalent (V8, §9).

- Stage A's RGM1–RGM7, re-expressed against the round-2 code.
- RGM8–RGM11: the post-encoding deadline check, the deadline from admission, the per-10^6-gas poll,
  and busy answers without a parse tree.
- The review's survivors: V1a, V1b, V2, V3, V4a, V4b, V5, V6, V7 and V8.

## 11. Evidence index (round 2)

All runs use Rust 1.99.1, release, `--locked`, under the shared CPU lock, on loopback 127.0.0.1.

| file | what it records | result |
|---|---|---|
| `evidence/rpcguard-r2-new-tests-3x-6a561b6.log` | the new and changed tests (15 net, 1 consensus, 1 admission, 9 rpc unit, 3 lp4), three consecutive runs on 6a561b6 | 3/3 green |
| `evidence/rpcguard-r2-entry-test-3x-dc4e3d1.log` | the test added in the second commit, three consecutive runs | 3/3 green |
| `evidence/rpcguard-r2-b5-stress-dc4e3d1.log` | review B5: the work-deadline test, 21 runs under load | 21/21 ok |
| `evidence/MUTATIONS-RPCGUARD-R2.md`, `evidence/mutations-rpcguard-r2.json` | mutation controls on dc4e3d1 | 20 caught, 1 equivalent |
| `evidence/rpcguard-r2-suite-pocold-dc4e3d1.log` | full pocold release suite, once at the end | exit 0 |
| `evidence/rpcguard-r2-suite-lp4-dc4e3d1.log` | full lp4-execution release suite (native.rs changed) | exit 0, no warnings |
| `evidence/rpcguard-r2-e2e-dc4e3d1.log` | tests/e2e_devnet.py and tests/e2e_site.py (fixed loopback ports, e2e lock) | both exit 0; 37 PASS, no FAIL |
| `evidence/rpcguard-r2-netkey-vectors.txt` | provenance of the netKey test vectors (the extension's own derivation) | 4 vectors |

**Not run here.** The Windows CI (`audit-r2-windows-verify.yml`) and the browser (Chrome) e2e. The
non-blocking pacer was chosen so that its behaviour is defined on Windows. Windows execution remains
unverified.

