# RpcGuard in pocold — spec item → mechanism → status → test → mutant

Scope: `development/m1/reference/network.md:182–330` (RpcGuard, D87/D88/D90/D92/D93/D94/D95). RpcGuard is a
local service policy, not a validity rule (D87, consensus.md §13): changing it never changes consensus and
needs no fork. The spec assumes an async server with a 20-thread compute pool and HTTP/1.1 keep-alive.
pocold is **one consensus thread plus a light lane**, HTTP/1.1 **one request per connection that closes
after its response**. For each mechanism this table records whether pocold **ENFORCES** it as specified,
provides an **EQUIVALENT** (a different mechanism giving the same or a stronger bound, with a proof), or
leaves it **NOT ENFORCED** (with the reason and what stays open). Code: `prototypes/pocold/src/rpc.rs`
(guard), `prototypes/pocold/src/lib.rs` (`RPC_ENFORCED`, `rpc_facts`), `prototypes/lp4-execution/src/native.rs`
(`simulate_for_profile` stop hook). Tests: `prototypes/pocold/tests/net.rs` (loopback sockets) and
`tests/consensus.rs` (direct `rpc::answer`). Running values: `pocol_getParams.rpcLimits`.

"Running value" is what the node runs with (reported to admission by `rpc_facts` and over `pocol_getParams`).
Where it differs from the spec default it is called out; the admission scope is already `experimental-devnet`,
never specification compliance (D-A02-SCOPE), so a looser running value is reported honestly, not as the spec.

## Transport and the S1 invariant (أ)

| spec item | pocold mechanism | status | test | mutant |
|---|---|---|---|---|
| HTTP/1.1 on 127.0.0.1, no HTTP/2, no pipelining | `serve` binds loopback only (else refuses); `respond`/`pace_write` write HTTP/1.1 with `Connection: close` | ENFORCED | existing `rpc_*` tests; `serve` loopback guard | — |
| one request at a time; next not read before sendDone | the connection closes after one response, so there is no next request on it (stronger than "one at a time") | EQUIVALENT (stronger) | every `rpc_*` test (one request/response per connection) | — |
| S1: ≤ 1 reservation and ≤ 1 waiting request per connection | one `conn` thread handles one request; one `Reply` reservation | ENFORCED | `an_answer_is_reserved_until_its_connection_has_written_it` | — |
| SO_SNDBUF = 32 KiB per connection | `std::net::TcpStream` exposes no portable `setsockopt`; per D93 SO_SNDBUF enters **no criterion** (it only shapes the accept/read gap for measurement), and the binding SendPacer rule holds regardless of the send-buffer size | NOT ENFORCED (no effect on any bound; kept absent to stay Windows-portable with no new dependency) | — (reported absent in admission) | — |

## Classification table (ب) and response limits (ج)

| spec item | pocold mechanism | status | test | mutant |
|---|---|---|---|---|
| light table (LIGHT_RESP_MAX 512 KiB) | `LIGHT_METHODS` + `is_light`; a light answer over LIGHT_RESP_MAX is −32008 | ENFORCED | `a_max_size_transaction_is_answered_in_the_light_lane`, rpc unit tests | — |
| heavy table (RESP_MAX 8 MiB) | heavy by default; `capped` → −32008 over RESP_MAX | ENFORCED | `responses_above_resp_max_become_an_error` | — |
| HEAVY_ACTIVE = 4 | one consensus thread ⇒ active heavy ≤ 1 ≤ 4 | EQUIVALENT (stronger); reported as 1 | `rpc_work_deadline_…` (one heavy at a time) | — |
| LIGHT_ACTIVE = 16 | one consensus thread drains the light lane ⇒ active light ≤ 1 ≤ 16 | EQUIVALENT (stronger); reported as 1 | `a_light_turn_runs_at_most_light_turn_requests_then_wakes_the_node` | — |
| HEAVY_QUEUE = 16, QUEUE_WAIT = 2 s → −32021 busy {retryAfterMs} | `reserve_heavy`: a bounded queue of `heavy_queue` places, waiting up to `queue_wait`; overflow is −32021 {busy, retryAfterMs ∈ [250,2000]} | ENFORCED | `heavy_queue_overflow_answers_busy_with_retry_after`, `abandoned_queued_bodies_are_capped_and_released` | RGM3 (no cap → no busy) |
| LIGHT_QUEUE = 32 | light lane capacity = `light_queue`; a full lane is −32021 busy | ENFORCED | `heavy_queue_overflow_…` (coexisting light), `a_light_turn_…` | — |
| per-connection token bucket 20/s, cap 20 → −32021 rate | one request per connection makes a *per-connection* bucket vacuous; a **per-source-IP** bucket (`Buckets`) gives the per-client bound the spec intends and is testable. Default loose (10 000/s) so a 20/s loopback bucket does not throttle the node's own tooling (the site publisher/fetcher burst far above 20/s); the **exact spec values (20/s, cap 20) are enforced under configuration and demonstrated by the test** | EQUIVALENT (per-source IP; default loose, spec values enforced+tested) | `rate_bucket_limits_a_source_then_refills` (rate=20, cap=20) | RGM2 (bucket disabled → no rate) |
| HEAVY_RESP_MEM = 48 MiB | `HEAVY_RESP_POOL` = 48 MiB; a full pool is −32021 busy before anything runs | ENFORCED | `a_full_heavy_pool_answers_busy_before_anything_runs` | existing M4-BUSY |
| LIGHT_RESP_MEM = 16 MiB | light pool = (conn_max+1)·512 KiB = 16.5 MiB ≥ 16 MiB (a light reservation never fails, S1) | ENFORCED (≥ spec) | `response_pools_reserve_shrink_and_release` | — |
| SCRATCH ≤ 16 MiB heavy, ≤ 1 MiB light → −32020 scratch | per-request `Budget` threaded through eth_getLogs/pocol_getLogs (and eth_call), charging the working bytes materialized; overflow is −32020 {scratch} with resume data, partial result dropped | ENFORCED (per-request accounting of handler allocations) | `get_logs_scratch_limit_is_32020_scratch_with_resume_data` | RGM6 (charge removed → no scratch) |
| encoding in 64 KiB segments inside the reservation | pocold builds the answer String within the reservation and shrinks to fit; it does not stream 64 KiB chunks | EQUIVALENT (memory bounded by the reservation; same ≤ reservation bound, not the streaming form) | `an_answer_is_reserved_…` | — |

## Request ownership and COMPUTE_DEADLINE (د, و)

| spec item | pocold mechanism | status | test | mutant |
|---|---|---|---|---|
| REQ_READ_DEADLINE = 10 s | `read_deadline` (whole request: line, headers, body) | ENFORCED | `rpc_connection_cap_…` (idle/trickle readers closed) | — |
| REQ_BUF = 1 MiB | request line + headers + body ≤ REQ_BUF; a header buffer allocated once, a body of exactly Content-Length | ENFORCED | `rpc_request_buffer_covers_headers_and_body` | — |
| IDLE = 30 s between requests | the connection closes after one response, so there is no idle period | EQUIVALENT (no idle period exists) | — | — |
| COMPUTE_DEADLINE 5 s heavy / 500 ms light, from acceptance incl. encoding → −32020 deadline | `Budget.compute_by` = accepted + COMPUTE_HEAVY/LIGHT; checked at handler entry and inside loops; −32020 {deadline} | ENFORCED | `light_compute_deadline_fires`, `heavy_compute_deadline_cancels_eth_call` | RGM4 (light check removed), RGM5 (eth_call stop hook disabled) |
| cancellation every 16 blocks / 1 MiB / 10^6 gas; CANCEL_MAX 100 ms | eth_getLogs checks the deadline every 16 blocks and charges scratch per matched log; eth_call polls the stop hook per loop body and per call/create frame (≥ once per JUMP loop) | EQUIVALENT (checks at least as often as the spec in block/byte terms; the per-10^6-gas check is replaced by a per-loop-body poll, a tighter bound on the gap, ≤ one loop body ≪ CANCEL_MAX) | `heavy_compute_deadline_cancels_eth_call`, `get_logs_scratch_…` | RGM5 |

## SendPacer (د.6, D90/D92/D93/D94)

| spec item | pocold mechanism | status | test | mutant |
|---|---|---|---|---|
| binding rule: close if sendTime > GRACE and A < R·sendTime (R=65536 B/s, GRACE=2 s) | `pace_write`: writes the answer straight from its reservation in chunks; A = bytes the socket accepted, sendTime = wall time since the first byte while A < size; closes on the rule, so a response of `size` bytes holds its reservation at most SEND_MAX(size) = GRACE + size/R + ENFORCE_SLACK | ENFORCED | `send_pacer_closes_a_slow_reader_after_grace` (slow reader closed after GRACE; honest reader delivered) | RGM1 (rule disabled → no close) |
| ENFORCE_SLACK = 200 ms (lateness bound), TIMER_EPS = 1 ms | re-checked after every partial write and at least every `pacer_backstop` (50 ms), so the close lateness is bounded; `pacerLateMaxMs` records it | EQUIVALENT for ENFORCE_SLACK (backstop re-check gives a bounded lateness, recorded); TIMER_EPS NOT ENFORCED (no exact 1 ms tie-break timer — kept absent in admission) | `send_pacer_…` (records pacerLateMaxMs) | — |
| sendDone (A=P=size) releases the reservation; starts IDLE | `pace_write` returns on A=size (sendDone counted); the `Reply` reservation drops at return; the connection then closes | ENFORCED | `send_pacer_…` (sendDone counted), `an_answer_is_reserved_…` | existing M13-RESV |
| PacerTrace (D93): 4 MiB ring of produce/accept/pend/close/sendDone events | pocold records close accounting (`pacerClosed`, `pacerLateMaxMs`, `sendDoneCount`) in the stats record; it does not keep the full per-event ring buffer | NOT ENFORCED (the full trace; the close accounting it gates on is ENFORCED) | `send_pacer_…`, `get_params_and_rpc_stats_…` | — |

## Batches (هـ)

| spec item | pocold mechanism | status | test | mutant |
|---|---|---|---|---|
| ≤ BATCH_MAX = 20 members | `BATCH_MAX`; a larger batch is −32600 | ENFORCED | `rpc_batches_answer_every_member_in_order_and_cap_their_length` | — |
| per-item admission, members run one at a time | members run sequentially on the one consensus thread (≤ 1 active); each member gets its own COMPUTE_DEADLINE and SCRATCH budget | EQUIVALENT (stronger: ≤ 1 active) | `rpc_batches_…`, `rpc_work_deadline_…` (batch tail skipped at the deadline) | existing M5-DEADLINE |
| streamed with chunked encoding | the whole batch answer is built within its reservation (BATCH_BYTES_HARD) then written under the pacer, not streamed per item | EQUIVALENT for memory (bounded by BATCH_BYTES_HARD); NOT ENFORCED for streaming | `an_answer_is_reserved_…` | — |
| BATCH_RESP_MAX = 16 MiB | the member that crosses BATCH_RESP_MAX, and every later one, is −32020 {batchBytes} | ENFORCED | `batch_members_beyond_the_byte_limit_are_not_run` | — |
| BATCH_WALL = 420 s backstop → batchWallHits | `batch_wall` checked between members; the tail is closed with −32020 {batchWall} and `batchWallHits` | ENFORCED (backstop) | covered by the admission R26 `batchWallMin ≤ batchWallMs` predicate and `handle_until_budgeted` | — |

## Other interfaces and stats

| spec item | pocold mechanism | status | test | mutant |
|---|---|---|---|---|
| RPC_CONN_MAX = 32, excess closed unread | `conn_max`; the acceptor refuses (503) and closes without reading | ENFORCED | `rpc_connection_cap_refuses_excess_unread_and_keeps_serving` | — |
| CONN_BUF = 64 KiB | the batch error array ≤ BATCH_MAX·ERR_ITEM_MAX+64 = SMALL_REPLY_MAX ≪ CONN_BUF | EQUIVALENT (the per-connection working/error buffer is bounded below CONN_BUF) | admission R26 `batchMax·errItemMax+64 ≤ connBuf` | — |
| pocol_getParams.rpcLimits | served (light) with the running RpcGuard limits | ENFORCED | `get_params_and_rpc_stats_report_the_limits` | RGM7 (a limit field zeroed) |
| pocol_getRpcStats | served (light) with the stat record pocold tracks (conns, resv, busy/rate counts, pacer closes/lateness, sendDone, scratch high-water, batchWallHits) | ENFORCED (the subset pocold tracks; per-permit gauges/snapshotsOpen/anchorRejects/traceDropped omitted) | `get_params_and_rpc_stats_report_the_limits` | RGM7 |

## Admission (R26) and the A13 RPC memory term

`pocold::RPC_ENFORCED` names the 26 enforced/equivalent fields at their running values; `heavy_active`/
`light_active` are reported as 1 (the single-thread equivalent) and `cancel_max_ms` as 100 (the equivalent
cancellation gap). Three fields stay **absent, never nominal**: `send_sock_buf` (no portable setsockopt; D93
no-criterion), `mem_total` (pocold bounds RPC memory through its own A13 budget, not a 192 MiB field), and
`timer_eps_ms` (backstop re-check, not an exact 1 ms timer). Under the experimental-devnet scope, the 14 R26
predicates reading only enforced fields are checked (all pass) and the 4 reading an absent field are waived and
reported; the specification scope refuses (`specification:rpc-absent`). Tests:
`pocold_admission_is_an_experimental_devnet_with_absent_rpc_mechanisms`,
lp4 `experimental_devnet_waives_only_r26_predicates_reading_absent_fields`.

The A13 resident bound (`pocold::resources::derive`, §2 rpc term) is recomputed for the new caps: queued heavy
bodies are bounded by HEAVY_QUEUE (16), the light lane by LIGHT_QUEUE (32), plus the ≤ 4096-entry token-bucket
map; the SendPacer writes the answer straight from its reservation (no second copy). The bound still fits the
6 GiB budget with its 1/8 reserve (`a13_boot_refuses_a_bound_above_the_memory_budget`,
`a13_bound_breakdown`); A13-DERIVATION.md §2 (rpc row) carries the proposed text.

## Mutants (scratch runner `run_mutations_rpcguard.py`; results in `evidence/MUTATIONS-RPCGUARD.md`)

Each mutant disables one mechanism and the named test must then FAIL (a timeout is incomplete, not caught):
RGM1 SendPacer rule, RGM2 rate bucket, RGM3 HEAVY_QUEUE cap, RGM4 light COMPUTE_DEADLINE, RGM5 eth_call stop
hook (heavy deadline/cancellation), RGM6 getLogs SCRATCH, RGM7 pocol_getParams/getRpcStats limits.
