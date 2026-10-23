# RpcGuard in pocold: two open limits that need a normative decision

**Status: PROPOSED — not approved.** Nothing in this document is implemented. Both items concern
RpcGuard, a local service policy (D87, consensus.md §13): neither touches validity, fork choice,
GenesisSpec, CP values or any protocol constant. Both would still change RPC-visible behaviour
beyond what network.md:182–330 says, so under the audit rules they are proposals only.

Context: development/audit-2026-10-22/RPCGUARD.md (per-item status), the round-2 review of
wf/rpcguard (findings M1, M2, B3) and the fix round on wf/rpcguard-r2.

## P1. RPC request rate across connections (network.md:215–218)

### What the approved text says, and what pocold does

> دلو رموز لكل اتصال بمعدل 20/s وسعة 20: المنفرد يستهلك رمزًا، والدفعة k رموزًا عند التحليل. النقص يعطي
> −32021 {rate, retryAfterMs} دون تنفيذ. … لا انتظار للرموز داخل طلب أو دفعة.

"A token bucket per connection, 20/s with capacity 20. A singleton takes one token, a batch of k
takes k at parse. A shortfall gives −32021 {rate, retryAfterMs} without running. … No waiting for
tokens inside a request or batch."

pocold closes every connection after one response. The fix round applies the bucket exactly as
written, per connection, to that one request (`rpc::rate_refused`): a full bucket of `bucket_cap`
tokens, k tokens taken. At the spec values (capacity 20 = BATCH_MAX) no request within BATCH_MAX is
ever refused. This is the same outcome the spec gives a client that opens a connection per request.

Neither the spec nor pocold bounds the aggregate request rate when clients reconnect: every new
connection starts with a full bucket. The only aggregate bounds are RPC_CONN_MAX (32 concurrent
connections), the admission queues (HEAVY_QUEUE 16, LIGHT_QUEUE 32) and QUEUE_WAIT, which answer
excess load with −32021 {busy}.

Stage A keyed a bucket by source IP instead. The review refuted it and the fix round removed it:

- Any 127/8 source address reaches the loopback listener, so one client could multiply its
  allowance, or reset every bucket by using more than 4096 addresses.
- Honest local tools sharing 127.0.0.1 were limited together.
- Refill was truncated below 1 ms, so sustained traffic above 1000 req/s admitted almost nothing.
- Per-IP keying is not in the approved text.

### Options

| option | rule | aggregate bound | per-client fairness | RPC-visible change |
|---|---|---|---|---|
| A (current) | per connection, on its one request | none beyond the conn cap and the queues | n/a | none (spec as written) |
| B | one bucket per server: rate RPC_CONN_MAX·20/s, capacity RPC_CONN_MAX·20 (640/s, 640) | the spec's persistent-connection aggregate (≤ RPC_CONN_MAX·rate) | none: one client can take it all | −32021 {rate} under aggregate load |
| C | HTTP keep-alive (IDLE 30 s, next request read after sendDone), bucket per connection | as the spec | per connection, as the spec | transport: connections persist; clients that read to EOF must honour Content-Length |
| D (stage A, rejected) | per source IP | none (evadable through 127/8) | wrong: groups honest tools | −32021 {rate} for co-located clients |

### Proposed text, if B is chosen

> pocold (one request per connection): an aggregate bucket per RPC server, refilled continuously at
> RPC_CONN_MAX·rate tokens/s up to RPC_CONN_MAX·bucket_cap, keeping the sub-token remainder between
> requests. A request takes its k tokens after the batch-size check and ORIGIN_DENY; a shortfall is
> −32021 {rate, retryAfterMs = ⌈(k − tokens)/(RPC_CONN_MAX·rate)⌉} without admission.

Tests it would need:

- sustained admission at sub-millisecond arrival intervals equals the refill rate (the refill
  regression the review found);
- a burst above capacity is refused with the right retryAfterMs;
- the local tooling (`pocol-site publish`/`fetch`, e2e_devnet.py, e2e_site.py) stays under the bound.

## P2. CANCEL_MAX for precompile runs (network.md:286)

### What the approved text says, and what pocold does

> رمز يُضبط عند الإغلاق أو أي مهلة، ويُفحص كل 16 كتلة ممسوحة وكل 1 MiB مرمّز وكل 10^6 gas. يحرر كل
> الموارد خلال ≤ CANCEL_MAX = 100 ms.

"A token is set at close or at any timeout, checked every 16 blocks scanned, every 1 MiB encoded and
every 10^6 gas. It releases every resource within ≤ CANCEL_MAX = 100 ms."

The fix round polls the stop hook at least every 10^6 gas of an interpreter frame
(`native::STOP_GAS`; lp4 test `the_stop_hook_is_polled_at_least_every_stop_gas`). A precompile
call is not interpreted, so it runs to its end. With eth_call's 30M gas, one BLAKE2F run of 29.9M
rounds took about 0.5 s on this host. A 20 ms deadline was answered −32020 between 480 and 569 ms
late (net test `a_precompile_call_past_its_deadline_is_32020_not_a_late_success`). The answer is
correct, because a late result is never returned, but cancellation is not bounded by 100 ms.
pocold therefore reports `cancel_max_ms` absent.

### Options

| option | effect on results | bound | cost |
|---|---|---|---|
| A (current) | none | precompile run ≤ its gas × the slowest precompile's time per gas (host-dependent; not proven) | none |
| B | eth_call/eth_estimateGas refuse (−32020 or halt) a single precompile call whose gas exceeds a per-precompile cap derived from a measured worst time per gas | ≤ 100 ms by construction on the measured host | RPC results differ from on-chain execution for large precompile calls |
| C | RPC-only re-implementations of BLAKE2F (poll between rounds), MODEXP and the pairing (poll between pairs) | close to STOP_GAS | duplicated cryptography; equivalence with revm must be proven by vectors |
| D | run each simulation on a worker thread and abandon it at the deadline | the answer at once; CPU and the state copy are released only at the end | breaks the one-thread A13 inventory; does not release resources within 100 ms |

If B or C is chosen, the deciding vectors are: BLAKE2F at 29.9M rounds, MODEXP at its worst
EIP-2565 pricing within 30M gas, and BN254 pairing with 880 pairs. Each is measured on the reference
host and on the Windows CI host.
