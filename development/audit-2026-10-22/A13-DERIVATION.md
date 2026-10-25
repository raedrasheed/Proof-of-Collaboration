# A13 — resource derivation for the actual representation

Scope: the resident memory of one pocold node (single-host simnet devnet) and the R18/R21 facts that
admission feeds to the gate. The claim is an upper bound on the heap bytes the node's containers request
plus its reserved thread stacks, for the admitted parameter domain, **under the conditions of §4**. It is
not a measurement, and it is not an unconditional bound on the process's resident memory: allocator
overhead and fragmentation are not modelled (§4, item 3b), and some terms rest on code inspection
(items 11, 13 and 16). §2b separates the model total, the measured RSS of a run and a guaranteed ceiling
(there is none). Code: `prototypes/lp4-execution/src/resources.rs` (`memory`), `admission.rs`
(R18/R21 facts), `prototypes/pocold/src/resources.rs` (node bound, checked at `Node::open`).
Arithmetic is checked u128 throughout; an overflow rejects the profile.

## 1. One state snapshot (`resources::memory::snapshot`)

pocold keeps full `revm::InMemoryDB` snapshots (no trie sharing). A hashbrown table with n ≥ 1 entries
has at most max(4, next_pow2(⌈8n/7⌉)) ≤ 6 + 16n/7 buckets, each one entry plus one control byte, plus a
16-byte trailing group (32 bytes counted with alignment). Entry sizes come from `size_of` of the real
types: account entry 216 B, slot 64 B, code entry 96 B, `InMemoryDB` 168 B (Rust 1.97, revm 19.7.0).
The bound holds for every distribution of slots over accounts (each storage table costs at most
6 + 16s/7 buckets), and it includes the 256-entry BLOCKHASH window.

Assumptions and where they are enforced:
- Containers hold only live state. revm's `CacheDB::commit` stores every accessed slot (zero values and
  read-only slots) and the EIP-161 cleanup leaves `NotExisting` entries; `user_phase::normalize` (after
  every USER transaction and SYSTEM call) removes both and shrinks oversized tables, and
  `drop_unreferenced_code` drops unreferenced code at block end. Root-neutral: absent and zero read
  alike in an EmptyDB-backed state. Regression `a13_reads_and_empty_calls_leave_no_container_residue`
  (1000 fresh SLOADs and empty CALLs leave no residue); its mutation (normalization off) fails.
- Accounts ≤ ACCT_CAP + 5 programs (genesis `check_caps`; USER `Halt::AcctCap`, D-A03-CAPS).
- Slots ≤ SLOT_CAP (USER `Halt::SlotCap`) + SYS_SLOT_MAX (post-block check in `verify_candidate`).
- Code entries ≤ accounts + 2 defaults.
- Validation: `resources::tests::snapshot_model_bounds_measured_clone_bytes` measures the bytes a real
  `clone()` allocates (thread-local counting allocator) for spread slots, concentrated slots at
  power-of-two boundaries, a grown-then-cleared table and a real genesis; each is below the model.

## 2. Node bound (`pocold::resources::derive`)

| term | formula | enforced by |
|---|---|---|
| snapshots | (1 genesis + K_hist + side_max + 10 transient) × snapshot (before C-1; after C-1 E3: head, genesis, side_max, MATERIALIZED, 2 transient and the pool's layer, see the C-1 E3 row of the totals table), plus one snapshot for a table growing in a working copy (old and new tables alive at once, one table at a time) | `Chain::retain` (K_hist window; side states ≤ side_max, lowest work pruned first); transient: apply copy, USER copy, per-tx engine and PAY copies, production clones, pool state and its copies, rolling rebuild (2). The pool's pending state commits through the block's `commit_tx` (EIP-161 cleanup, normalization) and refuses a transaction whose effects would pass SLOT_CAP, ACCT_CAP or SYS_SLOT_MAX (`PoolMeter`, checked against a recount), so it is one snapshot like the others |
| code | (3 + side_max) × CODE_CAP · 9/8 + snapshots × 97 B per code entry + one execution's new runtime (max(GAS_LIMIT, PER_CALL_GAS)/200 · 9/8). From C-1 S2 (2026-10-24); before it: snapshots × (CODE_CAP · 9/8 + 97 B per code entry), counted unshared | `code_caps::validate_snapshot` (logical code per state, duplicates counted per account). A state copy shares its runtime buffers (revm `Bytecode`: `Bytes` and an `Arc` jump table; `journal_measure::retained_states_of_one_lineage_share_their_code_buffers`), and under Cancun code leaves a state only in its creating transaction. So one lineage holds one set. A full set each is counted for every side state, for a rebuild or restore in progress, and for the pool's pending state, since a separate execution makes separate buffers (the same test's control) |
| history | From C-1 S1 (2026-10-24): (H_END+1 − W) × (per-block − header_max − E_max·24) offloaded canonical entries + W × per-block + min(W·BODY_MAX, TXBYTES_CAP) + min(W·E_max·EVID_BYTES_MAX, identities × (EVID_BYTES_MAX+24)) + min(W·txs per block, TX_CAP) × 380 B + min(W·LOG_BLOCK_MAX, LOG_CAP) × 33/32 + HISTORY_CACHE (16 MiB) + history.redb allocator (payload × 8 / 4096), with W = min(history_window or K_hist, H_END+1). Before S1: (H_END+1) × per-block + TXBYTES_CAP + TX_CAP × 380 B + LOG_CAP × 33/32 + identities × (EVID_BYTES_MAX+24) | H_END (apply_block); TX_CAP/TXBYTES_CAP chain-cumulative (block invalid); LOG_CAP (USER `Halt::LogCap`); evidence ≤ one per identity ever (a tombstoned record makes further evidence a host error), identities ≤ M_max + R_max · H_END |
| per block | 3 × (map slot of `Entry` 1184 B) + 2 × header_max + bloom/sig/proposer + 8·S + 32·(S+1) shares + 64·M ranges + an empty state | header_max = 768 + 9·S_max (network.md 3067 B for S=256) |
| side blocks (D-REORG-REDB) | (side_cap + 2·R_keep) × (per-block − header_max − E_max·24 + 48) offloaded metadata entries + one full block (per-block + BODY_MAX + min(BODY_MAX/85, GAS_LIMIT/21000) transactions with receipts + LOG_BLOCK_MAX) + EVICTED_MAX × 96 | `Chain::retain`, after every import and on replay. Every journaled non-canonical block is offloaded at that retain: its body (evidence included), receipts, tx hashes and encoded header are dropped and read back from the journal. Live: ≤ side_cap = R_keep = 2048 unprotected (the lowest-work unprotected leaf goes first, repeatedly, so the cap holds right after a reorg too) plus ≤ protect_max = 2·R_keep = 4096 blocks protected by a sync session (network.md:27). Replay: all ≤ side_cap + protect_max (`Chain::replaying`). None R_keep or more below the head, descendants removed with them. The one full block is the just-imported one before its retain, or the block `restore_canonical` is re-executing. Canonical blocks are never evicted; since C-1 S1 those below the resident window are offloaded too (history term). Derivation and proofs: proposals/D-REORG-REDB-DESIGN-FREEZE.md Revision 2 |
| queues | pool (32 MiB and ≤ POOL_MAX_TXS = 4096 transactions, plus entries) + orphans (16 MiB) + future (64) + templates (64) + seen caches (4096) + invalid (4096) + rejects (256) + receipt times (1024) + evidence pool (64) + per-peer queues for (peers_max = 8 inbound + one per dialer) + event queues (EVENT_QUEUE 128, NET_EVENT_QUEUE 32 per forwarder) | constants in `node.rs`, `chain.rs`, `net.rs` (A05) |
| rpc | conn_max × (4·(HEAD_MAX + READ_CHUNK) + REQ_BUF) requests + HEAVY_RESP_POOL (48 MiB) + (conn_max + 1) × LIGHT_RESP_MAX (512 KiB) + conn_max × SMALL_REPLY_PEAK (132,768 B) + HEAVY_QUEUE × (REQ_BUF + 256) + LIGHT_QUEUE × (LIGHT_BODY_MAX + 256) + parse tree (`parse_bytes_max(REQ_BUF)`) + answer being built (VEC × BATCH_BYTES_HARD + 4 × RESP_MAX). Round 3 code (`8039a09` and later); the row as it stood before RpcGuard is below the table | `rpc.rs` RpcGuard (RPCGUARD.md): connection cap (excess refused unread; finished threads joined before their slot is reused); REQ_BUF over request line, headers and body; response pools (the class maximum reserved at admission, shrunk to the answer, released when the Reply drops; a full heavy pool is −32021 busy); HEAVY_QUEUE places and LIGHT_QUEUE capacity, with QUEUE_WAIT bounding every wait before admission (−32021 busy); a queued body shared with its connection through an Arc, never copied (the Arc and the admission state fit the +256 B per body); busy and rate answers on connection threads keep ids as their encodings and take at most SMALL_REPLY_PEAK of heap (the kept id encodings, the answer, its HTTP header and one transient id parse, ID_PARSE_PEAK = 124,032 B; round 3, review RG2-m2: round 2 kept echoed ids as parse trees, up to 340,378 B per busy answer, evidence/rpcguard-r3/busy-path-peaks.log); the per-connection token bucket keeps no state; COMPUTE_DEADLINE from admission, plus a getLogs SCRATCH budget; the SendPacer writes straight from the reservation; JSON_VALUES_MAX before parsing (−32600); batch members one at a time, ≤ BATCH_RESP_MAX; a light answer over LIGHT_RESP_MAX is −32020 {resultBytes} (network.md:210), and `capped` (RESP_MAX → −32020 {resultBytes}); eth_getLogs stopping at RESP_MAX, LOGS_COUNT_MAX or LOGS_SCAN_BYTES |
| threads | (2 × peers_max + 4 × dials + conn_max + 6) × (IO_STACK 256 KiB + 4 KiB heap) + CONSENSUS_STACK 16 MiB + main thread 1 MiB + glibc stack cache 40 MiB | every thread is created by `pocold::threads::spawn` with an explicit reservation, so its resident stack cannot exceed it. Inventory (`resources::io_threads`): per inbound peer a reader and a writer, per configured peer a dialer, a forwarder, a reader and a writer, conn_max RPC connection threads, and 6 singletons (miner, two forwarders, timer, P2P listener, RPC acceptor). Exiting threads count too: the RPC acceptor, the P2P listener and each dialer join a finished thread before its place is reused (`threads::reap`), a reader joins its writer, and the old miner is joined before the next one starts (`miner::PEAK`, tested). The consensus thread runs every command; main only spawns and joins it |
| execution | `memory::execution(max(GAS_LIMIT, PER_CALL_GAS), B_code_max)` for one execution at a time (30M gas: 1,131.2 MiB) | derived from the gas schedule (§3a); eth_call/eth_estimateGas are capped at CALL_GAS_MAX = PER_CALL_GAS (compile-time check); every EVM execution runs on the consensus thread |

The rpc row as it stood from `687ac38` to `3c3792e`, before RpcGuard (kept for history; −32008 was replaced by −32020 {resultBytes} in RpcGuard round 3):

| term | formula | enforced by |
|---|---|---|
| rpc | conn_max × (2·(HEAD_MAX + READ_CHUNK) + REQ_BUF) requests + HEAVY_RESP_POOL (48 MiB) + (conn_max + 1) × LIGHT_RESP_MAX (512 KiB) + conn_max × SMALL_REPLY_MAX + queued_max (2·conn_max) × REQ_BUF + conn_max × LIGHT_BODY_MAX + parse tree (`parse_bytes_max`) + answer being built (3 × BATCH_BYTES_HARD + 4 × RESP_MAX) | `rpc.rs`: connection cap (excess refused unread; finished threads joined before their slot is reused), REQ_BUF over request line, headers and body together, a header buffer allocated once and a body of exactly Content-Length; response pools (`answer`: class maximum reserved before the request runs, shrunk to the answer, released when the reply drops; a full heavy pool is −32021 busy before anything runs; a light answer over LIGHT_RESP_MAX is −32008); queued heavy bodies capped (`Held`, 503 beyond); JSON_VALUES_MAX before parsing (−32600); batch members run and serialized one at a time with the delivered bytes ≤ BATCH_RESP_MAX; `capped` (RESP_MAX → −32008); eth_getLogs stopping at RESP_MAX, LOGS_COUNT_MAX or LOGS_SCAN_BYTES |

The rpc term at the round-3 code, itemized by `a13_bound_breakdown` (evidence/rpcguard-r3/a13-breakdown-8039a09.log):

| rpc item | B | MiB |
|---|---:|---:|
| connection requests (conn_max) | 36,700,160 | 35.0 |
| heavy response pool | 50,331,648 | 48.0 |
| light response pool ((conn_max + 1) × 512 KiB) | 17,301,504 | 16.5 |
| small answers outside the pools (conn_max × SMALL_REPLY_PEAK) | 4,248,576 | 4.05 (0.16 at round 2: conn_max × SMALL_REPLY_MAX) |
| queued heavy bodies (HEAVY_QUEUE = 16) | 16,781,312 | 16.0 (64.0 at 2·conn_max before RpcGuard round 2) |
| light lane (LIGHT_QUEUE = 32) | 139,264 | 0.13 |
| request parse tree | 9,175,040 | 8.75 |
| answer being built | 83,901,632 | 80.0 |
| **rpc total** | **218,579,136** | **208.5** (204.6 at round 2, `fa97594`) |

Notes on the §2 history term (caps track, round 3; no change to the model numbers):
- the logs term uses `caps::LOG_CAP`, which is 2^24 in the caps-test build, so the term is a smaller, still valid upper bound for that build;
- sizing the devnet TX caps to the CAPS-SUSTAINABILITY O2 minima (7.6·10^6 transactions, 3,931,840,000 B) makes the history term 6.98 GiB (with min(LOG_CAP, H_END·LOG_BLOCK_MAX); 7.38 GiB as coded; 10.48 GiB with N1's 2^32) and the whole model 11.12–14.62 GiB at `fa97594` (needing 12.71–16.70 GiB of budget). The 6 GiB gate refuses boot in every case unless canonical bodies and receipts move off the heap (proposals/CAPS-SUSTAINABILITY.md §5b, evidence/caps-r3/o2-memory-fa97594.json).

### 2a. D-A13-BUDGET: itemized bound, reductions and reserve (round 2)

At 45712cd the corrected model (§3a, rpc term) put the devnet default (default limits, two configured
peers) at 7,112,758,897 B (6.62 GiB), above the 6 GiB budget: `Node::open` refused to boot it. The owner
approved option 1 of D-A13-BUDGET: reduce local, non-consensus limits and keep the 6 GiB budget. That
approval does not cover consensus changes and waives no specification requirement.

Itemized model, before (45712cd) and after (`687ac38`, the head when this table was made: SIDE_BLOCKS_MAX 320, the exiting-threads term; later totals in §2b). `Bound::items` names every term; at 45712cd's values the
itemized arithmetic reproduces 45712cd's total exactly (7,071,790,705 B without configured peers, as its
failing boot test printed; two peers add 40,968,192 B).

| group | item | 45712cd (MiB) | after (MiB) |
|---|---|---:|---:|
| snapshots | head and K_hist retained states | 1,259.1 | 1,259.1 |
| snapshots | side_max side-branch states | 305.2 | 76.3 |
| snapshots | transient working copies | 381.5 | 381.5 |
| snapshots | table growth in a working copy | — | 38.2 |
| code | head and K_hist retained states | 135.3 | 135.3 |
| code | side_max side-branch states | 32.8 | 8.2 |
| code | transient working copies | 41.0 | 41.0 |
| history | blocks (H_END+1) | 495.8 | 495.8 |
| history | transaction bytes (TXBYTES_CAP) | 16.0 | 16.0 |
| history | transaction index and receipts (TX_CAP) | 7.2 | 7.2 |
| history | logs (LOG_CAP) | 1,056.0 | 1,056.0 |
| history | evidence | 0.5 | 0.5 |
| side | SIDE_BLOCKS_MAX stored side blocks | 285.2 | 132.3 (cap 256→320, round 2) |
| queues | transaction pool | 124.2 | 62.1 |
| queues | orphan blocks | 16.6 | 16.6 |
| queues | future blocks | 16.0 | 16.0 |
| queues | templates | 32.5 | 32.5 |
| queues | seen sets | 37.3 | 37.3 |
| queues | rejection and evidence caches | 2.0 | 2.0 |
| queues | peer send queues and frames | 85.1 | 25.0 |
| queues | main event queue | 64.1 | 32.0 |
| queues | network event forwarders | 48.0 | 24.8 |
| rpc | connection requests (conn_max) | 33.5 | 35.0 |
| rpc | answers held by connections | 512.2 (32 × 16 MiB) | 64.7 (pools) |
| rpc | queued heavy bodies (queued_max) | 64.0 | 64.0 |
| rpc | light lane (conn_max) | 0.1 | 0.1 |
| rpc | request parse tree | 8.8 | 8.8 |
| rpc | answer being built | 48.0 | 80.0 (corrected) |
| threads | I/O thread stacks and heap | 27.9 | 15.7 |
| threads | exiting not-yet-joined (conservative) | — | 10.5 |
| threads | consensus stack | 16.0 | 16.0 |
| threads | main stack and heap | 1.0 | 1.0 |
| threads | exited-stack cache | 40.0 | 40.0 |
| execution | frames, code analysis, preallocations, precompiles | 128.6 | 128.6 |
| execution | memory and operation classes (worst gas split) | 1,461.4 | 1,002.5 |
| **total** | | **6,783.3** (7,112,758,897 B) | **5,363.1** (5,623,469,297 B) |

Changes, each checked to be local before it was made: none changes block validity, state roots, gas
rules or accepted-transaction semantics, none goes below a normative minimum, and a maximum-size valid
block is processed as before.
- One change failed the reorganization check after it was made: SIDE_BLOCKS_MAX 64 made long competing
  branches unadoptable (second review). It was reverted to the 45712cd value, 256.
- The remaining gap between 256 and R_keep predates this decision and is recorded as §4 item 18.

| change | before → after | saved (MiB) | why it is local and within the specification | operational trade-off |
|---|---|---:|---|---|
| RPC response pools (mechanism) | 16 MiB per connection → 48 MiB heavy + (conn_max+1) × 512 KiB light | 447.5 | modelled on RpcGuard LIGHT_RESP_MAX, HEAVY_RESP_MEM, LIGHT_RESP_MEM (network.md (ج)); RpcGuard is local (consensus.md:29); RPC_CONN_MAX stays 32 | a heavy request meeting a full pool is answered −32021 busy at once (no QUEUE_WAIT); a light answer over 512 KiB is −32008. Not the RpcGuard permit mechanism, so the RpcGuard fields stay absent in admission |
| execution classes (accounting correction) | 1,461.4 → 1,002.5 | 458.9 | proof (§3a): an empty storage map allocates nothing (`loaded_accounts_start_with_unallocated_storage_maps`), so a map's share belongs to the account's first slot | none |
| answer being built (correction) | 48.0 → 80.0 | −32.0 | the batch String grows (counted at 3 × its maximum) | none |
| undercounts found by the second review | — | −41.5 | a working copy's growing table (38.2), the lossy header copy (up to 3 B per input byte), one event held by each blocked forwarder | none |
| light answers | eth_getTransactionByHash carried `raw` beside `input` (about 4 × TX_MAX) | — | the standard fields only (raw only when the transaction does not decode), within network.md:201's 2·TX_MAX + 2 KiB, so a TX_MAX transaction stays answerable in the light lane | none |
| side_max | 8 → 2 | 253.5 | NodeLocal parameter (consensus.md:29: local, outside CP); R11/R20/R21 hold | a third competing side tip's state is pruned and rebuilt on demand from its nearest retained ancestor (CPU, §4 item 6) |
| SIDE_BLOCKS_MAX | 256 → 64 → **256** (reverted) | 179.3 at 256, by the gas bound on transactions per side block | The second review showed that 64 made a heavier branch more than about 64 blocks long unadoptable. network.md:144 requires adoption up to R_keep (2048), and a branch is held as side blocks until it is heavier. 256 is the value at 45712cd. The saving now comes from a proven tightening instead: a validated block holds at most GAS_LIMIT/21,000 = 380 transactions, not BODY_MAX/85 = 2,313 | adoption depth is SIDE_BLOCKS_MAX, reverted to 256 here and then raised to 320 in round 2 (below R_keep: §4 item 18); the cap holds after a reorg; evicted hashes are refused when received again |
| POOL_MAX_BYTES | 64 → 32 MiB | 62.1 | network.md:157 "pool ≤ 64 MiB" (an upper limit) | 256 transactions of TX_MAX (128 KiB) or 4096 small ones; beyond, −32016 |
| peers_max (inbound) | 32 → 8 | 72.3 (queues and threads) | network.md:156 "≤ 50 peers" (an upper limit) | at most 8 inbound peers; a devnet node has 2 |
| EVENT_QUEUE | 256 → 128 | 32.1 | network.md:156 "queue ≤ 256" (an upper limit) | senders block earlier (backpressure) |
| NET_EVENT_QUEUE | 64 → 32 per forwarder | 24.0 | local constant | peer readers block earlier behind a busy node |

Not changed, and why:
- K_hist stays 32 (governance.md:15). Lowering it would save about 42 MiB per block of depth. But a
  fork deeper than K_hist is rebuilt from genesis (up to H_END = 20,000 blocks on the devnet), and the
  RPC trie window narrows (consensus.md §10).
- RPC_CONN_MAX stays 32 (network.md:213).
- Terms set by consensus caps are unchanged: GAS_LIMIT and PER_CALL_GAS, LOG_CAP, H_END, TX_CAP,
  TXBYTES_CAP, ACCT_CAP, SLOT_CAP and SYS_SLOT_MAX.
- TRANSIENT_SNAPSHOTS stays 10: it is an inventory, and lowering it would need proof.

Reserve. The boot gate is now stricter: the model total must fit in 7/8 of the budget
(`RESERVE_KEEP_EIGHTHS`), so 12.5% (768 MiB of 6 GiB) is kept for what the model does not count.
- Devnet default: model total 5,623,469,297 B (5.237 GiB). Required budget ceil(8·total/7) = 6,426,822,054 B (≈ 15 MiB under the 6 GiB budget, over the 768 MiB reserve).
  That leaves 15,628,890 B (≈ 14.9 MiB) unused below the budget (reconciliation and workload RSS: §2b).
- What the reserve is for: allocator chunk headers and size-class rounding, which add up to about 31 B
  per allocation; fragmentation and per-thread arenas, which are not bounded; and the inspection-based
  inventories (§4 items 11, 13, 16).
- Evidence: the measured RSS in §2b. The reserve is a margin, not a proof: §4 item 3b stays OPEN.

The boot test asserts four things separately (`a13_boot_refuses_a_bound_above_the_memory_budget`):
- the approved default boots;
- a budget one byte below its requirement is refused;
- exactly the requirement boots;
- network-scale caps (ACCT_CAP 10^6, SLOT_CAP 4·10^6) are refused.

Second independent review (of 45712cd..b132a05). Its findings and what was done:
- **SIDE_BLOCKS_MAX 64 blocked adoption of branches longer than about 64 blocks (HIGH).** Reverted to
  256, and the gap to R_keep is recorded (§4 item 18).
- **Restart failed on duplicate journal records of re-fetched evicted blocks (HIGH).** Evicted hashes
  are refused on import. Replay retains after every record, as live import does, and skips duplicates
  and records of evicted blocks.
- **The busy path parsed over-limit bodies (MEDIUM).** It now applies JSON_VALUES_MAX first
  (`a_busy_answer_does_not_parse_an_over_limit_body`).
- **The side-block term did not hold right after a reorg (MEDIUM).** Trimming now repeats until the
  cap holds.
- **eth_getTransactionByHash for TX_MAX transactions answered −32008 (MEDIUM).** Fixed: `raw` is
  dropped from the answer.
- **Two tests depended on the host (MEDIUM).** The miner test now stops at height 2 and counts starts;
  the flood test no longer asserts a ratio, and a deterministic wake test was added.
- **Test gaps (LOW).** Added the end-to-end reservation test (`an_answer_is_reserved_until_its_connection_has_written_it`,
  whose mutation fails) and corrected the inventory test's bound for one not-yet-joined RPC thread.
- **Undercounts (LOW).** Added to the model.
- **The stats method reused the spec's name (LOW).** Renamed `pocold_rpcCounters`; pocol_getRpcStats
  stays unavailable.

### 2a-redb. D-REORG-REDB: the side term re-derived (owner-approved storage repair)

The 320 full side blocks (132.3 MiB) are replaced by offloaded metadata. Devnet profile: per-block term
26,067 B; an offloaded entry is 26,067 − 3,072 (encoded header) − 96 (evidence) + 48 (protect-set slot)
= **22,947 B** (`resources::derive`, `side_entry`). Terms printed by `a13_bound_breakdown` on the final
commit (`evidence/a13-breakdown-redb.json`, 9ce5a7c):
- side/offloaded side-block metadata (side_cap + 2·r_keep = 6,144 entries): **140,986,368 B**;
- side/one full block before offload or during restore: **433,635 B**;
- side/evicted-hash FIFO (EVICTED_MAX): **98,304 B**;
- side total **141,518,307 B = 134.96 MiB** (was 320 × 433,563 = 138,740,160 B = 132.31 MiB at 687ac38).
Model total **5,627,687,516 B** (was 5,623,469,297 B): +4,218,219 B = +2,778,147 (side) + 1,440,072, the
`history/blocks` term growing by 72 B per block (20,001 blocks). `Entry` gained `body_off` and
`offloaded`, 24 B per map slot counted three times. Canonical blocks stay whole, so the canonical
history terms keep their meaning and only the slot size changed: storage.md:70 retains them "until the
end", so no RPC scope changed.
New condition recorded: `open-replay-transient`, the whole journal held by `store::open` plus two
replay-index entries per record while replaying. This was pre-existing and is not in the steady-state bound.

### 2b. Model total, measured RSS and guaranteed ceiling

Reported on five separate axes, so none is read as the others.

Model totals, each dated to the code it was computed on (the heading "Final code (D-REORG-REDB,
`9ce5a7c` and later)" used here until round 3 was stale: RpcGuard changed the rpc term after it):

| code | model total | gate requirement ceil(8·total/7) | reserve | unused | source |
|---|---:|---:|---:|---:|---|
| `45712cd` (before D-A13-BUDGET) | 7,112,758,897 B (6.62 GiB) | — (refused) | — | — | §2a |
| `687ac38` (round 2 final code) | 5,623,469,297 B (5.237 GiB) | 6,426,822,054 B | 803,352,757 B | 15,628,890 B | axes 1–3 below |
| **D-REORG-REDB final code** (`9ce5a7c`; unchanged at `3c3792e` and at the caps round-2 head `c3a78e7`) | **5,627,687,516 B (5.241 GiB)** | **6,431,642,876 B** | **803,955,360 B = 766.7 MiB** | **10,808,068 B = 10.3 MiB** | evidence/a13-breakdown-redb.json |
| **integrated head after RpcGuard round 2** (merged at `ba7d294`; measured at `273e785` by the second caps review, at `fa97594` in caps round 3, and at `938cb94` by the third review) | **5,577,343,580 B (5.194 GiB)** | **6,374,106,949 B** | **796,763,369 B = 759.9 MiB** | **68,343,995 B = 65.2 MiB** | evidence/caps-r3/a13-fa97594.log; RPCGUARD.md §8 |
| **round-3 code** (RpcGuard round 3, `8039a09`; merged at `ba67038`; unchanged by round 3c, `dd7d1ec`, and at the head `c959379`) | **5,581,426,268 B (5.198 GiB)** | **6,378,772,878 B** | **797,346,610 B = 760.4 MiB** | **63,678,066 B = 60.7 MiB** | evidence/rpcguard-r3/a13-breakdown-8039a09.log; `a13_bound_breakdown` asserts the total on Linux x86_64 and passes on `2b1a571` (evidence/integration-r3/pocold-2b1a571.log) |

| **C-1 S2** (shared code buffers, 2026-10-24, on the tree after `af2f3a8`) | **5,487,223,178 B (5.110 GiB)** | **6,271,112,204 B** | **783,889,026 B = 747.6 MiB** | **171,338,740 B = 163.4 MiB** | evidence/decision-package/a13-devnet-breakdown-s2.log; the code group drops from 191,130,849 B (182.3 MiB) to 96,927,759 B (92.4 MiB) on the devnet, which is the whole change of the total (−94,203,090 B), and from 54.69 GiB to 9.69 GiB at the network profile (evidence/decision-package/a13-network-profile-s2.log: total 105.83 GiB, gate 120.95 GiB, still far over 6 GiB) |
| **C-1 S1** (canonical history off the heap below the K_hist window, 2026-10-24) | **4,323,240,949 B (4.026 GiB)** | **4,940,846,799 B** | **617,605,850 B = 589.0 MiB** | **1,501,604,145 B = 1432.0 MiB** | evidence/c1-s1/a13-devnet-breakdown-s1.log; the history group is now the window (K_hist full blocks, capped by the chain caps), the offloaded per-block metadata, and history.redb's cache (16 MiB) and allocator. A window of the whole chain reproduces the S2 total except for the logs term, now also bounded per block by LOG_BLOCK_MAX (`a13_bound_breakdown`). Network profile: 105.83 → 90.93 GiB, gate 103.92 GiB (evidence/c1-s1/a13-network-profile-s1.log) |
| **C-1 S3a** (retained canonical states as diffs, 2026-10-24) | **3,601,500,638 B (3.354 GiB)** | **4,116,000,730 B** | **514,500,092 B = 490.7 MiB** | **2,326,450,214 B = 2218.7 MiB** | evidence/c1-s3a/a13-devnet-breakdown-s3a.log. The snapshots are the head, genesis (counted as a full one), side_max, 2 materialized states, the 10 transient copies and the growth copy, against 1 + K_hist + side_max + 10 + growth before. Plus (2·K_hist + side_max + 1) × `diff_max` (resources.rs: the gas schedule bounds a block's changed slots and accounts). Network profile: 90.93 → 41.41 GiB, gate 47.33 GiB (evidence/c1-s3a/a13-network-profile-s3a.log) |
| **C-1 S4** (old canonical entries slimmed, 2026-10-24) | **3,322,680,105 B (3.094 GiB)** | **3,797,348,692 B** | **474,668,587 B = 452.7 MiB** | **2,645,102,252 B = 2522.6 MiB** | evidence/c1-s4/a13-devnet-breakdown-s4.log. The canonical entries deeper than slim_depth (2·R_keep + E_win + 257) are counted at 3 × the inline entry plus an empty state; the others keep the per-block term. history.redb's payload adds each block's nonce ranges. Network profile: 41.41 → 37.96 GiB, gate 43.38 GiB (evidence/c1-s4/a13-network-profile-s4.log) |
| **C-1 E1** (incremental state root, 2026-10-24) | **3,486,909,657 B (3.247 GiB)** | **3,985,039,608 B** | **498,129,951 B = 475.1 MiB** | **2,457,411,336 B = 2343.6 MiB** | evidence/c1-e1/a13-devnet-breakdown-e1.log. A new trie group: the head state's trie, one parent trie derived or built (at most one at a time on the consensus thread; its distinct nodes counted as a whole trie) and the changed paths of the block executed on it (`trie_paths`: 65 nodes per changed slot and per changed account, from `block_writes`). A trie of n keys is counted at 2n nodes of `state_trie::node_bytes` (168 B world, 88 B storage, Arc counts included) plus 2n child pointers; measured on the near-cap devnet state at 162 B per key, branches included (evidence/c1-e1/validation-near-cap-e1.log). The entry grows by its trie handle. Network profile: 37.96 → 40.20 GiB, gate 45.94 GiB; the trie group is 2.23 GiB (evidence/c1-e1/a13-network-profile-e1.log) |
| **C-1 E2** (whole-state checks from a state summary, 2026-10-24) | **3,489,051,177 B (3.249 GiB)** | **3,987,487,060 B** | **498,435,883 B = 475.3 MiB** | **2,454,963,884 B = 2341.2 MiB** | evidence/c1-e2/a13-devnet-breakdown-e2.log. Each entry that is not slimmed holds its state's `state_summary::Summary`, boxed (the per-block term adds its size). Network profile: 40.20 GiB, gate 45.94 GiB (evidence/c1-e2/a13-network-profile-e2.log) |
| **C-1 E3** (executor, pool and RPC on overlays, 2026-10-25) | **3,186,963,844 B (2.968 GiB)** | **3,642,244,394 B** | **455,280,550 B = 434.2 MiB** | **2,800,206,550 B = 2670.5 MiB** | evidence/c1-e3/a13-devnet-breakdown-e3.log. TRANSIENT_SNAPSHOTS 10 → 2 (a block's merged child; a rolling re-execution's state and next merged state), POOL_LAYER_SNAPSHOTS 1 (the pool's layer counted as a whole state until D-7's value bounds it), and the applied block's overlay (`overlay_max`, in the diffs group). `Entry.state` is an `Arc`, so the entry is smaller. Network profile: 28.08 GiB, gate 32.09 GiB (evidence/c1-e3/a13-network-profile-e3.log) |

Each row reconciles exactly: model + reserve + unused = 6,442,450,944 B. Stage A of RpcGuard printed an
intermediate 5,577,577,052 B, which also counted a per-source token-bucket map (233,472 B) that round 2
removed. Round 3 added conn_max × (SMALL_REPLY_PEAK − SMALL_REPLY_MAX) = +4,082,688 B (RPCGUARD.md §8);
the rpc term is 218,579,136 B (208.5 MiB). Measured RSS was last taken on `3c3792e` (row "redb-final"
in axis 4); it was not re-measured on the round-3 code. The paragraphs below give the same five axes
as recorded at 687ac38, kept for history.

**1. Calculated model terms** (`pocold::resources::derive`, every cap at its maximum at once, under §4's
conditions). Devnet default: **5,623,469,297 B = 5.237 GiB**. The itemized terms are §2a's "after" column;
`Bound::items` is the machine-readable form, printed by `a13_bound_breakdown`.

**2. Explicit reserve** (the 1/8 boot gate, `RESERVE_KEEP_EIGHTHS = 7`). The gate admits a boot only when
`budget_required(total) = ceil(8·total/7) ≤ MEM_BUDGET`. For the devnet total that is
ceil(8 × 5,623,469,297 / 7) = **6,426,822,054 B**, so the reserve it holds back is
6,426,822,054 − 5,623,469,297 = **803,352,757 B = 766.1 MiB** for what the model does not count.

**3. Remaining budget** (unused headroom below the 6 GiB cap after the gate):
6,442,450,944 − 6,426,822,054 = **15,628,890 B = 14.9 MiB**.

These three reconcile exactly to the budget:
5,623,469,297 (model) + 803,352,757 (reserve) + 15,628,890 (unused) = 6,442,450,944 B = 6.000 GiB.
The owner's review quoted the pre-round-2 figures "5.20 GiB … 50 MiB". Raising SIDE_BLOCKS_MAX 256 → 320
added 56.0 MiB of side-block state and the exiting-threads term added 10.5 MiB, so the model rose to
5.237 GiB and the unused headroom fell from ≈ 50 MiB to 14.9 MiB. The 766 MiB reserve is unchanged.

**4. Measured peak RSS under each workload.** `tools/measure_rss.py`: a 3-node release devnet, 90 s idle
production, then 90 s of ordinary and bounded-adversarial RPC load. This is what a real run touched; it
reaches none of the caps, so it is not evidence about the worst case and is not the bound.

| run (commit) | workload | peak RSS / node (VmHWM) | threads / node | model total | RSS ÷ model |
|---|---|---:|---:|---:|---:|
| redb-final (`3c3792e`, D-REORG-REDB final code; `evidence/rss-redb-final.json`) | 90 s idle, then 71,466 light + 3,853 30M-gas eth_calls + 352 heavy batches + 193 transfers | 11.98–12.30 MB (idle 10.1–10.3 MB) | 26–29 | 5,627,687,516 B | 0.0021–0.0022 |
| final (`d610492`, code tree-equal to `bb9d8b8`; `evidence/rss-final.json`) | 90 s idle, then 48,065 light + 2,287 30M-gas eth_calls + 242 heavy batches + 187 transfers; height 154, 4 peers each | 12.26–12.32 MB (idle 10.5–10.6 MB) | 26–29 | 5,623,469,297 B | 0.0022 |
| b132a05 (`evidence/rss-b132a05.json`, before the second review's changes) | 39,815 light + 1,960 eth_calls + 194 batches + 187 transfers; height 157, 4 peers | 11.9–12.0 MB | — | 5,506,111,035 B | 0.0022 |
| 10 full-cap state clones (`lp4-execution/tests/rss_snapshot.rs`) | 20,005 accounts, 115,536 slots | +181,104,640 B vs 10 × 40,006,582 B modelled | — | — | 0.45 |

The devnet run sits at 0.22% of the model: a 3-node, 154-block run fills none of the caps (no max side
branch, no full canonical history to H_END, no full response pools). The state-clone run is the only one
that loads the largest single term (snapshots, 1.72 GiB of the model) to its cap, and there the model's
own slack covers the allocator's headers and page use at 0.45 of the modelled bytes. One passing RSS run
is not a worst-case proof.

**5. Unmodelled overhead and unresolved assumptions.** No guaranteed process-memory ceiling exists. The
model leaves open, and the 766 MiB reserve is the margin (not a proof) for:
- allocator per-allocation headers and size-class rounding (glibc ≤ 31 B/allocation; estimated below);
- fragmentation and per-thread arenas (not bounded by anything);
- the inspection-based inventories (§4 items 11, 13, 16);
- the five conditions `derive` records on the live `a13` status (allocator overhead, transient-snapshot
  inventory, main-thread stack, revm representation, CPU/timing), echoed in `evidence/rss-final.json`.

Allocation-header estimate for the large terms (glibc, ≤ 31 B/allocation):
- history: ≈ 10 allocations/block × 20,001 blocks, plus one per receipt (≤ TX_CAP): under 7 MB;
- logs: ≈ 1 per receipt, inside encoded receipts: under 1 MB;
- execution and RPC terms: a few large buffers.

An operating-system limit (cgroup `memory.max`, `RLIMIT_AS`) would turn an overrun into a failure rather
than make the bound hold; none is configured. §4 item 3b stays OPEN.

R21 fact (admission): (K_hist + side_max) × snapshot = 34 × 38.2 MiB = 1.27 GiB ≤ HIST_TRIE_BUDGET, so the devnet is
admitted without the simnet retentionStress exception; at network-scale caps the bound exceeds the budget
and only that exception admits a simnet node (`resource_rules_r14_to_r21`).

### 2c. C-1 E4/E5: the store-mode bound (2026-10-25, `derive` with `Limits::state_store`)

In store mode every retained state is a version pinned in state.redb and read in place. No whole state,
diff or E1 trie is held; the checkpoint encoder refuses an entry that holds one. `derive` itemizes what is
held instead. Each term names the code it rests on (src/resources.rs). Network-profile values are from
evidence/c1-e4/a13-final.log (commit fc24969).

| item | term | why it is bounded | network |
|---|---|---|---:|
| snapshots/the pool's layer | 1 whole state | the pool's gas is not bounded until the D-7 value is approved | 1.63 GiB |
| diffs/the block's overlay | `overlay_max` | as in whole-state mode (C-1 E3) | 0.004 GiB |
| store/a block's batch | `BATCHES` (1) × `batch_max` | one batch at a time: `child_state` and `rolled` commit it before the next block (inspection) | 1.02 GiB |
| store/node cache | `NODE_CACHE` (256 MiB) | resident bytes: `CACHE_ENTRY` + `Node::resident_bytes` per node, enforced by `Cache::put` | 0.25 GiB |
| store/redb page cache | `STATE_PAGE_CACHE` (64 MiB) | set on the builder | 0.06 GiB |
| store/redb allocator | `redb_allocator_bytes(state_file_max)` | redb 2.6.4 keeps, for every 4 GiB region of the file, a buddy allocator sized for the whole region; `redb_region_allocator` mirrors buddy_allocator.rs and bitmap.rs | 1.81 GiB |
| store/stored-version handles | `stored_versions` × `pinned_bytes` | genesis, the K_hist window, side_max, a rolling rebuild, and an abandoned window until `settle` | 0.005 GiB |
| store/a checkpoint being written | `checkpoint_bytes` | its bytes (`REC_MAX` per entry), the entry index, and redb's copy | 0.08 GiB |
| code/read by the execution | one code set | each loaded account's code is read from the store; bounded by CODE_CAP | 1.13 GiB |
| code/the pool's state | one code set | the pool's own creates | 1.13 GiB |
| history/entries without a state | one empty state (C-1 E5) | every such entry shares `chain::empty_state` | 0 |

**The largest state.redb file** (`state_file_max`):
- the head's and genesis's versions whole;
- every other version an entry or a checkpoint pins. Each of those differs from the head by the paths of
  the blocks between them, and by at most a whole state;
- the code every block to H_END can deploy (code is kept for good);
- the checkpoints' snapshots.

Key preimages are no longer a separate term: since E5 a leaf keeps its key's preimage, and the preimage is
released with the leaf.

Everything is counted at STATE_FILE_FACTOR (12). At the network profile every version saturates, about 108
whole-state versions. This is the adversarial worst case on disk: every block makes maximal writes along
65-node paths.

**The file factor** is the file size over the bytes stored (journal_measure::jm_store_mode_disk_impact).
It was measured after live import, after an open resumed from a checkpoint and after an open replayed
from genesis, and after each close (evidence/c1-e4/disk-phases-*.log, disk-impact-final.md):
- at most 6.07 with 14.9 MB stored;
- at most 11.31 with 1.5 to 2.8 MB stored. redb doubles a file while it is below one region, so a small
  file carries more slack; above one region the file grows a region at a time;
- redb's allocated pages are at most 2.38 times the stored bytes.

The first measurement gave about 18. That came from closing: a closing node released every version in a
non-durable transaction of its own, and redb reuses those pages only after a durable commit. Since E5
part 3 a close leaves the versions to the next open, which releases them in one durable transaction.

Below one region the allocator term is one region's allocator, whatever the factor. The factor is not
established for terabyte files (condition `store-file-factor`). Each unit of the factor is about 0.15 GiB
of the network bound.

**Result** (tests/network_budget.rs; the computed bound, not measured RAM):

| profile | whole-state mode | store mode |
|---|---:|---:|
| network (governance.md genesis parameters) | 27.92 GiB (gate 31.91) | **9.67 GiB (gate 11.05)** |
| devnet as pocold boots it | 2.91 GiB (gate 3.33) | 3.36 GiB (gate 3.83) |

How the network store bound moved:
- 10.58 GiB at E4.5 part 1;
- 10.24 GiB after E5 part 1 (no preimage term);
- 9.07 GiB after E5 part 2 (redb's allocator counted as it is built);
- 9.67 GiB after E5 part 3 (the measured factor of 12 in place of history.redb's 8).

At the devnet profile store mode is the larger bound. Its fixed caches and its worst-case batch and file
terms outweigh the small states they replace.

**Measured RSS** is in evidence/c1-e4/disk-impact-final.md. It covers small states and does not test the
bound.

What the store-mode bound still holds at the network profile, and what would lower it, is in
DECISION-PACKAGE.md ("Measured after E4 and E5").

### 2d. D-7 and the audit of what an execution loads and keeps (2026-10-25)

§2c is kept as recorded. This section adds the pool's gas bound (decision D-7, approved 2026-10-25) and
re-derives the terms that depend on it. Before any term was lowered, the code paths of revm 19.7 that load
accounts, slots and code were audited, together with how long the loaded data stays. The audit changed
three terms: one up and two down. It also withdraws one projection.

**D-7, as implemented** (src/node.rs; tests in tests/consensus.rs):
- **The bound.** The pooled transactions' declared gas limits sum to at most G. G is
  `POOL_GAS_BLOCKS` × GAS_LIMIT (4 × 8,000,000 = 32,000,000 at both profiles).
  - It is a local setting: `Limits::pool_gas_max`, or `pocold run --pool-gas-max GAS`.
  - A value below GAS_LIMIT is refused at open, because a transaction a block can hold must fit an empty
    pool.
  - A13 counts the pool at G, so a G the budget cannot hold is refused at open too ("within the resource
    limits").
  - It is pool policy only. No block-validity or consensus rule changes.
- **Admission** (`admit_tx`), in this order:
  1. size: -32014;
  2. decoding and chain: as before;
  3. a duplicate is answered with its hash and counts nothing;
  4. the byte and count bounds: -32016 pool full;
  5. the gas bound: -32016 pool full (gas). This is checked before execution, so a refused transaction
     costs no execution and changes nothing;
  6. execution on the pending state;
  7. the cap meter.
- **Replacement.** There is none. A second transaction with a pooled one's sender and nonce, whatever its
  fee, fails its execution on the pending state (-32000, NonceTooLow) and changes no counter. The pooled one
  leaves only when a new head makes it invalid.
- **Removal.** Only at a new head (`rebuild_pool`). Every pooled transaction is re-executed on the new head.
  One the head included, or one that is no longer valid, is dropped, and the counters are recounted from
  what stays. There is no expiry.
- **Re-insertion after a reorganization** (consensus.md: excluded transactions return to the pool once
  checked again). The order is:
  1. the abandoned blocks' transactions, oldest block first, each block in its own order;
  2. then the previous pool, in its order;
  3. then its backlog.

  Each is admitted within every pool bound. One that no longer fits the gas bound is dropped and is not
  pooled later; a later, smaller one is still admitted.

  **Relay of a returned transaction** (a local policy). A transaction that leaves an abandoned block and is
  admitted again is offered to every peer (`Relay::Offer`, through `Peer::offer`):
  - a peer with half its outbound queue in use does not get it, and the peer is kept;
  - one reorganization can return up to a whole pool at once, so plain gossip, which drops a peer whose queue
    is full, is not used;
  - the previous pool's transactions are not sent again, since they were relayed when first admitted;
  - `pocol_status` reports `stats.reinsertedOffered` and `stats.reinsertedUnoffered`.

  Why: e2e_integrated failed 2 of 4 runs on 919a50c, and failed again in a diagnostic run, at "pools
  settled after the heal". Node c held 7 returned transactions (8,356,420 gas) and no other node had them.
  - A node that is not drawn never builds a block, and c was not drawn at any of the 215–224 heights after
    the heal, nor did it win any of them.
  - The cause is the active set (consensus.md §2: A_h = {lastShare ≥ h−W_act or graceStart ≥ h−W_act}, with
    W_act = 32). At the heal the majority branch was 31–61 heights past the fork point, and c was no longer in A_h. It
    has no assignment and no longer mines (its production reads "mining=false"). It returns only through
    `reactivate`.
  - In the passing run that was checked, the branch was 12 heights past the fork point, and c was drawn 17
    times after the heal.
  - So the membership behaviour is the specified one. The defect was that the returned transactions reached
    nobody else.

  Still open: a returned transaction that a peer refused, or that no peer had room for, stays here until
  this node is drawn. It is not offered again. The peer queue bound is unchanged (the A13 peer term counts
  `queue_bytes_max` per peer).
- **Counters.** `Node::pool_audit` recomputes them from the pool's contents: gas and bytes summed over the
  admitted transactions, backlog bytes over the backlog, each transaction pooled once, and every bound.
  - It held after each of 160 mixed steps: submissions inside and past the bound, duplicates, same-nonce and
    wrong-nonce transactions, relays during a backlog, one-item slices, new heads and reorganizations.
  - Count of each kind of step: 31 admitted, 41 refused for gas, 2 relays in a backlog, 12 heads, 13
    reorganizations.
- **RPC.** eth_sendRawTransaction past the bound answers -32016 with the message "-32016 pool full (gas)".
  pocol_status reports `poolGas` and `poolGasMax`.
- **Revalidation does not hold up consensus.** The run loop takes one event between two slices of
  revalidation. The test runs `Node::run` with the pool at its bound: four BLAKE2F transactions of 7.9M gas,
  which no stop hook can cut short.
  - Two blocks arrive back to back. The second is imported while the first head's revalidation is still
    pending, and an RPC request is answered between slices.
  - In release on 9bd9bc0 (evidence/d7-bound), one such transaction took 189 ms. The second block and the
    answer took 736 ms, against about four transactions plus two imports.
  - The hold measurement at the bound (`d7_pool_revalidation_hold_under_a_heavy_pool`, four such
    transactions): sliced, the longest hold was 193 ms (one transaction); revalidating at once, the import
    held the thread 627 ms.
  - The gas bound alone bounds no time. What bounds the hold is the slice (POOL_SLICE, 50 ms) plus one
    transaction, and that transaction's time is measured, not derived. Gas is not time:
    - BLAKE2F is priced per round;
    - in store mode each cold account is a state.redb read.

**The audit of revm 19.7.** Sources: revm-19.7.0 journaled_state.rs and context/, revm-interpreter-15.2.0
instructions/host.rs and interpreter/contract.rs, and this repository's state_view.rs, view.rs, node_trie.rs
and state_store.rs.

| path | gas paid before the load | code loaded | how long it stays |
|---|---|---|---|
| sender (validation, fee) | none (intrinsic) | store mode: its code is read with the account (`TrieState::info`); a sender with code is then rejected (EIP-3607) | until the transaction ends |
| recipient of the transaction (`make_call_frame`, `load_code`) | none (intrinsic) | yes | until the transaction ends; kept if touched (a call touches it) |
| coinbase (fee) | none (warm, EIP-3651) | store mode: with the account | as above; touched by the fee |
| access-list addresses (`initial_account_load`) | 2,400 each, intrinsic | store mode: with the account | until the transaction ends (untouched) |
| BALANCE, EXTCODESIZE, EXTCODEHASH, EXTCODECOPY, CALL family, SELFDESTRUCT's beneficiary | **none before the load**: the account (and, through `load_code`, its code) is loaded, then the cold or warm cost is charged. A frame that cannot pay keeps the load and fails; a frame costs at least a warm CALL (100) | EXTCODE\* and calls: yes; BALANCE and SELFDESTRUCT: store mode only, with the account | until the transaction ends (a revert only marks it cold) |
| SLOAD | none before the load (the slot is inserted, then 2,100 or 100 is charged) | — | until the transaction ends; an account created in the same transaction keeps every slot it loaded in its committed entry |
| a frame's code | — | revm analyses raw code per frame (`Contract::new` → `to_analysed`): a padded copy and a jump table | until the frame returns (execution term, `fixed_heap`) |
| created code | 200 per byte (deposit) | analysed once | in the state, the layer or the overlay |

Findings:
1. **Store mode reads code with every account.** `TrieState::info` reads the code with the account, and
   `StateStore::code` returns a fresh copy. So in store mode every account load brings its code, whether or
   not the execution runs or reads it. In whole-state mode a load clones the state's `Bytecode`, which
   shares its buffers.
2. **Gas does not bound those copies at the network profile.** An account load costs as little as 100 gas,
   through a frame that runs out of gas after the load.
   - One 30M-gas execution could load 300,000 accounts × B_code_max (32,768) bytes = 9.2 GiB.
   - CODE_CAP (1 GiB) is smaller. The copies are of distinct existing accounts, so they are at most the
     logical code of every existing account.
   - So the store-mode term "code read by the execution in progress" stays one CODE_CAP set: 1.125 GiB at
     the network profile. That set also covers the copies a block's or template's overlay keeps for its
     touched accounts, since one execution and one overlay run at a time.
   - **The projection "a gas-derived execution code bound, about −1.0 GiB" (DECISION-PACKAGE.md, "Measured
     after E4 and E5") is withdrawn.**
   - Loading code lazily (code_hash only, code read on demand) would not change the worst case. EXTCODESIZE
     and EXTCODEHASH load the whole code (`load_code`), unpaid in the same way.
3. **The pool's layer keeps only touched accounts.** `Overlay::commit` takes only touched accounts, and a
   touch is paid:
   - a call or a transfer to a cold account (2,600);
   - a call or transfer to a warm account not loaded before: an access-list entry (2,400 paid), the
     precompiles, the coinbase;
   - a creation (32,000);
   - a self-destruct's beneficiary.

   A touch in a reverted frame is undone (AccountTouched). So with G gas the layer has at most
   3·⌊G/21,000⌋ + ⌊G/2,400⌋ + 32 accounts (`layer_writes`): 17,934 at 32M.
   - In store mode each keeps its code copy, so the pool's code is at most
     min(CODE_CAP, 17,934 × B_code_max) plus its creations (G/200 bytes).
   - In whole-state mode the touched accounts share the head's buffers, and only the creations are new.
4. **A created account keeps every slot it loaded.** That includes zero-valued slots and slots loaded in
   frames that ran out of gas. This was not counted before.
   - **Confirmed by a witness** run on a local node only and kept outside the repository, like the other
     adversarial programs; its log is in evidence/d7-bound. One transaction of 1,000,000 gas left 2,000 slot
     entries in the pool's layer, where counting one slot per 2,900 gas of writes allows 344.
   - So a layer's slot entries are at most ⌊g/2,900⌋ + ⌊g/100⌋ (SLOT_LOAD_GAS_MIN).
   - **Consequence for the block overlay.** `overlay_max` counted changed slots only (one per 2,900 gas) and
     each element at twice its inline size. It is re-derived with `layer_bytes`, every element at
     `memory::entry_bytes`: 0.004 → 0.041 GiB.
   - **Consequence for the pool's layer.** "One whole state" did not bound the layer either: zero-valued
     slots are not counted by SLOT_CAP. Before D-7 the pool's gas was bounded only by POOL_MAX_TXS ×
     GAS_LIMIT, so that term was an undercount. With D-7 the layer is bounded by G.

**The terms after D-7 and the audit** (src/resources.rs: `layer_writes`, `layer_bytes`, `pool_gas`, `overlay_max`;
test `d7_a13_pool_terms_follow_the_gas_bound`):

| item | before (§2c, fc24969) | now | network | devnet |
|---|---|---|---:|---:|
| the pool's layer | one whole state (snapshots) | `layer_bytes(layer_writes(G))` (diffs) | 1.633 → 0.127 GiB | 0.037 → 0.127 GiB |
| the pool's code, store mode | one CODE_CAP set | touched accounts' code (≤ CODE_CAP) + creations | 1.125 → 0.618 GiB | 0.0022 → 0.0041 GiB |
| the pool's code, whole-state mode | one CODE_CAP set | its creations (G/200 bytes) | 1.125 → 0.0003 GiB | 0.0022 → 0.0003 GiB |
| containers of the pool's layer | one snapshot's | inside the two terms above | 0.090 → 0 GiB | |
| the block overlay | changed slots, ×2 | `layer_bytes` of 5/4 GAS_LIMIT + SYSTEM | 0.004 → 0.041 GiB | 0.004 → 0.041 GiB |
| an abandoned body in revalidation | not counted | BODY_MAX + its transactions' headers | +0.0004 GiB | +0.0004 GiB |
| code read by the execution, store mode | one CODE_CAP set | unchanged (finding 2) | 1.125 GiB | 0.0022 GiB |

A bound past POOL_MAX_TXS × GAS_LIMIT counts as that, since the count bound binds first. CODE_CAP binds
the store-mode pool code at the devnet profile, not at the network one. Condition `revm-loading` records
what rests on source inspection.

**Result** (tests/network_budget.rs; the computed bound, not measured RAM):

| profile | whole-state mode | store mode |
|---|---:|---:|
| network | 27.92 → **25.24 GiB** (gate 28.85) | 9.67 → **7.61 GiB** (gate 8.69) |
| devnet | 2.91 → 3.04 GiB (gate 3.47) | 3.36 → 3.48 GiB (gate 3.98) |

At the devnet profile both bounds rose. Their states are small, so the D-7 layer (0.127 GiB) is larger than
the whole state it replaces (0.037 GiB), and the overlay is re-derived. That whole state was not a bound on
the layer (finding 4).

**The network store-mode bound is 7.61 GiB. The model cap is 5.25 GiB (6 GiB with its reserve), so it is
2.36 GiB over.** Its largest terms:

| item | GiB |
|---|---:|
| state.redb allocator | 1.81 (a 14.3 TiB adversarial file, 3,653 regions) |
| execution's code set | 1.125 |
| EVM execution | 1.10 |
| a block's batch | 1.02 |
| history | 0.63 |
| the pool's code | 0.62 |
| node cache | 0.25 |

The options, with their numbers and effects, are in DECISION-PACKAGE.md ("After D-7 and the code-loading
audit"). No bound was lowered to reach the budget.

## 3. System gas (R18) and timing (R14/R19)

- Gas: per-call maxima measured by `resources::tests::sys_gas_envelope_fixture` (worst case plus a
  sweep-deletion scenario, which also exposed two gaps in the earlier P7 fixture: ordinary-phase pruning
  and sweep deletions were never exercised), composed into the worst call sequence per phase; the
  fixture fails if any value exceeds the table. Worst composition 87.7M ≤ G_SYS 96M (measured worst
  block 83.7M). Applicable only inside S_max ≤ 256, M_max ≤ 256, D ≤ 16, E_max ≤ 4, RET ≤ 128; outside
  it the gas facts are absent and R18 fails.
- Timing: measured per profile on the admitting machine (blocks with a GAS_LIMIT compute loop through
  closing and the final block). Representative, not adversarial worst case.

### 3a. EVM execution memory (`resources::memory::execution`, round 2, corrected)

One execution consuming at most G gas, with code at most `B_code_max` (revm 19.7, CANCUN). The first
round-2 version charged each kind of state separately at full gas and assumed that a loaded account or
slot costs its cold gas. The independent review showed that revm loads an entry into the journaled state
and the engine database before it charges the cold cost. So a frame that then runs out of gas keeps one
entry it did not pay for. The model was rewritten accordingly:

- **Operation classes** (`memory::classes`). Each class has the heap one operation leaves behind for the
  rest of the execution (growth peaks included) and the least gas the operation costs. A frame that runs
  out of gas after a load keeps that one entry and cannot load another. Creating the frame costs at least
  a warm CALL (100 gas). The classes:
  - an account loaded unpaid (100 gas);
  - a slot loaded unpaid (100 gas);
  - an account with its first slot (200 gas; it carries both storage maps' own share, since an empty
    hashbrown map allocates nothing, which is tested);
  - a TSTORE slot (100 gas);
  - a journaled write (100 gas);
  - a committed empty frame, whose journal Vec revm keeps after a commit (100 gas);
  - a log (375 gas), and its data and topics (8 gas per byte);
  - created code (200 gas per byte) and a creation (32,000 gas);
  - a modexp output (at most 192 B per 200 gas, EIP-2565).

  Paid loads (cold 2600/2100, access lists 2400/1900) add the same entries for more gas.

  With a accounts, s slots and m ≤ min(a, s) non-empty maps, the bytes are at most A·a + S·s + B·m for at
  least 100(a + s) gas. Over that region the largest bytes per gas is at a = s or on an axis, which are
  the three state classes. Mixing classes adds nothing beyond the largest rate, since each class is linear
  in its own gas (`class_heap`).
- **Memory** (`memory_heap`). At most N = 2·1025 regions are paid for at once (the active frames, plus one
  returned child per frame whose output is held), from disjoint gas, at 3w + ⌊w²/512⌋ ≥ 3w + w²/512 − 1
  each. By convexity their words total at most W = N·(words(g/N + 2) + 1). The bytes counted:
  - the shared buffer, at 3 × its length (Vec capacity ≤ 2 × the length, plus the old buffer while it
    reallocates);
  - the frames' inputs (copies of ranges of their callers' memory);
  - the returned outputs held: 160 B per word.
- **Gas split.** `memory_heap` is increasing and `class_heap` is linear, so on each step of a 4096-point
  grid the sum is at most memory_heap(g_k+1) + class_heap(G − g_k). The bound is the largest of these.
- **Fixed part** (`fixed_heap`). It covers:
  - 1025 frames, each with a 32 KiB stack and a boxed frame of ≤ 4 KiB (size checked by a test);
  - each frame's analysed code: revm re-analyses raw bytecode per frame into a padded copy and a jump
    table, at most max(B_code_max, 49,152 B of init code), with one frame also holding the raw copy;
  - the call-stack and shared-memory preallocations, and small precompile outputs (64 B per frame);
  - 33 fixed accounts;
  - the BLOCKHASH entries the engine database caches (revm asks it only for the last 256 numbers);
  - precompile working memory ≤ 8 × the largest single-frame memory, and 8 MiB of static tables.

At G = 30M and B_code_max = 24,577 the bound is 1,131.2 MiB: fixed part 128.6 MiB, plus 1,002.5 MiB at the
worst gas split.

revm facts it relies on, checked in the revm 19.7.0 / revm-interpreter 15.2.0 sources:
- frames run iteratively from a `Vec<Frame>` (capacity 1025);
- `checkpoint` pushes one journal Vec per frame, and a revert truncates it;
- loads precede the cold charge (host.rs `sload`, `balance`, the call target);
- `Contract::new` analyses raw bytecode per frame;
- the initcode limit is 2 × MAX_CODE_SIZE, unless a code-size limit is set (LP4 sets one only around the
  deposit check);
- BLOCKHASH queries the database only within 256 blocks;
- `Stack` has capacity 1024;
- an empty `HashMap` does not allocate;
- type sizes come from `size_of`.

A revm upgrade requires re-checking these facts.

Validation:
- Public, model-level: `resources::tests::execution_model_bounds_measured_adversarial_peaks`. The earlier
  flood, recursion and memory cases run at 30M gas against the bound. Every peak is far below it (largest:
  TSTORE flood, 93 MB).
- Also public: `loaded_accounts_start_with_unallocated_storage_maps`, which checks the map accounting.
- Private: the measurements that exercise unpaid loads, committed-frame journals and deep recursion with
  large code, each against its own term rather than the total, are kept out of this public repository.
  They are delivered to the owner in the private review package (`evidence/PRIVATE-REVIEW-PACKAGE.md`
  lists the files and hashes). The public tests do not replace them.

## 4. Assumptions, one by one (round 2)

Each assumption of the bound and of the R14/R18/R19/R21/R25/R26 facts, with what was done:
- **ENFORCED**: code now makes it true, and the bound uses the enforced value;
- **DERIVED**: a conservative bound from stated rules, validated by measurement;
- **INSPECTION**: holds by the structure of the code, but no counter or test enforces it;
- **OPEN**: not established. The corresponding acceptance obligation stays open.

The admission reports each open item that affects a gate fact as a `Condition`. A `Scope::Specification`
admission is refused while any remains (D-A02-SCOPE).

| # | assumption | status | basis / remaining obligation |
|---|---|---|---|
| 1 | SYS gas is monotone in the domain fields (GAS_ENVELOPE covers every profile in GAS_DOMAIN) | OPEN | No opcode-level worst-case derivation. Admission condition `gas-monotonicity-assumed` (R18) |
| 2 | R14/R19 timing is a worst-case bound | OPEN | `measure` applies one synthetic GAS_LIMIT compute workload per phase on this host, a representative sample. Not a bound for worst-case state size, world-root rebuild, PAY or settlement paths. Admission condition `timing-not-a-bound` (R14, R19). **Round 3 (JOURNAL-GROWTH-AND-REPLAY.md §3.2a, §3.2d), measured on this host:** one valid one-tx MODEXP block validates in about 1.0 s, and in about 1.3 s with the state at the devnet caps, above the devnet t_exec = 1 s (single_host; R14 requires t_exec ≥ validate_p99, governance.md:93); a valid 380-transfer block re-executes in about 10.2 s on a near-cap devnet state, above t_exec = 1 s and T_blk = 4 s. The admission gate itself was not re-measured |
| 3a | thread stacks and the exiting-thread overlap | ENFORCED (measured + conservative) | Every thread is spawned with an explicit reservation and counted at it (io_threads). The inventory is enforced by join ordering: the acceptor, listener and dialers join a finished thread before reusing its place (`threads::reap`); a reader joins its writer; the miner is joined before the next starts. A thread can finish between its reaper's visits: the bound on exiting-not-yet-joined threads is E = peers_max + dials + conn_max (writers join synchronously; singletons never respawn), counted CONSERVATIVELY at a full IO_STACK each (10.5 MiB). Measurement (evidence/threadmem.rs, evidence/THREAD-INVENTORY.md): a finished joinable thread retains only ~25.8 KiB, not 256 KiB — the bulk returns to the glibc stack cache (the 40 MiB STACK_CACHE term) — so the term is an upper bound, not the measured figure, as the owner directed (measurement is evidence, not a guaranteed ceiling). Tests: `peer_threads_stay_within_the_inventory_while_consensus_is_stalled`, `miner_replacement_keeps_at_most_one_miner_thread` (handle high-water 1; mutation fails), F1's lost-wakeup unit test. Residual: the main thread's stack is platform-reserved, counted at 1 MiB (INSPECTION) |
| 3b | allocator per-allocation overhead and fragmentation | OPEN (reserve kept) | Not modelled; the total is requested bytes. The boot gate keeps 1/8 of the budget outside the model (D-A13-BUDGET). Measured: full-cap snapshot clones use 0.45 of their model in RSS; header estimate for history under 8 MB (§2b). Fragmentation is not bounded. Status condition `allocator-overhead` |
| 4 | revm per-transaction journal, engine cache and memory fit in the transient-snapshot allowance | DERIVED (replaced, corrected) | Its own term, §3a (1,131.2 MiB at 30M gas): operation classes (unpaid loads included), memory over a gas split, a fixed part (per-frame code analysis, BLOCKHASH cache). Validated publicly at model level and by private adversarial measurements, each case against its own term (PRIVATE-REVIEW-PACKAGE.md). Depends on the revm 19.7 facts listed in §3a (status condition `revm-representation`). One execution at a time is by INSPECTION |
| 5 | world-root rebuild per block; `eth_getTransactionByHash` chain scan | OPEN (CPU) | Not memory terms; part of the timing obligation (2). **Measured (round 3, §3.2b):** `apply_block` clones the state and recomputes the whole world root on every block, about 3 µs per live slot and about 6 µs per account on the devnet (about 0.23 s with both devnet caps nearly full); at the network caps the world root alone takes about 14.4 s (synthetic state). **Round 3c (§3.2d):** every USER tx runs `validate_snapshot` and two whole-snapshot clones, and every scan keccaks each runtime (`code_len` hash_slow), so re-execution is the per-block term + txs × (validate_snapshot + 2 clones) + creates × current_total, each O(accounts + slots + logical code bytes). Measured near the devnet caps: 380-transfer block 10.2 s, CREATE2 child 2.4 s (about 8 ms per create), empty block 0.41 s; attributed by four scratch timing mutants. The create term `current_total` is 0.47–0.54 s per 247-create block at the devnet ACCT_CAP (accounts only, §3.2c). Network: about 7.9 s per tx projected (linear, about 512× beyond the measured code range). Round 3b's "a create-heavy block is the per-block worst" was withdrawn in round 3c |
| 6 | deep-fork rebuild re-executes from the nearest retained ancestor | memory ENFORCED, CPU OPEN | Two snapshots (`a13_rebuild_of_a_deep_fork_keeps_only_the_target_state`); CPU proportional to depth. **Round 3 (§5.3):** below K_hist the nearest retained ancestor is genesis, and a deep reorg pays the rebuild twice, because `retain` prunes the canonical fork point below head−K_hist: per block 1.8 ms (empty) to about 1.0 s (worst kind measured); a depth-2048 reorg near the devnet tip takes 96 s (empty) to about 11 h (worst kind), in two stalls that each exceed D_att |
| 7 | every new head re-executes the pool | memory ENFORCED, CPU OPEN | ≤ POOL_MAX_TXS, one execution at a time; CPU not bounded. **Measured in a loaded reorg (round 3, §5.3):** the adopting import's pool re-execution of 50 abandoned one-tx MODEXP transactions took about 50 s; the bound of up to 1024 blocks (REORG_RESTORE_MAX) is from reading the code. **Since `462fffc`** (PR #27 review thread): the walk reaches the common ancestor, so up to R_keep = 2,048 abandoned blocks are restored (the old walk stopped after 2·1,024 steps and lost the oldest ones). Their bodies are read from the journal one at a time; an unmodelled transient, a copy of every detached transaction (≤ TXBYTES_CAP = 16 MiB on the admitted profiles), is gone |
| 8 | timing measured at load; R25d calibration is synthetic | OPEN for specification | Admission conditions `timing-not-a-bound` and `calibration-synthetic` (R25) |
| 9 | R26 facts for unimplemented RpcGuard mechanisms | FIXED as evidence; mechanisms IMPLEMENTED in part (round 3) | Absent fields enter the gate as 0 and are never nominal. Round 2 recorded: 4 predicates checked, 14 waived; the 22 mechanisms not implemented. **Round 3 (RPCGUARD.md §8):** RpcGuard is implemented (owner approved); 25 facts are present at their running values, 6 of them by an equivalent bound named in the admission notes; 4 are absent (scratch_heavy, scratch_light, mem_total, cancel_max_ms). In the experimental-devnet scope 15 of the 18 R26 predicates are checked and pass, and 3 are waived and reported. The specification scope still refuses (`specification:rpc-absent`) |
| 10 | RetentionStore (disk) and redb trie | OPEN | Not implemented. The governance R21 historical-trie model is not exercised. The gate's deferred items `LP4:general-R18`, `LP4:general-R21` and `LP4:caps64-minimum-SYS_SLOT_MAX` remain (admission conditions `gate-deferred-*`) |
| 11 | TRANSIENT_SNAPSHOTS = 10 live clones (C-1 E3: 2, plus POOL_LAYER_SNAPSHOTS = 1) | INSPECTION | Listed in `resources.rs` with their code locations; no runtime counter. Since C-1 E3 the block, production, template selection, RPC simulation and the pool run on overlays, and the two remaining copies are named in `resources.rs`. Status condition `transient-snapshot-inventory` |
| 12 | hashbrown layout and entry sizes | DERIVED | Sizes via `size_of`; growth policy validated for the pinned toolchain by `snapshot_model_bounds_measured_clone_bytes` |
| 13 | EVM executions do not overlap | INSPECTION | Blocks, pool, eth_call/estimateGas and admission timing run on the consensus thread (`EXECUTIONS` = 1) |
| 14 | RPC answers held by connections | ENFORCED | Response pools (`rpc::answer`): the class maximum is reserved before the request runs and released when the reply drops; a full heavy pool answers busy before anything runs. Tests `response_pools_reserve_shrink_and_release` and `a_full_heavy_pool_answers_busy_before_anything_runs` (its mutation, reservations never fail, fails) |
| 15 | RPC request bodies, queued and in flight | ENFORCED | A body of exactly Content-Length ≤ REQ_BUF. Queued heavy bodies are capped at queued_max (HEAVY_QUEUE = 16 since RpcGuard round 2) and released when skipped. Test `abandoned_queued_bodies_are_capped_and_released` (peak = cap; its mutation, no cap, fails); since `1cc96c4` it runs with HEAVY_QUEUE 2, QUEUE_WAIT 5 ms and up to 12 rounds, assertions unchanged (Windows run 20 flake) |
| 16 | the answer being built: one member's JSON tree and string ≤ 4 × RESP_MAX | INSPECTION | The parse tree of the request is ENFORCED (JSON_VALUES_MAX before parsing, `parse_bytes_max`). The member's result tree is bounded by RESP_MAX of output (`capped`), but its tree-to-text ratio is counted at 4 by inspection |
| 18 | adoption of a heavier competing branch at any depth ≤ R_keep (network.md:144) | **IMPLEMENTED (D-REORG-REDB, owner-approved 2026-10-23); verification on the final commit: REPAIR-REPORT.md §D-REORG-REDB.** Mechanism and proof: proposals/D-REORG-REDB-DESIGN-FREEZE.md Revision 2: metadata fork choice; offloaded side blocks; protected locator sync sessions that re-fetch evicted branches; restore of adopted blocks; replay equal to live. Tests: `adoption_at_the_spec_depth_2048_and_not_at_2049` (release), `r_keep_boundary_adopts_at_depth_r_keep_and_keeps_the_valid_chain_beyond`, `d133_tie_break_at_depth_400_holds_through_eviction_and_refetch` (release), `a_session_branch_is_adopted_through_a_flood_of_competing_side_branches`, `a_sync_session_refetches_an_evicted_branch_and_serves_it`. The round-2 text below is kept for history: | OPEN (architectural); depth raised 256 → 320 | Fork choice (`better`, `rebuild_canonical`) walks a branch's ancestors through resident `self.blocks`, and `retain` drops only leaves (no holes), so a competing branch must be FULLY resident to be adopted: the one-shot adoption depth IS SIDE_BLOCKS_MAX. Round 2 raised it 256 → 320 (the largest value fitting the budget with margin, D-A13-BUDGET addendum) via the tested validate()+insert() path. A branch deeper than 320 is PRESERVED in the journal (lossless) and NOT refused forever; it is simply not adopted in one shot — the node stays on the valid lighter chain (consensus.md D118: fetched by sync; governance.md:200: manual checkpoint beyond R_keep). Reaching R_keep = 2048 within budget needs the block bodies off the heap (~0.85 GB otherwise), i.e. a redb block store + streaming reorg — a consensus-critical mechanism PROPOSED for explicit owner approval (proposals/D-REORG-REDB.md), not implemented. No consensus rule is weakened: the node never adopts an invalid chain. Tests: `adopt_a_heavier_branch_at_the_cap_and_survive_restart` (a 270-deep heavier branch is adopted and survives restart; mutation cap=256 fails it), `a_branch_deeper_than_the_cap_is_preserved_not_adopted` (a 382-deep branch is kept in the journal, not adopted, reopens without panic), and `a_competing_branch_within_side_blocks_max_is_adopted` (150-deep) |
| 17 | the budget's reserve | ENFORCED (gate) | `check` requires the model total ≤ 7/8 of the budget (`RESERVE_KEEP_EIGHTHS`). The boot test asserts that the default boots, that one byte below its requirement is refused, and that exactly the requirement boots |

Consequence:
- The devnet admission is an **experimental-devnet admission** (D-A02-SCOPE), reported as such at boot
  and in `status`.
- The model total (5,581,426,268 B = 5.198 GiB at the round-3 code; 5.237 GiB, 5,623,469,297 B, when
  this list was written at 687ac38; dated totals in §2b) is conditional on:
  - item 3b, which has a 12.5% reserve kept for it but is not proven;
  - item 4's revm facts;
  - items 11, 13 and 16, which rest on inspection.
- It is not a measured value and not a guaranteed ceiling (§2b).
- A13 is not closed: items 1, 2, 3b, 5, 6 (CPU), 7 (CPU), 8 and 10 remain open acceptance obligations.
  Item 18 (R_keep adoption) is implemented by D-REORG-REDB, and its verification status is recorded in
  REPAIR-REPORT.md.
- Round 3 adds the critical performance findings below and keeps the three journal obligations OPEN.

### 4a. Critical performance findings (round 3, 2026-10-24): all OPEN

Measured on this host on the devnet profile (JOURNAL-GROWTH-AND-REPLAY.md, journal rounds 3–3c; code
whose src equals `fa97594`'s, so they apply to the head). Each is a lower bound on the worst case. None
is mitigated; the mitigations in §7 of the journal report are PROPOSED.

| finding | measured | limit it exceeds | cause | items |
|---|---|---|---|---|
| a valid block of 380 transfers on a devnet state with accounts, slots and code near the caps | about 10.2 s (`1d094de`, evidence/journal-r3c/txstate.log) | T_blk = 4 s (and t_exec = 1 s) | per-tx `code_caps::validate_snapshot` plus two whole-snapshot clones (`native::build_engine`), and a keccak of every runtime on each scan (`code_caps::code_len`) | 2, 5 |
| the worst measured one-transaction full-gas block (MODEXP, small even modulus, long exponent) | about 1.0 s (0.96–1.08 s; about 1.3 s with the state at the devnet caps) | devnet t_exec = 1 s | per-gas cost of the precompile, about 128 ns/gas | 2 |
| the whole state root on every block | about +0.23 s per block near the devnet SLOT_CAP/ACCT_CAP; about 14.4 s per block at network caps (synthetic) | grows with the live state | `apply_block` clones the state and rebuilds the world root | 5 |
| the worst devnet open at H_END | about 7.3 h, plus about 8.5 min of TX_CAP-bounded transfer blocks | none stated; a restart takes hours | open replays every record from genesis (journal obligation) | 2, 6 |

The three journal obligations (§8 of the journal report) stay OPEN: disk growth (no compaction; the
solicited re-fetch re-journal vector), re-execution from genesis (open, and the deep-fork rebuild paid
twice), and the open-time memory transient (about 1.0× the journal on top of the steady chain; condition
`open-replay-transient`). The network profile is not admissible on pocold (TXBYTES_CAP = 8 GiB alone
exceeds the 6 GiB budget), so every network figure is a projection.

## 4-r1. Open obligations as recorded in round 1 (kept for history)

1. Gas monotonicity in the domain fields is assumed, not proved; no opcode-level worst-case derivation.
2. R14/R19 timing is a representative measurement, not a worst-case bound (e.g. worst-case state size
   for the full world-root rebuild per block, or worst-case PAY/settlement paths).
3. Thread stacks are assumed to keep ≤ 64 KiB resident; allocator fragmentation and per-allocation
   headers are not modelled.
4. revm's per-transaction journal and engine cache grow with the keys a transaction touches (bounded by
   gas, ≈ GAS_LIMIT/2100 slots, a few MiB) and are covered only by the transient-snapshot allowance.
5. The full world root is rebuilt from all accounts every block (CPU proportional to state size), and
   `eth_getTransactionByHash` scans the canonical chain; both are CPU, not memory, costs.
6. A deep-fork rebuild re-executes every block from the nearest retained ancestor (memory is now two
   snapshots, CPU is proportional to the depth).
7. Every new head re-executes the pool (≤ POOL_MAX_TXS transactions, each on a copy of the pending
   state): CPU, not memory.
8. R14/R19 timing is measured when a node loads the devnet (`load_spec`, used by `run` and `status`), on
   that machine; the record init-devnet writes is informational. R25d is the declared synthetic devnet
   calibration (`--work-bits`), not a measured hash rate.
9. R26 receives pocold's implemented RpcGuard values from its code (`pocold::rpc_facts`: connection cap,
   request size, RESP_MAX, BATCH_MAX, BATCH_RESP_MAX, LOGS_COUNT_MAX, LOGS_SCAN_BYTES). pocold does not
   implement the remaining RpcGuard mechanisms: HEAVY/LIGHT response memory accounting, scratch budgets,
   BatchStreamer pacing, rate buckets, RPC_MEM_TOTAL. Those fields keep their nominal values; the memory
   they would bound is covered by the RPC term above instead.
10. The node bound covers pocold's in-memory representation only; the spec's RetentionStore (disk) and
   redb-based trie are not implemented, so the governance R21 historical-trie model is not exercised.
