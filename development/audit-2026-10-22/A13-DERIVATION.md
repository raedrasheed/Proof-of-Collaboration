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
| snapshots | (1 genesis + K_hist + side_max + 10 transient) × snapshot, plus one snapshot for a table growing in a working copy (old and new tables alive at once, one table at a time) | `Chain::retain` (K_hist window; side states ≤ side_max, lowest work pruned first); transient: apply copy, USER copy, per-tx engine and PAY copies, production clones, pool state and its copies, rolling rebuild (2). The pool's pending state commits through the block's `commit_tx` (EIP-161 cleanup, normalization) and refuses a transaction whose effects would pass SLOT_CAP, ACCT_CAP or SYS_SLOT_MAX (`PoolMeter`, checked against a recount), so it is one snapshot like the others |
| code | snapshots × (CODE_CAP · 9/8 + 97 B per code entry) | `code_caps::validate_snapshot` (logical code per state); counted unshared |
| history | (H_END+1) × per-block + TXBYTES_CAP + TX_CAP × 380 B + LOG_CAP × 33/32 + identities × (EVID_BYTES_MAX+24) | H_END (apply_block); TX_CAP/TXBYTES_CAP chain-cumulative (block invalid); LOG_CAP (USER `Halt::LogCap`); evidence ≤ one per identity ever (a tombstoned record makes further evidence a host error), identities ≤ M_max + R_max · H_END |
| per block | 3 × (map slot of `Entry` 1184 B) + 2 × header_max + bloom/sig/proposer + 8·S + 32·(S+1) shares + 64·M ranges + an empty state | header_max = 768 + 9·S_max (network.md 3067 B for S=256) |
| side blocks (D-REORG-REDB) | (side_cap + 2·R_keep) × (per-block − header_max − E_max·24 + 48) offloaded metadata entries + one full block (per-block + BODY_MAX + min(BODY_MAX/85, GAS_LIMIT/21000) transactions with receipts + LOG_BLOCK_MAX) + EVICTED_MAX × 96 | `Chain::retain`, after every import and on replay. Every journaled non-canonical block is offloaded at that retain: its body (evidence included), receipts, tx hashes and encoded header are dropped and read back from the journal. Live: ≤ side_cap = R_keep = 2048 unprotected (the lowest-work unprotected leaf goes first, repeatedly, so the cap holds right after a reorg too) plus ≤ protect_max = 2·R_keep = 4096 blocks protected by a sync session (network.md:27). Replay: all ≤ side_cap + protect_max (`Chain::replaying`). None R_keep or more below the head, descendants removed with them. The one full block is the just-imported one before its retain, or the block `restore_canonical` is re-executing. Canonical blocks are never offloaded or evicted (history term). Derivation and proofs: proposals/D-REORG-REDB-DESIGN-FREEZE.md Revision 2 |
| queues | pool (32 MiB and ≤ POOL_MAX_TXS = 4096 transactions, plus entries) + orphans (16 MiB) + future (64) + templates (64) + seen caches (4096) + invalid (4096) + rejects (256) + receipt times (1024) + evidence pool (64) + per-peer queues for (peers_max = 8 inbound + one per dialer) + event queues (EVENT_QUEUE 128, NET_EVENT_QUEUE 32 per forwarder) | constants in `node.rs`, `chain.rs`, `net.rs` (A05) |
| rpc | conn_max × (2·(HEAD_MAX + READ_CHUNK) + REQ_BUF) requests + HEAVY_RESP_POOL (48 MiB) + (conn_max + 1) × LIGHT_RESP_MAX (512 KiB) + conn_max × SMALL_REPLY_MAX + queued_max (2·conn_max) × REQ_BUF + conn_max × LIGHT_BODY_MAX + parse tree (`parse_bytes_max`) + answer being built (3 × BATCH_BYTES_HARD + 4 × RESP_MAX) | `rpc.rs`: connection cap (excess refused unread; finished threads joined before their slot is reused), REQ_BUF over request line, headers and body together, a header buffer allocated once and a body of exactly Content-Length; response pools (`answer`: class maximum reserved before the request runs, shrunk to the answer, released when the reply drops; a full heavy pool is −32021 busy before anything runs; a light answer over LIGHT_RESP_MAX is −32008); queued heavy bodies capped (`Held`, 503 beyond); JSON_VALUES_MAX before parsing (−32600); batch members run and serialized one at a time with the delivered bytes ≤ BATCH_RESP_MAX; `capped` (RESP_MAX → −32008); eth_getLogs stopping at RESP_MAX, LOGS_COUNT_MAX or LOGS_SCAN_BYTES |
| threads | (2 × peers_max + 4 × dials + conn_max + 6) × (IO_STACK 256 KiB + 4 KiB heap) + CONSENSUS_STACK 16 MiB + main thread 1 MiB + glibc stack cache 40 MiB | every thread is created by `pocold::threads::spawn` with an explicit reservation, so its resident stack cannot exceed it. Inventory (`resources::io_threads`): per inbound peer a reader and a writer, per configured peer a dialer, a forwarder, a reader and a writer, conn_max RPC connection threads, and 6 singletons (miner, two forwarders, timer, P2P listener, RPC acceptor). Exiting threads count too: the RPC acceptor, the P2P listener and each dialer join a finished thread before its place is reused (`threads::reap`), a reader joins its writer, and the old miner is joined before the next one starts (`miner::PEAK`, tested). The consensus thread runs every command; main only spawns and joins it |
| execution | `memory::execution(max(GAS_LIMIT, PER_CALL_GAS), B_code_max)` for one execution at a time (30M gas: 1,131.2 MiB) | derived from the gas schedule (§3a); eth_call/eth_estimateGas are capped at CALL_GAS_MAX = PER_CALL_GAS (compile-time check); every EVM execution runs on the consensus thread |

### 2a. D-A13-BUDGET: itemized bound, reductions and reserve (round 2)

At 45712cd the corrected model (§3a, rpc term) put the devnet default (default limits, two configured
peers) at 7,112,758,897 B (6.62 GiB), above the 6 GiB budget: `Node::open` refused to boot it. The owner
approved option 1 of D-A13-BUDGET: reduce local, non-consensus limits and keep the 6 GiB budget. That
approval does not cover consensus changes and waives no specification requirement.

Itemized model, before (45712cd) and after (current head `687ac38`: SIDE_BLOCKS_MAX 320, the exiting-threads term). `Bound::items` names every term; at 45712cd's values the
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

**Final code (D-REORG-REDB, `9ce5a7c` and later):** model **5,627,687,516 B**, gate requirement
ceil(8·total/7) = **6,431,642,876 B**, reserve **803,955,360 B = 766.7 MiB**, unused **10,808,068 B =
10.3 MiB**; 5,627,687,516 + 803,955,360 + 10,808,068 = 6,442,450,944 B. Measured RSS on the final code:
row "redb-final" in axis 4. The paragraphs below give the same five axes as recorded at 687ac38, kept
for history.

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
| 2 | R14/R19 timing is a worst-case bound | OPEN | `measure` applies one synthetic GAS_LIMIT compute workload per phase on this host, a representative sample. Not a bound for worst-case state size, world-root rebuild, PAY or settlement paths. Admission condition `timing-not-a-bound` (R14, R19) |
| 3a | thread stacks and the exiting-thread overlap | ENFORCED (measured + conservative) | Every thread is spawned with an explicit reservation and counted at it (io_threads). The inventory is enforced by join ordering: the acceptor, listener and dialers join a finished thread before reusing its place (`threads::reap`); a reader joins its writer; the miner is joined before the next starts. A thread can finish between its reaper's visits: the bound on exiting-not-yet-joined threads is E = peers_max + dials + conn_max (writers join synchronously; singletons never respawn), counted CONSERVATIVELY at a full IO_STACK each (10.5 MiB). Measurement (evidence/threadmem.rs, evidence/THREAD-INVENTORY.md): a finished joinable thread retains only ~25.8 KiB, not 256 KiB — the bulk returns to the glibc stack cache (the 40 MiB STACK_CACHE term) — so the term is an upper bound, not the measured figure, as the owner directed (measurement is evidence, not a guaranteed ceiling). Tests: `peer_threads_stay_within_the_inventory_while_consensus_is_stalled`, `miner_replacement_keeps_at_most_one_miner_thread` (handle high-water 1; mutation fails), F1's lost-wakeup unit test. Residual: the main thread's stack is platform-reserved, counted at 1 MiB (INSPECTION) |
| 3b | allocator per-allocation overhead and fragmentation | OPEN (reserve kept) | Not modelled; the total is requested bytes. The boot gate keeps 1/8 of the budget outside the model (D-A13-BUDGET). Measured: full-cap snapshot clones use 0.45 of their model in RSS; header estimate for history under 8 MB (§2b). Fragmentation is not bounded. Status condition `allocator-overhead` |
| 4 | revm per-transaction journal, engine cache and memory fit in the transient-snapshot allowance | DERIVED (replaced, corrected) | Its own term, §3a (1,131.2 MiB at 30M gas): operation classes (unpaid loads included), memory over a gas split, a fixed part (per-frame code analysis, BLOCKHASH cache). Validated publicly at model level and by private adversarial measurements, each case against its own term (PRIVATE-REVIEW-PACKAGE.md). Depends on the revm 19.7 facts listed in §3a (status condition `revm-representation`). One execution at a time is by INSPECTION |
| 5 | world-root rebuild per block; `eth_getTransactionByHash` chain scan | OPEN (CPU) | Not memory terms; part of the timing obligation (2) |
| 6 | deep-fork rebuild re-executes from the nearest retained ancestor | memory ENFORCED, CPU OPEN | Two snapshots (`a13_rebuild_of_a_deep_fork_keeps_only_the_target_state`); CPU proportional to depth |
| 7 | every new head re-executes the pool | memory ENFORCED, CPU OPEN | ≤ POOL_MAX_TXS, one execution at a time; CPU not bounded |
| 8 | timing measured at load; R25d calibration is synthetic | OPEN for specification | Admission conditions `timing-not-a-bound` and `calibration-synthetic` (R25) |
| 9 | R26 facts for unimplemented RpcGuard mechanisms | FIXED as evidence, mechanisms OPEN | Absent fields enter the gate as 0 and are never nominal. In the experimental-devnet scope, only the R26 predicates reading absent fields are waived (4 checked, 14 waived) and reported. The specification scope refuses (`specification:rpc-absent`). The 22 mechanisms themselves are not implemented |
| 10 | RetentionStore (disk) and redb trie | OPEN | Not implemented. The governance R21 historical-trie model is not exercised. The gate's deferred items `LP4:general-R18`, `LP4:general-R21` and `LP4:caps64-minimum-SYS_SLOT_MAX` remain (admission conditions `gate-deferred-*`) |
| 11 | TRANSIENT_SNAPSHOTS = 10 live clones | INSPECTION | Listed in `resources.rs` with their code locations; no runtime counter. Status condition `transient-snapshot-inventory` |
| 12 | hashbrown layout and entry sizes | DERIVED | Sizes via `size_of`; growth policy validated for the pinned toolchain by `snapshot_model_bounds_measured_clone_bytes` |
| 13 | EVM executions do not overlap | INSPECTION | Blocks, pool, eth_call/estimateGas and admission timing run on the consensus thread (`EXECUTIONS` = 1) |
| 14 | RPC answers held by connections | ENFORCED | Response pools (`rpc::answer`): the class maximum is reserved before the request runs and released when the reply drops; a full heavy pool answers busy before anything runs. Tests `response_pools_reserve_shrink_and_release` and `a_full_heavy_pool_answers_busy_before_anything_runs` (its mutation, reservations never fail, fails) |
| 15 | RPC request bodies, queued and in flight | ENFORCED | A body of exactly Content-Length ≤ REQ_BUF. Queued heavy bodies are capped at queued_max and released when skipped. Test `abandoned_queued_bodies_are_capped_and_released` (peak = cap; its mutation, no cap, fails) |
| 16 | the answer being built: one member's JSON tree and string ≤ 4 × RESP_MAX | INSPECTION | The parse tree of the request is ENFORCED (JSON_VALUES_MAX before parsing, `parse_bytes_max`). The member's result tree is bounded by RESP_MAX of output (`capped`), but its tree-to-text ratio is counted at 4 by inspection |
| 18 | adoption of a heavier competing branch at any depth ≤ R_keep (network.md:144) | **IMPLEMENTED (D-REORG-REDB, owner-approved 2026-10-23); verification on the final commit: REPAIR-REPORT.md §D-REORG-REDB.** Mechanism and proof: proposals/D-REORG-REDB-DESIGN-FREEZE.md Revision 2: metadata fork choice; offloaded side blocks; protected locator sync sessions that re-fetch evicted branches; restore of adopted blocks; replay equal to live. Tests: `adoption_at_the_spec_depth_2048_and_not_at_2049` (release), `r_keep_boundary_adopts_at_depth_r_keep_and_keeps_the_valid_chain_beyond`, `d133_tie_break_at_depth_400_holds_through_eviction_and_refetch` (release), `a_session_branch_is_adopted_through_a_flood_of_competing_side_branches`, `a_sync_session_refetches_an_evicted_branch_and_serves_it`. The round-2 text below is kept for history: | OPEN (architectural); depth raised 256 → 320 | Fork choice (`better`, `rebuild_canonical`) walks a branch's ancestors through resident `self.blocks`, and `retain` drops only leaves (no holes), so a competing branch must be FULLY resident to be adopted: the one-shot adoption depth IS SIDE_BLOCKS_MAX. Round 2 raised it 256 → 320 (the largest value fitting the budget with margin, D-A13-BUDGET addendum) via the tested validate()+insert() path. A branch deeper than 320 is PRESERVED in the journal (lossless) and NOT refused forever; it is simply not adopted in one shot — the node stays on the valid lighter chain (consensus.md D118: fetched by sync; governance.md:200: manual checkpoint beyond R_keep). Reaching R_keep = 2048 within budget needs the block bodies off the heap (~0.85 GB otherwise), i.e. a redb block store + streaming reorg — a consensus-critical mechanism PROPOSED for explicit owner approval (proposals/D-REORG-REDB.md), not implemented. No consensus rule is weakened: the node never adopts an invalid chain. Tests: `adopt_a_heavier_branch_at_the_cap_and_survive_restart` (a 270-deep heavier branch is adopted and survives restart; mutation cap=256 fails it), `a_branch_deeper_than_the_cap_is_preserved_not_adopted` (a 382-deep branch is kept in the journal, not adopted, reopens without panic), and `a_competing_branch_within_side_blocks_max_is_adopted` (150-deep) |
| 17 | the budget's reserve | ENFORCED (gate) | `check` requires the model total ≤ 7/8 of the budget (`RESERVE_KEEP_EIGHTHS`). The boot test asserts that the default boots, that one byte below its requirement is refused, and that exactly the requirement boots |

Consequence:
- The devnet admission is an **experimental-devnet admission** (D-A02-SCOPE), reported as such at boot
  and in `status`.
- The 5.237 GiB model total (5,623,469,297 B) is conditional on:
  - item 3b, which has a 12.5% reserve kept for it but is not proven;
  - item 4's revm facts;
  - items 11, 13 and 16, which rest on inspection.
- It is not a measured value and not a guaranteed ceiling (§2b).
- A13 is not closed: items 1, 2, 3b, 5, 6 (CPU), 7 (CPU), 8 and 10 remain open acceptance obligations.
  Item 18 (R_keep adoption) is implemented by D-REORG-REDB, and its verification status is recorded in
  REPAIR-REPORT.md.

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
