# A13 — resource derivation for the actual representation

Scope: the resident memory of one pocold node (single-host simnet devnet) and the R18/R21 facts that
admission feeds to the gate. The claim is an upper bound on the heap bytes the node's containers request
plus its reserved thread stacks, for the admitted parameter domain, **under the conditions of §4**. It is
not a measurement, and it is not an unconditional bound on the process's resident memory: allocator
overhead and fragmentation are not modelled (§4, item 3b), and some terms rest on code inspection
(items 4, 11 and 13). Code: `prototypes/lp4-execution/src/resources.rs` (`memory`), `admission.rs`
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
| snapshots | (1 genesis + K_hist + side_max + 10 transient) × snapshot | `Chain::retain` (K_hist window; side states ≤ side_max, lowest work pruned first); transient: apply copy, USER copy, per-tx engine and PAY copies, production clones, pool state and its copies, rolling rebuild (2). The pool's pending state commits through the block's `commit_tx` (EIP-161 cleanup, normalization) and refuses a transaction whose effects would pass SLOT_CAP, ACCT_CAP or SYS_SLOT_MAX (`PoolMeter`, checked against a recount), so it is one snapshot like the others |
| code | snapshots × (CODE_CAP · 9/8 + 97 B per code entry) | `code_caps::validate_snapshot` (logical code per state); counted unshared |
| history | (H_END+1) × per-block + TXBYTES_CAP + TX_CAP × 380 B + LOG_CAP × 33/32 + identities × (EVID_BYTES_MAX+24) | H_END (apply_block); TX_CAP/TXBYTES_CAP chain-cumulative (block invalid); LOG_CAP (USER `Halt::LogCap`); evidence ≤ one per identity ever (a tombstoned record makes further evidence a host error), identities ≤ M_max + R_max · H_END |
| per block | 3 × (map slot of `Entry` 1184 B) + 2 × header_max + bloom/sig/proposer + 8·S + 32·(S+1) shares + 64·M ranges + an empty state | header_max = 768 + 9·S_max (network.md 3067 B for S=256) |
| side blocks | SIDE_BLOCKS_MAX (256) × (per-block + BODY_MAX + receipts + LOG_BLOCK_MAX) | `Chain::retain`: ≤ 256 non-canonical blocks (lowest-work leaves leave first), none R_keep (2048) or more below the head, descendants removed with them |
| queues | pool (64 MiB and ≤ POOL_MAX_TXS = 4096 transactions, plus entries) + orphans (16 MiB) + future (64) + templates (64) + seen caches (4096) + invalid (4096) + rejects (256) + receipt times (1024) + evidence pool (64) + per-peer queues for (peers_max inbound + one per dialer) + event queues | constants in `node.rs`, `chain.rs`, `net.rs` (A05) |
| rpc | conn_max × (REQ_BUF + HEAD_MAX + BATCH_RESP_MAX + BATCH_MAX × 256 B) + BATCH_RESP_MAX + 4 × RESP_MAX | `rpc.rs`: connection cap (excess refused unread), REQ_BUF over request line, headers and body together (network.md:229; `rpc_request_buffer_covers_headers_and_body`), headers alone ≤ HEAD_MAX, batch members run and serialized one at a time with the delivered bytes ≤ BATCH_RESP_MAX (later members −32020 {batchBytes}, not run), `capped` (RESP_MAX → −32008 with the request id), eth_getLogs stopping at RESP_MAX of result, LOGS_COUNT_MAX or LOGS_SCAN_BYTES (−32020 with resume data) |
| threads | (2 × peers_max + 4 × dials + conn_max + 6) × (IO_STACK 256 KiB + 4 KiB heap) + CONSENSUS_STACK 16 MiB + main thread 1 MiB + glibc stack cache 40 MiB | every thread is created by `pocold::threads::spawn` with an explicit reservation, so its resident stack cannot exceed it (round 2). Inventory (`resources::io_threads`): per inbound peer a reader and a writer, per configured peer a dialer, a forwarder, a reader and a writer, conn_max RPC connection threads, and 6 singletons (miner, two forwarders, timer, P2P listener, RPC acceptor). The miner is joined when replaced; a peer reader joins its writer, delivers Closed, and only then releases its slot; an RPC thread releases its slot as its last action. The consensus thread runs every command; main only spawns and joins it |
| execution | `memory::execution(max(GAS_LIMIT, PER_CALL_GAS))` for one execution at a time (30M gas: 890.7 MiB) | derived from the gas schedule (§3a); eth_call/eth_estimateGas are capped at CALL_GAS_MAX = PER_CALL_GAS (compile-time check); every EVM execution runs on the consensus thread |

Single-host devnet default (D-A13-PROFILE; side_max 8, default limits, two configured peers): **5.87 GiB**
≤ the 6 GiB node budget (`node::MEM_BUDGET`), under the conditions of §4: snapshots 51 × 38.2 MiB, code
209.1 MiB, history 1575.6 MiB (LOG_CAP dominates), side blocks 285.2 MiB, queues 426.0 MiB, RPC 592.7 MiB,
threads 84.9 MiB, execution 890.7 MiB (record: `a13_boot_refuses_a_bound_above_the_memory_budget` prints
`A13-BOUND`). History of the figure: 4.71 GiB before the first independent review (the RPC term had counted
one RESP_MAX response per connection while a batch could build more, and the pool's pending state was not
capped); 4.92 GiB after it; 5.87 GiB in round 2, once thread stacks were counted at their enforced
reservations instead of an assumed 64 KiB resident each, and EVM execution memory got its own derived term
instead of being assumed inside the transient-snapshot allowance. The node reports the bound and its
conditions in `status` (`a13`). A budget below the bound, or
network-scale caps (ACCT_CAP 10^6, SLOT_CAP 4·10^6), make `Node::open` refuse to boot
(`a13_boot_refuses_a_bound_above_the_memory_budget`).

R21 fact (admission): (K_hist + side_max) × snapshot = 1.49 GiB ≤ HIST_TRIE_BUDGET, so the devnet is
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

### 3a. EVM execution memory (`resources::memory::execution`, round 2)

One execution consuming at most G gas (revm 19.7, CANCUN). Every term is paid in gas:
- memory: at most 2·1025 regions are paid for at once (the active frames, plus one returned child per frame
  whose output is still held). A region of w words costs 3w + w²/512, from disjoint gas, so by convexity
  their total is at most W = 2050 · words(G/2050). The shared buffer keeps at most twice its peak (Vec
  growth). Each frame's input is a range of its caller's memory. Each frame holds one return buffer: either
  a returned child's memory or a precompile output no larger than the caller's memory, plus 64 B. Total:
  128·W bytes;
- stacks and frames: 1025 × (1024 words + 4 KiB);
- journal: every entry-producing operation costs ≥ 100 gas and adds ≤ 2 entries, plus two per frame;
  Vec growth doubles;
- transient storage (TSTORE ≥ 100 gas per key) and loaded state (cold account ≥ 2400 gas, cold slot ≥ 1900
  gas including access lists, plus 32 fixed accounts): each table counted at twice its final size (rehash),
  and loaded state counted twice (it is also cached by the engine DB);
- logs: data ≤ G/8 B, ≤ G/375 entries and topics. Created code ≤ G/200 B (code deposit) plus its analysis,
  ≤ G/32000 creations;
- precompile working memory ≤ 8 × the largest single-frame memory, plus 8 MiB of static tables.

revm facts it relies on were checked in the revm 19.7.0 / revm-interpreter 15.2.0 sources:
- frames run iteratively from a `Vec<Frame>` (capacity 1025), not by recursion;
- `SharedMemory::free_context` truncates the buffer to the caller's checkpoint;
- `Stack` is a `Vec` with capacity 1024;
- the JournalEntry variants are the ones listed above;
- type sizes come from `size_of`.

Validation (`resources::tests::execution_model_bounds_measured_adversarial_peaks`, peak heap through a
counting allocator, 30M gas): bound 933,973,782 B. Measured peaks:

| case | peak (B) |
|---|---|
| TSTORE flood | 93,126,494 |
| cold SLOAD flood | 4,286,765 |
| LOG flood | 6,781,034 |
| largest single-frame memory returned whole | 7,930,802 |
| memory-carrying recursion 1 KiB | 17,355,638 |
| memory-carrying recursion 16 KiB | 25,507,382 |
| 3.9 MB identity output held as return data | 5,962,507 |

The bound is loose by design (the 63/64 rule limits depth far more than convexity assumes). A revm
upgrade requires re-checking the listed facts.

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
| 3a | thread stacks keep ≤ 64 KiB resident | ENFORCED (replaced) | Every thread is spawned with an explicit reservation and counted at it. The thread inventory is enforced by join/release ordering (miner joined, reader joins writer, slots released last). Invariant test `peer_threads_stay_within_the_inventory_while_consensus_is_stalled`, worst 13 = bound 13. Mutation note: restoring the old ordering did not make that test fail, because event-queue backpressure blocks the listener, so the ordering is guaranteed by construction rather than by that test. Residual: the main thread's stack is platform-reserved and counted at 1 MiB because it only spawns and joins (INSPECTION) |
| 3b | allocator per-allocation overhead and fragmentation | OPEN | Not modelled. The total is requested bytes. Status condition `allocator-overhead` |
| 4 | revm per-transaction journal, engine cache and memory fit in the transient-snapshot allowance | DERIVED (replaced) | Its own term, §3a (890.7 MiB at 30M gas), with measured adversarial peaks below it. It depends on the revm 19.7 behaviour listed there (status condition `revm-representation`). One execution at a time is by INSPECTION (all EVM work on the consensus thread) |
| 5 | world-root rebuild per block; `eth_getTransactionByHash` chain scan | OPEN (CPU) | Not memory terms; part of the timing obligation (2) |
| 6 | deep-fork rebuild re-executes from the nearest retained ancestor | memory ENFORCED, CPU OPEN | Two snapshots (`a13_rebuild_of_a_deep_fork_keeps_only_the_target_state`); CPU proportional to depth |
| 7 | every new head re-executes the pool | memory ENFORCED, CPU OPEN | ≤ POOL_MAX_TXS, one execution at a time; CPU not bounded |
| 8 | timing measured at load; R25d calibration is synthetic | OPEN for specification | Admission conditions `timing-not-a-bound` and `calibration-synthetic` (R25) |
| 9 | R26 facts for unimplemented RpcGuard mechanisms | FIXED as evidence, mechanisms OPEN | Absent fields enter the gate as 0 and are never nominal. In the experimental-devnet scope, only the R26 predicates reading absent fields are waived (4 checked, 14 waived) and reported. The specification scope refuses (`specification:rpc-absent`). The 22 mechanisms themselves are not implemented |
| 10 | RetentionStore (disk) and redb trie | OPEN | Not implemented. The governance R21 historical-trie model is not exercised. The gate's deferred items `LP4:general-R18`, `LP4:general-R21` and `LP4:caps64-minimum-SYS_SLOT_MAX` remain (admission conditions `gate-deferred-*`) |
| 11 | TRANSIENT_SNAPSHOTS = 10 live clones | INSPECTION | Listed in `resources.rs` with their code locations; no runtime counter. Status condition `transient-snapshot-inventory` |
| 12 | hashbrown layout and entry sizes | DERIVED | Sizes via `size_of`; growth policy validated for the pinned toolchain by `snapshot_model_bounds_measured_clone_bytes` |
| 13 | EVM executions do not overlap | INSPECTION | Blocks, pool, eth_call/estimateGas and admission timing run on the consensus thread (`EXECUTIONS` = 1) |

Consequence:
- The devnet admission is an **experimental-devnet admission** (D-A02-SCOPE), reported as such at boot
  and in `status`.
- The 5.87 GiB figure is conditional on 3b, 4 (revm facts), 11 and 13.
- A13 is not closed: items 1, 2, 3b, 5, 8 and 10 remain open acceptance obligations.

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
