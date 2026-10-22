# A13 — resource derivation for the actual representation

Scope: the resident memory of one pocold node (single-host simnet devnet) and the R18/R21 facts that
admission feeds to the gate. The claim is a conservative upper bound for the admitted parameter domain,
not a measurement. Code: `prototypes/lp4-execution/src/resources.rs` (`memory`), `admission.rs`
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
| snapshots | (1 genesis + K_hist + side_max + 10 transient) × snapshot | `Chain::retain` (K_hist window; side states ≤ side_max, lowest work pruned first); transient: apply copy, USER copy, per-tx engine and PAY copies, production clones, pool state and its copies, rolling rebuild (2). The pool's pending state is normalized after every transaction and refuses a transaction whose effects would pass SLOT_CAP, ACCT_CAP or SYS_SLOT_MAX (`PoolMeter`), so it is one snapshot like the others |
| code | snapshots × (CODE_CAP · 9/8 + 97 B per code entry) | `code_caps::validate_snapshot` (logical code per state); counted unshared |
| history | (H_END+1) × per-block + TXBYTES_CAP + TX_CAP × 380 B + LOG_CAP × 33/32 + identities × (EVID_BYTES_MAX+24) | H_END (apply_block); TX_CAP/TXBYTES_CAP chain-cumulative (block invalid); LOG_CAP (USER `Halt::LogCap`); evidence ≤ one per identity ever (a tombstoned record makes further evidence a host error), identities ≤ M_max + R_max · H_END |
| per block | 3 × (map slot of `Entry` 1184 B) + 2 × header_max + bloom/sig/proposer + 8·S + 32·(S+1) shares + 64·M ranges + an empty state | header_max = 768 + 9·S_max (network.md 3067 B for S=256) |
| side blocks | SIDE_BLOCKS_MAX (256) × (per-block + BODY_MAX + receipts + LOG_BLOCK_MAX) | `Chain::retain`: ≤ 256 non-canonical blocks (lowest-work leaves leave first), none R_keep (2048) or more below the head, descendants removed with them |
| queues | pool (64 MiB and ≤ POOL_MAX_TXS = 4096 transactions, plus entries) + orphans (16 MiB) + future (64) + templates (64) + seen caches (4096) + invalid (4096) + rejects (256) + receipt times (1024) + evidence pool (64) + per-peer queues for (peers_max inbound + one per dialer) + event queues | constants in `node.rs`, `chain.rs`, `net.rs` (A05) |
| rpc | conn_max × (MAX_BODY + 16 KiB + BATCH_RESP_MAX + BATCH_MAX × 256 B) + BATCH_RESP_MAX + 4 × RESP_MAX | `rpc.rs`: connection cap (excess refused unread), request size, batch members run and serialized one at a time with the delivered bytes ≤ BATCH_RESP_MAX (later members −32020 {batchBytes}, not run), `capped` (RESP_MAX → −32008 with the request id), eth_getLogs stopping at RESP_MAX of result, LOGS_COUNT_MAX or LOGS_SCAN_BYTES (−32005) |
| threads | (2 × peers_max + 3 × dials + conn_max + 8) × 64 KiB resident stack | thread creation bounded by the A05 caps (inbound) and the configured peers (outbound) |

Single-host devnet default (D-A13-PROFILE; side_max 8, default limits, two configured peers): **4.92 GiB**
≤ the 6 GiB node budget (`node::MEM_BUDGET`): snapshots 51 × 38.2 MiB, code 209 MiB, history 1576 MiB
(LOG_CAP dominates), side blocks 285 MiB, queues 426 MiB, RPC 593 MiB, threads 7 MiB. (Before the independent
review: 4.71 GiB. The RPC term had counted one RESP_MAX response per connection while a batch could
build more, and the pool's pending state was not capped; both are now enforced as above.) A budget below the bound, or
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

## 4. Open obligations (not claimed)

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
