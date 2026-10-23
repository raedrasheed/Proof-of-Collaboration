# D-REORG-REDB — frozen design and acceptance tests (owner-approved implementation)

Status: **APPROVED for implementation** as a repair to meet the R_keep adoption requirement, D133 and
block validity fully preserved (owner message 2026-10-23). The six consensus proposals are **not**
approved by that message. This document freezes the design and the acceptance tests **before** any
implementation, per the owner's point 1. Any deviation that would change a normative rule stops for
explicit approval.

## 1. Goal and non-goals

- **Goal:** adopt a heavier valid branch at any fork depth ≤ R_keep = 2048 (network.md:143), within the
  6 GiB budget, with D133 and block validity unchanged.
- **Non-goals (unchanged):** D133 fork-choice rule; block validity / state roots / gas / accepted-tx
  semantics; genesisHash; the six consensus proposals. The local retention limit is **not** turned
  into a block-validity rule (owner point 4).

## 2. Key facts the design rests on (verified in the current code)

1. `chain::better`/`key`/`rebuild_canonical` read only metadata — `total_work`, `parent`, `height`,
   and `key = (signed, importSeq, blockHash)` — never a body or executed state
   (`src/chain.rs` `better` lines 462–476). **So fork choice already computes the full D133 total
   order from metadata; no rule changes.**
2. Every validated imported block is already journaled, canonical or side, before `insert`
   (`src/node.rs` import: `journal.append(encode_record(header, body, result))` at line 244). **The
   journal is already a complete, durable, off-heap store of every block's bytes.**
3. `retain` is the only thing that bounds memory, and it does so by **removing** side entries past
   `SIDE_BLOCKS_MAX = 320` (`self.blocks.remove`), because a resident `Entry` carries the full
   `body`, `receipts`, `tx_hashes` and (within the window) `state`.
4. `ensure_state` already rebuilds a pruned block's state on demand by rolling re-execution from the
   nearest ancestor that still has state, using each block's `body`.

So the change is **storage, not fork choice**: give the journal a by-hash index, let `Entry` hold its
body/receipts/state off-heap (in the journal) beyond a small resident window, and let `retain` keep
**metadata** for the whole R_keep window instead of deleting side blocks at 320. Adoption then reaches
R_keep through the existing `better` + `ensure_state` path.

## 3. Design

### 3.1 Block store = the journal + a by-hash index

- `Journal::append` returns the record's **frame offset** (`u64`, the value of `end` before the write).
- New `Journal::read_at(offset) -> Result<(header, body, result), StoreError>`: seek, read the frame,
  verify `lenCheck` and `sha256(payload)` (same checks as replay), `decode_record`. A failed check is
  a hard error (never a silent empty body).
- A by-hash index `offset_of: HashMap<[u8;32], u64>` lives in `Chain` (the metadata owner), filled:
  - on live append: the node sets `entry.body_off = Some(off)` after `append` returns `off`;
  - on replay: the node already decodes every payload into `(header, body, result)` and forms the
    `Block`; it records `off` (recomputable: offsets start at 40, each frame is `payload.len() +
    OVERHEAD`) as it goes.
- The journal file itself is unchanged on disk (append-only, two-slot commit, fsync-ordered). The
  index is in-memory, rebuilt on every open from the committed records — never a new on-disk format.

### 3.2 Entry: resident window vs off-heap

`Entry` gains `body_off: Option<u64>` (journal frame offset) and an `offloaded: bool`. An **offloaded**
entry has `body`, `receipts`, `tx_hashes` and `header.encoded` cleared (empty), keeping only metadata:
`hash, parent, height, total_work, import_seq, signed, ts, target, base_fee, gas_used, seal, is_final,
result, cum_txs, cum_tx_bytes, cum_log_bytes, drawn, ranges`, and the parsed `header` fields (minus the
`encoded` bytes). State is already governed by `pruned`.

Residence policy (deterministic, tied to the existing window):
- **State** (`pruned`): resident for the canonical `K_hist` window and the `side_max` retained side
  tips — **unchanged**.
- **Body/receipts/tx_hashes/header.encoded** (`offloaded`): resident for the same set that keeps state
  (not pruned) **plus just-imported blocks until the next `retain`**; offloaded otherwise. So an
  offloaded block always has its bytes in the journal (it was journaled at import), and `body_off` is
  set.
- Anything needing offloaded content fetches it with `read_at(body_off)`: `ensure_state`
  (re-execution), `GetBlock`/`GetRange` (serving peers), the A11 reorg (abandoned-branch tx recovery,
  re-deriving `tx_hashes` from the fetched body). RPC history reads stay inside the trie window
  (`K_eff ≤ K_hist`, consensus.md §10: outside it is −32017), so RPC never needs an offloaded body.

### 3.3 retain: keep R_keep metadata, enforce D118 per height

`retain` changes from "delete side blocks past a count" to:
1. Prune **state** at height ≤ head−K_hist (unchanged) and **offload** body/receipts/tx_hashes for any
   block whose state is pruned (set `offloaded`, clear bytes, keep `body_off`).
2. Enforce **D118 per height** within the window `[head−R_keep, head]`: at each height keep the
   canonical block and **at most one** non-canonical block — the one highest in cumulative work for
   its branch, then earliest `importSeq` (consensus.md §10 / D118). A losing same-height non-canonical
   block and its descendants are removed.
3. Remove any non-canonical block at height ≤ head−R_keep, with its descendants (unchanged boundary).
4. Keep executed state for at most `side_max` side tips (unchanged).

Count bound after `retain`: ≤ (R_keep+1) canonical metadata entries within the window + ≤ R_keep
non-canonical metadata entries (one per height) = **≤ 2·R_keep+1 ≈ 4097 entries**, each metadata-only
beyond the resident window.

### 3.4 Adoption (unchanged mechanism, now reaching R_keep)

A heavier branch is adopted exactly as today: its new child is imported → `validate` (needs the
parent's state, obtained by `ensure_state` on `NeedsRebuild`, which now fetches offloaded bodies from
the journal) → `insert` runs `better` on metadata → `rebuild_canonical` walks parents → `retain`. No
new splice path, no new fork-choice code. `better` already preserves D133.

### 3.5 Crash consistency and write ordering

Invariant: **the journal is the source of truth.** On restart, replay re-executes every committed
block in import order and rebuilds the chain, state, receipts, `importSeq` and the by-hash index
exactly (A04, already verified). The in-memory metadata index and offload flags are derived state,
rebuilt on open; they are never the source of truth and are never persisted. Write ordering is
unchanged: `append` writes the record, `sync_data`, then updates the fsynced commit file; a block is
committed iff its full record is fsynced and counted. Because offload only ever drops bytes that are
already durably in the journal, no crash can lose data the journal did not already hold. There is no
new on-disk artifact and no new ordering constraint.

## 4. Resource accounting — multiple branches (owner point 2)

Per-branch, within the R_keep window, bounded explicitly:

| item | count bound | size bound | residence / eviction | refetch |
|---|---|---|---|---|
| canonical metadata | ≤ R_keep+1 | ~1–2 KB each (header fields, result, ranges, cum_*) | resident within R_keep; removed beyond | n/a (in journal) |
| non-canonical metadata | ≤ R_keep (D118: ≤1/height) | ~1–2 KB each | resident within R_keep; the D118-loser per height and >R_keep removed | re-fetched by sync if it becomes heavier (D118) |
| executed state snapshots | ≤ K_hist+1 canonical + side_max side | ≤ snapshot bound each | pruned at height ≤ head−K_hist; side past side_max pruned | rebuilt by `ensure_state` re-execution |
| resident bodies/receipts | = the not-pruned set (K_hist + side_max + just-imported) | ≤ BODY_MAX + receipts each | offloaded when state is pruned | `read_at` from journal |
| journal records (disk) | all imported within retention | ≤ MAX_RECORD each | append-only; **compaction past R_keep is a documented follow-up** | the durable copy |
| by-hash index (RAM) | = resident metadata entries | 40 B/entry | rebuilt on open; grows/shrinks with metadata | n/a |

**Memory model (A13, 6 GiB kept):** the dominant resident terms shrink because offloaded canonical and
side blocks no longer carry body/receipts/logs/state. The side term becomes metadata-only; the history
`blocks`, `logs` and body terms count only the resident window, not H_END/R_keep. Exact bytes go in
A13-DERIVATION after implementation; the boot gate and 1/8 reserve are unchanged. **Proven bounds are
separated from measured RSS and from assumptions** (A13-DERIVATION §2b layout).

**Disk:** the live working set is ≤ (2·R_keep) × MAX_RECORD. The append-only journal file holds all
imported history absent compaction (a pre-existing property, unchanged by this change); compaction to
bound it past R_keep is recorded as a follow-up, not implemented here, and is local (no validity/root
effect).

## 5. Acceptance tests (frozen before implementation)

Derived from the accepted text; a retention/storage limit is never turned into a validity rule.

1. **Depth 2048 adoption.** Build a canonical chain, fork a strictly-heavier branch 2048 deep from an
   ancestor at depth 2048, deliver its blocks, assert the node adopts it (head = the heavy branch tip)
   and serves/produces on it. Memory stays within the A13 budget (asserted via the model).
2. **2049 behaviour from the text, not a new validity rule.** A heavier branch forked 2049 deep:
   network.md:143 adopts "at depth ≤ R_keep"; consensus.md §11 routes deeper rollbacks to a manual
   checkpoint, and D118 keeps retention "local, not validity". So at 2049 the node **does not adopt in
   one shot and does not mark the branch invalid** — it stays on the valid lighter chain; the deeper
   branch is preserved in the journal. The test asserts: head unchanged, the 2049-branch blocks are
   **not** marked invalid (no `Reject::Block`), and no panic. It does **not** assert the branch is
   refused as invalid (that would be inventing a validity rule).
3. **D133 tie-break at depth.** Two equal-cumulative-work branches forked > 320 and ≤ 2048 deep; assert
   the head is the one D133's key selects (signed before fallback; then smaller importSeq; then smaller
   blockHash at the LCA children) — identical to the in-window decision, now at depth. Mutating the key
   order flips the result (mutation control).
4. **Evicted-branch re-fetch within R_keep.** A branch dropped by the old count cap is, under the new
   retention, kept as metadata within R_keep and adopted when it becomes heavier **without** being
   refused; a branch beyond R_keep is still removed and its re-delivery handled by sync (D118).
5. **Crash consistency.** Inject a crash (a) between the journal `append` fsync and the commit update,
   (b) mid-adoption (after `insert`, before `retain` completes), (c) with an offloaded body: after
   restart the head, canonical chain, executed state, by-hash index and journal are mutually
   consistent — head is the old chain or the fully-adopted new chain, never a partial mix — and every
   resident block's offloaded body is readable from the journal.
6. **Off-heap read fidelity.** For a block whose body is offloaded, `read_at` returns bytes that
   re-hash to the block hash and re-execute to the committed state root (so an off-heap body is never
   silently wrong or empty).
7. **6 GiB budget under multi-branch load.** With the window full of canonical + one non-canonical
   per height across R_keep, the A13 model total stays within the 6 GiB budget behind the 1/8 reserve,
   and measured RSS is reported separately (not as the bound).
8. **Positive controls** for tests 1, 3, 4, 6 (the scenario is built and the adopted/served path runs),
   so a pass cannot mean the path was never reached.

A **TIMEOUT** on any test is recorded as incomplete, never as a pass (owner point 6).

## 6. Independent review before coding

This frozen design is sent to an independent reviewer (a separate agent instance) to refute: the D133
claim (metadata suffices), the crash invariant, the D118-per-height count bound, and the 2049 "not a
validity rule" reading. Implementation begins only after that review; its result is recorded in the
repair history.
