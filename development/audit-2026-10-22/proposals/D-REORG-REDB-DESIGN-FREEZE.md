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
   network.md:143 adopts "at depth ≤ R_keep"; governance.md:200 routes deeper rollbacks to a manual
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

---

## Revision 1 (after the independent adversarial review)

An independent agent instance tried to refute the four load-bearing claims. Result: CLAIM 1 (D133 on
metadata) CONFIRMED, CLAIM 2 (journaled-before-offload crash invariant) CONFIRMED, CLAIM 4 (2049 is not
a validity rule) CONFIRMED in substance, **CLAIM 3 (the §4 count bound) REFUTED on two points**, plus a
miscitation and a broader-than-stated rewiring. All verified against the code and spec. The frozen
design above is superseded by this revision where they conflict; it is kept for the record.

### R1. Canonical metadata is resident for the whole chain (≈ H_END+1), not R_keep (fixes §3.3/§4)

`retain` removes only non-canonical blocks: `gone` is built from `side(self) = !is_canonical`
(chain.rs:405-407), and `rebuild_canonical`/`canonical: Vec`/`is_canonical`/`canonical_at` and the
`better` LCA walk all require the full head→genesis chain. **Canonical metadata is therefore never
evicted** and scales with H_END (= 129600, governance.md:16; already the model's
`history/blocks (H_END+1)` term), not R_keep. The "≤ 2·R_keep+1 ≈ 4097 entries" bound in §4 is wrong
(≈ 63× undercount); removing canonical metadata to make it true would panic `rebuild_canonical` and
break `is_canonical`, `GetRange` history and the LCA walk, so it must not be attempted.

**Corrected accounting.** This change does **not** reduce the canonical metadata count; that term
(history/blocks ≈ H_END+1 entries) is unchanged from today and already in the A13 model. The memory
**win** is elsewhere: offloading each block's **body, receipts and log bytes** beyond the K_hist
window moves the large *aggregate* resident terms — `history/logs (LOG_CAP)` ≈ 1.03 GiB,
`history/transaction bytes` and `history/.../receipts` — down to the K_hist window only (they are read
on demand from the journal outside it). Net resident drops ≈ 1 GiB. A13 is re-derived with: the
metadata term on H_END (unchanged), the offloaded byte terms on the K_hist window, and the side term
on the metadata cap below.

### R2. One-per-height + the evicted refusal loses a valid heavier branch (fixes §3.3; the core bug)

`retain` adds **every** removed hash (including a per-height-losing non-canonical branch dropped with
its descendants) to the `evicted` set (chain.rs:425); `import` (node.rs:227) and `replay` (node.rs:141)
then **refuse** any evicted hash. Counterexample: two side branches A, B fork from a canonical ancestor
within R_keep; A is marginally heavier per height, so retain keeps A and removes all of B → B's hashes
are evicted. B later gets a heavy extension and becomes the single heaviest valid branch; on
re-delivery its blocks are refused by `was_evicted` until the 1024-entry FIFO drains
(adversarially controllable). A **valid heavier branch within R_keep is not adopted** — defeating the
Goal and contradicting the proposal's "holding R_keep metadata removes the eviction within R_keep."
D118 explicitly expects the dropped branch to be "يُعاد جلبه بالمزامنة إن صار أثقل" (re-fetched by sync
if it becomes heavier); the refusal blocks exactly that path.

**Fix (two parts, both within D118/D133):**
1. **Retain competing-branch metadata under a generous cap**, not just one per height. Raise retention
   from `SIDE_BLOCKS_MAX = 320` full entries to `SIDE_META_MAX` *metadata* entries (each ~1–2 KB vs
   ~0.42 MiB), evicting the lowest-work leaf first only past the cap (the existing `retain` leaf
   algorithm, now on metadata). With a cap well above the realistic number of competing valid
   branches, two branches within R_keep are both retained and `better` adopts the heavier **directly,
   with no re-fetch**. D118 mandates *at least* canonical + 1 non-canonical per height; keeping more is
   a local retention choice that only improves liveness and changes no rule.
2. **Scope the evicted refusal to beyond R_keep**, so D118 re-fetch works when the cap is exceeded. A
   re-delivered block is refused only when it cannot lead to an adoptable branch, i.e. when it is
   beyond the window (`height + R_KEEP <= head_height`); within the window it is accepted and
   re-validated (D118 re-fetch). Replay stays correct because a re-fetched branch is journaled
   parent-before-child (orphan resolution fetches the parent first), so on replay its records are in
   ascending height and no record hits UnknownParent; the replay `was_evicted` skip is scoped the same
   way. The original purpose of the refusal — stopping an *unadoptable* (beyond-R_keep) branch from
   being re-fetched/re-executed/re-journaled every sync turn — is preserved.

New acceptance test (added to §5): **two competing branches.** A and B fork within R_keep; A leads, so
retain may drop B; B then becomes heaviest. Assert B is adopted (head = B tip) — directly if under the
metadata cap, or via re-fetch if B was evicted — and never permanently refused within R_keep. Positive
control: the adopted-B path executes.

### R3. Offload rewiring is broader than §3.2 stated (acknowledged, scoped)

- `ensure_state` is a `Chain` method but the journal lives in `Node`; its signature and every call
  site must thread a journal reader, including the **replay** loop (node.rs:136-150) which runs before
  the `Node` exists and must read through `rec.journal`. Borrow-checker-feasible (disjoint fields),
  but a real refactor, not a one-liner.
- `detached_txs` (A11, node.rs:317) reads `e.body.txs` and `e.tx_hashes` of abandoned blocks that may
  be offloaded; `tx_hashes` is **not** in the journal record (record = header/body/result), so it is
  re-derived by re-hashing the fetched body (keccak per tx).
- `GetBlock`/`GetRange` (node.rs:544-548) and `eth_getBlockByHash` (rpc.rs:431) send
  `header.encoded`/`body.encode()`, empty when offloaded — they must read from the journal. Serving
  peers is the very mechanism the D118 re-fetch in R2 relies on, so this must land.

### R4. Genesis-never-offloaded invariant (documented, guarded)

The offload invariant ("offloaded ⇒ bytes in the journal") holds because genesis is created in
`Chain::new` (never journaled, chain.rs:141-144) **and** is never offloaded: `retain` excludes height
0 from state pruning (chain.rs:404), and offload is gated on pruned state. The implementation asserts
`height > 0 && body_off.is_some()` before offloading, so a future change that pruned genesis would fail
loudly rather than create an offloaded entry with no journal backing.

### R5. Citation fix (both files)

The manual-checkpoint-beyond-R_keep text is **governance.md:200** ("تراجع أعمق من R_keep: checkpoint
يدوي"), and the rollback-to-R_keep-then-TrieRebuild text is **consensus.md §10 (التعافي, lines
227-231)** — not "consensus.md §11", which is "التقدم (مشروط)". Fixed here and in D-REORG-REDB.md.

### Net effect on the plan

The design remains storage-only in its rules (D133 and validity unchanged) and still reaches R_keep.
The corrections are: count the canonical metadata on H_END (not R_keep) in A13; retain competing side
metadata under `SIDE_META_MAX` and scope the evicted refusal to beyond R_keep so D118 re-fetch works;
thread the journal reader through `ensure_state`/`detached_txs`/serving and re-derive `tx_hashes`;
guard the genesis invariant; and the two-branch test is added. Implementation proceeds on this revised
design.
