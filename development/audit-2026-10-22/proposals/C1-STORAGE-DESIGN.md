# C-1 storage program and D-6 checkpoints: design freeze (2026-10-24)

The owner approved D-1 option (a) on 2026-10-24: complete S1–S5 so that pocold runs the network profile
within 6 GiB, with equivalence proofs, data preservation and crash tests. D-6 is approved too: local state
checkpoints that keep the block history the spec requires, check their own integrity and recover from a
partial write.

This document fixes the design and the acceptance tests **before** the code, as was done for
D-REORG-REDB. None of it changes validity, roots, receipts, genesisHash, the wire format or an RPC result.
If a step would change one of them, it stops and goes back to the decision package.

## Invariants kept by every stage

- **I1 (source of truth).** `blocks.journal` stays append-only and is never compacted (storage.md:70:
  blocks are kept "until the end"). Every other on-disk structure is **derived**: it can be rebuilt from
  the journal by re-execution, and a lost or damaged copy is rebuilt, never trusted.
- **I2 (equivalence).** On every suite, replay and e2e run, the node answers every RPC block, transaction,
  receipt and log query exactly as it did before the stage, and its head, canonical chain and side sets
  after each journal record are those of live import (the D-REORG-REDB replay equivalence).
- **I3 (crash order).** Derived data for a block is written before the block's journal record. A crash
  in between leaves an orphan entry that nothing points to, never a journaled block without its data.
  Open checks that the derived stores cover the journal and rebuilds whatever is missing.
- **I4 (bounded memory).** Each stage replaces a `derive()` term by a proven bound: a cache with a fixed
  size, or a window of blocks. A `derive()` breakdown and the A13 pin are updated with it.

## The store

- The spec's store is redb (storage.md:63–73). pocold adds **redb 2.6.4**, which needs Rust ≥ 1.85
  (pocold uses 1.99.1). Its only runtime dependency, libc, is already in the lock; everything else it
  lists is dev-only.
- Its page cache is set explicitly (`Builder::set_cache_size`) and counted in A13. redb commits are
  crash-safe (copy-on-write with checksummed commit slots). I1 does not rely on that alone: a store that
  fails to open, or is inconsistent with the journal, is deleted and rebuilt.

## S1: canonical history off the heap (storage.md:70)

- `history.redb` holds two tables:
  - RECEIPTS: block hash → the encoded receipts of every validated block, side blocks included;
  - TXIDX: (tx hash, block hash) → index.
  It is written at import before the journal append (I3), and at replay for re-executed blocks.
- `Chain::retain` offloads canonical journaled blocks older than the resident window (head − K_hist).
  Their body and encoded header come from the journal; their receipts and transaction index come from
  `history.redb`. Blocks inside the window stay resident.
- Readers use one view:
  - RPC: blocks, transactions, receipts, logs, getHeaders, getBlockRlp;
  - P2P: GetFrom, GetRange and GetBlock.
  `find_tx` uses TXIDX and takes the canonical candidate.
- `restore_canonical` is no longer needed for receipts: the receipts of an adopted side block were stored
  when it was imported. It remains only to make blocks inside the resident window whole.
- **A13:** the history group (tx bytes, receipts and index, logs, evidence: 14.56 GiB at the network
  profile) is replaced by:
  - K_hist + 1 resident full blocks;
  - the redb cache;
  - the per-block metadata entries, which stay until S4.
- **Acceptance tests:**
  1. RPC equivalence: for every block, transaction, receipt and log, the answer of an offloaded block
     equals the answer before offload. This holds live and after reopen, on a chain with reorgs.
  2. P2P serving of offloaded canonical blocks: a node syncs from one whose history is offloaded.
  3. Crash and data preservation:
     - a crash between the receipts write and the journal append (simulated);
     - `history.redb` deleted, truncated or corrupted.
     In each case open rebuilds the store from the journal and the RPC answers are unchanged.
  4. `derive()` shows the new terms; the A13 pin is updated.
  5. Mutation controls: a receipt read from the wrong block, a missing TXIDX entry, and offloading
     inside the window.

### S1 status (2026-10-24): landed; evidence/c1-s1/

What was built as frozen above, and what was added after the tests showed a gap:
- `src/history.rs`: the two tables, written at import before the journal append (I3) and at replay for
  every re-executed block. Replay commits without fsync and makes them durable every 256 blocks and at
  the end; the journal records already exist, so a crash before that only means replay refills again.
- **Added: the store is never trusted past what it can prove.** The tests found two gaps, now closed:
  - a truncated `history.redb` made redb **panic** at open (an internal assertion), not return an error;
  - a flipped byte in a transaction-index key went **undetected** on read (redb checks page checksums
    only in `check_integrity`). The transaction was then reported "not found".
  The fixes:
  - open catches a panic inside redb and runs redb's full `check_integrity` (every page checksum). A store
    that fails either is set aside as `history.redb.aside` and rebuilt by replay. The check costs about
    1.0–1.4 s per GiB of store (measured), against the replay from genesis that open does anyway;
  - each receipts record carries keccak(block hash ++ record). A transaction-index entry is checked
    against the block's transaction hashes. Either failure while running marks the store damaged
    (`history.redb.damaged`), and the next open rebuilds it;
  - while the store is marked damaged, an RPC history read is **−32603**, never a block without its
    receipts, a shortened log list or "not found". An import's history write fails, and the node stops
    as on a failed journal append (exit 70). This cannot happen with an intact store, which was the only
    store before S1.
- `pocol_status` reports historyRefilled, historyRebuilt and historyDamaged.
- **Window:** `Limits::history_window`, default K_hist. A test reference sets `u64::MAX` (nothing
  offloaded).
- **Disk:** the redb file was at most 4.1 times the bytes it stores (synthetic records; redb grows by
  regions and rounds values to page orders). The A13 allocator term counts a factor of 8.

**A13, measured by `derive()`:**

| | before S1 | after S1 |
|---|---:|---:|
| devnet model total | 5,487,223,178 B | **4,323,240,949 B** |
| network history group | 19.19 GiB | **4.28 GiB**, of which 4.25 GiB is offloaded per-block metadata (S4) |
| network model total | 105.83 GiB | **90.93 GiB** (gate 103.92 GiB) |

A window of the whole chain reproduces the pre-S1 model exactly, apart from two differences:
- history.redb's cache and allocator are added;
- the logs term is now also bounded per block (LOG_BLOCK_MAX), which the USER phase enforces.

`a13_bound_breakdown` asserts this identity.

**Acceptance tests (all pass):**
- `canonical_history_off_the_heap_answers_as_it_did_resident` covers tests 1–3. A node that offloads
  answers as a resident reference after each of these:
  - live import, reopen;
  - deletion, junk overwrite and truncation of history.redb;
  - a crash between the history write and the journal append.
  It also checks:
  - a third node syncs the whole chain over P2P from the offloading node alone;
  - the transaction index is checked against the blocks themselves.
- `a_damaged_history_store_is_never_served_and_is_rebuilt` (test 3, extended):
  - 39 single-byte flips (receipts records, index keys, spread positions);
  - two kinds of wrong content that pass redb's checksums.
  No wrong answer is ever returned, and every damaged store is rebuilt.
- **Cross-version (I2):** the reference answers of the scenario on the tree before S1 (`e6025ce`) and on
  S1 are byte-identical (1,156,012 B, the same sha256).
- `a13_bound_breakdown` (test 4).
- Mutation controls (test 5): `evidence/c1-s1/mutants.log`.

## S3: retained and side states as reverse diffs; copy-on-write overlays (storage.md:70, D30)

- Only the head state is held in full.
- Each retained canonical state, and each side state, is the head state plus a **reverse diff**: the
  previous values of the accounts and slots that the blocks since then changed. The diffs cover at most
  R_keep blocks (2048, "diffs for 2048 blocks").
- A working copy (block apply, the USER phase, pool, production, RPC) is an **overlay**: writes go to a
  small map on top of a shared base. No full clone remains.
- A deep-fork rebuild starts from the head and applies reverse diffs. It no longer replays from genesis
  (journal review: the "double genesis rebuild").
- **A13:** the 45 full copies (73.49 GiB) become one copy, plus diffs bounded per block by the gas
  schedule (writes per block ≤ GAS_LIMIT / the cheapest state write), plus overlays bounded by the
  writes of the work in progress. Both bounds are derived and pinned with the stage.
- **Acceptance tests:**
  - every retained and side state read through diffs equals the full state it replaces, root by root,
    on every block of the suites;
  - the spec-depth 2048/2049 test and D133 at depth 400;
  - deep-reorg timing scales with depth, not height (measured);
  - overlay isolation: a dropped working copy leaves the base unchanged;
  - mutation controls.

## S5: live state on disk (storage.md:63–67)

- The head state lives in `state.redb`: accounts, slots and code, plus the reverse diffs of S3. A
  bounded cache sits in front of it.
- Every block commits its writes and its reverse diff in one redb transaction, after validation and
  before the journal append (I3). A crash leaves the store at a block that is either journaled or ahead
  of the journal by one block. Open detects the second case and rolls back one diff.
- The trie root stays recomputed from the stored state until C-2 item 4 adds the incremental root on
  this structure. That is a measured cost, not a memory term.
- **Acceptance tests:**
  - every block's stateRoot equals the in-memory implementation's (the suites);
  - crash tests: a kill between the state commit and the journal append, in both orders; a torn redb
    file; a missing file (rebuilt from the journal);
  - `a13_model_at_the_network_profile` is inverted and asserts `budget_required ≤ 6 GiB`;
  - RSS measured on a synthetic near-cap network state.

### S3 refinement (2026-10-24, before code): two parts

Reading the executor showed that S3 is two changes of very different reach:
- `lp4-execution` takes and returns whole `InMemoryDB` states (`apply_block` clones its parent, and the
  USER phase result is cloned back);
- its checks walk the whole state (`code_caps::validate_snapshot`, the genesis image check, the state
  root);
- `InMemoryDB` appears 124 times in `lp4-execution/src`.

**S3a: retained and side states as diffs (pocold only; the executor is unchanged).** This removes 34 of
the 45 copies: K_hist + 1 retained states and side_max side states, 55.5 GiB at the network profile.
- **Diffs.** Each stored block within the window, and each side block with a state, keeps a `StateDiff`:
  the before and after values of every account and slot that differ between its parent's state and its
  own. It is computed when the block is inserted, while both states are present (one comparison of the
  two maps).
- **Which states stay full.** The head stays full, and so does genesis (its state is the genesis
  allocation, small). Every other state is materialized on demand:
  - start from a clone of the head, which shares its code buffers (S2);
  - apply the before values from the head down to the lowest common ancestor;
  - apply the after values up the requested branch.
  At most one materialized state is alive at a time; it is a new A13 term, counted at one full copy.
- **Callers.** Every caller that read `&e.state` goes through `Chain::state_of`. It borrows the head's
  state and builds any other state. The callers are:
  - validating a child of a non-head block;
  - the RPC state queries at a tag;
  - production on a non-head parent;
  - rebuild and restore.
- **Bounds and A13.**
  - Per block, the changed slots are at most GAS_LIMIT / 2,900 (the cheapest first write of a distinct
    slot, warm SSTORE reset), plus SYS_KEYS_BLOCK_MAX.
  - The changed accounts are at most GAS_LIMIT / 21,000 × 3 (sender, recipient, coinbase), plus the
    accounts a CALL with value can touch per 9,000 gas, plus SYS_ACCT_BLOCK_MAX.
  - Storage cleared by an account's removal is bounded by the same writes: under Cancun only an account
    created in the same transaction is destroyed, so it had no earlier storage. This is to be confirmed
    against revm 19.7 and `commit_epoch` before the bound is pinned; if it does not hold, the diff keeps
    the cleared storage and the bound is stated without it.
  - The derived per-block diff bound × (K_hist + 1 + side_max) replaces the 34 copies in `derive()`.
- **CPU.** The comparison is O(state) per block, as the existing whole-state checks are. It is measured
  on the near-cap devnet state and reported with C-2. If it is too slow, the executor can return its
  written set instead; that would be an lp4 change.
- **Acceptance tests:**
  - every materialized state equals the full state it replaces, account by account and by stateRoot, at
    every height of the window, on chains with reorgs (the old resident copies kept as the reference in
    the test);
  - the suites unchanged: lp4 vectors, pocold consensus and caps, e2e, replay equals live, 2048/2049,
    D133 at 400;
  - RPC state answers at each retained tag are unchanged;
  - mutation controls: a diff missing a slot, a diff applied in the wrong direction, materialization
    from the wrong LCA.

**S3a status (2026-10-24): landed; evidence/c1-s3a/.**
- `src/statediff.rs`: a `StateDiff` holds the before and after value of every field that differs:
  accounts with their cached code, account state, each slot, contracts, block hashes and logs.
  `states_equal` compares every field, including the cached code that `AccountInfo`'s PartialEq ignores.
- `src/chain.rs`:
  - each validated block gets its diff;
  - `settle` (the end of `retain`) keeps full only the head, genesis and the side states within
    side_max;
  - `materialize` and `state_of` build any other state from the nearest full state through the diffs;
  - `validate` materializes a non-full parent itself, so its NeedsRebuild contract is unchanged.
- **Two findings made during the work, both fixed:**
  1. **An adopted branch must not break the path to the states below the fork.** When the adopted
     blocks had been pruned as side blocks, they had no diffs, and the retained canonical states below
     the fork became unreachable. They would then answer −32017 where the old code answered.
     - Fix: `restore_canonical` also re-executes canonical blocks above the cut that lack a diff, but
       only when a retained state lies below them.
     - The node calls `retain_unsettled`, then the restore, then `settle`, in live import and replay,
       so the fork point is still reachable during the restore.
  2. **No extra rebuild.** At first, after a fork below the cut, that re-execution rebuilt the adopted
     branch from genesis. Since no retained state lies below it, it is now skipped. The equivalence test
     shows the same rebuild count as the reference (20 and 20).
  3. **Kept side states must be full** (found from a surviving mutant).
     - The fault in the first version (`bef6c4f`): a side state kept within side_max could be held as a
       diff only, for example a block of the abandoned branch protected by a sync session. Once its
       neighbours were pruned it became unreachable. Had that branch been adopted again, its height
       would have answered −32017 where the code before S3a answered.
     - Fix: `settle` makes every kept side state full, materialized before the diffs that lead to it
       are dropped. Before S3a every kept side state was full too, so A13 already counts side_max full
       copies.
     - Test: the equivalence test now protects such a block, requires identical pruned flags for every
       block, and checks that the block answers again when it is canonical. It fails on `bef6c4f`'s
       behaviour (mutant SM11).
- **A13, measured by `derive()`:**

  | | before S3a | after S3a |
  |---|---:|---:|
  | devnet model | 4,323,240,949 B | **3,601,500,638 B** |
  | network snapshots group | 75.12 GiB | **27.76 GiB** (17 copies: head, genesis, side_max, 2 materialized, 10 transient, growth) |
  | network diff term | — | **0.46 GiB** (2·K_hist + side_max + 1 diffs of at most 7.0 MB each, derived from the gas schedule) |
  | network model total | 90.93 GiB | **41.41 GiB** (gate 47.33 GiB) |

  - A new condition, `s3a-removal`, records that a removed account keeps no earlier storage (Cancun).
  - Genesis is counted as a full copy. It is in fact the genesis allocation; a tighter term is open.
- **Validation time** at the near-cap devnet state (18,828 accounts, 46,636 slots): the diff alone takes
  12.5 ms per block. 380 transfers take 672 ms, against 655 ms for C-2's final code. An empty child takes
  491 ms, against 465 ms.
- **Acceptance tests (pass):**
  - `s3a_every_retained_state_equals_the_full_state_it_replaces`: 374 import steps, among them a 10-deep
    reorg, a re-reorg and a fork below the cut. 8,388 states are compared field by field and by
    stateRoot against a full-state reference. The canonical pruned flags are identical. At most 4 full
    states are held, against 35 in the reference.
  - `s3a_state_queries_answer_as_with_full_states`: every balance, nonce, code, storage and `eth_call`
    query at every height and tag equals the reference node's. This holds live, after two reorgs and
    after reopen, with the same rebuild and restore work.
  - The statediff unit tests: 2,000 random state pairs, both directions; composition over a chain; the
    cached code.
  - The S2 code-sharing test, now run over materialized states.
  - The full suites; the ignored deep-reorg tests; the mutation controls (`evidence/c1-s3a/`).

**S3b: transient working copies as overlays (an executor change, done together with S5).**
- This removes the 10 transient copies and the growth copy, 18.0 GiB at the network profile.
- It needs `lp4-execution` to run on a layered state: a `CacheDB` over a borrowed base, with whole-state
  iteration through a merged view, and the whole-state checks made incremental. The state root is
  C-2 item 4.
- S5 needs the same generalization, since its base is on disk. So S3b is designed and frozen with S5,
  as one executor change verified against the lp4 vectors, not as a separate pass.

Projected network model after S3a: 90.93 − 55.5 − 3.0 (the per-copy code containers) − 2.25 (side code
sets) ≈ **30.2 GiB, plus the diff and materialization terms (new)**. This is a projection until
`derive()` prints it.
**Correction after the code (S3a status below):** the measured total is 41.41 GiB. The projection
assumed two things that the code did not do:
- the side states as diffs: they stay full, so that a deep side branch does not rebuild;
- no extra copies: genesis and two materialized states are now counted.

### S5 + S3b design freeze (2026-10-24, before code): the executor on a layered state

**Why this is one stage.**
- After S3a and S4 the network model is 37.96 GiB. Most of what remains is full state copies:
  - the head, genesis, side_max and materialized states (9.80 GiB);
  - the 10 transient working copies and the growth copy (17.96 GiB).
- Removing them needs `lp4-execution` to run without whole states:
  - on a base it only reads (in memory, or `state.redb` for S5);
  - with an overlay for its writes;
  - returning the writes as a diff.
- The executor walks the whole state on every block in five places. Each must become incremental and be
  proven equal to the full computation:

| whole-state walk (lp4-execution) | replacement | proof |
|---|---|---|
| state root (`trie::state_root` over every account and slot) | an incremental trie: node hashes kept per account and storage trie, updated from the block's diff (C-2 item 4) | the full root recomputed and compared on every block of every suite (a test feature), and on every vector |
| `code_caps::validate_snapshot` and `inventory` | running totals of logical code per state, updated from the diff (C-2 item 2 already keeps them within a block) | equal to the full scan at every block in the suites |
| the caps counters (live user accounts and slots, system slots; `user_phase` lines 130–165) | counters updated from the diff | equal to the full scan at every block |
| `drop_unreferenced_code` (all accounts' code hashes) | a reference count per code hash, updated from the diff | the contracts map equal to the full rule at every block |
| `genesis.image.verify_candidate` (`check_caps`, the system slot count and the sum of every balance against the supply bound; the code and profile checks read five fixed accounts) | running totals (user accounts and slots, system slots, the balance sum) updated from the diff; the five fixed accounts read directly | equal results on every vector and block; a mutant that leaves a total stale must fail |

**The steps, each landed separately with its equivalence proof:**
1. **E1, incremental root.** This is also priority 2 (validation time): the root dominates the 465–491
   ms of an empty child at the near-cap state.
   - **How:** `p1_trie::node(rows, depth)` is a pure function of all the rows under the key prefix
     `rows[0].key[..depth]`. So a cache of each subtree's child reference (an inline encoding under 32
     bytes, or a hash), keyed by its prefix and invalidated along every changed key, reproduces the root
     exactly while recomputing only the changed paths.
   - **Cost:** about one entry of roughly 70–100 B per trie node. At the network caps (about 1M accounts
     and 4M slots) that is about 0.4–0.5 GiB. In memory it is a new A13 term. In S5 the node cache lives
     in `state.redb`, with only a bounded cache in memory.
2. **E2, running counters and code reference counts.**
3. **E3, the executor on a borrowed base with an overlay.** `apply_block(base, …)` returns its writes as a
   `StateDiff`. Every `parent.clone()` and `users.state().clone()` goes. The pool, production, RPC
   simulation and rebuilds use overlays. This removes the transient copies (S3b).
4. **E4, `state.redb`.** The head state and the window's reverse diffs live on disk behind a bounded cache.
   Each block commits its writes and its reverse diff before the journal append (I3). Open detects a store
   one block ahead and rolls it back. This is S5; D-6 checkpoints are committed versions of this store.
5. **E5, the two reductions that are still needed:**
   - a smaller inline entry;
   - the rebuild and the pool reading code from the store instead of their own sets.

**Unchanged:** validity, every root, every receipt, genesisHash, the wire format and every RPC answer.
If any step would change one of them, it stops and goes back to the decision package.

**Reference.** The current executor stays in the tree as a test-only reference until E4 lands, so that
every step is compared block by block against it, not only against vectors.

## S4: per-block metadata off the heap

- Entries older than R_keep keep only what fork choice and contexts need for the heights still reachable
  by a reorg. Everything else moves to `history.redb`, keyed by height and hash (storage.md "height 40 B").
- **Acceptance tests:** fork choice and the D-REORG-REDB tests unchanged; `derive()` term replaced.

### S4 status (2026-10-24): landed; evidence/c1-s4/

The frozen plan was to move old entries to `history.redb`. What was built instead: old entries stay in
memory but slimmed, and the journal plus a new `history.redb` table restore what was dropped, exactly.
The journal already holds the header and ParentResult bytes, so nothing else had to move.
- **What is slimmed:** canonical journaled entries deeper than `slim_depth` drop the header's heap fields,
  the ParentResult and the nonce ranges.
  - The default depth is 2·R_keep + E_win + 257. That covers any fork (R_keep), a head that fell back by
    up to R_keep, the evidence window, and the 256 ancestors of a child context.
  - Inside that depth no validation reads a slimmed entry.
  - Fork-choice fields, `drawn`, the scalars and the diff stay.
- **Restored, never trusted:**
  - the header and ParentResult come from the journal record, and the header must hash to the block;
  - the ranges come from history.redb (sealed, written before the journal append like the receipts).
  - Where restore happens:
    - a validation that needs a slimmed parent or evidence ancestor gets NeedsRebuild, and the node
      restores the entry (bounded retries);
    - a TrieRebuild re-executes slimmed blocks from restored copies;
    - RPC and P2P views restore too;
    - a restored entry is slimmed again once it is deep enough.
- **A13:**
  - network history group 4.28 → **0.83 GiB**; model 41.41 → **37.96 GiB** (gate 43.38 GiB);
  - devnet 3,601,500,638 → **3,322,680,105 B**.
  - A slimmed entry is still about 5 KB in the model, three times the inline `Entry` for map growth plus
    an empty state. A smaller inline entry is possible later.
- **Acceptance tests (pass):**
  - `s4_slimmed_entries_answer_as_full_ones_and_restore_exactly`: at depth 8,
    - exactly the canonical entries deeper than 8 are slimmed;
    - every block, transaction, receipt, log, header, RLP and P2P answer equals a never-slimming
      reference's;
    - every slimmed entry restores to the reference's fields;
    - a fork on a slimmed parent and a fork below the K_hist cut, which rebuilds through slimmed entries,
      both validate;
    - the same holds after reopen.
  - `s4_evidence_against_a_slimmed_ancestor_restores_it_first`: type-2 evidence whose ancestor is slimmed
    is accepted after the restore, with the same tombstone and state root as the reference.
  - Mutation controls: `evidence/c1-s4/mutants.log`.

## D-6: local state checkpoints (owner approved)

- A checkpoint is a **committed `state.redb` version at a canonical height h_c**: every CHECKPOINT_EVERY =
  2048 blocks, below head − R_keep, where no reorg can reach. It is recorded together with a serialized
  chain-metadata snapshot (all entries, without states) and the index of the last journal record it
  covers.
- **Integrity:**
  - a checkpoint is valid only if its file checksum verifies;
  - its state root equals the stateRoot committed in block h_c's header;
  - its metadata snapshot matches the journal records it claims, compared by their hashes.
- **Partial write:** a checkpoint is written to a temporary file, fsynced, renamed and the directory
  fsynced. A torn or unverifiable checkpoint is ignored with a log line, and open falls back to the
  previous one, or to genesis.
- **History kept:** the journal stays complete (I1). A checkpoint only shortens the re-execution at
  open; it never deletes a block, receipt or log.
- **Acceptance tests:**
  - open from a checkpoint equals open from genesis: head, canonical chain, every RPC answer, the next
    imports;
  - a torn checkpoint, a checkpoint with a flipped byte, and one whose root does not match: each is
    ignored, and open still succeeds through the fallback;
  - a kill during the checkpoint write;
  - open time measured with and without a checkpoint.
- **Order:** D-6 is built on S5. A checkpoint is then a persisted store version plus metadata, not a new
  serialization of a full in-memory state.

## Order of work

1. S1 (done).
2. S3a.
3. S5 with S3b (one executor change), and D-6 on it.
4. S4.

Each stage lands with its own commit, evidence directory, suites and mutation controls. Its `derive()`
output replaces the projection in DECISION-PACKAGE.md §1.
