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

## S4: per-block metadata off the heap

- Entries older than R_keep keep only what fork choice and contexts need for the heights still reachable
  by a reorg. Everything else moves to `history.redb`, keyed by height and hash (storage.md "height 40 B").
- **Acceptance tests:** fork choice and the D-REORG-REDB tests unchanged; `derive()` term replaced.

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

1. S1.
2. S3.
3. S5, with D-6 on it.
4. S4.

Each stage lands with its own commit, evidence directory, suites and mutation controls. Its `derive()`
output replaces the projection in DECISION-PACKAGE.md §1.
