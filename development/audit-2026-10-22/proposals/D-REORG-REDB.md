# D-REORG-REDB — off-heap block store for full R_keep-depth adoption (PROPOSED, needs owner approval)

Status: **PROPOSED. Not implemented. Needs explicit owner approval** before implementation, because
it adds consensus-critical code (a bespoke reorganization path). It is recorded here per the standing
rule that any new normative/consensus-adjacent mechanism needs explicit sign-off.

## Problem

network.md:143 requires a node to adopt a heavier valid branch at any fork depth ≤ R_keep = 2048
(governance.md). pocold's one-shot adoption depth is **SIDE_BLOCKS_MAX = 320** (A13-DERIVATION §4
item 18), memory-bound, because:
- fork choice (`chain::better`, `rebuild_canonical`) walks a branch's ancestors through resident
  `self.blocks` entries, and `retain` can only drop leaves without creating holes, so a competing
  branch must be **fully resident** to be adopted;
- a resident side block costs ~0.42 MiB in the A13 model; 2048 of them would add ~0.85 GB, which does
  not fit the 6 GiB budget beside the other terms.

A branch deeper than 320 is **preserved in the journal (lossless) and not refused**, but the node
stays on the valid lighter chain until the heavier branch is delivered within the cap or a manual
checkpoint is applied (consensus.md D118: "a branch that becomes heavier later is fetched by sync";
consensus.md §11: "a rollback deeper than R_keep: manual checkpoint"). This is a liveness gap, not a
safety break: the node never adopts an invalid chain.

## Proposed design

Move block **bodies** off the heap so the canonical chain and side branches are referenced by a
height/hash index with bodies on disk (the spec's redb block store), and make reorg a **streaming**
re-execution:
1. **Block store (redb or an append-only file + index).** `hash → (header, body, parentResult)` on
   disk; RAM holds only per-block metadata (hash, total_work, height, parent, signed ≈ 120 B) within
   R_keep. The journal already holds the bytes; this adds the by-hash index and on-demand reads
   (`Journal::read_at`, prototyped and reverted on this branch, kept in the private package).
2. **Fork choice on metadata.** `better`/LCA operate on the metadata index, not resident entries, so
   a competing branch need not be resident to be compared. Adopt only on **strictly greater** total
   work (no equal-work deep reorg), which sidesteps the D133 tie-break entirely.
3. **Two-pass streaming adoption (fail-closed).**
   - Pass 1 (validate, no mutation): stream the new branch from the LCA, re-executing one block at a
     time (rolling ≤ 2 state snapshots, as `ensure_state` already does), checking every state root,
     PoW, membership, evidence and parentResult. It touches nothing in `self.blocks`/`head`/
     `canonical`, so a failure needs no rollback.
   - Pass 2 (splice, only after Pass 1 fully succeeds): swap the canonical suffix height-by-height
     (spill the old block at height h, install the new one), keeping the resident set ≈ the canonical
     window. A crash mid-splice is recovered by journal replay (the old chain until the new branch is
     journaled).
   Peak resident ≈ the canonical window + O(1), independent of the reorg depth, so it reaches R_keep
   within budget.

## Why it is not implemented now

The 4-lens design panel (recorded in the repair history) rated this design's bespoke reorg the
riskiest option on the consensus-safety and implementation-risk lenses (it replaces the tested
`better()`/`insert()` fork choice and adds a splice/restore path executed with the chain mid-mutation),
while rating the two safe options (raise the resident cap; lossless journal) highest. The adopted
change (SIDE_BLOCKS_MAX 256 → 320 on the tested path, lossless journal, restart via replay) takes the
safe depth gain with zero new consensus code. Closing the remaining 320 → 2048 gap needs this design,
whose consensus-critical nature warrants explicit owner approval and a dedicated review before it is
written.

## Effects (if approved and implemented)

- Validity, state roots, gas rules, accepted-transaction semantics: **unchanged** (every adopted
  block is fully re-validated; adoption only on strictly greater work).
- Memory: the canonical-history term (H_END+1 blocks resident) would shrink substantially (bodies on
  disk), freeing budget; the side term becomes metadata-only.
- Disk: a bounded block store (≤ R_keep × max block ≈ 0.4 GB live, with compaction).
- Compatibility: local only (retention/storage), does not change genesisHash or block validity.

## Independent expected-result vectors (for the review of an eventual implementation)

- A heavier branch forked 2048 deep is adopted; forked 2049 deep is not (R_keep boundary).
- A branch that fails Pass-1 validation at block k leaves `head`/`canonical` unchanged (no rollback).
- A crash during Pass-2 splice: on restart the node is on the old chain or the fully-spliced new
  chain, never a partial mix (journal replay is atomic per record).
- Equal-work competing branch: not adopted (strictly-greater rule), matching D133's preference for
  the incumbent.
