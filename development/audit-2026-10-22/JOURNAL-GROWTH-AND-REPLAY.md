# Journal growth and re-execution-from-genesis — model, measurements, operational limits

Status: measurement and analysis (not normative). Scope: the on-disk block journal of `pocold`
(`prototypes/pocold/src/store.rs`) and the cost of re-execution from genesis it imposes at open, on a
deep-fork state rebuild, and on restore after an adoption. Two obligations are left **OPEN** at the
end; no mitigation is implemented here (none would be purely-local storage covered by the D-REORG-REDB
approval without touching validity, fork choice or RPC-visible data — see §7).

Branch `wf/journal`, base `a03e089` (code tree identical to `3c3792e`, the final D-REORG-REDB code).
Measurements were taken in release on this host (6.18.44-fc-v153, 4 CPUs) under `cpu.lock`, with the
committed, `#[ignore]`-marked measurement test `prototypes/pocold/tests/journal_measure.rs`. That test
only measures the existing code (`store::encode_record`/`encode_frame`, `Node::open` replay,
`Chain::ensure_state`, `Chain::restore_canonical`); it does not change behaviour and does not attack.
Raw logs: `evidence/journal-measure.log`. The adversarial re-fetch witness
(`prototypes/pocold/tests/zz_audit_witness_refetch.rs`, gitignored, **not committed**) produced
`evidence/witness-refetch.log`.

The two profiles referenced throughout (governance.md:5–16; `prototypes/lp4-execution/src/devnet.rs`):

| | GAS_LIMIT | BODY_MAX | TX_MAX | TXBYTES_CAP (cum.) | TX_CAP (cum.) | H_END | T_blk | R_keep | K_hist | S_max | E_max·EVID_BYTES_MAX |
|---|---|---|---|---|---|---|---|---|---|---|---|
| devnet (measured here) | 8,000,000 | 196,608 | 131,072 | 2^24 = 16 MiB | 20,000 | 20,000 | 4 s | 2048 | 32 | 256 | 4·8192 = 32 KiB |
| network (governance.md) | 8,000,000 | 196,608 | 131,072 | 2^33 = 8 GiB | 10^7 | 129,600 | 60 s | 2048 | 32 | 256 | 4·8192 = 32 KiB |

The devnet lowers TXBYTES_CAP/TX_CAP/H_END so an A13 resident bound fits the node budget
(`devnet.rs` comment). R_keep, K_hist, BODY_MAX, GAS_LIMIT, S_max are the network values.

---

## 1. What the journal stores, and what it does not (verified)

Format v2 (`store.rs` header): `journal = MAGIC(8) ‖ binding(32) ‖ record*`, with
`record = len(4) ‖ lenCheck(4) ‖ sha256(payload)(32) ‖ payload ‖ marker(1)`, i.e. `OVERHEAD = 41`
bytes of frame per record (`store::OVERHEAD`). The hard per-record limit is `MAX_RECORD = 4 MiB`.

The **payload** is `RLP([headerBytes, bodyBytes, parentResultBytes])` (`store::encode_record`). So a
record holds, for one block:
- its encoded **header** (`header.encoded`): fixed fields plus the PoW **share list** (9 bytes per
  share nonce, ≤ S_max = 256 shares; `resources::header_max = 768 + 9·S_max = 3072` B worst case);
- its encoded **body** = `RLP([txs, evidence])` (≤ BODY_MAX = 196,608 B; `types::Body::encode`);
- its **parentResult** = winner address + one (nonce, owner) pair per share (≈ 20 + 28·shares B, so up
  to ≈ 7.2 KiB at 256 shares; `node::result_bytes`). This is pocold-specific journal content, re-derived
  and checked on replay (`parentResultMismatch` halts open).

The record does **not** hold receipts, logs, executed state, the trie, or any index. Those are
**re-derived by re-executing the block on replay** (`store.rs` module doc; `chain::validate`/`reexec`).
This is the single most important structural fact for both obligations:

> **Journal disk size is driven by headers + transaction/evidence bytes + the share-derived
> parentResult. It is independent of receipts, logs, code, state and trie — which instead drive
> replay CPU and resident memory.**

### 1.1 Measured bytes per record (devnet, release; `JM-BYTES`)

One block of each kind, built on a real parent (`jm_journal_bytes_per_record`):

| block kind | txs | PoW shares | header B | body B | parentResult B | **record B** | receipts B (NOT stored) | charged log B (NOT stored) | gasUsed |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| empty (fallback, a=1) | 0 | 105 | 1,559 | 3 | 3,282 | **4,895** | 0 | 0 | 0 |
| full-gas transfers | 380 | 2 | 719 | 44,077 | 87 | **44,935** | 102,217 | 0 | 7,980,000 |
| log-heavy (546×LOG0) | 1 | 32 | 991 | 113 | 1,019 | **2,175** | 13,375 | 19,656 | 274,379 |
| full-BODY_MAX (2 big calls) | 2 | 30 | 973 | 196,583 | 957 | **198,568** | 538 | 0 | 827,344 |

(header and parentResult both grow with the PoW share count; the "empty" block above carried 105
shares, so its 1,559 B header and 3,282 B parentResult dwarf its 3 B body.)

Readings:
- The **empty** record is *not* small: at 105 shares its header (1,559 B) and parentResult (~3.3 KB)
  dominate; the body is 3 bytes (`EMPTY_BODY = 0xc2c0c0`). Header and parentResult both scale with the
  PoW share count (0…S_max=256). A 0-share block is ≈ 900 B; a 256-share block is ≈ 10 KB. **The empty
  record therefore ranges ≈ 0.9–10 KB**, driven by the share list, not the (absent) body.
- The **full-gas transfer** block journals 44,935 B but produces 102,217 B of receipts that are
  **not** journaled — a block whose on-disk record is 0.44× its re-derived receipts.
- The **log-heavy** block journals only **2,175 B** (one small deploy tx) while producing 13,375 B of
  receipts and 19,656 B of charged logs — **none journaled**. Logs cost replay CPU and resident
  memory, never journal disk. (The block hit `LOG_COUNT_MAX = 546`; the per-block charged-log ceiling
  is `LOG_BLOCK_MAX = 32 KiB`, still not journaled.)
- The **full-BODY_MAX** record is **198,568 B** ≈ BODY_MAX + header + overhead: the largest a normal
  block reaches. `MAX_RECORD = 4 MiB` is far above it (it bounds a malformed frame, not a valid block).

A linear fallback chain of 1,000 empty a=0 blocks (fewer shares) averaged **1,911 B/record**
(`JM-BUILD`, 1k calibration).

---

## 2. Disk growth model at H_END

### 2.1 Canonical content is bounded by the cumulative validity caps

The canonical chain's transaction count and bytes are bounded forever by the **chain-cumulative**
validity caps (`chain::validate` item 16: `p.cum_txs + … > TX_CAP || p.cum_tx_bytes + txBytes >
TXBYTES_CAP` ⇒ `blockReject`). So the canonical journal content at H_END is at most:

| component | bound | network value |
|---|---|---|
| headers | (H_END+1)·header_max = 129,601·3072 | **0.37 GiB** (matches storage.md:76) |
| transaction bytes | TXBYTES_CAP | **8.0 GiB** (matches storage.md:76 "transactions 8.00") |
| evidence bytes | ≤ (H_END+1)·EVID_BYTES_MAX (storage.md's 1 item/block) … ≤ (H_END+1)·E_max·EVID_BYTES_MAX | **0.99 GiB** … 3.96 GiB |
| parentResult | ≤ (H_END+1)·~7.2 KiB | **≈ 0.89 GiB** (pocold-only; not in the storage.md inventory) |
| framing (41 B) | 41·(H_END+1) | ≈ 5.3 MB |

**Canonical journal ≈ 10.2 GiB worst case** (headers 0.37 + tx 8.0 + evidence 0.99 + parentResult 0.89).
This is exactly the storage.md:76 "blocks" rows (headers + evidence + transactions = 9.36 GiB) **plus**
pocold's extra parentResult (~0.89 GiB). The remaining ~10 GiB of the storage.md 19.65 GiB-logical /
29.5 GiB-disk inventory (code, logs, receipts, state, live/historical trie, **reverse diffs**, side) is
**not in the journal** — it is re-derived on replay or (reverse diffs) not kept at all (§6).

### 2.2 Disk at H_END under each load

Per-record figures from §1.1; the journal file is the sum of all **appended** records
(append-only, no compaction, §3):

| load | per-block record | network H_END = 129,600 | devnet H_END = 20,000 |
|---|---|---|---|
| empty (typical share count) | ~1.9 KB | **≈ 0.25 GB** | ≈ 38 MB |
| empty (worst, 256 shares) | ~10 KB | ≈ 1.3 GB | ≈ 0.2 GB |
| typical (a few txs/block) | header+result+small body | 0.5–2 GB | ≈ 0.1–0.3 GB |
| maximum (cumulative caps) | — | **≈ 10.2 GiB** (§2.1; bounded by TXBYTES_CAP, not H_END·BODY_MAX) | bounded by devnet TXBYTES_CAP = 16 MiB of tx + 0.06 GiB headers/results ≈ **0.1 GiB** |
| adversarial (re-fetch) | +1 record per re-announce cycle per targeted block | **unbounded while targets stay in the R_keep window** (§4) | same |

Note the maximum-load figure is NOT H_END·BODY_MAX (that would be 129,600·198,568 ≈ 24 GB): the
cumulative TXBYTES_CAP = 8 GiB caps the total transaction-byte content of the **canonical** chain.
This cap does **not** bound side-block or re-fetched content (§4).

---

## 3. Re-execution from genesis: open-time replay

`Node::open` replays and re-executes **every committed journal record in import order**
(`node.rs` open: `store::decode_record` → `chain.validate` → `chain.insert` → `chain.retain` per
record), rebuilding state, receipts, tx hashes and fork choice exactly. There is no snapshot and no
checkpoint; open cost is Θ(number of records · per-block execution).

### 3.1 Measured replay (empty blocks, devnet, release; `JM-REPLAY`)

20,000 empty (fallback a=0) blocks built into one journal (389 s build, avg 1,144 B/record),
snapshotted at the devnet checkpoints; each snapshot reopened and the open timed:

| height | records | journal disk | open time | per-record (avg over 0..H) |
|--:|--:|--:|--:|--:|
| 1,000 | 1,000 | 1.91 MB | 2.63 s | 2.63 ms |
| 5,000 | 5,000 | 9.59 MB | 17.01 s | 3.40 ms |
| 20,000 | 20,000 | 22.89 MB | **137.07 s** | 6.85 ms |

**Open replay is super-linear.** The average per-record cost rises 2.63 → 3.40 → 6.85 ms as the
journal grows, so open is Θ(H²), not Θ(H). The cause is in the code, not the EVM: `Chain::retain` is
called after **every** replayed record (`node.rs` open loop) and it scans **all resident blocks**
several times (`let side=|c|c.blocks.values().filter(non-canonical)…`, called for `gone`, `side_now`
and `side_left`, plus the orphan-removal pass). For a linear canonical chain that resident set grows to
H, so each record pays Θ(H) retention work and the whole open is Θ(H²). Fitting `t_avg(H) = a + b·H/2`
to the three points gives a ≈ 2.4 ms (per-block re-execution) and b ≈ 3.9×10⁻⁴ ms per extra resident
block; the quadratic term overtakes re-execution above ≈ 6,000 blocks. (This retain-scan cost is a
pocold implementation property, not a spec requirement — a candidate local optimisation, §7.)

### 3.2 Measured per-record replay by block kind (devnet, release; `JM-KIND`)

40 blocks of each kind (building 20,000 full blocks is infeasible: each full-gas block re-executes
~380 transactions). Per-record replay cost includes a small fixed open overhead amortised over 40
records; for the transaction-heavy kinds that overhead is negligible against execution:

| kind | bytes/record | build s (40) | open s (40) | **per-record replay** |
|---|--:|--:|--:|--:|
| empty | 2,316 | 0.40 | 0.157 | 3.92 ms |
| log-heavy (546×LOG0) | 1,929 | 0.60 | 0.313 | 7.82 ms |
| full-BODY_MAX (2 big calls) | 199,131 | 0.88 | 0.286 | 7.16 ms |
| full-gas transfers (380 tx) | 47,077 | 10.85 | 2.768 | **69.21 ms** |

Replay time tracks **re-execution work**, not record size: the full-gas transfer block (47 KB record)
replays ~18× slower than an empty block because replay re-executes all 380 transactions and rebuilds
their receipts/state; the full-BODY_MAX block (199 KB record, 2 cheap calls) and the log-heavy block
(2 KB record, 546 logs) replay at ~7 ms. So a transaction-saturated chain's open time is driven by the
per-block execution cost (~69 ms here), not by the journal's byte size.

### 3.3 Extrapolation to network H_END = 129,600

**Method.** Open replay re-executes each record on its parent (cost `a` per block, from the fit and
§5.1 ≈ 2.4 ms for an empty block) plus the Θ(H) retain scan per record (slope `b ≈ 3.9×10⁻⁴` ms per
resident block, §3.1). Total open time to height H is `∑_{h≤H}(a + b·h) = a·H + b·H²/2`. The fit
reproduces the measured devnet point (predicted 126 s vs measured 137 s at H=20,000; the residual is
state-growth and allocator effects not in the two-parameter fit, so the projection is a lower bound).
For block kinds with transactions, `a` is the per-record replay of §3.2 (larger); the retain term `b`
is kind-independent.

| height | empty-block open: a·H | + retain b·H²/2 | **total (empty)** |
|--:|--:|--:|--:|
| 20,000 (devnet H_END) | 49 s | 78 s | ≈ 127 s (measured 137 s) |
| 129,600 (network H_END) | 311 s | **3,270 s** | **≈ 1 h (empty blocks)** |

So even an all-empty network chain replays from genesis in ≈ 1 hour at open, dominated by the Θ(H²)
retain scan. A chain carrying transactions replaces `a` with the per-kind replay of §3.2: at the
full-gas 69 ms/record, the re-execution term alone is 129,600 · 69 ms ≈ **2.5 h** on top of the retain
term — though a transaction-saturated chain is also bounded by TXBYTES_CAP = 8 GiB (≈ 190k full-gas
blocks' worth of tx bytes), so the realistic network chain mixes empty and full blocks and open lands
between ≈ 1 h and a few hours. This is the open-time cost of having no snapshot/checkpoint (§7).

### 3.4 Peak RSS during replay

Measured `VmHWM` across the replays was **237 MB**, reached during the 20,000-record open; resident
`VmRSS` after open was 138 MB (1k/5k) and 197 MB (20k). This is the devnet process, far under the
6 GiB A13 budget. The transient scales with the record count: `store::open` reads the whole journal
into memory (`read_to_end`), `Node::open` builds a two-entry replay index per record (`events`
HashMap) and holds `rec.payloads` (every payload) for the whole replay. At network H_END with
full-body records (≈ 198 KB each) the `rec.payloads` vector alone is the sum of all payloads — bounded
like the journal body content (§2). This open-time transient is deliberately **excluded** from the
A13 steady-state bound (`resources.rs` condition `open-replay-transient`; A13-DERIVATION §4) and grows
with the record count.

---

## 4. Adversarial re-fetch re-journal (witness)

**Vector.** A peer that announces a Status with cumulative work ≥ ours triggers a sync session
(`node::sync_tick`/`wants`). A session's blocks are **solicited**, so an evicted (honest, valid) side
block that is still inside the R_keep window is re-validated and **re-journaled**
(`node::import_with`: `journal.append` before the side cap evicts it again). The evicted-hash guard
(`chain::EVICTED_MAX = 1024`) blocks only **unsolicited** re-delivery; a session re-fetch is exempt by
design (consensus.md:235, "a branch that becomes heavier is fetched by sync"). `protect_max = 2·R_keep`
exempts a session's branch from the metadata side cap but is cleared when the session ends
(`end_session`), so across sessions the block is evicted and re-fetched again. The side cap bounds
**resident metadata**, not the **append-only journal on disk**. The blocks are valid, so no
1b/templateForm ban applies (`network.md`: banning is for 1b/templateForm faults).

### 4.1 Witness result (`WITNESS-REFETCH`, devnet, release)

Setup: a 40-block lighter branch and a heavier canonical branch; node with R_keep = 64, side_cap = 16;
all 40 lighter heights stay inside the window (head height 2). The side cap evicted 24 of them
(`evictedTotal = 24`, `residentSideBlocks = 16`). Each round plays one full sync session: solicited
re-fetch of the whole lighter branch, then session end (`protect.clear()` + `retain()`).

| round | records appended | bytes appended | cumulative records | cumulative disk B | refetched total | resident side after retain |
|--:|--:|--:|--:|--:|--:|--:|
| setup | — | — | 42 | 36,934 | 0 | 16 |
| 1 | 24 | 16,503 | 66 | 53,437 | 24 | 16 |
| 2 | 24 | 16,503 | 90 | 69,940 | 48 | 16 |
| 3 | 24 | 16,503 | 114 | 86,443 | 72 | 16 |
| … | … | … | … | … | … | 16 |
| 20 | 24 | 16,503 | 522 | 366,994 | 480 | 16 |

Every round appends exactly the 24 evicted blocks again (**16,503 B/round ≈ 688 B per re-journaled
block**, low-height few-share blocks), while the resident side-block count stays pinned at the cap
(16). Over 20 rounds the journal grew from 36,934 → 366,994 B (**+330,060 B, 10×**) with **no** change
to the head or the resident set. The growth is linear in rounds and unbounded as long as the rounds
continue and the targeted heights stay in the window.

### 4.2 Which existing bound stops it

| mechanism | bounds | stops journal re-growth? |
|---|---|---|
| side cap (`side_cap`, R_keep) | resident non-canonical **metadata** count | **No** — disk is append-only |
| `protect_max` = 2·R_keep | a live session's branch vs the side cap | **No** — cleared at `end_session`; next session re-fetches |
| `EVICTED_MAX` = 1024 | **unsolicited** re-delivery of an evicted hash | **No** — solicited (session) re-fetch is exempt |
| per-peer / queue limits | in-flight bytes, queue depth | **No** — they pace delivery, not cumulative disk |
| ban score | 1b/templateForm faults | **No** — re-announced blocks are valid |
| **R_keep window vs the moving head** | a block ≤ head−R_keep is refused before validation/journaling (`import_with`, the R2.8 fix) | **Partly** — the *only* limiter: once the honest head advances past height+R_keep the target can no longer be re-journaled |

So journal growth from re-fetch is bounded only by **how long the targeted heights remain within the
R_keep window of the advancing head** — i.e. by peer bandwidth and per-block validity cost while the
window covers them. With a **stationary head** (a passive follower, or an attacker pinning the tip) the
growth is linear in re-announce cycles and otherwise unbounded. This matches the task's open cost 4 and
D-REORG-REDB-DESIGN-FREEZE R2.8's "LOW, documented, not changed" note.

---

## 5. Deep-fork rebuild and restore

### 5.1 Deep-fork state rebuild starts from genesis (no reverse diffs)

Adoption at depth ≤ R_keep = 2048 needs the fork point's executed state. R21's K_hist window keeps
executed canonical states only for heights > head−K_hist (=32) and genesis (`chain::retain`: prune
`canonical[1..=head−K_hist]`). A fork point below the window therefore has a **pruned** state, and
`chain::ensure_state`/`ensure_state_with` rebuilds it by **re-executing from the nearest retained
ancestor, which below the window is genesis** — there are no reverse diffs. storage.md:70 and
consensus.md:229 expect reverse diffs for 2048 blocks ("فروق لـ2048 كتلة" / "التراجع بفروق عكسية لكل
الحالة"); pocold keeps none (A13-DERIVATION condition `cpu-and-timing`; D-REORG-REDB freeze R2.8).

#### Measured rebuild vs fork-point height (devnet, empty blocks, release; `JM-REBUILD`)

`Chain::ensure_state` on a canonical block whose state was pruned, after pruning all states but
genesis (worst case = rebuild from genesis):

| fork-point height | blocks re-executed | rebuild time | per-block |
|--:|--:|--:|--:|
| 100 | 100 | 0.21 s | 2.06 ms |
| 500 | 500 | 1.07 s | 2.14 ms |
| 1,000 | 1,000 | 2.49 s | 2.49 ms |
| 2,048 (R_keep) | 2,048 | 5.37 s | 2.62 ms |
| 3,000 | 3,000 | 7.00 s | 2.33 ms |

The rebuild cost is **linear in the fork-point height** (number of blocks re-executed from genesis),
≈ 2.4 ms/block for empty blocks, **not in the fork depth**. This is the rolling re-execution path
(`ensure_state_with`, two snapshots live), which has none of the Θ(H) retain scan that inflates open
(§3.1), so it is cleanly linear. A reverse-diff store (storage.md:70; consensus.md:229) would make it
scale with depth (≤ R_keep = 2048) regardless of the fork-point's height.

### 5.2 Restore after an adoption (`JM-RESTORE`)

After adopting a heavier branch, `Chain::restore_canonical` re-executes the adopted suffix from the
fork point to make the offloaded blocks whole (headers/bodies from the journal, receipts by
re-execution, each root-checked). Cost ≈ fork-point rebuild (§5.1, if the fork-point state is pruned)
plus one re-execution per adopted block.

Measured (`JM-RESTORE`): an adoption whose fork point was at genesis (resident state) and whose adopted
suffix was 3 blocks, 1 of them offloaded, restored in **0.010 s** — i.e. the per-block restore
re-execution matches §5.1's ≈ 2.4 ms/block, with no rebuild because the fork point was resident. The
restore of a **deep** adoption is therefore `restore ≈ rebuild(fork-point height, §5.1) + depth ·
2.4 ms`: when the fork point is below K_hist its state is pruned and the rebuild-from-genesis term
(linear in the fork-point height, §5.1) dominates. (The test's `theirs` branch overtook `ours` in only
3 blocks because fallback a=0 blocks carry more work than a=1 blocks, so the adopted suffix is short;
the dominant deep-reorg term is the fork-point rebuild, measured directly in §5.1.)

### 5.3 Deep-reorg latency vs consensus timing

A reorg to a fork point at height `f`, depth `d`, costs ≈ (rebuild from genesis to `f`, if `f` is below
K_hist) + (d re-executions for restore). From §5.1 the per-block re-execution is ≈ **2.4 ms** (empty
blocks; larger for blocks with transactions, §3.2). Compared with consensus timing (T_blk = 4 s devnet
/ **60 s network**; safe = head−6, finalized = head−60, consensus.md §12):

- **Shallow reorg inside K_hist** (fork point in the last 32 blocks, no rebuild): `d · 2.4 ms`. The
  safe-window depth is 6, so ≈ 14 ms — negligible against T_blk at either profile. This is the common
  case and it is fine.
- **Reorg at the spec depth R_keep = 2048, fork point far below K_hist**: the fork-point state is
  pruned, so the rebuild re-executes from genesis — at network height H that is **H · 2.4 ms**. At
  H = 129,600 that is ≈ **311 s ≈ 5 min** for empty blocks (longer under transaction load), plus
  2048 · 2.4 ms ≈ 5 s for the restored suffix. So a legal depth-2048 adoption near the network tip can
  take **minutes**, far exceeding T_blk = 60 s and the attestation/finality windows. The 2048-deep
  adoption test passes **functionally** (REPAIR-REPORT §3b, 51.8 s — but at devnet height ~611, where
  the genesis rebuild is short), which does not bound the latency at network height. A reverse-diff
  store (storage.md:70) would replace the H-term with a 2048-term (≈ 5 s), independent of height.

### 5.4 Fit to the devnet and network profiles

| aspect | devnet (H_END 20,000, T_blk 4 s) | network (H_END 129,600, T_blk 60 s) |
|---|---|---|
| journal disk, empty/typical | 38 MB … ~0.3 GB | 0.25 GB … ~2 GB |
| journal disk, max (cumulative caps) | ≈ 0.1 GiB (TXBYTES_CAP 16 MiB) | **≈ 10.2 GiB** (TXBYTES_CAP 8 GiB) |
| journal disk, adversarial re-fetch | unbounded within window (§4) | unbounded within window (§4) |
| open replay (empty) | 137 s (measured) | **≈ 1 h** (extrapolated, §3.3) |
| deep reorg at R_keep near tip | ~5–50 s (short genesis rebuild) | **≈ 5 min** (genesis rebuild, §5.3) |

- **Devnet**: fits. Open ≈ 2 min, disk tens of MB to ~0.1 GiB, deep reorgs seconds. The lowered
  H_END/TXBYTES_CAP keep every term small, and the A13 resident bound holds (REPAIR-REPORT §3b).
- **Network**: **does not fit comfortably without a mitigation.** Canonical disk (~10 GiB) is within
  the storage.md inventory, but: (1) open replays from genesis in ≈ 1 h (Θ(H²), §3.1/§3.3); (2) a legal
  deep reorg at the tip takes minutes vs a 60 s block interval (§5.3), because the fork-point state is
  rebuilt from genesis for want of reverse diffs (storage.md:70); (3) the append-only journal has no
  compaction, and the re-fetch vector (§4) is unbounded within the window. None of these is a
  correctness fault; each is an operational limit that a snapshot/compaction and reverse diffs (§7)
  would remove.

---

## 6. Spec comparison

| spec expectation | pocold | effect |
|---|---|---|
| storage.md:61 records keyed by (height, blockHash) for the canonical chain | journal is import-ordered append-only; a by-hash/offset index is in RAM (D-REORG-REDB) | functional parity for reads; no on-disk key index |
| storage.md:70 / consensus.md:229 reverse diffs for 2048 blocks | **none kept** | deep-fork rebuild and restore re-execute from genesis (§5) |
| storage.md:73–77 inventory ~19.65 GiB logical / 29.5 GiB disk | journal holds only headers+bodies+parentResult (~10 GiB); receipts/logs/code/state/trie re-derived | journal ≈ half the inventory; the rest is CPU at open |
| network.md:27 R stage ≤ 4096 headers/branch, ≤ 16384 total; :28 E stage bodies | pocold has no headers-first split: GetFrom/Block deliver full blocks and journal each | re-fetch re-journals full blocks (§4); headers-first would fetch/validate headers before bodies |
| network.md:144 adoption at depth ≤ R_keep | implemented (D-REORG-REDB) | correct; the **cost** is §5 |

---

## 7. Mitigation options (all PROPOSED; none implemented here)

Per the task, a mitigation is implemented only if it is **purely local storage behaviour covered by the
owner-approved D-REORG-REDB** (no change to validity, fork choice or RPC-visible data) **and fully
tested**. None of the following meets that bar within this track, so all are proposed, not implemented:

1. **Headers-first sync (network.md D38 R/E stages).** Fetch and H-pre-validate headers (≤ 4096/branch)
   before requesting bodies, and only journal a block once its branch is chosen. Reduces the re-fetch
   re-journal of §4 to header-sized work on the losing branch. **Normative / node-behaviour change**
   (new R/E message staging and journaling policy, RPC/P2P-visible): PROPOSED, not implemented.
2. **Dedupe markers for re-imported blocks.** Record that a (within-window) block was already journaled
   so a solicited re-fetch does not append a second copy, serving the existing record instead. Changes
   the journal's append semantics and the re-import/importSeq rule (consensus.md:205) and interacts with
   crash recovery and replay equivalence (D-REORG-REDB R2.5) — **not obviously validity-neutral**:
   PROPOSED, not implemented. (A conservative in-window variant could be local, but proving replay
   equivalence and crash consistency is a design task, not a measurement.)
3. **Journal compaction / snapshots.** Compact records below R_keep (or below finality) behind a signed
   state snapshot, so open replays from the snapshot rather than genesis, and disk is bounded past
   R_keep. storage.md's retention model already envisions a signed snapshot after ts_F+30d. This is the
   most promising **local-storage** direction, but a safe compaction must preserve the crash invariant
   ("journal is the source of truth", D-REORG-REDB §3.5), replay equivalence, and the ability to still
   serve/rebuild within R_keep — a frozen design + acceptance tests + mutation controls are required
   before implementation (as D-REORG-REDB itself was). PROPOSED, not implemented in this track.
4. **Reverse diffs (storage.md:70, consensus.md:229).** Keep per-block reverse state diffs for the last
   2048 blocks so a deep-fork rebuild/restore (§5) scales with depth, not with chain height. This is the
   spec's own mechanism. It is a substantial storage subsystem (diff capture on commit, apply on
   rollback, their own A13 term and crash handling) and changes derived-state residency broadly;
   PROPOSED, not implemented.

---

## 8. Obligations — both remain OPEN

- **Journal disk growth** (open costs 3 and 4): OPEN. The canonical journal is bounded (~10 GiB at
  network H_END, §2), but it is append-only with **no compaction**, and the **adversarial re-fetch**
  vector (§4) makes growth unbounded while targets stay in the R_keep window, stopped only by the head
  advancing. No mitigation implemented.
- **Re-execution from genesis** (open costs 1 and 2): OPEN. Open replays every record from genesis
  (§3); a deep-fork rebuild/restore re-executes from genesis for want of reverse diffs (§5). Measured
  and extrapolated here; no snapshot/diff mitigation implemented.

The passing 2048-deep reorg test (REPAIR-REPORT §3b) demonstrates **correctness** of adoption at the
spec depth; it does not bound the **open time, disk growth, or deep-reorg latency** this report
measures, and does not close these obligations.
