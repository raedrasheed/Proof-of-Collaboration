# Journal growth and re-execution-from-genesis — model, measurements, operational limits

Status: measurement and analysis (not normative). Scope: the on-disk block journal of `pocold`
(`prototypes/pocold/src/store.rs`) and the cost of re-execution from genesis it imposes at open, on a
deep-fork state rebuild, and on restore after an adoption. Two obligations are left **OPEN** at the
end; no mitigation is implemented here (none would be purely-local storage covered by the D-REORG-REDB
approval without touching validity, fork choice or RPC-visible data — see §7).

**Round 2 note.** This revision carries the stage-A model forward and corrects it against an independent
review (findings J-V1…J-V13, resolved in §9). The main corrections: a legal deep reorg pays the genesis
rebuild **twice**, not once (§5.3); the open-time memory transient is **≈ 2.3× the journal**, measured in
a fresh process (§3.4); open time under transaction load is bounded by **TX_CAP**, not TXBYTES_CAP, and
is tens of minutes, not "a few hours" (§3.2–§3.3); the super-linear open is **retain + rebuild_canonical**,
not retain alone (§3.1); record sizes vary with the PoW **share count** and are reported as slopes (§1.1);
the re-fetch vector also costs a **genesis rebuild per cycle** when the fork point is below K_hist (§4); and
the **network profile is not admissible on pocold at all** — the A13 history term alone (TXBYTES_CAP = 8 GiB)
exceeds the 6 GiB budget, so every "network" figure here is a projection for the spec's targets, not a
configuration this node boots (§3.3, §5.4).

Branch `wf/journal-r2`, base `a03e089` (code tree identical to `3c3792e`, the final D-REORG-REDB code;
stage A is `wf/journal` 86b339e). Measurements were taken in release on this host (6.18.44-fc-v153,
4 CPUs) under `cpu.lock`, with the committed, `#[ignore]`-marked measurement test
`prototypes/pocold/tests/journal_measure.rs` (which only measures existing code —
`store::encode_record`/`encode_frame`, `Node::open` replay, `Chain::ensure_state`,
`Chain::restore_canonical` — and does not change behaviour or attack). Raw logs:
`evidence/journal-measure.log` (stage A) and `evidence/journal-measure-r2.log` (this round). The
adversarial re-fetch witness (`prototypes/pocold/tests/zz_audit_witness_refetch.rs`, gitignored, **not
committed**) produced `evidence/witness-refetch.log` (stage A, fork at genesis) and
`evidence/witness-refetch-below-khist.log` (this round, fork below K_hist).

The two profiles referenced throughout (governance.md:5–16; `prototypes/lp4-execution/src/devnet.rs`):

| | GAS_LIMIT | BODY_MAX | TX_MAX | TXBYTES_CAP (cum.) | TX_CAP (cum.) | H_END | T_blk | D_att | R_keep | K_hist | side_max | S_max |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| devnet (measured here) | 8,000,000 | 196,608 | 131,072 | 2^24 = 16 MiB | 20,000 | 20,000 | 4 s | 25 s | 2048 | 32 | 8 | 256 |
| network (governance.md) | 8,000,000 | 196,608 | 131,072 | 2^33 = 8 GiB | 10^7 | 129,600 | 60 s | 300 s | 2048 | 32 | 8 | 256 |

The devnet lowers TXBYTES_CAP/TX_CAP/H_END so an A13 resident bound fits the node budget
(`devnet.rs` comment). R_keep, K_hist, side_max (= `single_host().side_max` = 8), BODY_MAX, GAS_LIMIT,
S_max are the network values. **pocold cannot admit the network profile** (§3.3): its A13 history term
includes the whole canonical transaction byte content (TXBYTES_CAP, `resources.rs` `history/transaction
bytes`), which at network is 8 GiB — already over the 6 GiB budget, so `resources::check` refuses to boot
it. Every network figure below is therefore a projection about the spec's targets, not this node.

---

## 1. What the journal stores, and what it does not (verified)

Format v2 (`store.rs` header): `journal = MAGIC(8) ‖ binding(32) ‖ record*`, with
`record = len(4) ‖ lenCheck(4) ‖ sha256(payload)(32) ‖ payload ‖ marker(1)`, i.e. `OVERHEAD = 41`
bytes of frame per record (`store::OVERHEAD`). The hard per-record limit is `MAX_RECORD = 4 MiB`.

The **payload** is `RLP([headerBytes, bodyBytes, parentResultBytes])` (`store::encode_record`). So a
record holds, for one block:
- its encoded **header** (`header.encoded`): fixed fields plus the PoW **share list** (≤ S_max = 256
  shares; `resources::header_max = 768 + 9·S_max = 3072` B worst case);
- its encoded **body** = `RLP([txs, evidence])` (≤ BODY_MAX = 196,608 B; `types::Body::encode`);
- its **parentResult** = winner address + one `(nonce, owner)` pair per share. Each pair encodes to
  **31 B** (`RLP[u64 8 B, addr 20 B]`, measured below), so parentResult ≈ 26 + 31·shares B, up to ≈ 8.0
  KiB at 256 shares (`node::result_bytes`). This is pocold-specific journal content, re-derived and
  checked on replay (`parentResultMismatch` halts open).

The record does **not** hold receipts, logs, executed state, the trie, or any index. Those are
**re-derived by re-executing the block on replay** (`store.rs` module doc; `chain::validate`/`reexec`).
This is the single most important structural fact for both obligations:

> **Journal disk size is driven by headers + transaction/evidence bytes + the share-derived
> parentResult. It is independent of receipts, logs, code, state and trie — which instead drive
> replay CPU and resident memory.**

### 1.1 Measured bytes per record (devnet, release; `JM-BYTES`, re-run on the committed test)

One block of each kind, built on a real parent (`jm_journal_bytes_per_record`). **Record size depends on
the PoW share count, which varies between runs** (the nonce search finds a run-dependent number of
sub-target shares ≤ S_max): both the header and parentResult grow with it, so these are single samples,
not fixed figures (J-V7). The stage-A log's single samples are not reproduced on the committed test; use
the per-share slopes below instead.

| block kind | txs | PoW shares | header B | body B | parentResult B | **record B** | receipts B (NOT stored) | charged log B (NOT stored) | gasUsed |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| empty (fallback, a=1) | 0 | 105 | 1,559 | 3 | 3,282 | **4,895** | 0 | 0 | 0 |
| full-gas transfers | 380 | 59 | 1,234 | 44,838 | 1,856 | **47,981** | 102,217 | 0 | 7,980,000 |
| log-heavy (546×LOG0) | 1 | 75 | 1,378 | 115 | 2,352 | **3,897** | 13,375 | 19,656 | 274,379 |
| full-BODY_MAX (2 big calls) | 2 | 62 | 1,261 | 196,587 | 1,949 | **199,852** | 538 | 0 | 827,344 |
| **full-gas compute** (1 OOG loop) | 1 | 4 | 737 | 103 | 149 | **1,040** | 269 | 0 | 7,950,000 |
| **full-gas log-heavy** (546 logs + filler) | 2 | 18 | 864 | 213 | 585 | **1,714** | 13,644 | 19,656 | 7,924,379 |

Per-share slopes (least-squares over the six samples, `evidence/journal-measure-r2.log`): **parentResult
≈ 31.0 B/share + 26 B** (→ ≈ 7,966 B at 256 shares, **0.96 GiB** cumulative at network H_END); **header
≈ 8.4 B/share + 722 B** (→ ≈ 2,863 B at 256 shares, under `header_max` = 3072).

Readings:
- The **empty** record is *not* small: at 105 shares its header (1,559 B) and parentResult (~3.3 KB)
  dominate; the body is 3 bytes. A 0-share block is ≈ 0.75 KB; a 256-share block is ≈ 10.8 KB. **The
  empty record ranges ≈ 0.75–10.8 KB**, driven by the share list, not the (absent) body.
- The two new **full-gas** rows confirm the structural fact from both sides. A **full-gas compute** block
  (one tx whose init code is a tight loop that runs out of 8M gas) journals only **1,040 B** (no caps bind
  it, so H_END of them is reachable — the open-time worst case, §3.2). A **full-gas log-heavy** block
  (546 logs then a compute filler to ≈ 7.9M gas) journals **1,714 B** while producing 13,644 B of
  receipts and 19,656 B of charged logs — **none journaled**. (A *single* tx cannot be both full-gas and
  546-log: exceeding the log caps halts the tx with all gas and **no** logs, and running out of gas
  reverts its logs; so the log-heavy full-gas block needs two txs.)
- The **full-gas transfer** block journals ~48 KB but produces 102 KB of receipts that are **not**
  journaled. The **full-BODY_MAX** record (~200 KB) is the largest a normal block reaches; `MAX_RECORD =
  4 MiB` bounds a malformed frame, not a valid block.

A linear fallback chain of empty a=0 blocks averaged ~1,144 B/record at 20k (`JM-BUILD`, stage A — fewer
shares than the a=1 samples above).

---

## 2. Disk growth model at H_END

### 2.1 Canonical content is bounded by the cumulative validity caps

The canonical chain's transaction count and bytes are bounded forever by the **chain-cumulative**
validity caps (`chain::validate` item 16: `p.cum_txs + … > TX_CAP || p.cum_tx_bytes + txBytes >
TXBYTES_CAP` ⇒ `blockReject`). So the canonical journal content at H_END is at most:

| component | bound | network value |
|---|---|---|
| headers | (H_END+1)·header_max = 129,601·3072 | **0.37 GiB** (matches storage.md:76) |
| transaction bytes | TXBYTES_CAP | **8.00 GiB** (matches storage.md:76 "transactions 8.00") |
| evidence bytes | ≥ (H_END+1)·EVID_BYTES_MAX (storage.md's 1 item/block) | **0.99 GiB** (floor) |
| evidence bytes | ≤ (H_END+1)·E_max·EVID_BYTES_MAX (per-block E_max=4) | 3.96 GiB (per-block ceiling) |
| parentResult | ≤ (H_END+1)·~7.97 KiB (31 B/share, 256 shares) | **≈ 0.96 GiB** (pocold-only; not in storage.md) |
| framing (41 B) | 41·(H_END+1) | ≈ 5.3 MB |

**Canonical journal ≈ 10.3 GiB** using storage.md's 1-evidence-item-per-block figure (headers 0.37 + tx
8.0 + evidence 0.99 + parentResult 0.96 + framing 0.005). The evidence term is the only soft one: the
**per-block** validity ceiling is E_max·EVID_BYTES_MAX (→ 3.96 GiB, canonical journal ≈ **13.3 GiB**), and
the A13 derivation bounds evidence instead by distinct identities (≈ 1.98 GiB, `A13-DERIVATION.md`
`history/evidence`). The ≈ 10.3 GiB figure is the storage.md inventory assumption, not the worst case;
the honest range is **≈ 10.3–13.3 GiB** (J-V11). The non-evidence terms (headers + tx + parentResult + framing
≈ 9.3 GiB) are firm. The rest of the storage.md ~19.65 GiB-logical / 29.5 GiB-disk inventory (code, logs,
receipts, state, live/historical trie, **reverse diffs**, side) is **not in the journal** — it is re-derived
on replay or (reverse diffs) not kept at all (§6).

### 2.2 Disk at H_END under each load

Per-record figures from §1.1; the journal file is the sum of all **appended** records
(append-only, no compaction, §3):

| load | per-block record | network H_END = 129,600 | devnet H_END = 20,000 |
|---|---|---|---|
| empty (typical ~105 shares) | ~4.9 KB | **≈ 0.6 GB** | ≈ 0.1 GB |
| empty (worst, 256 shares) | ~10.8 KB | ≈ 1.4 GB | ≈ 0.2 GB |
| empty (few shares, a=0 fallback) | ~1.1 KB | ≈ 0.15 GB | **22.9 MB** (measured, 20k records) |
| maximum (cumulative caps) | — | **≈ 10.3–13.3 GiB** (§2.1; bounded by TXBYTES_CAP, not H_END·BODY_MAX) | **≈ 0.22 GiB** (tx 16 MiB + headers 0.057 + parentResult 0.148 GiB) |
| adversarial (re-fetch) | +1 record per re-journal cycle per targeted block | **grows per cycle while targets stay in the R_keep window** (§4) | same |

The maximum-load figure is NOT H_END·BODY_MAX (≈ 24 GB): the cumulative TXBYTES_CAP = 8 GiB caps the
total transaction-byte content of the **canonical** chain. This cap does **not** bound side-block or
re-fetched content (§4). The measured devnet empty-chain journal at exactly 20,000 a=0 records was
**22.89 MB** (1,144 B/record average; `JM-BUILD`), correcting stage A's ≈ 38 MB estimate (J-V12).

---

## 3. Re-execution from genesis: open-time replay

`Node::open` replays and re-executes **every committed journal record in import order**
(`node.rs` open: `store::decode_record` → `chain.validate` → `chain.insert` → `chain.retain` per
record), rebuilding state, receipts, tx hashes and fork choice exactly. There is no snapshot and no
checkpoint; open cost is Θ(number of records · per-block execution) plus a per-record retention/index
term (§3.1).

### 3.1 Measured replay (empty blocks, devnet, release; `JM-REPLAY`, stage A)

20,000 empty (fallback a=0) blocks built into one journal, snapshotted at the devnet checkpoints; each
snapshot reopened and the open timed (these stage-A open times are correct and are not re-run):

| height | records | journal disk | open time | per-record (avg over 0..H) |
|--:|--:|--:|--:|--:|
| 1,000 | 1,000 | 1.91 MB | 2.63 s | 2.63 ms |
| 5,000 | 5,000 | 9.59 MB | 17.01 s | 3.40 ms |
| 20,000 | 20,000 | 22.89 MB | **137.07 s** | 6.85 ms |

**Open replay is super-linear** (Θ(H²)). The cause is in the code, not the EVM, and it is **two** O(H)
per-record terms, not one (J-V10). The per-record split, measured on a bare replaying chain
(`jm_replay_component_split`, `JM-SPLIT`, 6,000 blocks):

| height bucket | validate (ms) | insert → rebuild_canonical (ms) | retain (ms) |
|---|--:|--:|--:|
| 1..1000 | 2.90 | 0.04 | 0.10 |
| 5001..6000 | 2.77 | 0.60 | 1.36 |

`Chain::validate` is flat (~2.8 ms, the EVM re-execution). The super-linear part is `Chain::retain`
(scans **all** resident blocks several times per call; ~70% of it) **plus** `Chain::insert` →
`rebuild_canonical` (walks head→genesis on every head change; ~30%). Both grow to Θ(H); so
`∑_{h≤H}(a + b·h) = a·H + b·H²/2` with `a` the flat re-execution and `b` the combined O(H) slope. Stage A
attributed the quadratic to `retain` alone — an under-attribution the §7 optimisation candidate must
account for (both the retain scan and the canonical-index walk).

### 3.2 Measured per-record replay by block kind (devnet, release; `JM-KIND`)

40 blocks of each kind (building 20,000 full blocks is infeasible). Per-record replay includes a small
fixed open overhead amortised over 40 records (a ≈ 57 ms intercept, ≈ 1.4 ms/record at count 40, J-V9;
subtract it for the steady figure):

| kind | bytes/record | **per-record replay (ms)** | note |
|---|--:|--:|---|
| empty | 2,316 | 4.48 | flat re-execution |
| log-heavy (546×LOG0, 274k gas) | 1,929 | 4.97 | logs cost CPU/receipts, not journal |
| full-BODY_MAX (2 cheap calls) | 199,131 | 7.04 | big record, little compute |
| **full-gas compute** (1 tx, 8M-gas loop) | 2,006 | **9.64** | no cap binds it (§3.3) |
| full-gas transfers (380 tx) | 47,077 | **73.43** | **worst per-block**: 380 ECDSA recoveries + state |

Replay time tracks **re-execution work**, not record size. The worst per-block replay is the
transaction-saturated transfer block (73 ms, dominated by 380 signature recoveries), not the compute
loop (9.6 ms) or the big-but-cheap body-max block (7 ms).

### 3.3 Extrapolation to network H_END = 129,600 (a projection; pocold cannot boot this profile)

**pocold does not admit the network profile.** `Node::open` calls `resources::check` first; the A13
history term `history/transaction bytes (TXBYTES_CAP)` is the whole canonical transaction byte content,
= 8 GiB at network — already over the 6 GiB budget — so the check refuses to boot (`resources.rs`).
Canonical bodies are resident (D-REORG-REDB offloads only *non-canonical* blocks), which is why this term
is resident. The figures below are therefore projections about the spec's targets, for a hypothetical node
that could hold the network caps, **not** this node.

**Method.** Open time to height H is `a·H + b·H²/2`. A least-squares fit of this to the three devnet
`JM-REPLAY` points gives **a = 2.26 ms, b = 4.59×10⁻⁴ ms**, reproducing the measured 137.07 s at H=20,000
(J-V9; stage A's a=2.4, b=3.9×10⁻⁴ predicted 126 s and mislabelled the residual a "lower bound"). The
cache was warm (snapshots copied just before each open); the fit is one run per point. For kinds with
transactions, `a` is the per-kind replay of §3.2; the `b` term is kind-independent.

| height | empty: a·H | + b·H²/2 | **total (empty)** |
|--:|--:|--:|--:|
| 20,000 (devnet H_END) | 45 s | 92 s | ≈ 137 s (measured) |
| 129,600 (network, projected) | 293 s | **3,856 s** | **≈ 69 min (empty blocks)** |

So an all-empty network-scale chain would replay from genesis in **≈ 69 minutes** at open, dominated by
the Θ(H²) retain+index term (stage A's "≈ 1 h" was in range but used the wrong fit). Under **transaction
load** the binding cap is **TX_CAP, not TXBYTES_CAP** (J-V6): TX_CAP = 10⁷ limits full-gas transfer
blocks (380 tx each) to ≈ 26,315, whose replay term is 26,315 · 73 ms ≈ **32 min**; compute-heavy blocks
(1 tx, 8M gas) are bounded by no cap, so H_END of them replay in 129,600 · 9.6 ms ≈ **21 min**. Either
term is **tens of minutes**, on top of the empty Θ(H²) term — not stage A's "≈ 2.5 h". A realistic mixed
chain's open lands around **1–1.5 h**. This is the open-time cost of having no snapshot/checkpoint (§7).

### 3.4 Open-time memory transient (fresh-process; `JM-OPENMEM`)

The open transient is **≈ 2.3× the journal size**, measured correctly only in a fresh process (J-V4,
J-V5). `store::open` reads the whole journal (`read_to_end`) and `parse_v2` copies each payload into a
`Vec`, so the whole journal and the sum of payloads coexist; `Node::open` then holds every payload for
the entire replay. Measured on an 85-record full-BODY_MAX journal of 16,901,698 B:

| method | peak above baseline | peak / journal |
|---|--:|--:|
| **fresh process** (only opens; VmHWM from process start) | 39.5 MB | **2.34×** |
| same process as the build (VmHWM reset via `clear_refs`) | 14.5 MB | 0.86× (under-counts: allocator reuses the build's freed memory) |

Stage A reported a 237 MB VmHWM "reached during the 20,000-record open" — that was the process-lifetime
peak of the in-process **build** phase (VmHWM was already 237 MB before the first open and never rose
during any open; `rssAfter == rssBefore` at 1k/5k), not the open. Peak open RSS was never isolated in
stage A; this round measures it in a child process.

Consequences: at the maximum canonical journal (~10.3 GiB, §2.1) open would need **≈ 24 GiB** of RAM —
far over MEM_BUDGET = 6 GiB — so even if the network caps were resident-admissible, restart would not fit.
Under the adversarial vector (§4) the journal, and so the open transient, grows without bound, so a node
can be pushed into a state where it **cannot restart**. The open transient is deliberately excluded from
the A13 steady-state bound (`resources.rs` condition `open-replay-transient`); it is an open obligation in
its own right (§8).

---

## 4. Adversarial re-fetch re-journal (witness)

**Vector.** A sync session's blocks are **solicited**, so an evicted (honest, valid) in-window side block
is re-validated and **re-journaled** (`node::import_with`: `journal.append` before the side cap evicts it
again; `EVICTED_MAX` blocks only **unsolicited** re-delivery). This round's witness forks the evicted
blocks **below K_hist**, which exposes the cost stage A's genesis-forked witness could not see.

### 4.1 Two costs per cycle (`WITNESS-REFETCH-below-khist`, devnet, release)

Setup: canonical C of 600 a=0 blocks, fork point at height 300 (**below** K_hist = 32), a 40-block
lighter side branch S from the fork point; node with R_keep = 1024 (S stays in the window), side_cap = 16.
Each round re-imports S (solicited), then `protect.clear()` (mirrors `end_session`) + `retain()` (stands
in for the retain a later successful import runs). Every round, over 8 rounds:

| per cycle | measured | cost |
|---|--:|---|
| **disk** — records re-journaled | 24 records, **16,464 B** appended | append-only; linear, unbounded while in window |
| **CPU** — TrieRebuild re-executions | **316** (≈ fork-point height 300 + 16), ≈ 0.8 s devnet | genesis rebuild on the single consensus thread |
| resident side metadata | pinned at **16** (= side_cap) | the cap bounds metadata, not disk |
| evicted-hash total | grows 24→216 | — |

The **CPU amplification** is new (J-V2): because the lowest re-imported block's parent is the pruned
canonical fork point (below K_hist), each cycle re-executes from genesis — ≈ fork-point height blocks,
≈ **5 min of blocked event loop per cycle at a network-scale fork point**, on top of the disk re-journal.
Stage A's witness forked at genesis (headHeight 2), whose state is always resident, so it measured 0
rebuilds and saw only the disk cost. (Open replay does **not** re-pay this per round: replay's side set is
capped at side_cap + protect_max and the re-imports replay as `Duplicate` — the amplification is
live-only.)

### 4.2 What this witness drives, and the real per-session bound

The witness drives the **solicited-import + retention path directly**; it does **not** drive the TCP
sync-session lifecycle (Hello/`start_session`/`SESSION_GAP_MS`/`protect_max`/`best_h`). Two consequences,
from the code, bound the real vector (J-V3; the stage-A claim that growth is "unbounded, only the head
limits it" is downgraded to analysis):

1. **The cycle rate is gated by retain triggers.** `end_session` clears `protect` but does **not** call
   `retain` (`node.rs:578-581`); a `Duplicate` re-import does not either. So a live re-eviction (needed
   before the block can be re-fetched again) requires a **later successful import** to run `retain` — an
   honest block every T_blk, or other new blocks. The 16.5 KB "round" is a synthetic unit; the real
   cadence is paced by the honest chain's own progress.
2. **The per-session journaling is bounded.** A session ends when its protected branch reaches
   `protect_max = 2·R_keep = 4096` blocks (`sync_tick`). So one session re-journals at most
   `min(evicted-in-window, 4096)` records, ≈ **44 MB** of 256-share fallback records or ≈ **815 MB** of
   full-BODY_MAX records. The precondition for a full window of re-fetchable side blocks is more than
   side_cap resident in-window side blocks, which the attacker must first produce (real PoW cost per
   block).

So growth across sessions is **not free**: each cycle is gated by honest progress and costs the attacker a
heavier branch (or a flapping reorg), and each session's re-journal is bounded by `protect_max`. The one
**standing** limiter on cumulative disk is the **R_keep window advancing** past `height + R_keep` as the
honest head grows (`import_with` height guard, the R2.8 fix refuses a new block at or below head−R_keep
before validation/journaling). Which existing bound stops the growth:

| mechanism | bounds | stops journal re-growth? |
|---|---|---|
| side cap (`side_cap`, R_keep) | resident non-canonical **metadata** count | **No** — disk is append-only |
| `protect_max` = 2·R_keep | a live session's branch; caps **one session** at 4096 records | **Per session** — not across sessions |
| `EVICTED_MAX` = 1024 | **unsolicited** re-delivery of an evicted hash | **No** — solicited (session) re-fetch is exempt |
| per-peer / queue limits | in-flight bytes, queue depth | **No** — they pace delivery, not cumulative disk |
| ban score | 1b/templateForm faults | **No** — re-announced blocks are valid |
| **R_keep window vs the moving head** | a block ≤ head−R_keep is refused before validation/journaling | **The standing limiter** — once the head passes height+R_keep the target is no longer re-journaled |

The designed re-fetch (consensus.md §10: "الفرع الذي يصير أثقل لاحقًا يُجلب بالمزامنة") covers a branch
that becomes **heavier** (adoption), not re-fetching a **lighter** evicted branch (J-V13); the realistic
real-path growth is therefore repeated **adoption/flapping** (each adoption re-journals the adopted
offloaded branch and, below K_hist, pays the §5.3 double rebuild), bounded per session by `protect_max`.
The positive control that the real TCP session path performs a solicited re-fetch + restore end to end is
the committed test `a_sync_session_refetches_an_evicted_branch_and_serves_it` (tests/consensus.rs).

---

## 5. Deep-fork rebuild and restore

### 5.1 Deep-fork state rebuild starts from genesis (no reverse diffs)

A fork point below the K_hist window (=32) has a **pruned** state, and `ensure_state_with` rebuilds it by
**re-executing from the nearest retained ancestor, which below the window is genesis** — there are no
reverse diffs (storage.md:70 / consensus.md:230–232 expect reverse diffs up to R_keep, then TrieRebuild;
pocold keeps none, so a genesis TrieRebuild inside R_keep is a **conformance gap**, §6/§9).

Measured rebuild vs fork-point height (`jm_deep_fork_rebuild_vs_height`, `JM-REBUILD`, de-duplicated):

| fork-point height | rebuild time | per-block |
|--:|--:|--:|
| 100 | 0.245 s | 2.45 ms |
| 500 | 1.249 s | 2.50 ms |
| 1,000 | 2.402 s | 2.40 ms |
| 2,048 (R_keep) | 5.082 s | 2.48 ms |
| 3,000 | 7.407 s | 2.47 ms |

Rebuild cost is **linear in the fork-point height** (blocks re-executed from genesis), ≈ **2.4 ms/block**
for empty blocks, **not in the fork depth** — the clean rolling path (`ensure_state_with`, two snapshots
live), with none of the Θ(H) retain scan of open (§3.1). Reverse diffs would make it scale with depth
(≤ R_keep).

### 5.2 Deep reorg measured end to end (`jm_deep_reorg_latency`, `JM-REORG`)

Stage A's `jm_restore_cost` could not measure a deep restore (its competing branch forked at genesis and
overtook in 3 blocks, so the restore term was never exercised; J-V8). This round builds a real deep reorg:
canonical C of 600 blocks, fork point at height 300 (below K_hist), competing branch T of 286 blocks that
becomes strictly heavier and is adopted. Measured:

| phase | re-executions (`chain.rebuilds`) | time |
|---|--:|--:|
| first side import of T (NeedsRebuild of the fork point) | 300 | 0.624 s |
| adopting import (restore_canonical) | 300 (+ 284 suffix restored) | 1.470 s |
| **all T imports** | **600** | 3.278 s |
| reopen the resulting journal (replay re-pays both) | 600 | 5.262 s (886 records) |

The deep reorg re-executes the fork point from genesis **twice**: 600 rebuilds for a fork point at height
300, where the stage-A model predicted one rebuild of 300 (J-V1). See §5.3.

### 5.3 Deep-reorg latency vs consensus timing — the genesis rebuild runs TWICE

A legal adoption at depth `d`, fork point height `f` below K_hist, pays the genesis rebuild of `f`
**twice** on the single consensus thread, in two separate blocking stalls:

1. When the **first** competing block is validated: its parent is the canonical fork point, whose state is
   pruned → `NeedsRebuild` → `ensure_state_with` from genesis (`f` re-executions).
2. When the branch is **adopted**: `import_with` runs `retain()` **before** `restore_canonical`
   (`node.rs`: `self.chain.retain(); … restore_canonical(fork_h,…)`), and `retain` re-prunes the
   still-canonical fork point, so `restore_canonical`'s `ensure_state_with(fork point)` rebuilds it from
   genesis a **second** time (`f` re-executions), then re-executes the `d`-block suffix.

So **latency ≈ 2·rebuild(f) + 2·d·a** (two genesis rebuilds + validate-suffix + restore-suffix), i.e. two
stalls of ≈ `f·a` each. Measured per-block ≈ 2.08 ms (0.624 s / 300); the §5.1 rebuild path gives
≈ 2.4 ms. Projected to a reorg near the tip (`f ≈ H`, `d ≤ R_keep = 2048`):

| profile | two stalls of ≈ H·a | total ≈ 2·H·a | vs T_blk | vs D_att (attempt window) |
|---|--:|--:|---|---|
| network (H=129,600, a=2.4 ms) | ≈ 5.2 min each | **≈ 10.4 min** | T_blk = 60 s | **each stall ≫ D_att = 300 s** |
| devnet near H_END (H≈17,952, a=2.4 ms) | ≈ 43 s each | **≈ 86 s** | T_blk = 4 s | **each stall > D_att = 25 s** |

Both stalls exceed the attempt window D_att (governance.md:6: network 300 s, devnet 25 s) and the
safe(k_safe=6)/finalized(k_final=60) horizons translate to far less wall-clock than these stalls. A
**shallow** reorg inside K_hist (fork point in the last 32 blocks, no rebuild) is `d·a` ≈ 14 ms for the
safe depth 6 — negligible — and is the common case. The passing 2048-deep adoption test (REPAIR-REPORT
§3b, 51.8 s) is at devnet height ~611, where the genesis rebuild is short; it demonstrates **correctness**
of adoption at the spec depth and does **not** bound the latency at network height. A reverse-diff store
(storage.md:70) would replace each H-term with a ≤ R_keep term (≈ 5 s), independent of height, and would
also remove the double rebuild (the fork-point state would be restorable by applying ≤ R_keep reverse
diffs rather than re-executed).

### 5.4 Fit to the devnet and network profiles

| aspect | devnet (H_END 20,000, T_blk 4 s, D_att 25 s) | network (H_END 129,600, T_blk 60 s, D_att 300 s) |
|---|---|---|
| boots at this profile? | **yes** (A13 fits) | **no** — A13 history ≥ TXBYTES_CAP = 8 GiB > 6 GiB budget (§3.3) |
| journal disk, empty/typical | 23 MB … ~0.2 GB | (projected) 0.15 … ~0.6 GB |
| journal disk, max (cumulative caps) | ≈ 0.22 GiB | (projected) **≈ 10.3–13.3 GiB** |
| journal disk, adversarial re-fetch | grows per cycle within window (§4) | (projected) same |
| open replay (empty) | 137 s (measured) | (projected) **≈ 69 min** (§3.3) |
| open memory transient | ≈ 2.3× journal (§3.4) | (projected) ≈ 24 GiB at max journal ≫ budget |
| deep reorg at R_keep near tip | **≈ 86 s** (two ~43 s stalls, each > D_att = 25 s) | (projected) **≈ 10.4 min** (two ~5 min stalls, each ≫ D_att = 300 s) |

- **Devnet**: open ≈ 2 min and disk tens of MB fit, but a **deep reorg near H_END does not fit** — each of
  the two genesis-rebuild stalls (~43 s) exceeds both T_blk (4 s) and D_att (25 s). By ratio to T_blk the
  devnet deep reorg is *worse* than network (stage A's "deep reorgs seconds — fits" was wrong; J-V1).
- **Network**: not admissible on this node at all; as a projection it would (1) replay from genesis in
  ≈ 69 min at open (Θ(H²)); (2) take ≈ 10 min for a legal deep reorg at the tip in two blocking stalls;
  (3) need ≈ 24 GiB to open the maximum journal; (4) grow unboundedly under the re-fetch vector within the
  window. None is a correctness fault; each is an operational limit a snapshot/compaction + reverse diffs
  (§7) would remove.

---

## 6. Spec comparison

| spec expectation | pocold | effect / classification |
|---|---|---|
| storage.md:61 records keyed by (height, blockHash) for the canonical chain | import-ordered append-only journal; by-hash/offset index in RAM (D-REORG-REDB) | functional parity for reads; no on-disk key index |
| storage.md:70 / consensus.md:230–232 reverse diffs up to R_keep, then TrieRebuild | **none kept**; TrieRebuild from genesis inside R_keep | **conformance gap**: deep-fork rebuild/restore re-execute from genesis (§5), paid twice per reorg (§5.3) |
| storage.md:73–77 inventory ~19.65 GiB logical / 29.5 GiB disk | journal holds only headers+bodies+parentResult (~10.3 GiB); receipts/logs/code/state/trie re-derived | journal ≈ half the inventory; the rest is CPU/RAM at open |
| network.md:7, :26–28 D38 R stage ≤ 4096 headers/branch, ≤ 16384 total; E stage GetBodies | pocold has no headers-first split: GetFrom/Block deliver full blocks and journal each | **conformance gap** (approved text): re-fetch re-journals full blocks (§4) |
| network.md:144 adoption at depth ≤ R_keep | implemented (D-REORG-REDB) | correct; the **cost** is §5 |

---

## 7. Mitigation options (all PROPOSED; none implemented here)

Per the task, a mitigation is implemented only if it is **purely local storage behaviour covered by the
owner-approved D-REORG-REDB** (no change to validity, fork choice or RPC-visible data) **and fully
tested**. None of the following meets that bar within this track, so all are proposed, not implemented.
Two are **conformance gaps against already-approved spec text** (still needing a frozen design + tests
before implementation, like D-REORG-REDB itself); the others are new proposals.

1. **Headers-first sync (network.md D38 R/E stages — approved text, conformance gap).** Fetch and
   H-pre-validate headers (≤ 4096/branch) before bodies, and journal a block only once its branch is
   chosen. Reduces the §4 re-journal of a losing branch to header-sized work. The staging is approved
   (network.md:26–28); the "journal once the branch is chosen" part is the behaviour change. Needs a
   frozen design + tests; PROPOSED.
2. **Dedupe markers for re-imported blocks.** Record that a within-window block was already journaled so a
   solicited re-fetch serves the existing record instead of appending a copy. A marker record could still
   assign a new `importSeq` (consensus.md:205), and D118 (≤ 2 side per height, consensus.md:233–236)
   bounds how many markers a height needs; but proving replay equivalence and crash consistency
   (D-REORG-REDB R2.5) is a design task. PROPOSED.
3. **Journal compaction / signed snapshots.** Compact records below R_keep (or below finality) behind a
   signed state snapshot, so open replays from the snapshot rather than genesis and disk is bounded past
   R_keep (storage.md already envisions a signed snapshot after ts_F+30d). The most promising
   **local-storage** direction, but a safe compaction must preserve the crash invariant, replay
   equivalence and serve/rebuild within R_keep — a frozen design + acceptance tests + mutation controls
   first. PROPOSED.
4. **Reverse diffs (storage.md:70, consensus.md:230–232 — approved spec, conformance gap).** Keep per-block
   reverse state diffs for the last R_keep blocks so a deep-fork rebuild/restore scales with depth, not
   height, and the §5.3 double genesis rebuild disappears. The spec's own mechanism; a substantial storage
   subsystem (diff capture on commit, apply on rollback, its own A13 term and crash handling). PROPOSED.
5. **Reduce the open per-record cost (local optimisation candidate, OPT).** Make `retain` O(window) by
   tracking the non-canonical set incrementally, and keep the canonical index incremental instead of
   `rebuild_canonical` walking head→genesis per head change (§3.1), to make open Θ(H) rather than Θ(H²).
   Likely validity/fork-choice/RPC-neutral, but unimplemented and unverified here; it needs its own tests
   and a mutation control. PROPOSED (candidate for the orchestrator to scope).

---

## 8. Obligations — both remain OPEN

- **Journal disk growth** (open costs 3 and 4): OPEN. The canonical journal is bounded (~10.3–13.3 GiB at
  network H_END, §2) but append-only with **no compaction**; the **adversarial re-fetch** vector (§4)
  grows it per cycle while targets stay in the R_keep window, now shown to also cost a genesis rebuild per
  cycle below K_hist. Per-session re-journal is bounded by `protect_max`; cross-session growth is gated by
  honest progress and the moving window. No mitigation implemented.
- **Re-execution from genesis** (open costs 1 and 2): OPEN. Open replays every record from genesis (§3,
  Θ(H²), ≈ 69 min projected at network H_END); a deep-fork rebuild/restore re-executes from genesis
  **twice** for want of reverse diffs (§5.3), so a legal depth-2048 reorg near the tip takes ≈ 10 min in
  two stalls, each exceeding D_att. No snapshot/diff mitigation implemented.
- **Open-time memory transient** (surfaced this round): OPEN. Open needs ≈ 2.3× the journal in RAM
  (§3.4), excluded from the A13 steady-state bound; at the maximum or adversarial journal it exceeds the
  budget, so a node can be pushed into a state where it cannot restart. No mitigation implemented.

The passing 2048-deep reorg test demonstrates **correctness** of adoption at the spec depth; it does not
bound the open time, disk growth, deep-reorg latency, or open memory this report measures, and does not
close these obligations.

---

## 9. Review findings — resolution (round 2)

| # | finding | resolution |
|---|---|---|
| J-V1 (blocker) | deep-reorg model omits the second genesis rebuild | **Fixed in report.** Measured 600 rebuilds for a fork point at height 300 (`JM-REORG`); §5.2–§5.3 restate latency ≈ 2·rebuild(f) + 2·d·a ≈ 10 min network / 86 s devnet in two stalls, each > D_att. §5.4 devnet verdict corrected to "does not fit for deep reorgs near H_END". Not a code defect (correct behaviour, a documented cost); mitigation stays PROPOSED. |
| J-V2 (major) | re-fetch vector also costs a genesis rebuild per cycle | **Fixed in report + witness.** New witness forks below K_hist; `WITNESS-REFETCH-below-khist` shows 316 rebuilds/cycle (≈ fork-point height). §4.1 adds the CPU amplification to the open obligation. |
| J-V3 (major) | witness skips the real session path; boundsChecked were literals | **Downgraded to analysis.** §4.2 describes the real lifecycle (end_session does not retain; per-session bound = protect_max × record size; cycle rate gated by honest progress), cites the committed positive control, and the new witness OBSERVES its bounds. The refetch claim is PARTIAL, not VERIFIED. |
| J-V4 (major) | ~2.1× journal RAM at open; network profile not admissible | **Fixed.** `JM-OPENMEM-FRESH` = 2.34× journal (§3.4); §3.3/§5.4 state the network profile is not admissible (A13 history ≥ TXBYTES_CAP); open-memory added to §8. |
| J-V5 (major) | VmHWM misattributed; peak replay RSS never measured | **Fixed.** §3.4 explains the stage-A VmHWM was the build-phase peak; the fresh-process measurement isolates the open peak. |
| J-V6 (major) | wrong cap for tx-load open; compute-heavy block unmeasured | **Fixed.** §3.2 adds `full_gas_compute` (9.6 ms) and `full_gas_logs`; §3.3 bounds transfer load by TX_CAP (≈ 32 min) and compute by H_END (≈ 21 min), not the 2.5 h / TXBYTES_CAP claim. |
| J-V7 (major) | JM-BYTES from a pre-fix harness; single samples | **Fixed.** JM-BYTES re-run on the committed test (`journal-measure-r2.log`); §1.1 reports record size as per-share slopes and notes the share-count variance. |
| J-V8 (major) | jm_restore_cost cannot measure a deep restore | **Fixed.** Replaced with `jm_deep_reorg_latency` (fork below K_hist); restore measured within the real deep reorg (§5.2). |
| J-V9 (minor) | fit params were not the fit; "lower bound" artifact | **Fixed.** Least-squares a=2.26, b=4.59e-4 (reproduces 137 s); network ≈ 69 min; warm cache and single-run noted; "lower bound" dropped (§3.3). |
| J-V10 (minor) | Θ(H²) attributed to retain alone | **Fixed.** `JM-SPLIT` attributes it to retain (~70%) + insert/rebuild_canonical (~30%); §3.1 and the §7 optimisation updated. |
| J-V11 (minor) | parentResult byte/share and worst-case evidence/total | **Fixed.** 31 B/share (§1), parentResult 0.96 GiB, canonical worst stated as a range 10.3–13.3 GiB (§2.1), devnet max 0.22 GiB (§2.2). |
| J-V12 (minor) | inconsistent devnet disk / cited line / duplicate fps | **Fixed.** devnet empty 22.9 MB measured (§2.2); `jm_deep_fork_rebuild_vs_height` fps de-duplicated and re-run. |
| J-V13 (minor) | spec-citation/classification gaps | **Fixed.** §6/§7/§9: MIT-1 and MIT-4 re-labelled conformance gaps against approved text; consensus.md §10 citation corrected (covers a heavier branch, not a lighter evicted one); D118/marker note added for MIT-2. |
