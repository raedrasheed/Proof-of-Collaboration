# Decision package (2026-10-24)

**Status: for the owner's decision.** Nothing in this file is approved because it is written here, and no normative text is
edited. Each item has one of three tags:

- **[CONFORMANCE]**: brings pocold closer to text that is already approved (the M1 reference). It changes
  no block validity, root, receipt, genesisHash or RPC-visible result. Under the current authorization
  ("don't stop for routine implementation steps") it is being implemented, in the order of §6, each change
  with an equivalence test and a mutation control. You may stop or reorder it.
- **[NORMATIVE]**: changes protocol text, consensus, CP values, a protocol constant, the RPC interface or a
  node requirement. **It needs your approval.** Nothing here is implemented beyond the "provisional"
  implementations already recorded in proposals/README.md.
- **[SCOPE]**: no consensus effect, but a choice of target or effort that is yours to make.

The Arabic summary for approval is [DECISION-PACKAGE-AR.md](DECISION-PACKAGE-AR.md).

Priorities, as you set them:
1. booting the network profile within the budget;
2. block validation time;
3. sustainability of the caps;
4. journal growth and recovery cost.

The other pending decisions (the six consensus proposals and RpcGuard P1–P4) are in §5.

---

## 1. Priority 1: booting the network profile within 6 GiB

### Facts (measured with the code's own model)

`pocold::resources::derive` was run on the governance.md network parameters (K_hist 32), with the new
test `tests/network_budget.rs` (evidence/decision-package/a13-network-profile.log):

| group | GiB | why it is this large |
|---|---:|---|
| state snapshots | 75.12 | 45 **full copies** of the state (1.63 GiB each at ACCT_CAP 10^6, SLOT_CAP 4·10^6): head + 32 K_hist + 2 side + 10 transient copies |
| code | 54.69 | CODE_CAP (1 GiB) × 9/8 counted **per copy**, unshared at worst |
| history | 19.19 | all canonical history in memory: tx bytes 8.00, tx index and receipts 3.54, logs 1.03, evidence 1.99, per-block entries 4.63 |
| execution | 1.10 | one EVM execution at 30M gas |
| side blocks, queues, RPC, threads | 0.73 | — |
| **model total** | **150.83** | the gate needs ⌈8·total/7⌉ = **172.4 GiB**, against 6 GiB |

Round 3 wrote that "TXBYTES_CAP = 8 GiB alone exceeds the budget". That was true, but it understated
the gap about 25-fold. The dominant terms are the full state copies and code counted per copy.

The spec's own design is disk-backed. storage.md:63–73 keeps blocks, receipts, logs, code and indexes
in redb, with a live trie, historical versions K_eff ≤ 32 within 1.6 GiB, and diffs for 2048 blocks.
FINAL_DESIGN.md D30 sets "K_eff ≤ 32, diffs for 2048 blocks, TrieRebuild" because "128 exceeds 6 GiB".
So the 6 GiB budget is the spec's assumption, and pocold's in-memory architecture is what breaks it.

### C-1 [CONFORMANCE]: storage program toward storage.md / D30

Five stages. Each stage is validity-neutral, and each is verified against the current implementation:
the same roots, receipts and RPC answers on every suite and replay. The model figures below are
**projections from the measured items**. They will be replaced by `derive()` output as each stage
lands.

| stage | change (spec text) | network model after it (projected) |
|---|---|---:|
| S1 | canonical bodies, receipts, logs and evidence off the heap, read from the journal on demand, as D-REORG-REDB already does for side blocks (storage.md:70) | ≈ 136 GiB |
| S2 | code shared between snapshots and counted once, with a test that a snapshot clone does not copy code bytes or jump tables (revm `Bytes`/`Arc` sharing; under Cancun the retained canonical states share one code set) | ≈ 83 GiB |
| S3 | retained and side states as reverse diffs from the head (storage.md:70 "diffs for 2048 blocks", D30), and transient copies replaced by copy-on-write overlays | ≈ 14 GiB |
| S4 | per-block metadata older than R_keep off the heap (an index on disk) | ≈ 10 GiB |
| S5 | live state on disk behind a bounded cache: the spec's redb live trie (storage.md:63–67) | under 5.25 GiB, the budget less the 1/8 reserve (target) |

- **Consensus, genesisHash and validity:** none.
- **Compatibility:** the journal and storage format change. This is a local migration; no on-chain or RPC
  change.
- **Resources:** the disk grows toward the spec inventory (≈ 19.65 GiB logical, ≈ 29.5 GiB on disk at the
  network caps). Memory falls as in the table. Disk reads add latency to RPC history queries and to
  deep reorgs.

**Acceptance tests:**
1. `a13_model_at_the_network_profile` passes with `budget_required ≤ 6 GiB`. The test currently asserts
   the opposite and must be inverted when S5 lands.
2. For each stage, the moved term is gone from `derive()` and replaced by its proven bound.
3. The existing equivalence suites pass unchanged: lp4 vectors, pocold consensus and caps, e2e_devnet,
   replay equals live, the spec-depth 2048/2049 test and the D133 test at depth 400.
4. A crash test for each new on-disk structure, in the style of the D-REORG-REDB R2.5 tests.
5. Measured RSS on a synthetic near-cap network state stays under the budget.
6. One mutation control per stage.

### D-1 [SCOPE]: the target for the network profile

| option | what it means | effect |
|---|---|---|
| **(a) full conformance S1–S5** | pocold boots the network profile within 6 GiB, as the spec's design intends | largest effort; no spec change |
| (b) S1–S3 plus a larger node memory requirement (≈ 16 GiB) | stop at about 14 GiB | **[NORMATIVE]**: changes the node requirement behind D30 |
| (c) pocold stays devnet-only | the network node is a separate implementation | no work, but the network profile stays unverified |

**Recommendation: (a), in stages.** I am starting with S2 and S1 now, under C-1. You decide whether the
work continues through S5, or stops at S3 with (b).

---

## 2. Priority 2: block validation time

### Facts (JOURNAL-GROWTH-AND-REPLAY.md §3.2, A13-DERIVATION.md §4a)

| case | measured | budget |
|---|---|---|
| a valid block of 380 transfers on a near-cap devnet state | **≈ 10.2 s** | devnet T_blk = 4 s |
| the worst one-transaction block (MODEXP) | ≈ 1.0 s | devnet t_exec = 1 s (network t_exec = 3 s, governance.md) |
| the whole state root recomputed every block | ≈ 0.23 s devnet; ≈ 14.4 s at the network caps (synthetic) | — |
| network projection per transaction | ≈ 7.9 s (a linear projection) | network T_blk = 60 s |

The causes are implementation, not protocol. For every USER transaction, `native::execute_for_profile`:
- runs `code_caps::validate_snapshot` over the whole state, keccak-ing every runtime (`code_len` →
  `hash_slow`);
- `build_engine` clones the whole state (`with_db(snapshot.clone())`);
- `NativeContext::from_snapshot` clones it again (`pay::pre_transaction`).

Each create also rescans the state (`code_caps::current_total`). Every block clones the state and
rebuilds the world root.

### C-2 [CONFORMANCE]: result-equivalent execution

1. `validate_snapshot` runs once per phase, not per transaction. The phase-level checks stay where they
   are (`apply.rs:221` and `:293`). The invariant that makes this result-equivalent: within a phase, code
   enters only through CREATE, whose `create_return` hook enforces B_code_max and CODE_CAP. Under Cancun
   (EIP-6780) code leaves only within its creating transaction.
2. Verified code length per code hash, kept with the code, and a running logical-code total, instead of a
   keccak of every runtime on every scan.
3. A read-only view of the pre-transaction state for the engine and for PAY, instead of two full clones
   per transaction. revm writes into its journaled state, not into the database, during `transact()`.
4. An incremental state root and O(dirty) block checks: cached account storage roots and trie nodes,
   proven equal to the full `world_root` on every block (JOURNAL-GROWTH §7 option 7).

**Acceptance tests:**
1. Every existing vector and suite passes unchanged: lp4 169, pocold, caps, the consensus vectors and
   e2e_devnet.
2. On the same near-cap devnet state (`jm_tx_state_term`), the 380-transfer block validates in under
   T_blk/2 = 2 s, with ≤ 1 s as the aim.
3. The per-transaction cost no longer grows with the state size (a measured series).
4. An equivalence test between the incremental and the full root, and between running and scanned
   totals, on every block of the suites.
5. Mutation controls: a stale cache, a skipped dirty account, a wrong running total.

### D-2 [NORMATIVE / profile]: the per-gas worst case (MODEXP)

C-2 does not change the cost of a MODEXP block, which is pure precompile work.

| option | consensus | genesisHash | compatibility |
|---|---|---|---|
| **(a) keep the Cancun gas schedule; raise the devnet's local t_exec from 1 s to 2 s**, if the R14/R19 gate admits it with the derived timings | none: a local timing value. But it is the governance.md P11 / D-A02-PROFILE value, so it is a profile-text change that needs your approval | none | none |
| (a2) keep the gas schedule; lower the devnet GAS_LIMIT from 8M to 6M (worst MODEXP block ≈ 0.72 s) | devnet CP only | a new **devnet** genesisHash; no network change | the devnet diverges from the network gas limit |
| (b) reprice MODEXP for small moduli, as later Ethereum proposals do | gas schedule change: every vector, a hard fork | none for the spec bytes, but every existing chain changes | departs from Cancun |
| (c) cap precompile input sizes | a new validity rule | as (b) | departs from Cancun |

**Recommendation: (a).** The network profile already has t_exec = 3 s, so it covers the ≈ 1.0 s case.
Decide after C-2 is re-measured. If the gate refuses 2 s, take (a2). Use (b) only if the worst block
still exceeds the devnet budget after C-2.

**Acceptance tests:** admission passes with the new devnet timing; the R14/R19 calibration on a MODEXP
block stays ≤ t_exec; the vectors are unchanged.

---

## 3. Priority 3: sustainability of the caps (proposals/CAPS-SUSTAINABILITY.md)

### Facts

- TX_CAP (10^7), TXBYTES_CAP (2^33) and LOG_CAP (2^30) are cumulative per branch.
- On the network profile each can be exhausted before H_END, organically or by an attacker:
  - organically, at averages of 1.29 tx/s, 66 KB of transactions per block or 8.3 KB of logs per block;
  - by an attacker, in 23–37 days, for under 10^-5 coins at the idle base fee.
- After exhaustion, no user transaction can be included on that branch, or every logging transaction
  halts. The chain keeps producing system-only blocks, but rewards and refunded bonds can no longer be
  spent.
- genesisHash:
  - TX_CAP and TXBYTES_CAP are CP fields, so changing them changes genesisHash.
  - LOG_CAP is a constant outside the encoding, so the hash is unchanged.
  - Two nodes with different LOG_CAP therefore split silently, because Hello has no version.
  - This was verified with an independent keccak/RLP model and a Rust test.
- **Already done ([CONFORMANCE], implemented):**
  - the builder skips what no longer fits (execution.md:83);
  - templates that break the caps are not locked (consensus.md:101);
  - the caps-test build (validation.md:2065).

### D-3 [NORMATIVE]: the caps regime

| option | consensus | genesisHash | storage (network) | liveness |
|---|---|---|---|---|
| O1 keep as specified | none | none | 19.65 GiB logical | permanent freeze of user activity is reachable |
| **O2 unreachable by construction (N1–N3)**: gates R27–R29 with LOG_CAP 2^32, TX_CAP 5·10^7 and TXBYTES_CAP 24 GiB | three gate predicates; LOG_CAP is a new constant | **changes** (TX caps are CP); no network chain exists | ≈ 43 GiB logical (+23) | no cumulative freeze |
| O3 a linear allowance (N4) | a new validity/halt rule | changes only if BURST is in CP | unchanged | a griefable rate limit instead of a cliff |

**Recommendation: O2 on the network profile, and keep the approved devnet caps.**
- O2 adds no consensus mechanism.
- Its memory side depends on C-1 S1 (history off the heap); without S1 the devnet cannot even take the
  larger caps.

**Acceptance tests:**
1. Gate tests for R27–R29: the boundary passes and one below fails.
2. New genesis vectors from the independent model (`caps_model.py`), replayed by `caps_identity.rs`.
3. A test that exhaustion is unreachable at H_END under O2.
4. The caps-test build still reaches exhaustion.

### D-4 [NORMATIVE]: the interface items around the caps

| id | proposal | recommendation |
|---|---|---|
| N5 | the pool answers −32016 {cap} for a transaction that cannot fit the head branch's remaining room, and evicts such transactions when a new head leaves them no room. This also ends the "pool squatting" near the byte boundary | approve |
| N6 | `pocol_getCaps` → {txCount, txBytes, logBytes, txCap, txBytesCap, logCap} of the head branch. The method is listed in network.md:333, so serving it is conformance, but its fields are not specified; pocold answers −32601 today | approve the field list |
| N7 | `eth_call` and `eth_estimateGas` report an A03 halt instead of success | approve |
| N8 | state the scope in consensus.md:170: "the branch's counts up to the parent plus this block" (what the code does) | approve |

**Acceptance tests:** an RPC test for each; a pool eviction test across a reorg; the existing caps
tests unchanged.

### D-5 [NORMATIVE]: the identity of LOG_CAP

| option | meaning |
|---|---|
| (a) nothing | rely on there being no live chain; any later change of LOG_CAP is a silent split |
| **(b) a version in ForkSchedule and in Hello** | LOG_CAP (and any constant outside the CP) is tied to an activeVersion that peers compare at Hello (network.md) |
| (c) LOG_CAP into the CP | a CP schema version 2 (52 → 53 fields): GSV1 and every vector change |

**Recommendation: (b).** It is the smallest change that makes a constant change detectable, and it
leaves GSV1 alone.

**Acceptance test:** two nodes with different activeVersion refuse each other at Hello with a reported
reason, and identical nodes connect as before.

---

## 4. Priority 4: journal growth and recovery cost (JOURNAL-GROWTH-AND-REPLAY.md)

### Facts

- The canonical journal's worst case is about 11.3 GiB on the network profile.
- A re-fetched branch is journaled again; there is no deduplication.
- Open replays from genesis, with cost a·H + b·H²/2: about 66–69 min at the network H_END, and up to
  about 7.3 h on the devnet on a near-cap state.
- A deep reorg rebuilds the fork-point state from genesis, twice.
- Since `462fffc`, an adopting reorg restores up to R_keep abandoned blocks' transactions (derived:
  up to about 34 min for the worst kind).
- All three journal obligations stay OPEN.

### C-3 [CONFORMANCE] (after C-1 S3, with which it shares the diffs)

1. **Reverse diffs for the last R_keep blocks** (storage.md:70; consensus.md:230–232). A deep-fork
   rebuild scales with depth instead of height, and the double genesis rebuild disappears. This is S3 of
   C-1.
2. **An incremental canonical index**, so `rebuild_canonical` no longer walks head → genesis on every
   head change. This removes the b·H² term.
3. **Keep the fork-point state while a side branch depends on it** (option 6).
4. **Headers-first sync** (network.md D38, already approved). A losing branch is not journaled in full.
5. **Dedupe markers** for re-fetched blocks, so a re-fetch is not journaled again.

**Acceptance tests:**
1. Open time on the devnet scales with the blocks since the last checkpoint or diff window, not with H²,
   on a measured series.
2. A deep reorg at depth R_keep needs no genesis rebuild (measured).
3. Replay equals live after every record; the D-REORG-REDB crash tests pass.
4. Re-fetching a branch adds no journal bytes.
5. One mutation control per item.

### D-6 [SCOPE / NORMATIVE boundary]: bounding open time

| option | meaning | status |
|---|---|---|
| **(a) local state checkpoints** every 2048 blocks (the node's own verified state, written to disk; open replays from the latest one) | local storage only; nothing is trusted from outside | no approval needed; listed so that you know |
| (b) compacting block history below finality | storage.md:70 keeps blocks "until the end" | **[NORMATIVE]**: contradicts the retention text |
| (c) signed snapshots from others | storage.md mentions a signed snapshot after ts_F+30 days only | **[NORMATIVE]** before then |

**Recommendation: (a) only, and confirm that block history is never compacted (b is rejected).**

---

## 5. Other pending decisions

### 5a. The six consensus proposals ([README](README.md); each is implemented provisionally with its recommended alternative)

| id | question | recommendation |
|---|---|---|
| LOG-ACCT-01 | which bytes a log is charged | (c): 36 + 32·topics + data, ≤ 546 logs per block. The only reading consistent with every quoted text (LG2 and the receipt bound) |
| D-A03-DIRTY | what counts as "dirty", and when a halt makes the block invalid | A: a net change counts; a halt whose residue would exceed the limit makes the block invalid, and the builder skips it |
| D-A03-CAPS | what SLOT_CAP/ACCT_CAP count | 2: user state only; SYS_SLOT_MAX checked after the system phases (R18 makes it unreachable for an admitted profile) |
| D-BODY-MAX | encoded body or item sum | (a): the encoded body, the literal reading and what decode does |
| D-A03-SYSUSER | what the user-context SYS allowance counts | (a): storage writes to the programs only; balance credits do not count |
| LOG-CAP-AGGREGATE | the scope of LOG_CAP | chain: cumulative per branch, the bound A13 relies on. With D-3 O2 it becomes unreachable on the network |

**Consensus effect:** each fixes validity, receipts or roots where the text is silent. Approving the
recommended alternatives keeps the current code, with no change to genesisHash. Choosing another
alternative changes the code, the vectors and the validity of blocks produced on test devnets. No chain
exists outside local test runs.

**Acceptance tests:** the model vectors `proposals/vectors/*.json` (independent Python) and their Rust
replays pass. They already do for the recommended alternatives.

### 5b. RpcGuard P1–P4 ([RPCGUARD-R2-PROPOSALS.md](RPCGUARD-R2-PROPOSALS.md); local service policy, no consensus effect)

| id | question | recommendation |
|---|---|---|
| P1 | the request rate across connections | **C**: HTTP keep-alive with the bucket per connection. This is the model the text assumes (persistent connections, an aggregate ≤ RPC_CONN_MAX·rate) |
| P2 | CANCEL_MAX for precompile runs | **B**: eth_call/eth_estimateGas refuse, with −32020, a single precompile call whose gas exceeds a measured per-precompile cap. This is an explicit error, never a different result |
| P3 | an effectful method that finishes after its deadline | **A**: the deadline is checked before the effect; once the effect is applied, its result is answered |
| P4 | methods outside the classification table | **B**: add table lines for the methods pocold serves; −32601 before admission for every other method |

**Acceptance tests:** an RPC test for each chosen option, under the existing RpcGuard tests and mutation
controls.

---

## 6. What is being done now under the current authorization

Order, by dependency and by gain against risk:
1. **C-2 items 1–3.**
   - They are small and in one module.
   - They cut the measured 10.2 s and also remove two of the transient state copies of C-1.
2. **C-1 S2.** A measurement test of code sharing in a snapshot clone, then the code term changes.
3. **C-1 S1.** Canonical history off the heap, reusing the D-REORG-REDB offload.
4. **C-2 item 4.** The incremental state root.
5. **C-1 S3 together with C-3 item 1** (diffs), then C-3 items 2–5, then C-1 S4–S5 if you choose D-1 (a).

Each lands with:
- a fail-before or measurement test;
- an equivalence test;
- a mutation control;
- the full suites;
- an evidence directory.

None changes validity, roots, receipts, genesisHash or RPC results. If one would, it stops and comes
back here as [NORMATIVE].

## 7. Independent reviews still missing (requested 2026-10-24, results in REPAIR-REPORT.md when done)

| review | subject |
|---|---|
| R1 | caps round 3b (final `e985ce1`) on the current head |
| R2 | RpcGuard round 3c (`dd7d1ec`), including the Windows socket code |
| R3 | the journal round-3c measurements and projections, and the effect of `462fffc` |
| R4 | e2e round 4: does the test really detect non-convergence and the wrong branch (new mutants) |
| R5 | `462fffc` (the A11 reorg walk and the R14/R19 calibration) |

## 8. Tests to re-run on the final code (and why)

| test | last run | why it must be re-run |
|---|---|---|
| lp4 and pocold suites, release | `462fffc` | every C-1/C-2 change |
| debug runs (assert-release and pure debug, the consensus tests one at a time, spec depth included) | `3c3792e` | node.rs changed in round 3 and in `462fffc` |
| the ignored consensus tests (spec depth 2048/2049, D133 at 400, the A11 deep reorg) | `462fffc` | C-1 S1/S3 touch the same paths |
| D-REORG-REDB mutation controls (30) | `3342af3` | the reorg restore path changed in `462fffc`; C-1 changes storage |
| caps.rs, caps_identity, log_cap, the caps-test build | `2b1a571` / `462fffc` | C-2 changes USER execution |
| e2e_devnet, e2e_site | `462fffc` / `c959379` | every code change |
| the full LP10 integration: extension build and 234 unit tests, real Chrome e2e, integrated Chrome | `3c3792e` | round-3 RPC changes (RpcGuard, −32020) and every later change |
| witnesses: 17 observations and 15 positive controls (scratch only) | `3c3792e` | round-3 and later code |
| RSS measurement | `3c3792e` | C-1 changes memory |
| journal measurements (validation time, reorg restore, open) | round 3c | C-2 and C-1 change the measured paths |
| R14/R19 admission calibration | `462fffc` | C-2 changes the timing |
| Windows CI | `462fffc` (run 26) | runs on every push of the PR |

A Windows pass covers the repair-scope suites on Windows only. It is not acceptance.
