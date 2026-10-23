# Audit repair report: A01–A14 and dependencies (round 2)

> **Status: not accepted, not closed.**
> - PR #27 is a draft.
> - No finding is closed. Acceptance belongs to the owner, and none is recorded.
> - Six consensus proposals are awaiting the owner's decision.
> - A13 keeps open obligations (§5). The R_keep adoption blocker is addressed by D-REORG-REDB, a storage
>   repair the owner approved (D133 and validity unchanged; implementation and verification in §3b).
> - Windows was not run.
>
> This report replaces the round-1 report. §7 lists what round 1 overstated.

| Item | Value |
|---|---|
| Audited snapshot | `090eae4dc059d1a7df330d9fe674c873ac515564` (branch `claude/affectionate-pascal-rjhh2k`) |
| Repair branch, PR | `claude/audit-repair-a01-a14`, [PR #27](https://github.com/raedrasheed/Proof-of-Collaboration/pull/27) (draft) |
| Last implementation commit (prototypes/ and .github/) | `3c3792e` (D-REORG-REDB final code; before it, `687ac38`) |
| Integration-tested commit | `3c3792e` |
| Witness-tested commit | `3c3792e` |
| Real-Chrome-tested commit | `3c3792e` (in the integration) |
| Mutation-controlled commit | `3342af3` (Rust sources equal to `3c3792e`) |
| PR head | latest commit on `claude/audit-repair-a01-a14` (docs-only after `3c3792e`; see EVIDENCE-RECONCILIATION.md) |
| Tree equivalence | [EVIDENCE-RECONCILIATION.md](EVIDENCE-RECONCILIATION.md) |
| Plan, decisions | [REPAIR-PLAN.md](REPAIR-PLAN.md) |
| Per-finding status (five axes) | [FINDING-STATUS.json](FINDING-STATUS.json) |
| A13 derivation, breakdown, assumptions | [A13-DERIVATION.md](A13-DERIVATION.md) |
| Consensus proposals | [proposals/](proposals/README.md) |
| Arabic dashboard | [DASHBOARD-AR.md](DASHBOARD-AR.md) |

A witness printing NOT_REPRODUCED is an observation, not an acceptance pass. Test counts are not acceptance.

## 1. Status per finding

Each finding is recorded on five separate axes: implemented, verified, partially resolved, blocked and
accepted. The disposition is the weakest of them.

| Finding | Implemented | Verified (Linux) | Remaining | Disposition |
|---|---|---|---|---|
| A01 HIGH | yes | yes | D-BODY-MAX proposal | BLOCKED BY DECISION |
| A02 HIGH | yes | yes | Only an experimental-devnet admission is possible; timing is a sample, not a bound | PARTIALLY RESOLVED |
| A03 HIGH | yes (recommended alternatives, provisional) | yes; independent vectors | LOG-ACCT-01, D-A03-DIRTY, D-A03-CAPS, D-A03-SYSUSER, LOG-CAP-AGGREGATE | BLOCKED BY DECISION |
| A04 HIGH | yes | yes | Power loss untested; journal v2 untested on Windows | VERIFIED (Linux), BLOCKED BY ENVIRONMENT |
| A05 HIGH | partly | partly | RpcGuard partly implemented; no preemption; light methods light by size only | PARTIALLY RESOLVED |
| A06 HIGH | yes | yes, real Chrome | A request already initiated may be broadcast (reported, never "cancelled") | VERIFIED (Linux), BLOCKED BY ENVIRONMENT |
| A07–A12, A14 | yes | yes | — | VERIFIED (Linux), BLOCKED BY ENVIRONMENT |
| A13 HIGH | partly | partly | Open: gas monotonicity, worst-case timing, allocator overhead, CPU costs (including deep-reorg rebuild and restore), RetentionStore, journal compaction; no guaranteed memory ceiling. R_keep adoption: implemented by D-REORG-REDB (§3b) | PARTIALLY RESOLVED |

## 2. What was repaired

Round 1 (commits listed in FINDING-STATUS.json): the repairs of A01–A14 and the dependency changes, as
described per finding in REPAIR-PLAN.md.

Round 2, on the owner's review:
- **Admission scope (D-A02-SCOPE).**
  - RpcGuard facts that pocold does not enforce are absent, never nominal, and enter the gate as 0.
  - Only an experimental-devnet admission is possible, and only for a Simnet profile on a Simnet node.
  - The specification scope refuses every current profile and lists the open conditions.
  - The RPC field inventory is tied to `RpcLimits` at compile time.
- **A13: each assumption enforced, derived, inspected or kept open (A13-DERIVATION §4).**
  - Thread stacks are reserved explicitly, and exiting threads are joined before reuse.
  - The EVM execution model was rebuilt from per-gas operation classes, which cover entries revm loads
    before charging their cold cost.
  - RPC request and answer memory is enforced: exact-size bodies, a queued-body cap, a JSON value cap
    and response pools.
- **D-A13-BUDGET (owner approved option 1).** At 45712cd the corrected model put the default devnet at
  6.62 GiB, over the 6 GiB budget. Local, non-consensus reductions, two proven accounting corrections
  and the response pools bring it to 5.20 GiB. The boot gate now keeps a 1/8 reserve.
- **RPC work deadline, light lane and tick coalescing (D-A05-R2)**, then the review fixes:
  - a single pending Wake;
  - LIGHT_TURN;
  - the 413 drain;
  - the peer-close lost wakeup;
  - one miner thread at a time.
- **Wallet submission states (D-A06-SUBMIT): signed, queued for transport, request initiated, broadcast.**
  - Epochs and eligibility are rechecked after the transport reservation and immediately before
    submission.
  - A queued submission is cancelled on lock or revocation.
  - A broadcast transaction is never claimed cancelled.
- **Consensus decision proposals** (proposals/): for each, the exact normative text, the alternatives,
  a minimal example, the effects, and independent expected-result vectors. All are **PROPOSED**; none is
  approved.
- **Windows scope workflow** prepared, with explicit toolchains and the evidence bound to a full SHA. It
  has not run (§5).

## 3. Verification on the final implementation commit

Commands:
- `python3 development/audit-2026-10-22/tools/run_integration.py`: lp1-node with its accepted Rust 1.58.1,
  the extension build, and the LP10 suites (lp4 and pocold in release, extension unit, 3-node devnet,
  website publishing, real Chrome, Chrome with the integrated devnet).
- Debug runs of lp4-execution and pocold.
- The mutation controls (evidence/MUTATIONS-R2.md).
- The witness runner (programs in the private package).
- `tools/measure_rss.py`.

Earlier passing results are not reused as evidence for this code.

Results on the final code, separated by outcome (commit roles in EVIDENCE-RECONCILIATION.md; the
prototypes/ tree is `68ece272a3c7` at `687ac38`, `c19dc8a` and `ec09120` alike, so these apply to the
implementation commit):

- **PASS (Linux, release integration on `c19dc8a`, evidence/integration.json):** lp4-execution 162;
  pocold 110 (including the two R_keep adoption tests); extension build + 234 unit; 3-node devnet 17
  checks; website publishing 20 checks; real Chrome 79 checks; integrated Chrome 18 checks. Toolchains:
  cargo/rustc 1.97.0; lp1-node rustc 1.58.1; pinned rustc 1.99.1; node 22.22.0.
- **FAIL — expected platform limitation only:** lp1-node `store_journal`, 11 Windows-only tests
  executed on Linux and failed (UnsupportedPlatform), identical on `090eae4`; the integration records
  `failuresOnlyExpectedPlatformLimitation = true`. Not counted as a pass (§5).
- **NOT RUN:** Windows verification (the scoped workflow returns 404 on dispatch until its file is on
  main; §5, WINDOWS-VERIFICATION.md).
- **Witnesses (`ec09120`, evidence/witnesses-r2-final.log):** 17 observations, all NOT_REPRODUCED; 15
  positive controls OK, 0 MISSING, 0 erroneous REPRODUCED. An observation with its control, not an
  acceptance pass.
- **Measured RSS (final code, evidence/rss-final.json):** 12.26–12.32 MB VmHWM per node under idle +
  bounded adversarial load, 0.22% of the model. Measured, not the model bound and not a ceiling
  (A13-DERIVATION §2b).
- **Debug build (final code, evidence/debug-final.log):** lp4-execution full debug suite 162 passed;
  pocold lib 37 + admission 3 + net 20 = 60 passed.
- **TIMEOUT / INCOMPLETE — pocold `consensus` binary in debug.** Its single-threaded debug run was
  stopped at the 5000s wall cap before printing a result, so its debug outcome is **unknown**: a
  timeout does not distinguish a slow test from a stalled one, and no per-test result was captured.
  The release integration's pass (pocold 110) is separate evidence and does not stand in for the debug
  run. A per-test completion run (each test alone, with its own timeout) is in progress; until it
  reports, debug verification of this binary is not complete.
- **Mutation controls re-run on the final code (`687ac38`, evidence/mutations-final.json, §MUTATIONS):**
  14 of 14 test-failure mutations caught, plus the F6 compile-time field-inventory catch (15 controls in
  all). Each has a positive control (the named test passes on clean code) and a mutant run that fails
  with the test actually executed; zero-matching-test runs are rejected. The classifier correction and
  the M9/M2 re-targeting (from the first FINAL attempt) are recorded in evidence/MUTATIONS-R2.md.

## 3b. D-REORG-REDB (owner-approved): implementation and verification on the final code

**What it is.** A storage repair for adopting a heavier branch at depth ≤ R_keep = 2048
(network.md:144). D133, block validity, state roots, receipts and genesisHash are unchanged, and no
retention limit is a validity rule. Design, proofs and resource bounds are in
proposals/D-REORG-REDB-DESIGN-FREEZE.md, Revision 2:
- R2.3 multi-branch adoption theorem;
- R2.4 RPC scope matched to storage.md:70;
- R2.5 replay equal to live;
- R2.6 bounds;
- R2.8 independent review.

**Mechanism.**
- Non-canonical blocks are offloaded to metadata, with their bytes in the journal. Canonical blocks stay
  whole, so no RPC scope changed.
- At most R_keep unprotected side blocks are kept (D118's one per height).
- Locator sync sessions over Status `totalWork` re-fetch evicted branches. Their non-canonical blocks
  are protected, up to 2·R_keep (network.md:27).
- Adopted blocks are restored by root-checked re-execution.
- Replay replays every record. A re-import gets a new importSeq (consensus.md:205), a block with a
  pending child record is protected, and the largest R_keep the directory has used is applied.
- New blocks at or below head − R_keep are refused before validation, as local retention
  (governance.md:200), never as invalid.
- `eth_call`/`eth_estimateGas` on a pruned state now answer −32017 like the state reads (consensus.md
  §10). This was a pre-existing inconsistency found during the RPC check.
- `pocol_status` gains additive `retention` and sync counters.

**Why a metadata cap ≥ R_keep is not enough for several branches.** The cap evicts the lowest
cumulative work first, which is exactly the start of a deep competing branch. The guarantee therefore
rests on protected re-fetch (R2.1, R2.3), and the tests below exercise it with a flood past the cap.

**Defects found and fixed during verification** (each with a test and a mutation control):
- the spec-depth run exposed quadratic rebuilds of deep side branches, because the K_hist prune also
  dropped side states (`9ce5a7c`);
- an independent agent review (R2.8) found two HIGH session-liveness bugs. A block removed at once and
  a duplicate both counted as progress, and a Hello started a session at once. It also found three LOW
  items: orphaned session blocks, replay copy and offset, and R_keep persistence (`441ce73`). All fixed;
- a mutation control showed the flood test did not make replay protection load-bearing (`f2477e7`);
- another showed retain()'s boundary was masked by the import-time refusal (`3342af3`).

**Results, separated by outcome:**
- **PASS, release, spec depth with the default limits** (`--ignored`, evidence/spec-depth-441ce73.log;
  same `src/` as 3c3792e):
  - `adoption_at_the_spec_depth_2048_and_not_at_2049`: a 611-block heavier branch forked 2048 deep is
    adopted and survives restart. Forked 2049 deep it is not adopted and not marked invalid. 51.8 s;
  - `d133_tie_break_at_depth_400_holds_through_eviction_and_refetch`: signed-before-fallback wins
    400 deep, the smaller importSeq wins between two signed branches, and X is evicted (784) then
    re-fetched and adopted. 19.0 s.
- **PASS, release, the D-REORG-REDB acceptance tests** (in pocold 123):
  - R_keep boundary and retain boundary;
  - side cap with solicited-only re-fetch;
  - a multi-branch flood during a session;
  - replay importSeq and largest-R_keep rules;
  - off-heap fidelity;
  - crash around an adoption (fsynced-uncommitted and torn records);
  - a 3-node TCP re-fetch with RPC compared block by block and a third node served by the restored
    node;
  - long catch-up;
  - a false-Status peer that cannot hold the session;
  - out-of-order session blocks;
  - linear deep side import;
  - pruned-state eth_call.
- **Mutation controls (evidence/MUTATIONS-REDB.md): 30 of 30 caught.** These are 19 D-REORG-REDB
  controls plus the 11 earlier controls that still apply (the 687ac38 controls on the removed 320-cap
  tests are superseded). Each control passed on clean code, and its mutant failed with the test run.
  The superseded partial runs are kept unchanged:
  - one uncaught control (MR5) on 9ce5a7c;
  - one compile-fail and one uncaught control (MR3, MR7) on 441ce73.
- **Integration on 3c3792e (evidence/integration.json, last run):** every suite PASS except lp1
  `store_journal`, the expected Windows-only limitation (result FAIL;
  `failuresOnlyExpectedPlatformLimitation = true`):
  - lp4 162, pocold 123 (2 ignored: the spec-depth tests above), extension 234;
  - 3-node devnet 17/17, website 20;
  - real Chrome 79, integrated Chrome 18.
- **FAIL, recorded and classified: the earlier integration on 82ddb03 (code 3342af3).**
  - e2e-devnet failed at "heal: c reorganizes". c's isolated branch happened to be heavier, so a and
    b reorganized to it and all nodes converged, which is correct by D133. The check had assumed the
    a/b side was always heavier.
  - A standalone rerun failed "every miner produced blocks": the counter restarts with its process.
    That check also fails in 2 of 4 runs on the pre-change 687ac38.
  - Both checks now assert the protocol property (evidence/e2e-devnet-classification/, original logs
    kept).
- **Witnesses on 3c3792e (evidence/witnesses-redb-final.log):** 17 observations, all NOT_REPRODUCED;
  15 positive controls OK, 0 MISSING, 0 erroneous REPRODUCED.
- **Measured RSS on 3c3792e (evidence/rss-redb-final.json):** 11.98–12.30 MB VmHWM per node (26–29
  threads) under 71,466 light, 3,853 30M-gas, 352 batch and 193 transfer requests. That is 0.21–0.22%
  of the model, a measurement and not the bound.
- **A13 model on the final code (evidence/a13-breakdown-redb.json):** 5,627,687,516 B. The gate needs
  6,431,642,876 B of 6,442,450,944 B; reserve 803,955,360 B, unused 10,808,068 B (A13-DERIVATION §2a-redb,
  §2b).
- **Debug on 3c3792e** (evidence/debug-redb/; the 687ac38 partial record, 28 of 31 in pure debug, is
  kept unchanged as PARTIAL in evidence/debug-complete-687ac38.json):
  - phase A, assert-release (release with debug assertions and overflow checks), each consensus test
    alone including the two spec-depth tests: **44 of 44 PASS**;
  - phase B, pure debug, each consensus test alone: **in progress**;
  - phase C, the other pocold binaries in pure debug: **pending**. Until they report, debug
    verification of the final code is not complete. lp4-execution is unchanged since 687ac38 (its tree
    is identical), and its full debug run there was 162 PASS.

**Still open around R_keep:**
- journal compaction;
- the CPU cost of a deep reorg (fork-point state rebuilt from genesis below K_hist);
- the open-time replay transient;
- Windows (not run).

## 4. Independent review

Round 1:
- three reviews by separate agent instances (Rust side, extension side, review-fix commits);
- all confirmed findings were fixed (REPAIR-PLAN.md).

Round 2: two more reviews by separate agent instances, which ran code in scratch copies.
1. **df63725 (F1–F9).** All nine were fixed, each with a test and a mutation control:
   - a lost wakeup in the peer outbox;
   - an unbounded light-lane Wake;
   - the execution model's state accounting;
   - RPC request memory undercounted;
   - the scope guard let Synthetic through;
   - the field inventory was not tied to RpcLimits;
   - miner and thread overlap;
   - build-speed-dependent tests;
   - light requests overtaking heavy ones (documented).
2. **45712cd..b132a05 (the D-A13-BUDGET range).** Findings (A13-DERIVATION §2a):
   - SIDE_BLOCKS_MAX 64 blocked the adoption of long branches (HIGH): reverted to 256;
   - a restart failure on duplicate journal records (HIGH): fixed;
   - an unbounded parse on the busy path: fixed;
   - the side-block term after a reorg: fixed;
   - a light-answer regression for TX_MAX transactions: fixed;
   - two host-dependent tests: fixed;
   - test gaps and small undercounts: fixed;
   - the stats method's name: renamed.

These are agent reviews, not an external human audit, and the shared GitHub account is not an
independent approval. The owner has not yet reviewed the consensus proposals.

Both round-2 reviews ran the code in scratch copies, and every finding was treated as a defect with its
own regression test and a mutation control (evidence/MUTATIONS-R2.md), not as a test expectation to
adjust. The second review's highest findings (SIDE_BLOCKS_MAX 64 blocking adoption, the duplicate-record
restart failure) were HIGH; SIDE_BLOCKS_MAX was reverted to 256 and then raised to 320 on the tested
path, and the gap to R_keep is kept open as an architectural limitation (§5, D-REORG-REDB). No review
weakened a consensus rule, and no review constitutes acceptance.

## 5. Remaining limitations and blocked evidence

- **Windows: not run.**
  - The scoped workflow `audit-r2-windows-verify.yml` returns 404 on dispatch until its file is on
    `main`, and merging is not authorised (WINDOWS-VERIFICATION.md).
  - The repository is public, so a run would use free standard runners.
  - pocold's and the extension's Windows behaviour is untested: journal v2 file replacement and
    directory fsync, sockets, thread counts.
- **lp1-node `store_journal` (11 tests):** executed on Linux and **failed** with UnsupportedPlatform.
  This is the expected platform limitation (Windows-only atomic journal), identical on 090eae4, and is
  recorded as failures, not passes.
- **Original audit programs** (FINDINGS.json, REPRODUCE.md, overlays, SHA256SUMS): not received. Every
  witness was reconstructed from REPORT.md and carries a positive control.
- **A13** (A13-DERIVATION §4):
  - Open:
    - gas monotonicity;
    - worst-case timing;
    - allocator overhead and fragmentation (a reserve is kept, but nothing proves it suffices);
    - CPU costs;
    - RetentionStore and redb.
  - Inspection-only items remain.
  - There is no guaranteed process-memory ceiling. The measured RSS of a run is not the bound.
  - **R_keep adoption (formerly the architectural blocker):** implemented by the owner-approved
    D-REORG-REDB and verified as in §3b. Still open around it:
    - journal compaction (the journal is append-only and grows with imports and re-fetches; local,
      no validity effect);
    - CPU cost of a deep reorg: the fork point's state is rebuilt from genesis when it lies below
      K_hist, because pocold keeps no reverse diffs (consensus.md §10); condition `cpu-and-timing`;
    - the open-time transient (the whole journal is held while replaying; condition
      `open-replay-transient`).
- **A05:** RpcGuard is implemented only in part. Not implemented:
  - HEAVY/LIGHT permits and QUEUE_WAIT;
  - scratch budgets;
  - rate buckets;
  - per-class compute deadlines;
  - the send watchdog.

  A running request is not preempted.
- **A02:** only an experimental-devnet admission is possible. The R14/R19 timing sample fails closed
  under CPU contention: pocold's consensus tests in a debug build fail when run in parallel, and pass
  single-threaded on an idle host.
- **A06:** a request already initiated may reach the network and is reported as initiated or broadcast.
- **A04:** real power loss is untested.
- **Dependencies:** libsecp256k1 0.5.0 and rand 0.7.3 remain in lp1-node (accepted toolchain pin).
  derivative and paste remain as build-time proc-macros via revm.

## 6. Decisions

- **Approved by the owner:**
  - D-A13-BUDGET (option 1, local);
  - D-REORG-REDB (2026-10-23), a storage repair for R_keep adoption with D133 and validity fully
    preserved. It does not cover the six consensus proposals;
  - engineering decisions taken under the standing authorization (REPAIR-PLAN.md).
- **Proposed, awaiting the owner** (they change roots or validity):
  - LOG-ACCT-01;
  - D-A03-DIRTY (including the block-invalid halt-residue case);
  - D-A03-CAPS;
  - D-BODY-MAX;
  - D-A03-SYSUSER;
  - LOG-CAP-AGGREGATE.

  The implementation uses the recommended alternatives provisionally. Passing tests do not approve
  them. The historical M1 files are unchanged.
- **Reviews prepared for the owner (not decisions):**
  - proposals/INDEPENDENT-REVIEW-SIX-PROPOSALS.md;
  - proposals/LOG-CAP-AGGREGATE-ALTERNATIVES.md, on ways to avoid permanent exhaustion of LOG_CAP
    (LOG-CAP-AGGREGATE stays unapproved). It also flags that TX_CAP and TXBYTES_CAP are
    chain-cumulative and reachable before H_END on the network profile, which would make blocks
    invalid. That is a further normative question, not decided here.

## 7. Corrections to round 1

- "Closed with limitations" for every finding was overstated. No finding is closed (§1).
- **Witnesses:** "18/18 NOT_REPRODUCED" was 17 observations. Round 1 had no positive controls; round 2
  adds one per witness.
- **A13:** "4.92 GiB ≤ 6 GiB" was not an upper bound. Three things were undercounted or assumed:
  - thread stacks were assumed resident at 64 KiB;
  - EVM execution memory was assumed;
  - RPC answers were undercounted.

  The corrected model exceeded the budget until D-A13-BUDGET. The current 5.20 GiB is still conditional.
- **Windows** was labelled "blocked by platform". It is not run, for the precise reason in §5.
- **lp1-node:** the 11 `store_journal` tests were described as blocked. They executed and failed.
- **Rust 1.58.1** was said to be unavailable. It was installed through rustup, and lp1-node now runs
  with it in the integration.
- **A06:** round 1 left a submission proceeding after a lock while transport capacity was awaited.
  That gap is closed by the submission states.
