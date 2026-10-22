# Audit repair report: A01–A14 and dependencies (round 2)

> **Status: not accepted, not closed.**
> - PR #27 is a draft.
> - No finding is closed. Acceptance belongs to the owner, and none is recorded.
> - Six consensus proposals are awaiting the owner's decision.
> - A13 keeps open obligations, including an architectural blocker (§5).
> - Windows was not run.
>
> This report replaces the round-1 report. §7 lists what round 1 overstated.

| Item | Value |
|---|---|
| Audited snapshot | `090eae4dc059d1a7df330d9fe674c873ac515564` (branch `claude/affectionate-pascal-rjhh2k`) |
| Repair branch, PR | `claude/audit-repair-a01-a14`, [PR #27](https://github.com/raedrasheed/Proof-of-Collaboration/pull/27) (draft) |
| Last implementation commit (prototypes/ and .github/) | `__IMPL__` |
| Integration-tested commit | `__INTEG__` |
| Witness-tested commit | `__WIT__` |
| Real-Chrome-tested commit | `__CHROME__` |
| PR head | `__PRHEAD__` |
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
| A13 HIGH | partly | partly | Open: gas monotonicity, worst-case timing, allocator overhead, CPU costs, RetentionStore, adoption depth ≤ R_keep (architectural); no guaranteed memory ceiling | PARTIALLY RESOLVED |

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

__VERIFY__

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

__REVIEW2__

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
  - **Architectural blocker:** adoption of a heavier branch at any depth ≤ R_keep = 2048
    (network.md:143) needs about 0.85 GB more of in-memory side blocks, which does not fit beside the
    rest. pocold's adoption depth is SIDE_BLOCKS_MAX = 256. Meeting the rule needs disk-backed blocks.
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
