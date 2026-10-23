# e2e devnet, round 3: the second review's findings E2E-R3-1 … E2E-R3-9

This directory holds only new files. It follows `../e2e-mutation-r2/` and
`../e2e-integration/`; none of their files is edited, and §2 corrects what they say.

- **The test** is `prototypes/pocold/tests/e2e_devnet.py` at commit `0e51a36`, sha256
  `0c4987d0ec0c88f72d14820119ef4f970ffbc3ca7962c0084cbd4d1941a76b60`.
- **The review** found E2E-R3-1 to E2E-R3-9 and three surviving mutants, Mhu, Mtransient and Morph.
  It was run on `fa97594` with the test at sha256 `9d73605e…c1c15`.
- **No node code changed.** Every e2e run used a pocold built from this branch's tree, whose code
  equals `fa97594`'s. The base binary has sha256 `8bb91c8a…eaef1c` and pocol-sign `9e3e7fa5…ef0ea5`.
  Both were built with `CARGO_TARGET_DIR=<scratch>/wf-target-r3-e2e cargo build --release --locked
  --bins` under the cpu lock, with no warnings.
- **Mutants** are an export of `fa97594`'s `prototypes/` plus one patch each. The patches, the
  builder, the runner and the summaries exist only in the session scratch directory; none is
  committed.
- **E2E-R3-7** changes one unit test in `tests/consensus.rs`: test code only (§4.5).
- **This is not a full acceptance.** The full integration (`prototypes/lp10/run_lp10.py`) and the
  Windows workflow were not re-run.

## 1. Findings and their resolution

| Finding | Resolution | Evidence |
|---|---|---|
| E2E-R3-1 (major): the relay without a session never carried a block higher than a's head, so a longest-chain rule on the broadcast path (Mhu) passed | **Fixed.** c climbs until it is at least 2 blocks above a/b's tip, and the precondition asserts `ab_tip + 2 <= c_tip`. The relay below c's tip therefore ends at least one block above a's head, and that block is lighter | step 3; Mhu §4.2 |
| E2E-R3-2 (major): a's head was read once after each relay, so a switch that reverted at the next tick passed (Mtransient); no check that step 5 started no session | **Fixed.** The test reads a's `reorgs` and `syncSessions` counters before and after each relay. Step 5 must leave both unchanged. Step 6 must add exactly one session and no reorganization. a's and b's counters must not change across the heal | steps 4–6; Mtransient, Mwants §4.2 |
| E2E-R3-3 (major): no deep reorganization went through the unsolicited or orphan path | **Fixed.** Node d is a copy of c's store taken before the heal, with a listener, no peers and no miner. A test peer claiming genesis, so that d starts no session, sends a/b's branch above the fork tip first. d must switch from c's tip to a/b's tip with exactly one reorganization and zero sessions | step 4b; Morph, Mcount §4.2 |
| E2E-R3-4 (minor): F10, no heal while miners run | **Closed as coverage.** Node e is a second copy of c's pre-heal store. It joins a, b and c while they mine. Within 120 s, e's canonical block CONFIRM = 6 below its head must equal a's and lie above c's tip height; c's tip must not be canonical on e; e must count at least one reorganization. Telling most work from longest chain remains the frozen heal's job, since the live chain is also the higher one. No mutant here is caught by this check alone (§5) | step 8b |
| E2E-R3-5 (minor): the frozen tips were never compared | **Fixed.** After the miner checks, a, b and c restart connected and without miners, so no tip can move. Within 60 s they must reach one totalWork. Their canonical blocks must be identical up to the last height they all share, at most one block below the lowest head (D133 keeps equal-work siblings apart, consensus.md:224) | step 11; Mfollow §4.2, §4.3 |
| E2E-R3-6 (minor): b restarted connected after SIGKILL, so a lost journal plus a resync passed | **Fixed.** After SIGKILL, b first restarts alone (no peers, no miner). Its replayed head must be at least its pre-kill height less one (a torn tail loses at most one record), and its block at that height must be the one it had before the kill. Then b restarts connected | step 9; Mcrash §4.2, §4.3 |
| E2E-R3-7 (minor): the unit test `a_long_catch_up_is_not_bounded_by_the_protected_branch_size` was timing-dependent (once `syncRounds` = 1 in 11 runs) | see §4.5 | §4.5 |
| E2E-R3-8 (minor): the waits and the number of late blocks were not printed; README §3.4 said "always" | **Fixed.** Every named bounded wait prints `WAIT <what>: met/NOT met after <s> (bound <s>)`. The precondition line prints the number of late blocks, and the result line prints the test's own run time (`elapsed_s`). The wording is corrected in §2 here, because the round-2 README is not edited | logs; §2 |
| E2E-R3-9 (minor): the integrated 3/3 log records only the binary | **Fixed** in a new note, `PROVENANCE-e2e-integration.md`. It gives the script sha256 `9d73605e…c1c15`, the exact command, the working directory, the build and the locks, and points out that the log's `exit=0` lines are `tail`'s status, not the test's | `PROVENANCE-e2e-integration.md` |

## 2. Corrections to `../e2e-mutation-r2/README.md`

These hold for the round-2 test (`f583c7f`, sha256 `9d73605e…c1c15`):

- **§2, first bullet ("a rule that does not choose the strictly heavier tip fails …").** This held
  for the session path (the heal) and for a global rule (Mheight). It did not hold for the
  session-less path. c usually ended exactly one block above a/b, so the relay below c's tip never
  carried a block higher than a's head, and the review's Mhu (an unsolicited higher block becomes the
  head) passed 27/27. With round 3 (c ≥ a/b + 2, asserted), Mhu fails at that relay (§4.2).
- **§1, F3 "Fixed".** Read: *partly fixed*. The replay after the relay checks that the head
  persists. A transient switch that reverts at the next tick passed: the review's Mtransient passed
  27/27 twice. Round 3 catches it through a's reorganization counter (§4.2). That catch holds only
  if such a switch is counted as a reorganization (§5).
- **§3.4 ("c's first two late blocks always took attempts ≥ 1").** Read: *in the runs logged
  there*. The review's runs had late attempts `[2, 0, …]`, and so does round 3's `base-run3`, where
  the climb needed attempt 2 at the fifth late block. The precondition does not depend on this.
  The mechanism is printed, while the outcome (heavier and lower) is asserted.
- **§5, "No heal under mining (F10)".** Now covered by node e as a convergence check under mining
  (§1, E2E-R3-4). "One heal direction" remains stated scope.

## 3. The test (`0e51a36`)

Steps 1–3, the partition, are as in round 2, except for the higher climb. Each step below names
what it checks.

1. **c is isolated and frozen** at its head c0.
2. **a and b lead** c0 by more than LEAD = 4 c0 blocks of work and are frozen on one tip.
3. **c mines late** (PAUSE = 120 s after c0's timestamp) until it is **at least a/b's height + 2**,
   then is frozen. Precondition, asserted: a/b's tip is strictly heavier than c's tip, at least 2
   blocks lower, and at least 2 blocks past the fork. Printed: the work margins, the number of late
   blocks, their attempts and the climb time.
4. **Heal.** a's and b's counters are read, c is stopped, and its store is copied to `data/d` and
   `data/e`. c then rejoins without a miner. Checks: every head is a/b's tip; the canonical block at
   that height is a/b's tip; c's tip is canonical on no node; c reorganized exactly once; **a and b
   neither reorganized nor started a session**.
   - **4b. Heal without a session (node d).** d opens the copy (head c's tip) with a listener,
     no peers and no miner. A test peer sends a Hello claiming genesis, then a/b's branch above the
     fork in reverse order. Every block but the lowest arrives before its parent. Check: d's head
     goes from c's tip to a/b's tip, with reorgs +1 and syncSessions 0. d is stopped.
5. **Relay without a session** of c's branch below c's tip, whose last block is above a's head.
   Checks: a stores it, keeps its head, the branch is not canonical, and **a's reorgs and
   syncSessions are unchanged**.
6. **Relay in a session.** Checks: a stores c's tip, keeps its head, c's tip is not canonical,
   with **exactly one new session and no reorganization**.
7. **Replay of a** alone, as in round 2.
8. All three nodes mine again; production resumes.
   - **8b. Heal while mining (node e).** e first opens its copy alone, to read its starting head
     (c's tip), and is stopped. It then dials a, b and c, which are mining, with no listener and no
     miner. Bounded check (120 s), as in §1. e is stopped.
9. **SIGKILL crash of b.** b's head and its canonical block one below the head are read, then
   b is killed. b restarts alone; check: its replayed head is at least the pre-kill height less one,
   and its block at that height is unchanged. b is stopped and restarts connected with a miner;
   check: it rejoins.
10. ≥ 100 blocks; identical canonical blocks on the confirmed common prefix; the miner checks. All
    unchanged.
11. **Frozen tips.** a, b and c restart connected without miners. Checks: one totalWork within
    60 s; identical canonical hash, stateRoot and receiptsRoot up to the last height all three
    share, which must be at most one below the lowest head.
12. **Full restart replay** of each node and two independent `pocold status` replays, as before.
    The live heads are now read on frozen nodes.

33 checks (round 2: 27). The busy-port check covers 30300–30303 and 8540–8544: d uses RPC 8543 and
P2P 30303; e uses RPC 8544 and does not listen.
