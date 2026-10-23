# Evidence reconciliation (round 2, D-REORG-REDB final code)

Commit roles for the final verification, and proof that every evidence commit carries the same built
code (prototypes/ and .github/ trees), so the results apply to the final implementation.

| role | commit |
|---|---|
| audited snapshot | `090eae4` |
| last implementation commit (prototypes/ and .github/) | `3c3792e` |
| integration-tested commit | `3c3792e` (evidence/integration.json, last run) |
| witness-tested commit | `3c3792e` (evidence/witnesses-redb-final.log) |
| real-Chrome-tested commit | `3c3792e` (in the integration) |
| RSS-measured commit | `3c3792e` (evidence/rss-redb-final.json) |
| mutation-controlled commit | `3342af3`, whose Rust sources equal `3c3792e`'s. The two prototypes/ trees differ only in `tests/e2e_devnet.py`, by `git diff 3342af3 3c3792e -- prototypes` |
| spec-depth release runs | `441ce73` (evidence/spec-depth-441ce73.log). `prototypes/pocold/src/` is identical to `3c3792e`'s (`git diff 441ce73 3c3792e -- prototypes/pocold/src` is empty); the later commits only add and correct tests |

The debug-phase-A run (assert-release, `--include-ignored`) also runs both spec-depth tests on
`3c3792e` itself (REPAIR-REPORT §3b).

The integration's `dirty: true` is one uncommitted evidence file: the previous run's append to
`integration.json`, made by the failed run on 82ddb03 and committed later. No code was uncommitted. The
witness log header's "2 uncommitted paths" are evidence files written by the integration and the RSS
run.

## Tree equivalence (tools/reconcile.py)

```
| role | commit | prototypes/ tree | .github/ tree | code equal to the implementation commit |
|---|---|---|---|---|
| last implementation commit | `3c3792e90eb3c31c83abc91f26e861c8510a824f` | `85e63f96f225` | `347e2324e80c` | yes |
| integration-tested commit | `3c3792e90eb3c31c83abc91f26e861c8510a824f` | `85e63f96f225` | `347e2324e80c` | yes |
| witness-tested commit | `3c3792e90eb3c31c83abc91f26e861c8510a824f` | `85e63f96f225` | `347e2324e80c` | yes |
| real-Chrome-tested commit | `3c3792e90eb3c31c83abc91f26e861c8510a824f` | `85e63f96f225` | `347e2324e80c` | yes |
| PR head | `7e786137d66799c0b468e86d1fed8d47b8d1322e` | `85e63f96f225` | `347e2324e80c` | yes |

Commits after the implementation commit (1):

- `7e786137d667` audit-repair r2: final-code evidence for 3c3792e — integration, RSS, witnesses: 3 paths, all docs/meta (no code)

Result: every evidence commit and the head carry the implementation commit's code trees; later commits change development/ and root metadata (.gitignore) only.
```

---

## History: reconciliation as recorded for `687ac38` (before D-REORG-REDB)

### (round 2, 687ac38)

Commit roles for this round's verification, and proof that every evidence commit carries the same
built code (prototypes/ and .github/ trees), so the test results apply to the final implementation.

| role | commit |
|---|---|
| audited snapshot | `090eae4` |
| last implementation commit (prototypes/ and .github/) | `687ac38` |
| integration-tested commit | `c19dc8a` (code = 687ac38) |
| witness-tested commit | `ec09120` (code = 687ac38) |
| real-Chrome-tested commit | `c19dc8a` (in the integration) |
| PR head at this reconciliation | `ec09120` |

## Tree equivalence (tools/reconcile.py)

```
| role | commit | prototypes/ tree | .github/ tree | code equal to the implementation commit |
|---|---|---|---|---|
| last implementation commit | `687ac38be6c693ee2e92d65d77fa4dd90be2beb7` | `68ece272a3c7` | `347e2324e80c` | yes |
| integration-tested commit | `c19dc8a9f9fb38a41b7376e90152986965736d0d` | `68ece272a3c7` | `347e2324e80c` | yes |
| witness-tested commit | `ec091200f89d58c649cd49a23d2366b8501e1359` | `68ece272a3c7` | `347e2324e80c` | yes |
| real-Chrome-tested commit | `c19dc8a9f9fb38a41b7376e90152986965736d0d` | `68ece272a3c7` | `347e2324e80c` | yes |
| PR head | `d610492f9e4da579f9e88fbcaf3c05d54a59023a` | `68ece272a3c7` | `347e2324e80c` | yes |

Commits after the implementation commit (3):

- `c19dc8a9f9fb` audit-repair r2: document R_keep adoption depth 320 + D-REORG-REDB proposal; thread inventory evidence: 9 paths, all docs/meta (no code)
- `ec091200f89d` audit-repair r2: final integration on c19dc8a (code 687ac38): PASS but for the expected lp1 store_journal: 1 paths, all docs/meta (no code)
- `d610492f9e4d` audit-repair r2: gitignore the ephemeral witness programs (kept out of the public repo): 1 paths, all docs/meta (no code)

Result: every evidence commit and the head carry the implementation commit's code trees; later commits change development/ only.
```

Every role's prototypes/ tree is `68ece272a3c7` and .github/ tree is `347e2324e80c`: identical. The
commits after the implementation commit change only development/ docs and root metadata (.gitignore),
not the built code, so the integration, witness and Chrome results obtained on c19dc8a/ec09120 apply
to 687ac38 unchanged.

## Verification outcomes on the final code (separated, per the owner's instruction)

- **PASS (Linux):** lp4-execution 162, pocold 110 (incl. the two R_keep adoption tests), extension
  build + 234 unit, 3-node devnet 17, website publishing 20, real Chrome 79, integrated Chrome 18
  (evidence/integration.json, run on c19dc8a).
- **FAIL — expected platform limitation only:** lp1-node `store_journal` — 11 Windows-only tests
  executed on Linux and failed with UnsupportedPlatform, identically on the audited 090eae4. The
  integration records `failuresOnlyExpectedPlatformLimitation: true`. Not counted as a pass.
- **NOT RUN:** Windows verification (the scoped workflow returns 404 on dispatch until its file is on
  main; WINDOWS-VERIFICATION.md). Recorded separately, outstanding.
- **Witnesses (ec09120):** 17 observations, all NOT_REPRODUCED; 15 positive controls OK, 0 MISSING,
  0 erroneous REPRODUCED (evidence/witnesses-r2-final.log; A13 has no runtime witness; A02 contributes
  three). A NOT_REPRODUCED is an observation with its positive control, never an acceptance pass.
- **Measured RSS (final code):** evidence/rss-final.json (3-node devnet under idle + bounded
  adversarial load). Measured peak, not the model bound and not a guaranteed ceiling (A13-DERIVATION
  §2b).

## Witness provenance and positive controls

The witnesses were independently reconstructed from REPORT.md (the audit's own programs were not
received). Each prints `WITNESS <id> NOT_REPRODUCED` plus `CONTROL <id> OK|MISSING`, where the control
proves the scenario was built and the vulnerable path executed on the same build, so NOT_REPRODUCED
cannot mean the node refused to start, an API changed, or the path was never reached. Details:
evidence/WITNESS-CONTROLS.md.

## Restricted delivery of the exploit-shaped programs

The witness programs and the adversarial EVM measurement programs are NOT in this public repository
(the ephemeral copies are gitignored). They were delivered to the owner through the session's file
channel as a private review package; its files and SHA-256 hashes are recorded in
evidence/PRIVATE-REVIEW-PACKAGE.md (archive `fc46a03e…`; witnesses-r2.tgz `06730f27…`).
