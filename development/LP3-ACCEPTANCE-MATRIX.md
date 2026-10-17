# LP3 acceptance matrix

The unchanged original requirements remain in LP3-MILESTONE.md. Approved amendment
01 is additive: no M1 source or prior evidence is rewritten. Status as work resumes:

| Criterion | Scope/status | Evidence or remaining work |
|---|---|---|
| S0–S4 | Previously accepted/merged; preserve and audit | Prior S0/S1, S2, S3, S4 acceptance evidence; S4 merge c662bff |
| S5 R1–R26 evaluator | PASS under amendment 01; merged 18cf7ab | PR #15, codex-r2: 115 tests, 1450 oracle cases, 32 mutation controls |
| Original general R18 SYS derivation | DEFERRED LP4 — NOT PASSED | Amendment 01 tests 1, 4, 5 |
| Original general R21 trie bound derivation | DEFERRED LP4 — NOT PASSED | Amendment 01 tests 2, 4, 5 |
| Original caps/64 minimum SYS_SLOT_MAX | DEFERRED LP4 — NOT PASSED | Amendment 01 test 3 |
| Amended LP3 numeric R18/R21 fact evaluation | PASS evaluator on synthetic fixtures only | codex-r2 binding/version/coverage/provenance controls; boot disabled |
| S6 | PASS reference scope; merged 772cb1f | PR #16: strict type check, eight tests, independent Rust/TS/Python comparisons and mutation controls |
| S7 numerical gates | PASS scoped evidence; S7 NOT accepted | Actual AS1–AS19 traces, million full comparisons, ASQ/ASB and SV arithmetic; codex-r1 evidence |
| CF1–CF6 canonical binding | BLOCKED BY DESIGN | Labels occur only in M3 list; CF-DECISION.md proposes explicit core mapping, not an original pass |
| T0 final core acceptance audit | PENDING | Prior header/codec scope is not blanket V1–V26/H-full acceptance |
| S8 | PENDING | Integrated adversarial/mutation review |
| S9 | Ongoing | Arabic dashboard and PR evidence each completed cycle |
| Production boot | DISABLED | LP3 evaluator success is not execution or boot acceptance |

LP3 may be accepted only against the explicitly amended scope once every remaining
required criterion is supported. Deferred original obligations stay visible at handoff.
