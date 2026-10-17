# LP3 acceptance matrix

The unchanged original requirements remain in LP3-MILESTONE.md. Approved amendment
01 is additive: no M1 source or prior evidence is rewritten. Status as work resumes:

| Criterion | Scope/status | Evidence or remaining work |
|---|---|---|
| S0–S4 | Previously accepted/merged; preserve and audit | Prior S0/S1, S2, S3, S4 acceptance evidence; S4 merge c662bff |
| S5 R1–R26 evaluator | PASS under amendment 01; pending GitHub merge | PR #15, codex-r2: 115 tests, 1450 oracle cases, 32 mutation controls |
| Original general R18 SYS derivation | DEFERRED LP4 — NOT PASSED | Amendment 01 tests 1, 4, 5 |
| Original general R21 trie bound derivation | DEFERRED LP4 — NOT PASSED | Amendment 01 tests 2, 4, 5 |
| Original caps/64 minimum SYS_SLOT_MAX | DEFERRED LP4 — NOT PASSED | Amendment 01 test 3 |
| Amended LP3 numeric R18/R21 fact evaluation | PASS evaluator on synthetic fixtures only | codex-r2 binding/version/coverage/provenance controls; boot disabled |
| S6 | NOT RUN in this continuation | TS model, proper type checking, independent comparison |
| S7 | PENDING audit/completion | Named AS traces, million cases, ASQ/ASB, TJ/T0/CF/SV core |
| S8 | PENDING | Integrated adversarial/mutation review |
| S9 | Ongoing | Arabic dashboard and PR evidence each completed cycle |
| Production boot | DISABLED | LP3 evaluator success is not execution or boot acceptance |

LP3 may be accepted only against the explicitly amended scope once every remaining
required criterion is supported. Deferred original obligations stay visible at handoff.
