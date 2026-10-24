# Independent reviews of 2026-10-24

The owner asked that the missing independent reviews be completed. Each review was done by a separate
agent instance. Each reviewer was given the code and the spec, not the track's conclusions.

| review | subject | reviewed at | report |
|---|---|---|---|
| R1 | caps, round 3b final (`e985ce1`) | `ec148cf` | [R1-caps.md](R1-caps.md) |
| R2 | RpcGuard, round 3c (`dd7d1ec`), with the Windows socket code | `ec148cf` | [R2-rpcguard.md](R2-rpcguard.md) |
| R3 | the journal study, round 3c, and the effect of `462fffc` | `ec148cf` | [R3-journal.md](R3-journal.md) |
| R4 | e2e round 4: does the test detect non-convergence and the wrong branch? | `ec148cf` | [R4-e2e.md](R4-e2e.md) |
| R5 | `462fffc` (A11 reorg walk, R14/R19 calibration) | `ec148cf` | [R5-462fffc.md](R5-462fffc.md) |

Probes, witness tests, mutation runners and benchmark crates stayed in scratch, outside this public
repository. Only these reports are committed.

## Findings rated MEDIUM or above, and what happened to them

| finding | severity | disposition |
|---|---|---|
| R3-2: a reverting CREATE2-heavy transaction pays every `current_total` scan without changing the state, so the worst state-scan block is repeatable at every height | HIGH | C-2 item 2 (`2ce03c1`): a create reads only the journaled accounts. Re-measurement pending |
| R3-3: open restores every adopted branch only at its end, re-executing from the lowest offloaded canonical block. Any reorg doubles later opens | HIGH | **OPEN**: conformance fix queued (restore each adopted branch during replay) |
| R3-1: the "7.3 h + 8.5 min" devnet bound double-counts TX_CAP and omits the per-transaction state term (≈ 7.45 h before R3-2 and R3-3) | MEDIUM | study correction queued; C-2 changes the per-transaction term |
| R3-6: every new head re-executes the whole pool with no gas bound (about 68–95 min at 4,096 MODEXP transactions) | MEDIUM | needs a local-policy decision (a pool gas limit changes which transactions are accepted): added to the decision package. C-2 already removed the per-submission scan and clone |
| R3-7: after `462fffc` a detached transaction already on the new branch pays a full scan before its nonce rejection | MEDIUM | fixed by C-2 (`2ce03c1`); also R5-1 |
| R5-1: a normal reorg's shared transactions each pay a full scan and a clone (74.6 s against 32.0 s in the reviewer's benchmark) | MEDIUM | fixed by C-2 (`2ce03c1`): neither cost remains. Re-measurement pending |
| R2-1: one RPC batch holds the consensus thread (a P2P Hello waited 14.3 s; up to about 35 s by construction) | MEDIUM | **OPEN**: conformance fix queued (network.md (ط) separates RPC from consensus) |
| R1-1: near the TXBYTES room the builder offers transactions that depend on a skipped one and can starve an independent valid transaction | MEDIUM | **OPEN**: conformance fix queued (execution.md:83) |
| R1-2: no committed test pins LOG_CAP accumulation within a block, its per-branch scope, or `cum_log_bytes` in `meta_clone` (L1, L2 and L4 survive) | MEDIUM | **OPEN**: tests queued |
| R4-1: the e2e's only measure of "heavier" is the node's own totalWork, so a work-accounting bug that every node shares passes | MEDIUM | **OPEN**: test change queued |
| R4-2: relay and Hello-refresh breakage pass (full mesh; every sync starts from a new connection) | MEDIUM | **OPEN**: test change queued |

The LOW and NOTE findings are listed in each report. Those that need code or test changes are queued
after the items above, in the order of the decision package priorities.
