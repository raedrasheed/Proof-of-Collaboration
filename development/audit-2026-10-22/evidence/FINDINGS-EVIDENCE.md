# Per-finding reproduction and repair evidence (A01–A14, dependencies)

How to read this file:
- Each finding lists four things:
  - **reproduced**: the witness on the audited snapshot 090eae4 ([baseline-090eae4.log](baseline-090eae4.log));
  - **repair**: the commits;
  - **regression**: the tests in the product suites that assert the corrected behaviour;
  - **witness on the repair**: the same observation rerun on the repaired code.
- A witness prints REPRODUCED or NOT_REPRODUCED. It is an observation, never an acceptance pass.
- The witness programs themselves are kept local (see BASELINE.md). Their observation lines are in
  [witnesses-final.log](witnesses-final.log).
- Integration results for the final commit are in [integration.json](integration.json).

| Finding | Reproduced on 090eae4 | Repair | Regression tests (product suites) | Witness on the repair |
|---|---|---|---|---|
| A01 body binding | malformed copy cached the valid hash as invalid | ac3a951 | pocold `consensus::a01_malformed_or_unbound_bodies_reject_only_the_copy` (seven copies under one valid header: empty tx item, empty evidence item, empty tx among valid ones, undecodable tx bytes, undecodable evidence bytes, a valid tx the header does not commit to, an oversized tx item; each an envelope rejection, then the real body becomes head), `a01_committed_invalid_body_is_still_a_block_rejection_and_cached`, `a_valid_header_with_a_foreign_body_rejects_only_that_copy` | NOT_REPRODUCED |
| A02 admission | R9, R13 and SYS_SLOT_MAX=1 profiles built | 10678de | lp4 `admission::tests` (timing R1–R7, size R8–R13, resources R14–R21, identity R22–R26 at their boundaries; audit reproductions rejected with their rules; deterministic attributable rejections; the approved single-host and P11 profiles admitted), compile_fail doc tests (no `Genesis::build` or `Admitted` literal outside the gate), pocold `admission::{load_refuses_the_audited_profiles_and_admits_the_valid_one, init_devnet_refuses_gate_invalid_timing_and_writes_nothing}` | NOT_REPRODUCED ×3 (`-32018 ParamGate rejected [R9]`, `[R13]`, `[R14, R18, R19]`) |
| A03 runtime limits | 32 769-byte log accepted with status 1 | 10678de | lp4 `apply::tests::a03::*` (LOG_BLOCK_MAX below/at/above; 546/547 logs and topic charges; cumulative logs across transactions; a halt consumes no budget; LOG_CAP aggregate; dirty keys/accounts per block; SLOT_CAP/ACCT_CAP; the user-context SYS allowance; reverts except nonce and fee), `user_phase` meter unit test, pocold `consensus::a03_over_limit_log_halts_the_transaction_and_the_block_is_valid` | NOT_REPRODUCED (status 0, no logs) |
| A04 journal | one-bit length flip → `torn_tail`, 0 payloads | 20bedce | pocold `store::a04_*` (the audit case; every single-bit flip of a 3-record journal fails closed with files unchanged; truncation of committed records; boundary edits and duplicates; commit-file damage; zero-filled tail; v1 migration only when fully verified) plus the torn tail at every offset (v2) | NOT_REPRODUCED (`Corrupt(0)`) |
| A05 P2P/RPC bounds | 48 idle P2P sockets kept, threads 54 → 118 | a2dbf16 | pocold `net::*` (idle peers bounded and expired; only Hello before the handshake; oversized and stalled frames close the peer; a slow reader is dropped while consensus keeps serving; churn keeps threads and slots bounded; the RPC cap evicts idle readers and the whole-request deadline closes trickling clients), `rpc` unit test `responses_above_resp_max_become_an_error`. The RPC work deadline is not tested in isolation | NOT_REPRODUCED (see note) |
| A06 wallet transitions | conflict grant; signed raw before the click; submission after lock and identity change | 51aa8f7 | extension `tests/worker_test.mjs` (45 checks on the real worker; 28 fail on 090eae4); real Chrome `e2e_browser.mjs` A06 checks (conflict, display, identity before submission, lock, profile change, endpoint change, 30 s check) | NOT_REPRODUCED ×3 |
| A07 GenesisSpec decoder | five invalid specs accepted | 51aa8f7 | `tests/decoder_diff.mjs` (1151 items, 0 mismatches against the Rust verdicts), pocold `decoder_reference::reference_verdicts_for_the_decoder_corpus` | NOT_REPRODUCED |
| A08 RP header structure | malformed window accepted | 51aa8f7 | same corpus (every UT field, seal, shares, winner signature); live RP mutations in `e2e_browser.mjs` | NOT_REPRODUCED (`1`) |
| A09 receive reservations | peak 25 165 824 > 10 485 760 | 51aa8f7 | `worker_test.mjs` A09 (peak ≤ cap; release on fetch error, deadline, HTTP 500, pool exhaustion) | NOT_REPRODUCED (peak 8 388 608) |
| A10 ORIGIN_DENY | batch member executed | a2dbf16 | pocold `net::a10_origin_deny_applies_to_every_batch_member` | NOT_REPRODUCED |
| A11 reorg pool | transaction lost after a reorg | a2dbf16 | pocold `consensus::{a11_reorg_restores_detached_transactions_without_resubmission, a11_excludes_included_and_conflicting_transactions_and_keeps_order}` | NOT_REPRODUCED (pending nonce 1) |
| A12 storage admission | 0 of 8 refused while unsettled | 51aa8f7 | `worker_test.mjs` A12 (8th refused while unsettled; slots return when it settles) | NOT_REPRODUCED (1 of 8 refused) |
| A13 resource derivation | source review | 25be2da | lp4 `resources::tests::{snapshot_model_bounds_measured_clone_bytes, sys_gas_envelope_fixture}`, `apply::tests::a03::a13_reads_and_empty_calls_leave_no_container_residue` (mutation: normalization off → fails), pocold `consensus::{a13_side_branch_states_are_capped_and_rebuilt_on_demand, a13_rebuild_of_a_deep_fork_keeps_only_the_target_state, a13_boot_refuses_a_bound_above_the_memory_budget}`; derivation in [A13-DERIVATION.md](../A13-DERIVATION.md) | not a runtime witness |
| A14 response correlation | foreign id / jsonrpc 1.0 accepted | 51aa8f7 | `worker_test.mjs` A14 (13 malformed shapes rejected; exact result and error accepted) | NOT_REPRODUCED (`recvParse`) |
| Dependencies | libsecp256k1 0.5.0 (unmaintained), rand 0.7.3 (conditional) | 541b78b, 330c7d7 | equivalence: [secp-equivalence.md](secp-equivalence.md); pocold `secp_fixture::accepted_chain_fixture_signatures_recover_through_k256`; lp1-node accepted signature fixtures | n/a |

Note on A05: the live witness reported "alive 8" after 12 s. Those 8 sockets had received the node's 79-byte
Hello and reached EOF at 5.06 s, when the hello deadline closed them. The witness's `MSG_PEEK` counted the
buffered Hello bytes as a live connection. Node threads stayed bounded.

## Mutation and baseline controls
- A06/A09/A12/A14: `worker_test.mjs` on a build of 090eae4 → 12 pass, 28 fail
  ([worker-tests-on-baseline.log](worker-tests-on-baseline.log)).
- The A06 witness variant v2 (signing steps on a non-conflicting profile) reproduces on 090eae4
  ([witness-a06v2-baseline.log](witness-a06v2-baseline.log)).
- A13: with state normalization disabled, `a13_reads_and_empty_calls_leave_no_container_residue` fails. With
  side-state pruning disabled, `a13_side_branch_states_are_capped_and_rebuilt_on_demand` fails. Both mutations
  ran in isolated target directories.
- Old devnets, whose profiles are gate-invalid, are refused by the repaired binary: `[R3, R7, R14, R19, R25]`.
