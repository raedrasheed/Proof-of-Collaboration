#!/usr/bin/env python3
"""Writes development/audit-2026-10-22/FINDING-STATUS.json (round 2).

Each finding is classified on five separate axes, never folded into one "closed" label:
  implemented         YES | PARTIAL                 the repair code exists on the branch
  verified            VERIFIED (Linux) | PARTIAL    regression tests, mutation controls and the reconstructed
                                                    witness (with its positive control) on the recorded commits
  partiallyResolved   []                            requirements still technically incomplete
  blocked             {environment: [], decision: []} what only another environment, or an owner decision, can clear
  accepted            NOT ACCEPTED                  acceptance belongs to the owner; nothing is accepted here
The disposition is the weakest axis: PARTIALLY RESOLVED, then BLOCKED BY DECISION, then
VERIFIED (Linux) — BLOCKED BY ENVIRONMENT (Windows).

usage: python3 make_finding_status.py <commits.json>
commits.json: {"prHead", "lastImplementation", "integrationTested", "witnessTested", "chromeTested"}
"""
import json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(HERE)
WIN = "Windows on the exact commit: not run (no Windows host; the scoped workflow audit-r2-windows-verify.yml returns 404 on dispatch until its file is on main; see WINDOWS-VERIFICATION.md)"
WIT = "reconstructed witness (independently written from REPORT.md; the original audit programs were not received)"
NOREV = "round-2 changes reviewed by independent agent instances (two passes: the F1-F9 review of df63725 and the review of the D-A13-BUDGET range); no external human audit"

F = [
 ("A01", "HIGH", "Valid block hash poisoning through an unbound body", ["ac3a951", "d132203"],
  ["consensus::a01_malformed_or_unbound_bodies_reject_only_the_copy", "consensus::a01_committed_invalid_body_is_still_a_block_rejection_and_cached",
   "consensus::a_valid_header_with_a_foreign_body_rejects_only_that_copy", "consensus::body_max_bounds_the_encoded_body_not_the_item_sum", "consensus::d_body_max_vectors"],
  [], [], ["D-BODY-MAX (encoded body on every path; found while reviewing this repair)"]),
 ("A02", "HIGH", "ParamGate not enforced before boot", ["10678de", "d132203", "33f98b7", "77d6984"],
  ["admission::tests (R1–R26 at their boundaries; audit reproductions)", "admission::tests::{r26_predicates_are_the_gate_conjunction, absent_rpc_fields_enter_the_gate_as_zero_never_nominal, specification_scope_refuses_every_open_condition, experimental_devnet_waives_only_r26_predicates_reading_absent_fields}",
   "pocold admission::pocold_admission_is_an_experimental_devnet_with_absent_rpc_mechanisms", "compile_fail doc tests (no bypass constructor)",
   "admission::tests: the experimental scope admits only ProfileKind::Simnet (Synthetic and Network refused, review F5)", "RPC_FIELDS derived with an exhaustive RpcLimits pattern (review F6; omitting a field fails to compile)"],
  ["Only an experimental-devnet admission is possible: Specification scope refuses every current profile (rpc-absent, calibration-synthetic, timing-not-a-bound, gas-monotonicity-assumed, gate-deferred LP3 items)",
   "R14/R19 timing is a single measured sample on the booting host, not a p99 or worst-case bound; under CPU contention a debug build fails closed [R14, R19]",
   "R18 gas facts assume monotonicity in the domain fields (A13 §4 item 1)", "R26: 22 RpcGuard mechanisms are not implemented (absent, waived only in the experimental scope)"],
  [], ["D-A02-PROFILE (devnet parameters; engineering, approved under the standing authorization)"]),
 ("A03", "HIGH", "Runtime log and state limits not enforced", ["10678de", "07ac864", "b132a05"],
  ["apply::tests::a03::* (LOG_BLOCK_MAX, LG2, topics, cumulative, LOG_CAP, dirty keys/accounts, caps, halt semantics)", "apply::tests::a03::proposals::{log_acct_01_vectors, d_a03_dirty_vectors (status, halt kind and dirty-account count, incl. the block-invalid residue case), d_a03_caps_vectors, log_cap_aggregate_vectors}",
   "consensus::a03_over_limit_log_halts_the_transaction_and_the_block_is_valid"],
  [], [], ["LOG-ACCT-01", "D-A03-DIRTY (including the block-invalid halt-residue case)", "D-A03-CAPS", "D-A03-SYSUSER", "LOG-CAP-AGGREGATE"]),
 ("A04", "HIGH", "Journal frame corruption drops committed records", ["20bedce", "d132203", "cedabe7"],
  ["store::a04_* (every single-bit flip fails closed; truncation; boundary edits; commit-file damage; uncommitted tail; v1 migration; 4 KiB slots)"],
  ["Real power loss is not tested (simulated by file edits only)"], ["journal v2 on Windows (file replacement by rename with open handles, directory fsync skipped): untested"], ["D-A04-FORMAT journal v2 (local storage format, engineering)"]),
 ("A05", "HIGH", "P2P and RPC resource exhaustion", ["a2dbf16", "d132203", "cedabe7", "33f98b7", "45712cd", "77d6984", "b132a05", "a5e2517"],
  ["net::* (idle/hello deadlines, frames, slow reader, churn, inbound floods, connection cap, batches)", "net::rpc_work_deadline_skips_expired_work_and_releases_resources (deadline derived from the measured heavy duration; mutations: no skip, no batch deadline: each fails)",
   "net::legitimate_requests_progress_under_bounded_heavy_load", "net::a_light_turn_runs_at_most_light_turn_requests_then_wakes_the_node (mutation: no LIGHT_TURN bound fails)", "net::a_light_flood_coalesces_wakes_and_main_events_progress (mutation: a Wake per request fails)",
   "net::abandoned_queued_bodies_are_capped_and_released (mutation: no cap fails)", "net::a_full_heavy_pool_answers_busy_before_anything_runs (mutation: reservations never fail fails)", "rpc::tests::response_pools_reserve_shrink_and_release",
   "net::rpc_request_buffer_covers_headers_and_body (413 drained before close; its mutation is caught in release 2 of 3 runs, a race)", "net::tests::a_close_between_the_writers_test_and_its_wait_wakes_it (F1; mutation fails)",
   "net::miner_replacement_keeps_at_most_one_miner_thread (F7; mutation fails)", "net::peer_threads_stay_within_the_inventory_while_consensus_is_stalled (invariant check)",
   "net::light_lane_wakes_coalesce_until_taken (mutation fails)", "net::an_answer_is_reserved_until_its_connection_has_written_it (mutation fails)", "rpc::tests::a_busy_answer_does_not_parse_an_over_limit_body (mutation fails)",
   "consensus::a_max_size_transaction_is_answered_in_the_light_lane (mutation fails)"],
  ["RpcGuard is implemented only in part: connection cap, REQ_BUF, RESP_MAX, batch limits, log limits, a work deadline, a light lane with LIGHT_TURN, response pools after LIGHT_RESP_MAX/HEAVY_RESP_MEM/LIGHT_RESP_MEM (no permits, no QUEUE_WAIT, batches not streamed), queued-body cap, JSON value cap; HEAVY/LIGHT permits, scratch budgets, per-connection rate buckets, per-class compute deadlines and the send watchdog are not implemented",
   "A running request cannot be preempted: one heavy member (<= 30M gas) holds the consensus thread to completion", "Light methods are light by response size only (eth_sendRawTransaction executes; receipt and transaction lookups scan the chain): no light compute deadline"],
  [], []),
 ("A06", "HIGH", "Signing eligibility across wallet and profile transitions", ["51aa8f7", "4856842", "cedabe7", "df63725"],
  ["worker_test.mjs (A06 and A06-R2 submission states over a deterministic transport barrier; mutations: no re-check, no hook, submission under the mutex: each fails)", "e2e_browser.mjs real Chrome A06 and A06-R2 (lock, profile change and endpoint change while queued; lock after initiation)"],
  ["After a request is initiated it may be broadcast; it is reported as initiated/broadcast, never as cancelled (by design)"], [], ["D-A06-CONFLICT (engineering)", "D-A06-SUBMIT (changed expectation: a profile change during signing cancels the not-yet-initiated submission)"]),
 ("A07", "MEDIUM", "Extension GenesisSpec decoder accepts invalid specs", ["51aa8f7", "4856842"], ["tests/decoder_diff.mjs (1151 items vs Rust verdicts)", "pocold decoder_reference"], [], [], []),
 ("A08", "HIGH", "RP header structure not validated", ["51aa8f7"], ["decoder corpus (every UT field, seal, shares, winner signature)", "live RP mutations in e2e_browser.mjs"], [], [], []),
 ("A09", "MEDIUM", "Session receive reservations not atomic", ["51aa8f7"], ["worker_test.mjs A09 (peak <= cap; release on every path)"], [], [], []),
 ("A10", "MEDIUM", "ORIGIN_DENY not applied per batch member", ["a2dbf16"], ["net::a10_origin_deny_applies_to_every_batch_member"], [], [], []),
 ("A11", "MEDIUM", "Reorg drops detached transactions", ["a2dbf16", "d132203"], ["consensus::a11_reorg_restores_detached_transactions_without_resubmission", "consensus::a11_excludes_included_and_conflicting_transactions_and_keeps_order"], [], [], []),
 ("A12", "MEDIUM", "Storage admission released before the write settles", ["51aa8f7"], ["worker_test.mjs A12"], [], [], []),
 ("A13", "HIGH", "Resource derivations do not match the representation", ["25be2da", "d132203", "cedabe7", "33f98b7", "45712cd", "77d6984", "b132a05", "3c07cb5", "a5e2517", "66d69c6", "f7c345b", "54b2da1", "9ce5a7c"],
  ["resources::tests::{snapshot_model_bounds_measured_clone_bytes, execution_model_bounds_measured_adversarial_peaks (public cases), loaded_accounts_start_with_unallocated_storage_maps, sys_gas_envelope_fixture}", "lp4 tests/rss_snapshot.rs (full-cap snapshot clones: RSS 0.45 of the model)",
   "private adversarial execution measurements, each case against its own term (evidence/PRIVATE-REVIEW-PACKAGE.md; not in the public repository)", "consensus::{a13_* (side states, deep-fork rebuild, boot bound with separate default/below/exact/network-scale assertions, pool caps), a13_bound_breakdown}",
   "evidence/rss-*.json (measured RSS of a 3-node devnet under load: not worst-case evidence)", "A13-DERIVATION.md §2a, §2b, §4 (each assumption ENFORCED / DERIVED / INSPECTION / OPEN)",
   "consensus::a_competing_branch_within_side_blocks_max_is_adopted",
   "D-REORG-REDB (R_keep adoption): consensus::{adoption_at_the_spec_depth_2048_and_not_at_2049 and d133_tie_break_at_depth_400_holds_through_eviction_and_refetch (release, --ignored; evidence/spec-depth-9ce5a7c.log), r_keep_boundary_adopts_at_depth_r_keep_and_keeps_the_valid_chain_beyond, d133_tie_break_at_depth_holds_through_eviction_and_refetch, side_cap_holds_after_a_reorg_and_only_a_session_takes_an_evicted_block_again, a_session_branch_is_adopted_through_a_flood_of_competing_side_branches, replay_gives_a_reimported_block_a_new_import_seq, an_offloaded_block_is_served_viewed_and_re_executed_from_the_journal, a_crash_around_an_adoption_reopens_on_one_whole_chain, a_sync_session_refetches_an_evicted_branch_and_serves_it, a_long_catch_up_is_not_bounded_by_the_protected_branch_size, a_side_branch_below_the_k_hist_window_imports_without_rebuilding_each_parent, a_call_on_a_pruned_state_is_32017_not_an_empty_state_simulation}; mutation controls evidence/mutations-redb.json"],
  ["OPEN: gas monotonicity in the domain fields (§4.1)", "OPEN: R14/R19 timing is not a worst-case bound (§4.2)", "OPEN: allocator overhead and fragmentation (§4.3b); the boot gate keeps a 1/8 reserve for them, which is a margin, not a proof; the 5.241 GiB model total (5,627,687,516 B) counts requested bytes",
   "OPEN: CPU costs (world-root rebuild, chain scans, pool re-execution, deep-fork rebuild) (§4.5–4.7)", "OPEN: RetentionStore and the redb trie are not implemented (§4.10); the specification's node targets <= 750 MiB plus 192 MiB RPC (network.md:158), pocold's in-memory architecture needs 5.241 GiB of model", "CONDITION (not in the steady-state bound): open-time replay holds the whole journal (store::open, pre-existing) and a two-entry-per-record replay index",
   "INSPECTION only: transient-snapshot inventory, one EVM execution at a time, the answer-being-built tree ratio (§4.11, §4.13, §4.16)", "DERIVED with stated revm 19.7 facts: execution memory, operation classes (§4.4, §3a)",
   "No guaranteed process-memory ceiling exists (§2b)",
   "FOLLOW-UP (local, no validity effect): journal compaction; the append-only journal grows with every import and re-fetch (D-REORG-REDB-DESIGN-FREEZE.md R2.6)"], [], ["D-A13-BUDGET (owner approved option 1: local limits reduced, 6 GiB kept)", "D-REORG-REDB (owner approved 2026-10-23 as a storage repair for R_keep adoption; D133 and validity unchanged; §4.18 implemented)"]),
 ("A14", "LOW", "JSON-RPC responses not correlated with the request", ["51aa8f7", "d132203"], ["worker_test.mjs A14 (13 malformed shapes)", "rpc unit tests (-32008 carries the request id)"], [], [], []),
]

def main():
    commits = json.load(open(sys.argv[1]))
    integ = json.load(open(os.path.join(ROOT, "evidence", "integration.json")))["runs"][-1]
    out = {"auditedSnapshot": "090eae4", "repairBranch": "claude/audit-repair-a01-a14", "pr": "https://github.com/raedrasheed/Proof-of-Collaboration/pull/27",
           "commits": commits,
           "axes": {"implemented": "YES | PARTIAL", "verified": "VERIFIED (Linux) | PARTIAL: regression tests, mutation controls and the reconstructed witness with its positive control on the recorded commits",
                    "partiallyResolved": "requirements still technically incomplete", "blocked": "environment: only another platform can clear it; decision: only an owner decision can clear it",
                    "accepted": "owner acceptance; none is recorded"},
           "witnessProvenance": WIT, "integration": {"commit": integ["commit"], "result": integ["result"], "failuresOnlyExpectedPlatformLimitation": integ.get("failuresOnlyExpectedPlatformLimitation"),
               "suites": [{k: s.get(k) for k in ("suite", "exit", "pass", "executedAndFailed", "onlyExpectedPlatformLimitation", "platformNote") if k in s} for s in integ["suites"]]},
           "findings": []}
    for fid, sev, title, rc, tests, partial, env, dec in F:
        f = {"id": fid, "severity": sev, "title": title,
             "reproduction": {"onAuditedSnapshot": "REPRODUCED" if fid != "A13" else "source review (no runtime witness)", "by": WIT if fid != "A13" else "source review", "evidence": "evidence/baseline-090eae4.log"},
             "repairCommits": rc, "implemented": "PARTIAL" if fid in ("A05",) else "YES",
             "verified": {"status": "PARTIAL" if fid == "A13" else "VERIFIED (Linux)", "tests": tests,
                          "witnessOnRepair": "n/a (source review)" if fid == "A13" else "NOT_REPRODUCED with its positive control (evidence/WITNESS-CONTROLS.md)",
                          "commits": {"integration": commits["integrationTested"], "witness": commits["witnessTested"], "realChrome": commits["chromeTested"]}},
             "partiallyResolved": partial, "blocked": {"environment": [WIN] + env, "decision": dec}, "accepted": "NOT ACCEPTED (owner acceptance pending)",
             "independentReview": NOREV}
        f["disposition"] = ("PARTIALLY RESOLVED" if partial and fid in ("A02", "A05", "A13") else
                            "BLOCKED BY DECISION" if any(d for d in dec if "engineering" not in d and "standing" not in d and "changed expectation" not in d and "owner approved" not in d) else
                            "VERIFIED (Linux) — BLOCKED BY ENVIRONMENT (Windows)")
        out["findings"].append(f)
    out["summary"] = {d: [f["id"] for f in out["findings"] if f["disposition"] == d] for d in ("PARTIALLY RESOLVED", "BLOCKED BY DECISION", "VERIFIED (Linux) — BLOCKED BY ENVIRONMENT (Windows)")}
    out["summary"]["ACCEPTED"] = []
    json.dump(out, open(os.path.join(ROOT, "FINDING-STATUS.json"), "w"), indent=1, ensure_ascii=False); open(os.path.join(ROOT, "FINDING-STATUS.json"), "a").write("\n")
    print(json.dumps(out["summary"]))

if __name__ == "__main__":
    main()
