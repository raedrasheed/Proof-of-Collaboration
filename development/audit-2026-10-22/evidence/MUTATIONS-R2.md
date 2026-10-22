# Mutation controls for the round-2 review fixes (F1–F9) and D-A13-BUDGET

Each mutation re-breaks one fix, by a one-line source edit that is then restored. The test named must
then fail. Runner: `run_mutations.py`, kept with the private review material. These mutations only
remove fixes and hold no exploit payloads; their source edits are listed here. Commit: the b132a05
tree. Debug build unless noted.

| id | mutation | test | result |
|---|---|---|---|
| F1 | `close_outbox` sets the flag and notifies without the queue lock (the old code) | `net::tests::a_close_between_the_writers_test_and_its_wait_wakes_it` (unit; the close is issued exactly between the writer's test and its wait) | caught: the writer is not woken (timeout) |
| M1 | a Wake for every light request (no coalescing) | `a_light_flood_coalesces_wakes_and_main_events_progress` | caught |
| M2 | the new miner starts before the old one is joined (the old order in `lock`) | `miner_replacement_keeps_at_most_one_miner_thread` | first run: **not caught**, because /proc sampling missed the overlap. The test now asserts the miner-handle high-water mark (`miner::PEAK` = 1). Rerun: caught |
| M3 | no cap on queued heavy bodies | `abandoned_queued_bodies_are_capped_and_released` | caught |
| M4 | a response reservation never fails | `a_full_heavy_pool_answers_busy_before_anything_runs` | caught |
| M5 | requests dequeued after their deadline are run, not skipped | `rpc_work_deadline_skips_expired_work_and_releases_resources` | caught |
| M6 | batch members are started after the deadline | same | caught |
| M7 | no LIGHT_TURN bound (the lane is drained to empty) | first run against the flood test: **not caught**, because under that flood the lane empties between turns. The deterministic `a_light_turn_runs_at_most_light_turn_requests_then_wakes_the_node` was added. Rerun against it: caught |
| M8 | after 413, close at once with the input unread | `rpc_request_buffer_covers_headers_and_body` | a race. Debug: not caught (0 of 1). Release: caught in 2 of 3 runs. The fixed code passed 5 of 5 release runs |
| F6 | drop `timer_eps_ms` from the RPC field list | build | caught at compile time (the exhaustive `RpcLimits` pattern) |
| F8 dirty | report DirtyKeys where the block meter halts on dirty accounts | `apply::tests::a03::proposals::d_a03_dirty_vectors` (release) | caught (D2 tx 0: halt kind) |

## After the second review (45712cd..b132a05)

| id | mutation | test | result |
|---|---|---|---|
| M1b | a Wake for every light request | `light_lane_wakes_coalesce_until_taken` (deterministic; the flood test no longer asserts a ratio, which depended on build speed) | caught |
| M9 | retain evicts only the leaves present at the call (the old one-pass trimming) | `side_blocks_stay_within_the_cap_after_a_reorg_and_evicted_blocks_are_not_taken_again` (release) | caught |
| M10 | an evicted block is validated and journaled again | same | caught |
| M11 | replay fails on a duplicate record | `replay_skips_a_duplicate_record` (release) | caught |
| M12 | SIDE_BLOCKS_MAX 64 (the reverted reduction) | `a_competing_branch_within_side_blocks_max_is_adopted` (a 150-block-deep fork; release) | caught |
| M13 | the reservation is released before the answer is written | `an_answer_is_reserved_until_its_connection_has_written_it` | first run: **not caught** (the first sample landed between the answer being built and the connection taking it). The test now requires the reservation still to be there a second later. Rerun: caught |
| M14 | the busy path parses the body unconditionally | `rpc::tests::a_busy_answer_does_not_parse_an_over_limit_body` (counting allocator) | first run: not run (the runner's exact name lacked the module path, so 0 tests passed). Rerun with the full name: caught |
| M15 | tx_json carries `raw` beside `input` (the old encoding) | `a_max_size_transaction_is_answered_in_the_light_lane` (release) | caught |

A control that is not caught is recorded as such. M2, M7 and M13 were not caught by the first tests;
the tests were strengthened and the mutations rerun. M14's first run executed no test, which the
runner reported as a pass; it now uses the full name. M8 remains probabilistic. The whole set is rerun
on the final implementation commit (FINAL section below, once run).
