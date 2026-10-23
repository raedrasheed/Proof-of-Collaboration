# Windows verification of the repair scope (round 2)

Status (2026-10-23): **running through a pull_request trigger; no passing run yet.** See "Runs" at the
end. The sections before "Runs" are the original preparation record and are kept as they were.

## The existing workflows (inspected)

| workflow (on `main`) | trigger | covers | covers the repair scope? |
|---|---|---|---|
| `lp3-s1-windows-verify.yml` | manual dispatch | lp1-node only, Rust 1.58.1: full suite, LP2 storage journal, crash recovery, CLI harness | partly: lp1-node (including `store_journal`); not pocold, lp4-execution, journal v2, sockets or the extension |
| `lp3-regression.yml` | pull_request to `work/lp3-consensus-foundation` | the same script | not triggered by PR #27 (other base) |
| `lp4-execution-controls.yml` | pull_request to two LP4 bases, Ubuntu | LP4 controls | not Windows; not triggered by PR #27 |
| `lp3-typescript.yml` | pull_request, Ubuntu | LP3 model | no |

PR #27 has no check runs.

## Prepared for this scope
`.github/workflows/audit-r2-windows-verify.yml` and `.github/scripts/audit-r2-windows-verify.ps1`.

How it runs:
- Manual dispatch only.
- Windows Server 2022.
- The `commit` input is required and must be a full SHA. The script refuses any other checkout, and the
  artifact is named `audit-r2-windows-<sha>`.
- Actions are pinned to the same commit SHAs as the LP3 workflow. There are no secrets, and the
  token is read-only.

| check | toolchain | what it verifies |
|---|---|---|
| `lp1-store-journal` | Rust 1.58.1 | the Windows-only journal tests that execute and fail with UnsupportedPlatform on Linux (11 tests) |
| `lp1-node-all` | Rust 1.58.1 | the full lp1-node suite, including the secp backend change of this repair |
| `lp4-execution` | Rust 1.99.1, release | execution, admission scope, A13 execution model, proposal vector replays |
| `pocold` | Rust 1.99.1, release | journal v2 (store), P2P and RPC sockets (net), the work deadline and light lane, admission, consensus |
| `extension-npm-ci`, `-build`, `-unit` | Node 22.22.0, official zip, SHA-256 `c97fa376…c77a` pinned | the extension build and unit/worker suites |

What it does not cover:
- The real-Chrome and live-devnet suites. Playwright/Chromium and the Python devnets are not
  prepared for Windows.
- pocold's thread-count assertions. They read `/proc` and are reported as `THREADS-NOT-MEASURED`
  on Windows. The other assertions of those tests still run.

What deserves attention on Windows:
- Journal v2 replaces files by rename while other handles may be open. Windows has different
  sharing rules from Linux.
- Directory fsync is skipped on Windows (`sync_dir` ignores the open error).
- Socket timeouts.

## Why it has not run: the exact blocker
1. `POST /repos/raedrasheed/Proof-of-Collaboration/actions/workflows/audit-r2-windows-verify.yml/dispatches`
   with `ref=claude/audit-repair-a01-a14` and `commit=df637252fd0691dc5891295271d164bc132d04fe` returned
   **404 Not Found** (2026-10-22). GitHub dispatches a workflow only when its file is on the default
   branch (`main`). The file exists only on the PR branch, and merging into `main` is not authorized.
2. The LP3 S1 workflow is on `main` and could be dispatched against this branch, but it covers lp1-node
   only. It is manual by design, and running it was left to the owner in round 1, so it was not
   dispatched.
3. Billing:
   - The repository is now **public**. Its workflow comment ("private … uses the owner's included
     minutes") is out of date.
   - GitHub Actions on standard GitHub-hosted runners, Windows included, are free for public
     repositories.
   - Billing therefore does not block a run. The blocker is the dispatch rule and the merge
     authorization.

## Owner options (any one is enough)
- **A.** Put only the two `.github` files on `main` (a separate commit or PR containing just them),
  then dispatch "Audit repair r2 Windows verification (manual)" with the PR head SHA.
- **B.** Authorize a `pull_request` trigger for PR #27, limited to base `claude/affectionate-pascal-rjhh2k`
  and the repair paths. It would then run on every push, at the head SHA.
- **C.** For lp1-node only, dispatch the existing LP3 S1 workflow on `claude/audit-repair-a01-a14`
  with `commit` = the PR head SHA.

Until one of these happens:
- Windows evidence for the repair commit does not exist.
- Every Windows-dependent item stays BLOCKED (environment), in FINDING-STATUS.json and the dashboard.

## Runs

The owner's 2026-10-23 instruction ("complete the authorized works: RpcGuard and the Windows
verification") was taken as authorizing option B:
- commit a03e089 adds a `pull_request` trigger, limited to PRs into `claude/affectionate-pascal-rjhh2k`
  from this repository, and to the repair paths;
- the commit under test is the PR head SHA.
Nothing was merged into `main`, and manual dispatch is unchanged.

### Run 1: a03e089 (code tree identical to 3c3792e): FAIL
- Run: https://github.com/raedrasheed/Proof-of-Collaboration/actions/runs/39942501824 (pull_request).
- Artifact `audit-r2-windows-a03e089a35affc22fed9f5aa3c961eac97d61658`, zip SHA-256
  `6b2a90c1e45e118607438f3ffe96ea370478bd96de1f2917b328c6a7cc27f482`. Its content is copied unchanged to
  `evidence/windows-a03e089/`.
- Platform: Windows Server 2022 (NT 10.0.20348), image win22 20261012.333.1; Rust 1.58.1 / 1.99.1;
  Node 22.22.0, checksum verified.

| check | status | detail |
|---|---|---|
| lp1-store-journal | PASS | 12 passed, 0 failed (the Windows-only journal tests) |
| lp1-node-all | PASS | 150 passed, 0 failed, 20 binaries |
| lp4-execution | PASS | 162 passed, 0 failed, 19 binaries |
| pocold | **FAIL** | 75 passed, 48 failed, 12 binaries |
| extension npm ci / build / unit | PASS | unit: 234 passed |

The 48 pocold failures have **one cause**:
- All 48 are in `tests/consensus.rs` (28) and `tests/net.rs` (20), and each panics with
  `retention.rkeep: Access is denied. (os error 5)`.
- `retention_rkeep` (src/node.rs, added by D-REORG-REDB in 3c3792e) fsyncs the data directory with
  `File::open(dir)`. Windows cannot open a directory as a file without backup semantics, so every
  `Node::open` failed on Windows.
- `store::sync_dir` already skips that case. This new call did not, and the Linux suites cannot see the
  difference.
- No other test failed. Every test that did not call `Node::open` passed, including the
  store/journal v2 tests. The thread-count assertions were reported THREADS-NOT-MEASURED, as designed.

Fix (next commit): on non-Unix targets the directory fsync after the rename is skipped, as in
`store::sync_dir`. On Linux the code path is unchanged. Linux check:
`cargo test --release --locked --test consensus replay_uses_the_largest_r_keep` → 1 passed.
The fix is verified only by a Windows run on the commit that carries it (Run 2).

Durability note:
- On Windows, the rename of `retention.rkeep` is not followed by a directory flush. This is the same
  as the journal's own renames.
- A crash right after the rename can leave the old value. The old value is never smaller than the one
  used by the records written before it, because the file is raised before replay and never lowered.
  So the worst case is that the next open rewrites the file.

### Run 2: 5d25fae (the retention.rkeep fix): FAIL, with 3 tests left
- Run: https://github.com/raedrasheed/Proof-of-Collaboration/actions/runs/39951153803.
- Artifact `audit-r2-windows-5d25faecdb25776c068b86adb3d5ab2a63b8920a`, zip SHA-256
  `97767fff26350f6136d3ccb274368fb9fbf14fb4528ad53470ebf4b0208eeec7`. Copied unchanged to
  `evidence/windows-5d25fae/`.
- lp1-store-journal 12/12, lp1-node-all 150/150, lp4-execution 162/162 and the extension (234 unit tests)
  PASS again.
- pocold: **120 passed, 3 failed**. The retention.rkeep fix is verified on Windows: none of the 48
  earlier failures recur.

The 3 failures are all in `tests/net.rs`. Diagnosis from the code and the messages:

| test | Windows message | cause | fix (next commit) |
|---|---|---|---|
| `a_peer_that_stops_reading_is_dropped_and_consensus_keeps_serving` | `wait_until(1000, live==0)` false | The drop calls `shutdown(Both)`, which wakes the reader's blocked `read` on Linux but not on Windows. The dropped peer's reader then held its slot and thread until the idle deadline (60 s in the test, 300 s by default). **A real defect on Windows**: dropped peers kept inbound slots. | `read_by` blocks at most `READ_POLL` = 100 ms per read and returns once the peer's closed flag is set. New unit test `a_reader_sees_its_closed_flag_without_a_shutdown` sets only the flag (Windows semantics on any OS): with the flag ignored it waits 10.006 s and fails (`evidence/windows-fixes/read-poll-mutant-flag-ignored.log`); with the fix it passes. |
| `rpc_work_deadline_skips_expired_work_and_releases_resources` | heavy call answered 200, expected 504 | The test sets the deadline to a quarter of the measured end-to-end time of the heavy call. On Windows the measured time included Nagle plus delayed-ACK stalls (about 200 ms): `write!` on an unbuffered `TcpStream` issues one write per formatted piece, on both the test client and pocold's `respond`. So the deadline exceeded the real work. The same stall added about 200 ms to every RPC answer on Windows. | pocold sets `TCP_NODELAY` on accepted RPC sockets and writes the header and the body in two writes. The test client sets `TCP_NODELAY` and sends its request in one write. |
| `an_answer_is_reserved_until_its_connection_has_written_it` | `during` = 8388608 (only the stats request's own reservation) | Not determined. Either the 14 MiB answer was absorbed by the Windows loopback buffers while unread (then the test's premise does not hold there), or it was never observed above the threshold. | The message now reports `built` separately. Run 3 decides; the assertion is unchanged. |

Linux after the fixes: `cargo test --release --locked --lib --test net` → 39 + 20 passed
(`evidence/windows-fixes/linux-lib-net-after-fix.log`). The Windows result is Run 3.
