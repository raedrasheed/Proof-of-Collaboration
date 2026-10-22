# Windows verification of the repair scope (round 2)

Status: **prepared, not run.**
- The scoped workflow cannot be dispatched until its file is on the default branch.
- No Windows host is available in this environment.

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
