# Audit repair report: A01–A14 and dependencies

| Item | Value |
|---|---|
| Audited snapshot | `090eae4dc059d1a7df330d9fe674c873ac515564` (branch `claude/affectionate-pascal-rjhh2k`) |
| Repair branch | `claude/audit-repair-a01-a14` |
| Final repaired commit | pending: the integration run on `4856842` is in progress |
| Plan, decisions | [REPAIR-PLAN.md](REPAIR-PLAN.md) |
| Tracker | [FINDING-STATUS.json](FINDING-STATUS.json) |
| Evidence | [evidence/FINDINGS-EVIDENCE.md](evidence/FINDINGS-EVIDENCE.md), [evidence/integration.json](evidence/integration.json), [evidence/witnesses-final.log](evidence/witnesses-final.log) |
| Arabic dashboard | [DASHBOARD-AR.md](DASHBOARD-AR.md) |

Final acceptance below rests on the repaired code and the evidence listed, not on test counts. A witness
printing NOT_REPRODUCED is an observation, not an acceptance pass.

## 1. What was repaired

| Finding | Repair (commits) | Corrected behaviour |
|---|---|---|
| A01 HIGH | ac3a951, d132203 | A body is bound to the header roots before any body check. An unbound or uncommittable copy is an envelope fault, never a verdict on the hash. Orphan copies are deduplicated by header and body, and a junk copy triggers a re-request. |
| A02 HIGH | 10678de, d132203 | Every boot path (init-devnet, run, status, tests) goes through the full accepted ParamGate (R1–R26), whose facts come from the real artifacts. `Admitted` is the only bootable type. Timing is measured on the booting machine. R26 uses pocold's implemented RPC limits. |
| A03 HIGH | 10678de | LOG_BLOCK_MAX (LOG-ACCT-01 charges), 546 logs, LOG_CAP, DIRTY_BLOCK_MAX, ACCT_DIRTY_BLOCK_MAX, SLOT_CAP/ACCT_CAP (user state) and the user-context SYS allowance are enforced as exceptional halts: all gas charged, state reverted except nonce and fee, status 0, block valid. SYS_SLOT_MAX is checked after each block. |
| A04 HIGH | 20bedce, d132203 | Journal v2: authenticated record lengths and a two-slot commit file (separate sectors). Corruption of committed data fails closed with files untouched. Only bytes after the committed end (at most one record) are an interrupted append. v1 migrates only when fully verified. |
| A05 HIGH | a2dbf16, d132203 | P2P: inbound caps (peers, pre-Hello), Hello/frame/idle deadlines, per-peer writer threads with bounded queues, bounded event queues, separate outbound connections, range re-requests. RPC: connection cap (excess refused unread), whole-request/write/work deadlines, streamed batches with BATCH_RESP_MAX, bounded log results. |
| A06 HIGH | 51aa8f7, 4856842 | Signing eligibility across lock, timeout, wallet replacement, profile change/conflict/invalidity and endpoint identity change. Wallet and profile epochs are re-checked after every await, and transitions cancel pending approvals. The dialog shows the unsigned bytes and the signer signs exactly them, only after approval, under ProfileMutex (eligibility → identity → eligibility). A 30 s identity check runs. |
| A07 MEDIUM | 51aa8f7, 4856842 | The extension's GenesisSpec decoder mirrors the accepted Rust decoder (stage order, details, widths, bounds). Differential: 1151 items, 0 mismatches. |
| A08 HIGH | 51aa8f7 | The RP header decoder validates every field like the Rust header decoder before any trust result (same corpus). |
| A09 MEDIUM | 51aa8f7 | The session receive share is taken synchronously and released exactly once on every path. |
| A10 MEDIUM | a2dbf16 | With an Origin header, ORIGIN_DENY applies to every batch member before any member runs. |
| A11 MEDIUM | a2dbf16, d132203 | Transactions of detached blocks return to the pool, minus those on the new branch, revalidated, in deterministic order. They are read before pruning. |
| A12 MEDIUM | 51aa8f7 | Storage admission is released when the write settles, not on the reply. |
| A13 HIGH | 25be2da, d132203 | Memory bound derived from the actual representation (container model checked against a counting allocator), state normalization, enforced side-branch, queue, pool, RPC and batch caps. The bound is checked at `Node::open`: 4.92 GiB ≤ 6 GiB at the devnet default. Open obligations are listed in A13-DERIVATION.md §4. |
| A14 LOW | 51aa8f7, d132203 | Only a JSON-RPC 2.0 response with the request id and exactly one of result/error is accepted. The node's oversize error carries the id. |
| Dependencies | 541b78b, 330c7d7 | pocold recovers signatures with k256 instead of the unmaintained libsecp256k1 0.5.0, so rand 0.7.3 leaves its tree. Equivalence: 151 463 cases, 0 mismatches, plus identical RFC 6979 signatures. lp1-node keeps its accepted Rust 1.58.1 set. |

## 2. Verification on the final commit

Pending: the full integration run on `4856842` is in progress. This section is filled from evidence/integration.json when it completes.

## 3. Independent review

Pending: a second independent review of the review-fix commits `d132203` and `4856842` is in progress.

## 4. Decisions that need owner confirmation

These were taken under the standing authorization and are documented with alternatives in REPAIR-PLAN.md.
Some change roots or validity:

- **LOG-ACCT-01** (consensus, affects roots): a log is charged 36 + 32·topics + data bytes against
  LOG_BLOCK_MAX, with at most 546 logs per block. A log with 32 733–32 768 data bytes now halts.
- **D-A03-DIRTY** (consensus): if a halt's own nonce/fee effects would exceed ACCT_DIRTY_BLOCK_MAX, the
  block is invalid, because no state exists to fall back to. The spec text says exceptional halt.
- **D-A03-CAPS** (consensus): SLOT_CAP/ACCT_CAP bound the user state; system storage is bounded by
  SYS_SLOT_MAX. The preserved LP4 issuance test now uses SYS_SLOT_MAX (cp[40]).
- **D-BODY-MAX** (consensus alignment): BODY_MAX bounds the encoded body on the local path too, as
  consensus.md and the network path do.
- **D-A02-PROFILE**:
  - devnet defaults: T_blk 4, D_att 25, dFbWait 3;
  - caps: the approved caps/64, SYS_SLOT_MAX 65536, R_max 0, H_END 20000;
  - e2e profiles: c 8, D_att 41.

  The old profiles fail ParamGate.
- **D-A06-CONFLICT**: both profiles of a chainId with two genesis hashes are read-only.
- **D-A04-UNCOMMITTED / journal v2**: the local storage format changes (experimental; v1 migrates when it
  verifies).

## 5. Remaining limitations and blocked evidence

- **Windows: BLOCKED BY PLATFORM.**
  - No Windows host is available in this environment.
  - The repository's "LP3 S1 Windows verification (manual)" workflow (lp1-node with Rust 1.58.1) runs only
    on manual dispatch and uses the owner's Actions minutes, so it was not dispatched.
  - lp1-node `store_journal` (11 tests) needs Windows and fails identically on 090eae4.
  - pocold's own Windows behaviour (file locks, sockets) is untested.
- **Audit attachments** (FINDINGS.json, COVERAGE.md, REPRODUCE.md, overlays, SHA256SUMS) were not
  provided. Verification against them is blocked; every finding was reproduced independently from
  REPORT.md.
- **Rust 1.58.1** is not available here. lp1-node's Cargo.toml and Cargo.lock are byte-identical to the
  audited snapshot, and its only code change moves four lines behind a module boundary.
- A13 open obligations (A13-DERIVATION.md §4):
  - gas monotonicity is assumed;
  - timing is representative, not worst-case;
  - thread stack residency is assumed;
  - pool re-execution and the full root rebuild cost CPU;
  - RpcGuard memory accounting, scratch budgets, pacing and rate buckets are not implemented (R26 keeps
    their nominal values);
  - the RetentionStore/redb trie is not implemented.
- Documented residuals:
  - A06: a signed submission proceeds if the wallet locks while transport capacity is awaited. The 30 s
    check does not revoke read access on transport errors.
  - A05: the RPC work deadline is not tested in isolation; loopback only.
  - A04: reordered complete records pass the framing layer (replay then fails closed); hardware power
    loss is not tested.
- Dependencies:
  - libsecp256k1 0.5.0 and rand 0.7.3 remain in lp1-node (accepted toolchain pin).
  - derivative 2.2.0 and paste 1.0.15 (build-time proc-macros via revm/alloy) remain; replacing them
    requires a revm upgrade.
- Not done: no merge into main, no deployment, no real funds. Exploit-shaped witness programs stay local.
