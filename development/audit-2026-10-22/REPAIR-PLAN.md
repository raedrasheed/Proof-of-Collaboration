# Repair plan for audit A01–A14

Baseline and reproduction: [BASELINE.md](BASELINE.md). Tracker: [FINDING-STATUS.json](FINDING-STATUS.json).
Authority: the owner's standing authorization (OWNER-STANDING-AUTHORIZATION.md) and the owner's 2026-10-22
instruction to repair the audit findings on a dedicated branch. Local devnet only. No merge into main, no
deployment, no real funds.

Rules for this repair:
- Witnesses stay as observations: they print REPRODUCED or NOT_REPRODUCED. Corrected behaviour is asserted by
  separate regression tests in the product suites.
- No consensus rule, limit or expected value is changed to make a test pass. Where the specification is
  ambiguous, the decision is recorded below with alternatives, consequences and the recommended choice.
- Each finding closes only with evidence on the repaired code; blocked platforms stay blocked.

## Order and planned repairs

### A01 — body binding and the invalid-block cache (pocold `chain.rs`, `types.rs`)
- Compute body commitments with a classifying function. A body whose items cannot form a commitment (empty
  item, oversize encoding) or whose roots differ from the header is an **envelope** rejection (that copy
  only). Content checks of a bound body keep their block-level rejections.
- `mark_invalid` stays reserved for rejections that depend only on committed content.
- Tests: empty tx / empty evidence item / malformed tx bytes / mismatched roots, each followed by the
  legitimate body (accepted); a committed-but-invalid body (header commits to garbage) is still a block
  rejection and is cached.

### A02 — ParamGate and validated admission (lp4-execution `paramgate.rs`, `devnet.rs`; pocold `lib.rs`)
- New `paramgate::check(spec, local, nodeKind)` evaluating every rule whose inputs exist: R1–R7 (with the
  node's local timing), R8–R13, R16, R17, R18 (derived SYS bounds plus the measured genesis system slots ≤
  SYS_SLOT_MAX), R20, R22–R25, plus the CP schema bounds. It returns all violated rules in order. R14/R19
  (measured validate p99) and R15/R26 (gossip/RPC service constants) are checked against the node's
  constants and a measured p99.
- New `Admitted` type with private fields, constructible only through `admit(...)`, which runs the full gate
  and genesis construction. `devnet::build`, `devnet::load` and `pocold::load_spec` return `Admitted`;
  `pocold::chain::Spec` can only be made from an `Admitted`. `Genesis::build` stays available inside the
  crate and to its own unit tests only.
- Devnet profile consequence: the LP5–LP10 devnet defaults violate R16 (REG_RECORDS_MAX 8192 < 12386) and,
  with honest local timing (Δ ≥ 1 s, t_exec ≥ 1 s), R3/R7. The defaults move to gate-valid values; see
  decision D-A02-PROFILE.

### A03 — runtime log and state limits (lp4-execution `user_phase.rs`, `apply.rs`)
- A per-block meter (logs bytes and count, dirty storage keys, dirty accounts, live slots and accounts,
  cumulative log bytes) evaluated per transaction. A transaction that would exceed a limit ends in an
  **exceptional halt**: all of its gas is charged, its state changes are rolled back except the nonce and
  fee payment, its receipt has status 0 and no logs. The block stays valid.
- Tests: exactly at, one below and one above each limit; cumulative logs across transactions; receipts,
  gas, roots and state after a halt; a halted transaction does not consume the budget.
- Adjacent limits are reported separately: what is enforced, what remains open.

### A04 — journal framing (pocold `store.rs`)
- Journal format v2 (`POCOLJ2`): every record header carries its own check over the length, so a damaged
  length is detected as corruption (fail closed, files untouched) instead of a torn append.
- Classification of the bytes after the last verified record: empty → clean; a strict prefix of a valid
  record (header check valid or header incomplete) → torn append, recovered into a new journal with the
  original preserved; an all-zero suffix no longer than one maximal record → torn append; anything else →
  `Corrupt`.
- v1 journals: migrated automatically only when they parse completely with no torn tail; otherwise the node
  refuses to start (`LegacyNeedsReview`) and nothing is modified.
- Tests: exhaustive single-bit flips over every byte of a 3-record journal (each → Corrupt or, only inside
  the final incomplete record, torn), truncation at every offset of the last record (torn), boundary
  insertions and deletions, migration.

### A05 — network and RPC admission (pocold `net.rs`, `rpc.rs`, `node.rs`)
- P2P: global caps on established peers and on pre-Hello connections, a Hello deadline, read and write
  deadlines, bounded per-peer outbound queues (a writer thread per peer; broadcast never blocks on a
  socket; a full queue drops the peer), bounded inbound frame size (existing) and a bounded node event queue.
- RPC: a global connection cap with immediate 503 beyond it, header/body read deadlines, one bounded work
  queue to the node.
- Orphans: a global cap on parent keys and total orphan bytes. Invalid-block cache: bounded with
  deterministic eviction (only a cache; never a validity input).
- Tests: idle peers, missing Hello, slow reader, reconnect churn, excess RPC connections; legitimate clients
  keep being served; thread counts and queue sizes stay bounded.

### A06 — wallet and profile transitions (extension `sw.js`, `wallet.js`)
- Profile epoch and wallet epoch counters. Every await in the signing path re-checks: same profile epoch,
  same wallet epoch, wallet unlocked, profile not in conflict, endpoint chainId and genesis re-verified.
  Signing happens only after approval and only if all checks still hold. The signed bytes equal the
  displayed unsigned payload, and the hash shown is the signing hash. Lock, profile change and endpoint
  change cancel pending approvals.
- A conflict profile is read-only: no accounts, no signing.
- Tests on the real worker with the Chrome mock, then real Chrome.

### A07 — complete GenesisSpec verification in the extension (`rp.js`)
- Full schema: top-level arity, specVersion, chainId width and value, 52 CP values with widths and bounds,
  allocRoot 32 bytes, M0List as a list of [id20, reward20] members, sorted and unique, sysCodeHash 32
  bytes, canonical RLP, size limit, depth limit. Differential test against the Rust decoder on positive
  fixtures and on every single-field mutation.

### A08 — RP header structure (`rp.js`)
- Validate all 18 UT fields (types, widths, canonical integers), signature/proposer shapes, nonce, share
  list and winnerSig before any trust result. Differential test against the Rust header decoder on
  mutations of every field.

### A09 — atomic receive reservations (`transport.js`)
- One reservation ticket covers the session budget and the pool budget, taken synchronously in FIFO order,
  released exactly once on every path (success, error, timeout, abort, session teardown).

### A10 — ORIGIN_DENY per batch member (`rpc.rs`)
- With an Origin header, every batch member is checked before any member executes. Denied members return
  −32601 and never reach the node. Malformed members return −32600.

### A11 — reorg transaction restoration (`node.rs`)
- On a head change, collect the transactions of blocks detached from the old canonical chain, drop those
  included in the new canonical chain, and re-admit them after the existing pool in deterministic order
  (by detached height, then position). Each one is revalidated against the new head (nonce, balance, fee,
  pool limits).

### A12 — storage admission ownership (`sw.js`, `records.js`)
- `RecordStore.write` returns `{reply, settled}`. Admission is released on `settled`, never on the reply.
  A write that never settles keeps its admission (bounded by the limit).

### A13 — resource derivations (development/lp4/p7-resources, new derivation document)
- A conservative derivation over the admitted parameter domain, tied to the code, covering system gas,
  code bytes and container overhead, retained canonical history, side branches (with an enforced global
  side-branch cap), indexes, queues and working memory, with checked arithmetic. Obligations that cannot be
  proved stay open.

### A14 — JSON-RPC response correlation (`transport.js`)
- Require `jsonrpc === "2.0"`, `id` equal to the request id, exactly one of `result` and `error`, and an
  error object `{code: integer, message: string, data?}`.

### Dependencies
- Review the OSV results: libsecp256k1 0.5.0 (unmaintained, cryptographic), derivative, paste
  (unmaintained, proc-macro), rand 0.7.3 (conditional unsoundness; RUSTSEC-2026-0097 = GHSA-cq8v-f236-94qc).
  Establish reachability. Replace libsecp256k1 only with vector-verified equivalence (signatures, recovery,
  encodings).

## Decisions

### D-A03 LOG-ACCT-01 — log accounting for LOG_BLOCK_MAX (consensus; affects roots)
Ambiguity: execution.md fixes LOG_BLOCK_MAX = 32 KiB with exceptional halt and names a derived log count of
546 (LG2: 546 logs succeed, 547 halt). storage.md gives the stored log size as 36+len. Neither states how
topics count, nor whether the 546 count is a separate limit.
- (a) bytes = Σ(36 + |data|), no count limit: topics are uncounted; a block can hold 910 empty logs,
  contradicting the 546-log receipt bound (2·LOG_BLOCK_MAX + 546·512) used in RECV derivations.
- (b) bytes = Σ|data| only: contradicts LG2 (546 logs of 24 bytes are far below 32 KiB).
- (c) **recommended**: per log 36 + 32·|topics| + |data| bytes, cumulative per block ≤ LOG_BLOCK_MAX
  (equality allowed), **and** at most 546 logs per block; the first transaction that would exceed either
  limit halts exceptionally. Consistent with 36+len for LOG0, with LG2 (546·60 ≤ 32768 and the 547th halts),
  and with the 546-log receipt bound.
Consequences: deterministic; roots change only for blocks containing over-limit transactions (previously
accepted with status 1). No accepted vector changes. Applied under the standing authorization as the
recommended option; recorded for independent confirmation.

### D-A02-PROFILE — devnet defaults must pass ParamGate (profile, not a rule)
The LP5–LP10 devnet profile violates R16 and, with honest timing, R3/R7. Options: (a) adopt P11 timing
(T_blk=10, D_att=60, Δ_fb_wait=6), the approved dev profile; (b) a gate-valid single-host profile that uses
φ=0, which is exact on one machine (Φ=0, Δ=1, t_exec=1, Δ_rel=5, Δ_fb_wait=3, D_att=25, Γ=5, T_blk=4,
REG_RECORDS_MAX=16384); (c) exempt simnet from R1–R7 (rejected: it weakens the gate). Recommended:
**(b) for single-host suites, (a) for any multi-host use**. The node refuses any combination that fails the
gate. Earlier LP5–LP10 evidence was produced with a profile that this gate now rejects; that evidence is
kept as historical and the suites are re-run.

### D-A04-FORMAT — journal v2
An experimental local storage format, not a protocol change. v1 migrates only when it parses completely;
an ambiguous v1 journal is never auto-repaired.
