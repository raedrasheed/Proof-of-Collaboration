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

### A02 — ParamGate and validated admission (lp4-execution `admission.rs`, `devnet.rs`; pocold `lib.rs`, `chain.rs`, `main.rs`)
- As implemented: the accepted LP3 evaluator `gate::check` (lp1-node `gate.rs`, `param_gate.rs`,
  `timing.rs`, shared byte-for-byte) evaluates R1–R26 and returns every violated rule in order. A
  first-draft plan for a new `paramgate.rs` was dropped in favour of reusing the accepted evaluator.
  `admission::admit` builds its facts from the real artifacts (D-A02-FACTS) and the node's local
  parameters; schema/decode failures are R24.
- `Admitted` has private fields and only `admit` constructs it (compile-fail doc tests pin E0624/E0451).
  `Genesis::build` is crate-private; `devnet::load` (an unadmitted load path) is removed; `devnet::build`
  returns a candidate whose `admit` measures timing and runs the gate. `pocold::chain::Spec` is
  constructible only from an `Admitted`; `pocold::load_spec` (run, status) and `init-devnet` run the gate
  and refuse boot with `-32018 ParamGate rejected [...]`.
- Devnet and test profiles move to gate-valid values (D-A02-PROFILE).

### A03 — runtime log and state limits (lp4-execution `user_phase.rs`, `apply.rs`)
- A per-block meter (logs bytes and count, dirty storage keys, dirty accounts, live slots and accounts,
  cumulative log bytes) evaluated per transaction. A transaction that would exceed a limit ends in an
  **exceptional halt**: all of its gas is charged, its state changes are rolled back except the nonce and
  fee payment, its receipt has status 0 and no logs. The block stays valid.
- Tests: exactly at, one below and one above each limit; cumulative logs across transactions; receipts,
  gas, roots and state after a halt; a halted transaction does not consume the budget.
- Adjacent limits are reported separately: what is enforced, what remains open.
- As implemented: `user_phase::caps` (LOG_BLOCK_MAX, LOG_COUNT_MAX=546, LOG_CAP, DIRTY_BLOCK_MAX,
  ACCT_DIRTY_BLOCK_MAX), SLOT_CAP/ACCT_CAP over the user state (D-A03-CAPS), the user-context SYS
  allowance (D-A03-SYSUSER); LOG_CAP uses the canonical ancestors' charged log bytes
  (`BlockInput::cum_log_bytes`, pocold `Entry::cum_log_bytes`). The profile-free Cancun control path is
  left geth-equivalent.

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
- After the independent review (D-A05-REVIEW):
  - outbound dials are counted apart from inbound slots;
  - excess RPC connections are refused unread, as network.md says (no eviction);
  - batch members are streamed with BATCH_RESP_MAX;
  - eth_getLogs stops at RESP_MAX of result;
  - a stalled head re-requests ranges;
  - a failed peer-thread spawn reports Closed and frees the dial address;
  - orphans are deduplicated by header and body, and a junk orphan copy triggers a re-request.

### A06 — wallet and profile transitions (extension `sw.js`, `wallet.js`)
- Profile epoch and wallet epoch counters. Every await in the signing path re-checks: same profile epoch,
  same wallet epoch, wallet unlocked, profile not in conflict, endpoint chainId and genesis re-verified.
  Signing happens only after approval and only if all checks still hold. The signed bytes equal the
  displayed unsigned payload, and the hash shown is the signing hash. Lock, profile change and endpoint
  change cancel pending approvals.
- A conflict profile is read-only: no accounts, no signing.
- Tests on the real worker with the Chrome mock, then real Chrome.
- As implemented (`sw.js`, `wallet.js`, `viewer.js`):
  - `profiles()` re-validates every stored profile on each read, so an invalid one is listed with `invalid`
    and is unusable. Conflict is recomputed over the whole set (D-A06-CONFLICT).
  - Profile changes run under ProfileMutex and bump `eligibilityEpoch`. Every wallet transition (create,
    unlock, lock, timeout) bumps `walletEpoch`. Either cancels pending approvals: the dialog is withdrawn
    (`dismiss`) and the request ends 4100 (wallet) or 4901 (profiles). Sessions whose profile was removed,
    changed or invalidated are revoked: frame torn down, port closed.
  - A wallet request captures both epochs and re-checks them after every await (`changed`).
  - `signEligible`: the profile equals the session's frozen copy, no conflict, the session is connected, the
    wallet unlocked, the epochs unchanged, and RP with h ≥ 1 and a successful window.
  - The confirmation shows the unsigned payload `0x02 ‖ RLP(fields)` and its signing hash.
  - After approval, under ProfileMutex: eligibility, then identity (endpoint `eth_chainId` and `pocol_status`
    genesis), then eligibility again. Only then is the key derived; the address must still be the granted
    one; the epochs are re-checked; exactly the shown payload is signed (`signUnsigned` re-derives the hash
    from the bytes); then eth_sendRawTransaction.
  - The identity check also runs every 30 s per session (browser.md); a mismatch revokes the session with
    4901. The same tick enforces the lock timeout.
  - The account grant is bound to the granted address, so a replaced wallet is not covered by an old grant.

### A07 — complete GenesisSpec verification in the extension (`rp.js`)
- Full schema: top-level arity, specVersion, chainId width and value, 52 CP values with widths and bounds,
  allocRoot 32 bytes, M0List as a list of [id20, reward20] members, sorted and unique, sysCodeHash 32
  bytes, canonical RLP, size limit, depth limit. Differential test against the Rust decoder on positive
  fixtures and on every single-field mutation.
- As implemented: `lib/refdec.js` mirrors the accepted Rust decoders (lp1-node `genesis_spec.rs` stage order
  gsStructure → gsVersion → gsCount → gsInt → gsLen → gsRange → gsOrder → gsSys, with the same details;
  `header.rs` for headers). `rp.js` uses them as `decodeSpec` and `decodeHeader`. The Rust verdicts are
  generated by `pocold/tests/decoder_reference.rs` (`REFERENCE_WRITE=1`) into
  `pocol-extension/tests/data/decoder-verdicts.json`. Without that variable the same test checks that the
  committed verdicts still equal the Rust decoders' output. `tests/decoder_diff.mjs` compares
  1151 items (258 accepted): 0 mismatches.

### A08 — RP header structure (`rp.js`)
- Validate all 18 UT fields (types, widths, canonical integers), signature/proposer shapes, nonce, share
  list and winnerSig before any trust result. Differential test against the Rust header decoder on
  mutations of every field.
- As implemented: see A07 (same corpus and reference test; every UT field, the seal, the share list and the
  winner signature are mutated individually).

### A09 — atomic receive reservations (`transport.js`)
- One reservation ticket covers the session budget and the pool budget, taken synchronously in FIFO order,
  released exactly once on every path (success, error, timeout, abort, session teardown).
- As implemented: the session share is checked and taken synchronously before the pool wait; one `release`
  guarded by flags returns the pool and session shares exactly once.

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
- As implemented: `RecordStore.submit` returns `{reply, settled}` (`write` keeps returning the reply), and
  the `storage_set` route releases admission on `settled`.

### A13 — resource derivations (development/audit-2026-10-22/A13-DERIVATION.md)
- As implemented: a container model of the actual snapshot representation (validated against a
  counting allocator), state normalization so containers follow the live state, rolling TrieRebuild,
  enforced side-branch caps, RPC response and log-scan caps, bounded evidence/reject/seen queues, and a
  node bound (snapshots, code, history, side blocks, queues, RPC, threads) checked at `Node::open`
  against the node memory budget. R21 facts use the same model. Open obligations are listed in the
  derivation, not claimed.

### A14 — JSON-RPC response correlation (`transport.js`)
- Require `jsonrpc === "2.0"`, `id` equal to the request id, exactly one of `result` and `error`, and an
  error object `{code: integer, message: string, data?}`.
- As implemented, plus: a non-200 status is a transport failure even if the body is a valid response.

### Dependencies
- Review the OSV results: libsecp256k1 0.5.0 (unmaintained, cryptographic), derivative, paste
  (unmaintained, proc-macro), rand 0.7.3 (conditional unsoundness; RUSTSEC-2026-0097 = GHSA-cq8v-f236-94qc).
  Establish reachability. Replace libsecp256k1 only with vector-verified equivalence (signatures, recovery,
  encodings).
- As implemented (D-DEP-SECP): libsecp256k1 0.5.0 was reachable only through `hashes::recover_address`
  (lp1-node `hashes.rs`, compiled into pocold by `#[path]`). The recovery call now goes through a per-crate
  `secp_backend`:
  - pocold, the node: k256 0.13.4, already locked in pocold and lp4-execution via revm and txsign;
  - lp1-node, the accepted LP3 reference evaluator: its accepted libsecp256k1, unchanged.
- rand 0.7.3 was reachable only through libsecp256k1, so it leaves pocold's lockfile; it stays only in
  lp1-node's, where the advisory's `log` feature is not enabled.
- derivative 2.2.0 and paste 1.0.15 are build-time proc-macros reached through revm/alloy. They stay:
  replacing them needs a revm upgrade, which is out of scope. They are unmaintained notices, not
  vulnerabilities.

## Decisions

### D-A06-CONFLICT — both profiles of a chainId with two genesis hashes are read-only
- Rule (browser.md:20): a chainId repeated with another genesis is read-only, marked conflicting, and gets
  4100 for signing.
- The audited code flagged only the profile added later, once, at add time.
- Alternatives considered:
  - (a) Flag only the later profile. Insertion order would decide which network may sign. The flag would
    also go stale when the other profile is removed.
  - (b) Flag both while both exist (chosen).
- (b) is the conservative reading of "a duplicated chainId" and does not depend on order. Removing either
  profile clears the conflict for the other.
- No consensus or root consequence.
- Test consequence: the real-Chrome e2e kept its `othernet` profile, so it now checks the conflict first
  (4100), removes `othernet` for the wallet path, and re-adds it for the netKey-binding check. No
  assertion was weakened.

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
Correction to the first draft of this plan: R16 uses the profile's own Lmax = max(U, 2·E_win+D+1), not the
network constant 4113. For the devnet (U=40, E_win=16, D=4) R16 needs 64+2·(40+2048) = 4240 ≤ 8192, so the
LP5–LP10 devnet profile did **not** violate R16; REG_RECORDS_MAX stays 8192. It violated the timing rules:
with honest local timing (Δ ≥ 1 s, t_exec ≥ 1 s) the old e2e flags (T_blk=1, D_att=4, Δ_fb_wait=1) fail R3
and R7 (`pocold init-devnet` now prints `-32018 ParamGate rejected [R3, R7]` for them).
Options: (a) P11 timing; (b) a gate-valid single-host profile with φ=0 (exact on one machine: one clock);
(c) exempting simnet from R1–R7 (rejected: it weakens the gate). **Chosen: (b) for single-host suites, (a) for
multi-host use.** Local: Δ=1, φ=Φ=0, t_exec=1, Δ_rel=5, Γ=5 (σ=2, X^W=7). Devnet defaults: T_blk=4, c=2,
Δ_fb_wait=3, D_att=25 (R7: 25+5 ≥ 2(7+8)). The e2e suites use T_blk=1, c=8, D_att=25 (pocold) and T_blk=2,
c=8, D_att=41 (extension): a larger c makes an attempt with one miner offline exhaust its nonce space rarely
(e^{-8·2/3}), and R7 then requires the longer D_att. Earlier LP5–LP10 evidence was produced with a profile
that this gate rejects; it is kept as historical and the suites are re-run on admitted profiles.

### D-A02-FACTS — where each gate fact comes from (no caller-supplied "ok")
The accepted LP3 evaluator (`lp1-node/src/gate.rs`, shared byte-for-byte) decides; `lp4-execution
admission.rs` assembles its facts from the real artifacts and labels them:
- identity (R23, R24a): allocRoot re-derived from the alloc, sysCodeHash of the bundled programs, balances.
- R18 slots/keys/accounts: the P7 derivation `resources::derive`, raised to the system slots measured in the
  constructed genesis; the user context is charged SYS_KEYS_USER_MAX keys and 16 accounts.
- R18 gas: per-call maxima measured by `resources::tests::sys_gas_envelope_fixture` (worst case plus a
  sweep-deletion scenario; the test fails if any measurement exceeds the table), composed into the worst
  call sequence of each phase (ordinary 2E+7 calls; final 2E+7+(D−1) settleFinal). Applicable only inside
  the measured domain S_max ≤ 256, M_max ≤ 256, D ≤ 16, E_max ≤ 4, RET ≤ 128; outside it the facts are
  absent and R18 fails. Monotonicity in those fields is an assumption, kept open under A13.
- R14/R19: a timing record measured for the exact profile (`admission::measure`: blocks applied to a
  scratch copy of the genesis, each with a GAS_LIMIT compute loop, through closing and the final block).
  It is representative, not a worst-case proof (A13).
  - Taken by init-devnet, and again by every node when it loads the devnet (`pocold::load_spec`, used
    by `run` and `status`) on the machine that boots it.
  - The value devnet.json records is informational (review finding: it was read back at boot, so a value
    from another machine or an edited value would pass).
  - A measurement takes well under a second for the devnet profile.
- R21: (K_hist + side) full snapshots at ACCT_CAP·200 + (SLOT_CAP+SYS_SLOT_MAX)·96 bytes (pocold keeps
  full snapshots). At network caps this exceeds HIST_TRIE_BUDGET; single-host simnet nodes are admitted
  only through the gate's own simnet retentionStress exception, which the report states. A node kind
  `Node` never gets it.
- R25d: the devnet's H_cal is recorded as a synthetic fixture (chosen difficulty, not a measured rate);
  target_g is computed from it with the R25d formula.
- R26: the RpcGuard values pocold implements come from its code (`pocold::rpc_facts`); the mechanisms it
  does not implement keep nominal values and are listed in A13-DERIVATION.md §4 (review finding: all of
  R26 used the nominal values).

### D-A02-PROPOSER — when the signed proposer builds (local production, not consensus)
With Φ=0 a template stamped max(L(0), C) while C < L(0) is in the future for every receiver, which then
correctly ignores it, leaving only the proposer mining. The proposer now waits until C+Φ ≥ L(0) before
building. The timestamp formula is unchanged; only the moment of building moves.

### D-A03-CAPS — SLOT_CAP and ACCT_CAP bound the user state
Ambiguity: genesis `check_caps` counted every account and slot, including the five system programs, against
SLOT_CAP/ACCT_CAP, while the spec gives system storage its own bound (SYS_SLOT_MAX, R18) and makes the caps
an exceptional halt (a SYSTEM call cannot halt). Counting system slots would let user transactions fill
the cap and the same block's system phase then invalidate the block. Options: (1) count everything and make
the USER phase reserve headroom for later system writes (couples execution to program internals); (2) the
caps bound the user state (everything outside the five programs) and SYS_SLOT_MAX bounds the programs'
storage, checked after the block. **Chosen: (2)**, the split R21's bound already uses (SLOT_CAP+SYS_SLOT_MAX).
Compatibility: block validity changes only where total slots > SLOT_CAP ≥ user slots, unreachable at devnet
caps; the preserved LP4 test of post-phase-2 cap atomicity now uses SYS_SLOT_MAX, the cap that governs the
storage phase 2 writes.

### D-A03-DIRTY — what DIRTY_BLOCK_MAX and ACCT_DIRTY_BLOCK_MAX count
Per block, the union over USER transactions of the storage keys and accounts whose value changed in the
transaction (net per transaction; an account receiving and paying out the same amount is unchanged). A
transaction whose diff would exceed either set halts. The halt's own nonce/fee effects always apply; if
even they would exceed ACCT_DIRTY_BLOCK_MAX (or create an account beyond ACCT_CAP), the transaction cannot
be included (block invalid; builders skip it, as for TX_CAP).

### D-A03-SYSUSER — the user-context SYS allowance
Counted as storage keys of the five system programs changed by USER transactions (≤ SYS_KEYS_USER_MAX), the
programs whose storage they change (≤ 16), and none while closing (`SysWriteClosing`); each is an exceptional
halt. Escrow balance credits (coinbase tips) and the ChunkFactory nonce are not storage writes. The v1
programs expose no USER-callable storage write, so this is enforced but currently vacuous; R18's user
allowance relies on it.

### D-A13-PROFILE — devnet limits that a full-snapshot node can hold
pocold keeps full state snapshots and its whole history in memory. At network-scale caps the A13 bound
is hundreds of GiB, so a single-host devnet must use smaller, approved limits: the caps/64 values of
validation.md T18b (ACCT_CAP 20000, SLOT_CAP 50000, CODE_CAP 2^21, TXBYTES_CAP 2^24, TX_CAP 20000),
SYS_SLOT_MAX 65536 (≥ the derived 42138), R_max = 0 (the v1 programs implement no registration),
H_END 20000 / H_CLOSE 19000, side_max 8. Bound 4.71 GiB ≤ the 6 GiB node budget; R21 then holds without
the simnet retentionStress exception. Alternatives: keep network caps and raise the budget (rejected:
hundreds of GiB), or exempt the devnet from the memory check (rejected: it is the A13 requirement).

### D-A05-REVIEW — changes after the independent review (local limits, not consensus)
- RPC connection cap: network.md:213 says an excess connection is closed without being read. The first
  repair instead evicted the oldest connection still reading after 1 s (and the plan said "immediate 503").
  A flood could then cut off an honest client that was still uploading. Now: at RPC_CONN_MAX the new
  connection gets 503, unread; idle readers end at the whole-request deadline. A refused client may see a
  reset instead of the 503.
- Batches: network.md:276. The member that makes the delivered bytes exceed BATCH_RESP_MAX (16 MiB), and
  every later member, is answered −32020 {batchBytes} without running.
- Oversized single responses keep −32008 but now carry the request id. The extension's A14 check
  requires the id; with `id: null` this error had become a client-side recvParse.
- P2P outbound: peers_max/handshaking_max bound inbound connections only. Each configured peer has one
  dialer holding at most one connection, so a local process filling the inbound slots cannot stop the
  node from reaching its peers.
- Range sync: `Peer::offer` stops a response at half the requester's queue. The requester now asks the
  best announced peer for the next range when its head has not moved for 1 s, at most once a second.
- Pool: the pending state follows the block caps (SLOT_CAP, ACCT_CAP, SYS_SLOT_MAX) and is normalized
  after every transaction. A transaction that would pass a cap is refused (`-32000 … SlotCap`), because it
  would halt in a block. POOL_MAX_TXS = 4096 bounds the re-execution work at each new head.

### D-A04-UNCOMMITTED — bytes after the committed end are an interrupted append
- Rule: if every committed record verifies, and what follows the committed end is at most one maximal
  record, those bytes were never committed (an append commits before the next begins). They are recovered
  as an interrupted append whatever they contain: the original is kept as `blocks.journal.torn-n`.
- Why: the review found that a crash can persist a later page of an append before its header page. The
  first repair then refused to boot although the commit file proves the bytes were never committed.
- Still failing closed:
  - fewer verified records than committed, or the verified end before the committed end;
  - more than one maximal record of trailing bytes;
  - anything after an extra, uncommitted complete record (that would be a second uncommitted append).
- Commit slots now sit at offsets 0 and 4096 (separate sectors). The first v2 layout (128 bytes, both
  slots adjacent) is read and rewritten in the new layout on open.
- Compatibility: only journals written by this branch use v2, and they open unchanged. v1 handling is
  unchanged.
- Changed test expectation: `a04_zero_filled_tail_is_an_interrupted_append` asserted Corrupt for non-zero
  bytes after the last committed record. It now asserts recovery with the original kept. Two new
  fail-closed cases sit next to it (oversized tail; garbage after an extra record).
- `complete_record_corruption_is_never_skipped` no longer accepts an `Ok` outcome.

### D-BODY-MAX — BODY_MAX bounds the encoded body on every path (consensus alignment)
- consensus.md:56: Body = [txs, evidence] ≤ BODY_MAX.
  - `Body::decode` (blocks from peers and from the journal) checked the encoded length.
  - `Chain::validate` (every import, own blocks included) checked the sum of item bytes.
  - The producer kept 1024 B of margin over the item sum.
- Consequence: a miner could build and import a block of about 350 transactions whose encoding exceeds
  BODY_MAX. Its peers would drop that block at decode, and its own journal replay would fail.
- Change:
  - `validate` checks the encoded length, so a committed oversized body is a block rejection;
  - template selection counts each transaction's RLP header;
  - the signed template drops transactions until the encoded body (evidence included) fits.
- This is a validity change on the local path only. It now matches the spec and the network path, so no
  valid block of the spec becomes invalid.

### D-DEP-SECP — k256 replaces libsecp256k1 in the node; the reference evaluator keeps its accepted set
- Reachability: `recover_address` verifies header proposer signatures and winner signatures. A different
  verdict there would split consensus between versions. So the replacement was accepted only after an
  equivalence check with both libraries linked side by side, behind the unchanged `check_sig_shape` filter
  (r ∈ [1, n), s ∈ [1, n/2], v ∈ {0, 1}).
- Corpus:
  - 50 000 honest signatures;
  - 100 000 arbitrary byte strings through the filter;
  - 1 263 boundary combinations of r, s, v and the message (0, 1, n−1, n, n+1, 2^256−1, p−1, values that
    are not x-coordinates);
  - 200 messages near n;
  - 3 wrong lengths.
- Result: identical verdicts and keys (0 mismatches). RFC 6979 signatures from both libraries were
  byte-identical in all 50 000 cases. Evidence: `evidence/secp-equivalence.md`. The two code paths compared
  are exactly the two `secp_backend` bodies.
- Why lp1-node keeps libsecp256k1:
  - lp1-node declares `rust-version = "1.58"`, and its README requires `cargo build/test --offline` to pass
    on Rust 1.58.1 with the accepted lock (the LP3 S1 Windows workflow uses 1.58.1).
  - The k256 0.13 tree needs Rust ≥ 1.65 (base64ct 1.8.3 needs 1.85). A first attempt that moved lp1-node to
    k256 was reverted for this reason.
  - lp1-node's Cargo.toml and Cargo.lock are byte-identical to the audited snapshot.
- Alternatives not taken:
  - an older k256 for lp1-node: not in the offline registry, and an older line of the same library;
  - a revm upgrade for derivative/paste: broad and consensus-relevant.
- Residual: the unmaintained crate remains in the reference evaluator only. Moving it is a one-function
  change once the LP3 toolchain pin is lifted.
- Compatibility: no root, encoding or verdict change (equivalence above). pocold's lockfile only loses the
  libsecp256k1 tree, including rand 0.7.3; nothing is added.

### D-A04-FORMAT — journal v2
An experimental local storage format, not a protocol change. v1 migrates only when it parses completely;
an ambiguous v1 journal is never auto-repaired.
