# CAPS-SUSTAINABILITY — LOG_CAP, TX_CAP and TXBYTES_CAP over a chain's life

> **Status: PROPOSED — not approved.** Every normative change below exists only in this file. The M1
> reference is not edited. LOG-CAP-AGGREGATE and the other five consensus proposals stay unapproved.
> Only conformance items are implemented (§6): the builder's skip (execution.md:83), template locking
> (consensus.md:136), and the caps-test build constant (validation.md:2065).

This study builds on [LOG-CAP-AGGREGATE.md](LOG-CAP-AGGREGATE.md) and
[LOG-CAP-AGGREGATE-ALTERNATIVES.md](LOG-CAP-AGGREGATE-ALTERNATIVES.md). The alternatives file
recommends A1a for LOG_CAP (2^32 plus gate R27), and its §6 flags TX_CAP and TXBYTES_CAP without
analysing them. This file analyses all three caps together, measures what happens at exhaustion, and
gives one integrated recommendation.

Numbers come from the independent model `model/caps_model.py`. It uses Python's standard library only,
runs with `python3 -I`, and writes deterministic output to `vectors/caps-sustainability.json`. Code
references are to `wf/caps` at the commits named in §6.

## 1. The three caps

| | LOG_CAP | TX_CAP | TXBYTES_CAP |
|---|---|---|---|
| text | execution.md:82: "LOG_CAP=1 GiB: exceptional halt" | execution.md:83: "the block is invalid, and the builder skips the transaction"; consensus.md:170, item 16: "txBytes and txCount within the caps" | the same, plus D49 (FINAL_DESIGN.md:5168): "TXBYTES_CAP on len(rawTx)" |
| kind | protocol constant, **not in CP** | CP field 38 (u64), consensus.md:23 | CP field 37 (u64), consensus.md:23 |
| scope | cumulative per branch: the charged log bytes of the parent's canonical ancestors plus this block (the provisional "chain" reading of LOG-CAP-AGGREGATE) | cumulative per branch: the parent's count plus this block's (code reading, A13-DERIVATION.md:42; storage.md:76–77 budgets receipts and indexes for 10^7 transactions) | cumulative per branch: the parent's bytes plus this block's (storage.md:76 "transactions 8.00 GiB" = 2^33) |
| unit | 36 + 32·topics + \|data\| per log, logs of successful frames only (LOG-ACCT-01 (c), provisional) | 1 per transaction in the body | raw transaction bytes, without the RLP item header |
| response | the transaction halts (status 0, whole gas limit charged, nonce and fee kept) | the block is invalid; the builder skips | the same |
| network | 2^30 | 10^7 | 2^33 |
| devnet (devnet.rs:36–42, not normative) | 2^30 | 20,000 | 2^24 |
| caps/64 (validation.md:2061–2062) | 2^30 | 20,000 | 2^24 |
| caps-test (validation.md:2065) | **2^24** | 20,000 | 2^24 |
| code | `user_phase.rs:24–25` (constant), `:197` (check), `:217` (halt); `chain.rs:344` (`cum_log_bytes`) | `chain.rs:335` → `Chain::within_caps` `:351`; `apply.rs:250` checks only one block's count against TX_CAP (labelled "TX_MAX") | `chain.rs:335`, `:351` |

The spec never says "cumulative" in so many words. That reading follows from three things: the
inventory, the fact that the caps-test build makes LOG_CAP reachable, and the vacuity of a per-block
reading (LOG_BLOCK_MAX ≤ 32 KiB < LOG_CAP; BODY_MAX < TXBYTES_CAP).

The counters are per branch because each one is derived from the parent block (`Entry.cum_*`, set in
`validate`).

## 2. Reachability before H_END

**Per-block maxima.** All four profiles share GAS_LIMIT = 8M, BODY_MAX = 196,608, TX_MAX = 131,072 and
LOG_BLOCK_MAX = 32 KiB.

| quantity | per block | how it is reached | gas |
|---|---:|---|---:|
| transactions | 380 = ⌊8,000,000 / 21,000⌋ | gas binds; bytes would allow 1,927 of the 100-byte minimal EIP-155 transfer | 7,980,000 (190 at the 4M target: 3,990,000) |
| raw tx bytes | 196,592 = 131,072 + 65,520 | two transactions whose encoded body is exactly BODY_MAX | 827,528 (zero calldata, 4 gas/byte); nonzero bytes still stay under 4M |
| charged log bytes | 32,768 | one LOG0 of 32,732 zero bytes (36 + 32,732) | 288,349 |

**Base-fee rule.** London (execution.md:97). With t = GAS_LIMIT/2 = 4M:
- above the target: b' = b + max(1, ⌊b·(u−t)/t/8⌋);
- below it: b' = b − ⌊b·(t−u)/t/8⌋.

The base fee is burned (economics.md:66, incentives.md:68).

At u ≤ t it never rises, and it falls to its floor: below 8 wei for empty blocks, and below 8t/(t−u) in
general. Filling TXBYTES_CAP or LOG_CAP needs 21% and 7% of the target, so the attacker pays the idle
base fee.

Filling TX_CAP faster than the target needs blocks above it, and those compound the base fee by about
×1.124 per full block. Starting from 7 wei, after 212 full blocks a single block costs one block subsidy
(2·10^18 wei, governance.md:9). The sustainable rate is therefore the target, about 190 transactions per
block.

Priority fees are not specified. The model assumes 0, because pocold's pool is FIFO and a proposer may
include its own transactions. Costs are the burned base fee, simulated exactly in integers. The
starting base fee is either the idle 7 wei or baseFee0 = 10^9. 1 coin = 10^18 wei.

| profile | cap | fastest (blocks, time) | at the 4M target | before H_END | organic: per-block average that exhausts it exactly at H_END | attack cost from 7 wei / from 1 gwei |
|---|---|---|---|---|---|---|
| network (T_blk 60 s, H_END 129,600) | TX_CAP 10^7 | 26,316 (18.3 d), unsustainable | 52,632 (36.6 d) | **yes** | 77.2 tx (20.3% of max; 1.29 tx/s) | 1.47·10^12 wei / 12.8 coins |
| | TXBYTES_CAP 2^33 | 43,695 (30.3 d) | same | **yes** | 66,280 B (33.7%) | 2.5·10^11 wei / 0.0083 coins |
| | LOG_CAP 2^30 | 32,768 (22.8 d) | same | **yes** | 8,285 B (25.3%) | 6.6·10^10 wei / 0.0025 coins |
| devnet (4 s, 20,000) | TX_CAP 20,000 | 53 (212 s) | 106 (424 s) | **yes** | 1.0 tx (0.26%) | 3.0·10^9 wei / 0.42 coins |
| | TXBYTES_CAP 2^24 | 86 (344 s) | same | **yes** | 839 B (0.43%) | 5.0·10^8 wei / 0.0083 coins |
| | LOG_CAP 2^30 | 32,768 > H_END | — | no | 53,687 B > the 32,768 maximum | — |
| caps/64 (10 s, 4,000) | TX_CAP | 53 (530 s) | 106 (1,060 s) | **yes** | 5.0 tx (1.3%) | as devnet |
| | TXBYTES_CAP | 86 (860 s) | same | **yes** | 4,194 B (2.1%) | as devnet |
| | LOG_CAP 2^30 | 32,768 > H_END | — | no | — | — |
| caps-test (10 s, 4,000) | LOG_CAP 2^24 | 512 (5,120 s) | same | **yes** | 4,194 B (12.8%) | 1.0·10^9 wei / 0.0025 coins |

**Reading.**
- On the network profile, each cap is exhausted organically before H_END by a sustained average of
  1.29 transactions per second, 66 KB of transactions per block, or 8.3 KB of logs per block.
- An attacker exhausts each within 23–37 days. The cost is under 10^-5 coins at the idle base fee, and
  at most 12.8 coins (6.4 block subsidies) if the base fee starts at 1 gwei.
- On the devnet and caps/64, the TX caps fall to 53 and 86 blocks of full load.

**Correction to LOG-CAP-AGGREGATE-ALTERNATIVES.md §6.**
- TXBYTES_CAP needs at least **43,695** blocks, not 43,691. A block carries at most 196,592 raw bytes,
  not BODY_MAX.
- At 190 transactions per block (3.99M gas, just under the target) the base fee falls slowly
  (×(1 − 1/3,200)); it is not flat.

## 3. Effects at exhaustion

### 3a. TX_CAP or TXBYTES_CAP reached on a branch

This section covers a branch whose remaining room fits no pooled transaction.

| subject | spec-intended | code before `9094f98` | code now |
|---|---|---|---|
| user transactions of every kind (transfers, contract calls and creations, the registry's register / deregister / claimBond) | none can be included on this branch (item 16) | same validity | same |
| builder (`template_txs`) | skips the transaction (execution.md:83) | the template carried every pooled transaction (see the two rows below) | skips what passes the room, with that sender's later transactions; signed empty blocks at the normal pace |
| …past TXBYTES_CAP | — | own block invalid ("16 caps"); every height waited U(0)+Γ for a fallback (devnet 74–78 s per block, measured; network about 330 s = D_att 300 + Γ 30) | — |
| …more pooled transactions than TX_CAP | — | `apply_block` refused the block (`Budget("TX_MAX")`, apply.rs:250); the builder emptied it; **nothing was ever included, although room existed** | — |
| received signed templates | a violating template counts as absent, then sticky FB at T_j (consensus.md:136) | locked and mined, wasting attempt 0 | not locked (`node.rs:557`) |
| validation, sync, journal replay | item 16 against the parent's counters | same | same, with one definition (`Chain::within_caps`) |
| system phases, rewards, settlement | not transactions, so unaffected | continue; pots are the subsidy (no tips) | same |
| funds | — | reward balances, and the bonds refunded at closing (`markClose`), can no longer be spent on this chain | same |
| mempool | not specified: network.md:149–153 lists −32014, −32015, and −32016 for "full" and "after F" | accepts; transactions that can never be included stay until POOL_MAX (4,096 or 32 MiB), then −32016 "pool full" | same; proposal N5 |
| RPC | — | eth_sendRawTransaction returns a hash whose receipt stays null; `pocol_getCaps` (network.md:333) answers −32601 | same; proposal N6 |
| reorg at the boundary | the counters follow the branch | adoption by work alone (D133); detached transactions return to the pool (A11) and are includable on a branch with room | tested |

### 3b. LOG_CAP reached

This section covers the case where the remaining room is smaller than a transaction's charge.

| subject | spec | code |
|---|---|---|
| a transaction whose logs (successful frames) would pass the room | exceptional halt | `Halt::LogCap`: status 0, no logs, gas limit charged, nonce + 1, fee = gas limit × price, tip to Escrow, all other state reverted |
| ERC-20/721 transfers, approvals, mints (they emit events) | halt | halt: tokens are frozen |
| plain transfers, calls that emit nothing, registry operations | unaffected | unaffected (tested) |
| contract creation | the same rule: a CREATE halts if and only if its constructor's logs pass the room | tested: a CREATE without logs deploys; one whose constructor logs creates nothing, is charged its gas limit, and consumes the creator's nonce (so that address is never used) |
| logs of a reverted sub-call | not charged (LOG-ACCT-01) | not counted |
| partial room | the first transaction that would pass it halts; a later, smaller one may fit | as specified (LOG-CAP-AGGREGATE G1/G2) |
| system phases and programs | — | a system call cannot log: the v1 programs have no LOG opcode (model scan), and any system log is `ApplyError::Logs` (apply.rs:217). They neither count nor halt |
| rewards, settlement | unaffected | unaffected; halted transactions still pay tip × gas limit into the pot |
| builder | halts are valid blocks | includes them (tested through the node) |
| mempool | no rule | accepts. The pending state runs without the A03 meter, so the pool believes the transaction succeeds |
| RPC | — | eth_call and eth_estimateGas simulate without the meter (rpc.rs:439). They report success for a transaction that will halt and cost its whole gas limit (proposal N7) |
| reorg | per branch | `Entry.cum_log_bytes` comes from the parent (chain.rs:344) |

## 4. Identity: genesisHash, and why "unchanged" is not "compatible"

genesisHash = keccak256(GenesisSpec), where GenesisSpec = RLP([specVersion, chainId, CP, allocRoot,
M_0List, sysCodeHash]). ForkSchedule is not included (consensus.md:7, :11). Results from the model,
replayed by `lp4-execution/tests/caps_identity.rs`:

| item | result |
|---|---|
| Keccak-256 | K1–K3 (validation.md:60–62), "", "abc" and a 43-byte vector; the permutation matches hashlib SHA3-256 at every length 0–700 (five rate blocks) |
| GSV1 | rebuilt from the validation.md:65–72 segments and, separately, from its field values: 341 bytes, CP 179, M_0List 88, payload 338; SHA-256 = the E05 inputSha256 |
| H_GSV1 | `de518e30…eb2277`, the E05 three-library record (it is not in the spec text itself) |
| GSV1, TX_CAP + 1 / TXBYTES_CAP + 1 | `bf9aeabe…56aa39` / `90e4a907…c25c8c` (both change) |
| devnet (777900, g_ts 1,700,000,000, miners a, b, c; 375 bytes from the Rust builder) | `4db6aa5c…d8e638`, identical in the release build (LOG_CAP 2^30) and the caps-test build (2^24) |
| devnet, CP-only TX_CAP + 1 / TXBYTES_CAP + 1 | `979fda9c…e75eed` / `52cbbb44…c0fc58`. A rebuilt genesis also changes allocRoot, because ChainCaps (C0C004) stores all 52 CP values at slots 0..51 (genesis_builder.rs:62) |
| schemas | the 6 GenesisSpec fields and 52 CP names of consensus.md:7, :19–25 equal the Rust table; LOG_CAP and LOG_BLOCK_MAX are in neither. Every one of the 52 fields round-trips and enters the hash; a 53rd CP item is `gsCount` |
| other inputs | sysCodeHash recomputed from `tests/data/system-v1.json` (`4f8712dd…`), with no LOG opcode in any program; ForkSchedule is not hashed; LOG_CAP enters neither CP nor allocRoot |

**"genesisHash unchanged" does not mean "compatible".**

Two nodes with different LOG_CAP share genesisHash, netKey and the handshake. pocold's Hello carries
chainId, genesisHash, head, height and work, but no protocolVersion, although network.md:7's Status
includes it. They agree block for block until the branch's charged log bytes cross the smaller cap.

From that block on, a logging transaction gets status 1 on one node and a halt on the other. Its
receipts, gasUsed, logsBloom and stateRoot differ, so each node rejects the other's blocks at item 17:
a silent chain split.

Only a ForkSchedule entry makes the change detectable, through protocolVersion in the header (item 1b
netVersion) and in Status. The code supports v1 only (`ForkSchedule::new`), and the extension's light
client accepts version 1 only (rp.js:40).

A TX_CAP or TXBYTES_CAP change is a CP change, and so a different chain:
- a new genesisHash and netKey;
- `store::open` refuses the old data directory, whose journal is bound to genesisHash;
- networks.json must change.

## 5. Options

All five options keep the conformance of §6.

| | consensus | storage at the caps | resident memory (pocold) | compatibility | liveness and griefing | complexity |
|---|---|---|---|---|---|---|
| **O1** keep the caps, freeze as specified (status quo + §6) | none | inventory 19.65 GiB logical (storage.md:73); pocold journal ≈ TXBYTES_CAP + 4 B per tx + 3.3 KB per block (network 8.4 GiB; receipts and logs are not stored, replay recomputes them) | history term TXBYTES_CAP + 380·TX_CAP + LOG_CAP·33/32 (resources.rs:103–107): devnet 1,079 MiB; network 12.6 GiB (already refused by the 6 GiB A13 gate) | none | the chain continues, but user activity is frozen permanently; network: organically at 20–34% average use, by griefing for ≤ 12.8 coins | done |
| **O2** unreachable by construction (A1a extended to all three) | gate R27: H_END·LOG_BLOCK_MAX ≤ LOG_CAP; R28: H_END·⌊GAS_LIMIT/21000⌋ ≤ TX_CAP; R29: H_END·TXB_BLOCK ≤ TXBYTES_CAP, where TXB_BLOCK is the largest raw-byte sum of a body ≤ BODY_MAX (196,592). Only exception: the simnet caps-test build. TX caps are CP, so a new genesisHash; LOG_CAP is a constant (same hash; a hard fork via ForkSchedule on any existing chain, but none holds > 1 GiB of logs) | network at LOG_CAP 2^32, TX_CAP 5·10^7, TXBYTES_CAP 24 GiB: inventory ≈ 43.2 GiB logical (txs 8.0 → 24.0, receipts 0.50 → 2.5, indexes 0.63 → 3.15, logs 1.0 → 4.0; 42.8 at the exact R27–R29 minima), ≈ 65 GiB on disk at the spec's 1.5× ratio | network term 45.8 GiB; devnet at R28/R29 sizes ≈ 7.0 GiB (7,148 MiB with the min(LOG_CAP, H_END·LOG_BLOCK_MAX) tightening), so the 6 GiB A13 gate refuses boot (model headroom today: 9,457,060 B). **Needs canonical history off-heap first** (bodies and receipts read from the journal beyond K_hist, as D-REORG-REDB did for side blocks: a local storage decision). Also, eth_getTransactionByHash scans the canonical chain linearly (rpc.rs:455), and `Node::open` holds the whole journal (A13 condition open-replay-transient) | GSV1 unchanged (a frozen vector; gate rules are not decode rules); devnet genesis files regenerated; networks.json gets the new network genesisHash; no RPC change | no cumulative freeze; only the per-block limits remain | low: three values, three gate predicates, the inventory re-derived |
| **O3** linear allowance: cum_X(block h) ≤ ⌊h·CAP_X/H_END⌋ + BURST_X for txs, tx bytes and log bytes (a log halt, a tx block invalid) | a new validity/halt rule, a protocol change; BURST is new CP or derived | lifetime ≤ CAP + BURST: inventory unchanged | unchanged | new vectors at the h boundaries; pocol_getCaps should expose the allowance | never permanent. Throughput is capped at the lifetime average plus the burst: network 77 tx, 66 KB, 8.3 KB of logs per block. A griefer can take each block's allowance; the base fee does not price it below the target, so honest users must outbid on tips | moderate |
| **O4** sliding window (A2 generalized) | as O3 | ≤ ⌈H_END/W⌉·cap | unchanged | as O3 | a stall of up to W minus the fill time per saturation | moderate |
| **O5** remove the caps from validity (A4 generalized) | for TX caps a CP schema change (version 2, 50 fields: GSV1, refdec.js and every vector change) | as O2 | as O2 | heavy | as O2 | high for the schema |

**Integrated recommendation** (the owner decides):
1. **Keep the §6 conformance in every case.** It removes the stall and the starvation, and makes the
   spec's "freeze the component, not the chain" (validation.md:2129) what the code does.
2. **Network profile: O2 for all three caps**, under one principle: "no cumulative cap may be reachable
   before H_END". This means R27–R29 and LOG_CAP = 2^32, TX_CAP = 5·10^7, TXBYTES_CAP = 24·2^30.
   - The LOG_CAP part is exactly A1a.
   - It adds no consensus mechanism, keeps the halts and invalidity as defence in depth, and keeps T18b
     reachable through the caps-test exception.
   - The price is about +23 GiB of logical storage. The network genesisHash changes, but no network chain
     exists: devnet.rs refuses 777001.
3. **If the 19.65 GiB inventory is a hard requirement: O3 for all three.** It is one mechanism, and it is
   preferred over O4 because it has no window-edge stall. It turns the cliff into a griefable rate
   limit.
4. **Devnet: keep the approved D-A13-PROFILE caps.** With §6, exhaustion at 53 blocks (TX_CAP) or 86
   blocks (TXBYTES_CAP) of full load is the declared freeze, not a stall. Resize only after a local
   canonical-history offload, because O2 sizes break the A13 bound.

## 5a. Normative proposals (PROPOSED, not approved)

| id | proposal | text touched |
|---|---|---|
| N1 | R27 + LOG_CAP = 2^32 (= A1a; already proposed) | execution.md:82, governance.md (gate), validation.md:2065, storage.md:73/77 |
| N2 | R28: H_END·⌊GAS_LIMIT/21000⌋ ≤ TX_CAP; network TX_CAP = 5·10^7 | governance.md:13 (CP), gate, storage.md:76–77 |
| N3 | R29: H_END·TXB_BLOCK(BODY_MAX, TX_MAX) ≤ TXBYTES_CAP; network TXBYTES_CAP = 24·2^30 | governance.md:13 (CP), gate, storage.md:76 |
| N4 | the alternative to N1–N3: the O3 linear allowance | execution.md:82–83, consensus.md:170 |
| N5 | pool: −32016 {cap} for a transaction the head branch can never include; such transactions leave the pool (re-checked after a reorg) | network.md:149–153 |
| N6 | pocol_getCaps → {txCount, txBytes, logBytes, txCap, txBytesCap, logCap} of the head branch, plus an alert for governance.md:197's "freeze and alert" | network.md:333, governance.md:197 |
| N7 | eth_call and eth_estimateGas report an A03 halt (or apply the meter) instead of success | execution.md:101–102 |
| N8 | state the scope explicitly: "the counts of the branch up to the parent plus this block" (item 16; LOG-CAP-AGGREGATE for logs) | consensus.md:170 |

## 6. What is implemented (conformance), and the evidence

| change | spec | commit | evidence (development/audit-2026-10-22/evidence/caps/) |
|---|---|---|---|
| `Chain::within_caps` and `caps_room`: the one definition of item 16; validate calls it (same arithmetic, checked, so an overflow cannot wrap) | consensus.md:170, D49 | bdb14bb | `unfixed-bdb14bb.log`; the full suites in `suites-release-a0dd771.log` |
| `Node::template_txs` skips past the room (and the sender's later transactions) | execution.md:83 | 9094f98 | fails without it: `unfixed-bdb14bb.log` (6/6), `unfixed-final-tests-reverted-builder.log` (the final tests on the unfixed builder, 6/6), `unfixed-ddf023a-live-trace.log` (the stall traced); passes: `caps-tests-a0dd771.log` |
| `try_lock_signed` treats an over-cap template as absent | consensus.md:136 | 9094f98 | `a_received_template_past_the_caps_is_treated_as_absent` in the same logs |
| cargo feature caps-test: LOG_CAP = 2^24; admission refuses anything but a simnet profile on a simnet node | validation.md:2065 | a797c83, a0dd771 | `caps-test-build-a0dd771.log`; both suites in that build: `suites-caps-test-a0dd771.log` |
| model, vectors, identity test | — | bc53984 | `caps-model-a0dd771.log`, `caps-tests-a0dd771.log` |

Suites at a0dd771, which carries the final code (later commits add documents only):

| build | lp4-execution | pocold |
|---|---|---|
| release | 165 pass, 0 fail | 129 pass, 0 fail, 2 ignored (the spec-depth tests, not run) |
| caps-test | 165 pass | 131 pass, 2 ignored |

No compiler warnings. These runs do not establish full acceptance. The network-profile figures come from
arithmetic and the model; no network-profile chain was run.

Not implemented, and why:
- **HIST_TRIE_BUDGET = 64 MiB** of the same caps-test line: pocold has no historical trie and no K_eff
  (T18b L12/L13), so the value would only alter R21's admission arithmetic.
- **The pool rule:** the spec states none (N5).
- **protocolVersion in pocold's Hello** (network.md:7): an open conformance gap of the wire format,
  outside this track.
- **Punishing the peer** that sent a violating template (consensus.md:136): pocold has no peer scoring
  for templates.
