# VA-spec v1 — PoCol peer validation and synchronization (local devnet)

Status: specification for LP6 written before/with the peer code in
`prototypes/pocold/src/net.rs` and `node.rs`; reviewed against consensus.md
§4, §8 (envelope classes D129–D140), §9 (D133) and §10 (D118). Local devnet
transport only (loopback); it is not a production P2P design.

## 1. Transport and framing
- TCP, loopback addresses only (inbound non-loopback peers are dropped).
- Frame = `u32 BE length || RLP([type, ...fields])`, `1 <= length <= 8 MiB`.
- Decoding is strict: canonical RLP, exact arity, minimal integers, fixed
  32-byte hashes, 8-byte nonces; re-encoding must equal the received bytes.
- Any malformed frame closes the connection. Malformed input never reaches
  block state, is never stored and never marks a block invalid.

| type | message | fields |
|---|---|---|
| 0 | Hello | chainId, genesisHash, headHash, headHeight, nodeName |
| 1 | Block | headerBytes, bodyBytes |
| 2 | Template | signed-template shell (header encoding with nonce 0), body |
| 3 | Share | TemplateID, nonce (8 bytes) |
| 4 | GetBlock | blockHash |
| 5 | GetRange | startHeight, count (<= 512) |
| 6 | Tx | raw signed envelope |

## 2. Network identity
`Hello.chainId` and `Hello.genesisHash` must equal cfg; otherwise the peer is
closed (wrong network). activeVersion is checked per header (H-pre 1b).

## 3. Block import pipeline (H-pre, H-full, envelope classes)
1. Decode header (strict, <= 3067 B) and body (<= BODY_MAX, canonical).
2. Duplicate blockHash → ignored. Known-invalid blockHash or invalid parent →
   blockReject (ancestorInvalid).
3. Unknown parent → orphan pool (<= 16 per parent) and `GetBlock(parent)` to
   the sender; orphans are retried when the parent imports.
4. Future (ts > C+Φ) → future queue (<= 64), retried on every tick.
5. Parent state outside the K_hist window → TrieRebuild (re-execution with
   root checks), then retry.
6. H-pre 1–9 and H-full 10–17 (chain.rs). Failures depending only on `sig`
   or `winnerSig` bytes are **envReject**: this copy is dropped, the blockHash
   stays acceptable from another copy and is not recorded as invalid.
   Every other failure is **blockReject**: the blockHash is recorded invalid
   and so are its descendants (ancestorInvalid).
7. Accepted block → fsynced journal record → in-memory insert → D133 head
   update → relay to all peers except the sender.

## 4. Synchronization
- On connect each side sends Hello. If the peer's head is unknown and higher,
  request `GetRange(ourHeight+1, min(diff,512))` and `GetBlock(peerHead)`.
- `GetRange` answers canonical blocks in height order and stops at the first
  missing height. `GetBlock` answers any stored block except genesis.
- Forks: blocks whose parents are unknown recurse through `GetBlock(parent)`
  until a known ancestor; the heavier branch then wins by D133.

## 5. Templates and shares (consensus §4)
- Template: accepted only for the current parent at a=0 while in WAIT; checks
  signature, proposer = Draw(h,0), window, Φ, and that the UT equals the
  template rebuilt from apply(parent, body) (1b independence). Otherwise held
  (<= 64) for a parent not yet imported.
- Share: accepted only for the locked TemplateID, `nonce < nMax`,
  `SHA256(TemplateID||be64(n)) <= T_share`; ownership follows from the range.
- Shares and templates never change validity rules; they only feed the
  honest builder (shareList) and the proposer flow.

## 6. Bounds (local service policy)
Frame 8 MiB; orphans 16/parent; future 64; held templates 64; GetRange 512;
rejects log 256; pool 64 MiB raw; RPC body 1 MiB, batch <= 20; side-block
retention via K_hist state window (full headers/bodies retained).

## 7. Verified scenarios
`prototypes/pocold/tests/e2e_devnet.py`: 3 processes, >= 100 H-full blocks,
late join, partition/heavier branch/heal, SIGKILL crash/restart, garbage
frames, wrong-network Hello, invalid block over P2P, RPC transactions,
identical hash/stateRoot/receiptsRoot at every height, deterministic replay.
