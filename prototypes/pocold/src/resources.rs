//! A13: conservative resident-memory bound of a pocold node for an admitted profile and its
//! local limits, derived from the actual representation and the enforced caps. Every term
//! names the code that enforces its assumption; arithmetic is checked (an overflow is a
//! rejection, never a wrap). `Node::open` refuses to boot when the bound exceeds the
//! node's memory budget. Derivation and open obligations: development/audit-2026-10-22/
//! A13-DERIVATION.md.
use std::mem::size_of;
use pocol_lp4_execution::{profile::ConsensusParams,resources::memory,user_phase::caps};
use crate::{chain::{self,Entry},header::Header,net,node::{self,Limits},types::{Block,Body}};

/// Snapshots alive besides the retained ones: apply_block's working copy, the USER phase
/// copy, the per-transaction engine database and the PAY pre-transaction copy, production
/// clones of the parent (begin_attempt, lock), the pool's pending state and its execution
/// copies, and the rolling rebuild (two). Counted generously: 10.
pub const TRANSIENT_SNAPSHOTS:u128=10;
/// glibc keeps up to 40 MiB of exited threads' stacks for reuse (the nptl stack cache);
/// counted on every platform.
pub const STACK_CACHE:u128=40<<20;
/// Heap of one thread outside its stack (std's Thread, its packet and name).
pub const THREAD_HEAP:u128=4096;
/// The main thread only collects the arguments, spawns the consensus thread and joins it
/// (main.rs). Its stack is reserved by the platform (RLIMIT_STACK, the PE header), not by
/// pocold, so it is counted at 1 MiB by that code structure (A13-DERIVATION §4, residual).
pub const MAIN_STACK_RESIDENT:u128=1<<20;
/// EVM executions alive at once: blocks, pool re-execution, eth_call/eth_estimateGas and the
/// admission timing all run on the consensus thread, one at a time.
pub const EXECUTIONS:u128=1;
const _:()=assert!(crate::rpc::CALL_GAS_MAX<=pocol_lp4_execution::apply::PER_CALL_GAS,"eth_call gas exceeds the execution model");
/// Threads alive at once, every one created by `threads::spawn` with its reservation: per
/// inbound peer a reader and a writer (`net::spawn_peer`: the reader joins the writer and
/// releases the slot as its last action); per configured peer a dialer, an event forwarder,
/// a reader and a writer; conn_max RPC connection threads; the miner (joined before it is
/// replaced), the miner and listener forwarders, the timer, the P2P listener and the RPC
/// acceptor (6). Plus the consensus and main threads. Exiting threads are counted: the RPC
/// acceptor, the P2P listener and each dialer join a finished thread before its place is used
/// again (threads::reap), and a reader joins its writer.
pub fn io_threads(peers_max:usize,dials:usize,conn_max:usize)->Option<u128>{add(&[mul(2,peers_max as u128)?,mul(4,dials as u128)?,conn_max as u128,6])}
/// Smallest valid transaction encoding (a signed legacy transfer exceeds it).
pub const MIN_TX_BYTES:u128=85;
/// Intrinsic gas of every transaction. A block's transactions reserve their gas limits against
/// GAS_LIMIT and use at least this each (user_phase: the reservation check and `used <= limit`), so a
/// valid block holds at most GAS_LIMIT / TX_GAS_MIN transactions.
pub const TX_GAS_MIN:u128=21_000;
/// Receipt encoding without logs: status, cumulative gas, a 256-byte bloom, list headers.
pub const RECEIPT_BASE:u128=300;
/// Longest stored rejection reason (chain::REASON_MAX) and status rejects kept (node).
pub const REASON_MAX:u128=chain::REASON_MAX as u128;

/// Largest encoded header for S_max shares: fixed fields <= 768 bytes, 9 per share nonce.
pub fn header_max(s_max:u16)->u128{768+9*u128::from(s_max)}

/// What the bound does not establish (A13-DERIVATION §4). The total is the sum of requested
/// heap bytes and reserved stacks under these conditions, not an unconditional bound on the
/// resident memory of the process.
pub const CONDITIONS:&[(&str,&str)]=&[
    ("allocator-overhead","allocator per-allocation overhead and fragmentation are not modelled"),
    ("transient-snapshot-inventory","TRANSIENT_SNAPSHOTS (10) and EXECUTIONS (1) are inventories by code inspection, not enforced by a counter"),
    ("main-thread","the main thread's stack is reserved by the platform; counted at 1 MiB because it only spawns and joins"),
    ("revm-representation","the execution term relies on revm 19.7 behaviour checked by source inspection (iterative frames, SharedMemory truncation, fixed stack capacity) and by measured adversarial peaks"),
    ("cpu-and-timing","CPU costs (world-root rebuild, chain scans, pool re-execution, deep-fork rebuild) are not memory terms; worst-case timing is not bounded"),
    ("open-replay-transient","Node::open holds the whole journal's payloads (store::open, pre-existing) and a replay index of two entries per record while replaying; this open-time transient grows with the journal and is not part of the steady-state bound"),
];
/// The model total and its parts. `items` itemizes every group term ("group/item", bytes); the
/// group fields are the sums of their items and `total` is the sum of all items.
#[derive(Clone,Debug,PartialEq,Eq)]
pub struct Bound{
    pub snapshots:u128,pub snapshot_bytes:u128,pub code:u128,pub history:u128,pub side_blocks:u128,
    pub queues:u128,pub rpc:u128,pub threads:u128,pub execution:u128,pub total:u128,
    pub items:Vec<(&'static str,u128)>,
}
fn add(v:&[u128])->Option<u128>{v.iter().try_fold(0u128,|a,b|a.checked_add(*b))}
fn mul(a:u128,b:u128)->Option<u128>{a.checked_mul(b)}

/// The bound, or None on arithmetic overflow.
pub fn derive(cp:&ConsensusParams,k_hist:u32,side_max:u32,limits:&Limits,dials:usize)->Option<Bound>{
    let s=u128::from(cp.S_max);let m=u128::from(cp.M_max);let hdr=header_max(cp.S_max);
    // Snapshot: accounts <= ACCT_CAP user accounts (genesis check_caps, USER halts AcctCap)
    // + 5 programs; slots <= SLOT_CAP (USER halts SlotCap) + SYS_SLOT_MAX (post-block check);
    // code entries <= accounts + 2 defaults; containers normalized after every commit.
    let accounts=u128::from(cp.ACCT_CAP).checked_add(5)?;let slots=u128::from(cp.SLOT_CAP).checked_add(u128::from(cp.SYS_SLOT_MAX))?;
    let snapshot_bytes=memory::snapshot(accounts,slots,accounts.checked_add(2)?)?;
    let snapshots=add(&[1,u128::from(k_hist),u128::from(side_max),TRANSIENT_SNAPSHOTS])?;
    // Code: CODE_CAP logical bytes per snapshot (code_caps), with analysis, unshared at worst.
    let code_per=memory::code_bytes(u128::from(cp.CODE_CAP),accounts)?;let code=mul(snapshots,code_per)?;
    let (retained,side_states)=(1+u128::from(k_hist),u128::from(side_max));
    let mut items=vec![("snapshots/head and K_hist retained states",mul(retained,snapshot_bytes)?),("snapshots/side_max side-branch states",mul(side_states,snapshot_bytes)?),
        ("snapshots/transient working copies",mul(TRANSIENT_SNAPSHOTS,snapshot_bytes)?),
        // A table that grows in a working copy keeps its old allocation until the new one is filled:
        // one table at a time (single consensus thread), at most a whole snapshot's tables.
        ("snapshots/table growth in a working copy",snapshot_bytes),
        ("code/head and K_hist retained states",mul(retained,code_per)?),("code/side_max side-branch states",mul(side_states,code_per)?),("code/transient working copies",mul(TRANSIENT_SNAPSHOTS,code_per)?)];
    // Per block kept in memory: the map slot (Entry inline), the canonical index, header heap
    // (encoded, ut_raw, bloom, proposer, sig, share nonces), ParentResult shares, nonce ranges
    // (members <= M_max), an empty pruned state and evidence (E_max items <= EVID_BYTES_MAX).
    let entry=size_of::<([u8;32],Entry)>() as u128;
    let per_block=add(&[mul(entry+1,3)?,64,mul(hdr,2)?,256+20+65+64,mul(8,s)?,mul(32,s+1)?,mul(64,m)?,
        memory::empty_snapshot()?,mul(u128::from(cp.E_max),24)?])?;
    // Evidence: valid evidence tombstones its identity, and evidence against a tombstone is
    // a host error (block invalid), so the chain holds at most one item per identity ever:
    // M_max initial records plus R_max registrations per block (D86 registry rotation).
    let identities=u128::from(cp.M_max).checked_add(mul(u128::from(cp.R_max),u128::from(cp.H_END))?)?;
    let evidence=mul(identities,u128::from(cp.EVID_BYTES_MAX)+24)?;
    // Canonical chain: <= H_END+1 blocks; transactions <= TX_CAP and their bytes <= TXBYTES_CAP
    // (chain cumulative, block invalid beyond); logs <= LOG_CAP charged bytes (USER halts),
    // encoded at most 33/32 of their charge; receipts and hashes per transaction.
    let hist=[("history/blocks (H_END+1)",mul(u128::from(cp.H_END)+1,per_block)?),("history/transaction bytes (TXBYTES_CAP)",u128::from(cp.TXBYTES_CAP)),
        ("history/transaction index and receipts (TX_CAP)",mul(u128::from(cp.TX_CAP),24+24+32+RECEIPT_BASE)?),("history/logs (LOG_CAP)",u128::from(caps::LOG_CAP)/32*33),("history/evidence",evidence)];
    let history=add(&hist.map(|x|x.1))?;items.extend(hist);
    // Side blocks (D-REORG-REDB): every journaled non-canonical block is offloaded to metadata at the
    // retain() that follows its import (Chain::retain): its encoded header and body (evidence included),
    // receipts and tx hashes are dropped, so an entry is the per-block term less one header and the
    // evidence, plus its protect-set slot. Live: <= side_cap unprotected + protect_max (2·r_keep) held
    // by a sync session. Replay: all <= side_cap + protect_max (Chain::replaying). One full block is
    // resident between its insert and that retain (or while restore_canonical re-executes it): its
    // transactions are bounded by its body and by its gas.
    let side_txs=(u128::from(cp.BODY_MAX)/MIN_TX_BYTES).min(u128::from(cp.GAS_LIMIT)/TX_GAS_MIN);
    let side_block=add(&[per_block,mul(u128::from(cp.E_max),u128::from(cp.EVID_BYTES_MAX))?,u128::from(cp.BODY_MAX),mul(side_txs,24+24+32+RECEIPT_BASE)?,u128::from(caps::LOG_BLOCK_MAX)/32*33])?;
    let side_entries=add(&[limits.side_cap as u128,mul(2,u128::from(limits.r_keep))?])?;
    let side_entry=per_block.checked_sub(hdr)?.checked_sub(mul(u128::from(cp.E_max),24)?)?.checked_add(32+16)?;
    let side_meta=mul(side_entries,side_entry)?;let side_full=side_block;
    let evicted=mul(chain::EVICTED_MAX as u128,2*(32+16))?;
    let side_blocks=add(&[side_meta,side_full,evicted])?;
    items.extend([("side/offloaded side-block metadata (side_cap + 2·r_keep entries)",side_meta),("side/one full block before offload or during restore",side_full),("side/evicted-hash FIFO (EVICTED_MAX)",evicted)]);
    // Queues and caches (node.rs, net.rs constants).
    let frame=net::MAX_FRAME as u128;let block=size_of::<Block>() as u128;let l=&limits.net;
    let pool=add(&[node::POOL_MAX_BYTES as u128,mul(node::POOL_MAX_BYTES as u128/MIN_TX_BYTES,32+24+24)?])?;
    let orphans=add(&[node::ORPHAN_BYTES_MAX as u128,mul((node::ORPHAN_PARENTS_MAX*node::ORPHANS_PER_PARENT) as u128,block+64)?])?;
    let future=mul(node::FUTURE_MAX as u128,frame+block)?;let templates=mul(node::TEMPLATES_MAX as u128+1,2*frame+block)?;
    let seen=add(&[mul(node::SEEN_MAX as u128+1,3*hdr+128)?,mul(node::SEEN_MAX as u128+1,192)?])?;
    let caches=add(&[mul(chain::INVALID_MAX as u128,32+REASON_MAX+64)?,mul(node::RECEIVED_MAX as u128+1,64)?,mul(node::REJECTS_MAX as u128+1,64+REASON_MAX+64)?,
        mul(node::EVIDENCE_POOL_MAX as u128,u128::from(cp.EVID_BYTES_MAX)+24)?,mul(node::FUTURE_MAX as u128,32)?])?;
    // Inbound peers <= peers_max; outbound <= one per dialer (net::dial).
    let peers=mul(l.peers_max as u128+dials as u128,add(&[l.queue_bytes_max as u128,2*frame,4096])?)?;
    // Each forwarder also holds the one event it is blocked sending (+1).
    let (main_events,net_events)=(mul(node::EVENT_QUEUE as u128,frame+256)?,mul((1+dials) as u128,mul(net::NET_EVENT_QUEUE as u128+1,frame+256)?)?);
    let q=[("queues/transaction pool",pool),("queues/orphan blocks",orphans),("queues/future blocks",future),("queues/templates",templates),("queues/seen sets",seen),
        ("queues/rejection and evidence caches",caches),("queues/peer send queues and frames",peers),("queues/main event queue",main_events),("queues/network event forwarders",net_events)];
    let queues=add(&q.map(|x|x.1))?;items.extend(q);
    // RPC (rpc::conn): per connection its header buffer (HEAD_MAX+READ_CHUNK, and its lossy UTF-8
    // copy, up to 3 bytes per input byte) and a body of exactly Content-Length <= REQ_BUF bytes. Answers held
    // by connections are within the response pools (rpc::answer: light (conn_max+1) x
    // LIGHT_RESP_MAX, heavy HEAVY_RESP_POOL), except small busy answers and HTTP literals
    // (SMALL_REPLY_MAX each). A heavy body can outlive its connection in the main queue: at most
    // queued_max of them (rpc::Held). The light lane holds <= conn_max bodies of <=
    // LIGHT_BODY_MAX. The consensus thread handles one request at a time: its parse tree
    // (rpc::parse_bytes_max, enforced by JSON_VALUES_MAX) and the answer being built: the batch
    // so far (a growing String: VEC x BATCH_BYTES_HARD) plus one member (its JSON tree and
    // string, a log result stopping at RESP_MAX), counted as 4 x RESP_MAX by inspection.
    let r=&limits.rpc;use crate::rpc::{REQ_BUF,HEAD_MAX,READ_CHUNK,RESP_MAX,LIGHT_BODY_MAX,HEAVY_RESP_POOL,BATCH_BYTES_HARD,SMALL_REPLY_MAX};
    let rq=[("rpc/connection requests (conn_max)",mul(r.conn_max as u128,(4*(HEAD_MAX+READ_CHUNK)+REQ_BUF) as u128)?),
        ("rpc/heavy response pool",HEAVY_RESP_POOL as u128),("rpc/light response pool ((conn_max+1) x LIGHT_RESP_MAX)",crate::rpc::light_pool(r) as u128),
        ("rpc/small answers outside the pools (conn_max)",mul(r.conn_max as u128,SMALL_REPLY_MAX as u128)?),
        ("rpc/queued heavy bodies (queued_max)",mul(crate::rpc::queued_max(r) as u128,REQ_BUF as u128+256)?),("rpc/light lane (conn_max)",mul(r.conn_max as u128,LIGHT_BODY_MAX as u128+256)?),
        ("rpc/request parse tree",crate::rpc::parse_bytes_max(REQ_BUF)),("rpc/answer being built",memory::VEC*(BATCH_BYTES_HARD as u128)+4*(RESP_MAX as u128))];
    let rpc=add(&rq.map(|x|x.1))?;items.extend(rq);
    // Threads: reserved stacks (an upper bound on their resident stack) and per-thread heap.
    use crate::threads::{IO_STACK,CONSENSUS_STACK};
    let io=io_threads(l.peers_max,dials,r.conn_max)?;
    // Exiting-not-yet-joined threads (point 3): a reader/outbound-reader/RPC-conn thread can finish
    // between its reaper's visits. Bound E = peers_max + dials + conn_max (writers are joined by
    // their reader synchronously; singletons never respawn). Measured ~25.8 KiB resident each (the
    // bulk of the stack returns to the exited-stack cache counted below); counted CONSERVATIVELY at a
    // full IO_STACK each, so the term is an upper bound, not the measured figure (evidence/thread-
    // inventory + threadmem). 
    let exiting=(l.peers_max+dials+r.conn_max) as u128;
    let th=[("threads/I/O thread stacks and heap",mul(io,IO_STACK as u128+THREAD_HEAP)?),("threads/consensus stack",CONSENSUS_STACK as u128),
        ("threads/main stack and heap",MAIN_STACK_RESIDENT+2*THREAD_HEAP),("threads/exited-stack cache",STACK_CACHE),
        ("threads/exiting not-yet-joined (conservative)",mul(exiting,IO_STACK as u128)?)];
    let threads=add(&th.map(|x|x.1))?;items.extend(th);
    // EVM execution buffers, journal, transient storage and loaded state (A13 obligation 4).
    let (gas,code_max)=(memory::execution_gas(cp.GAS_LIMIT),u128::from(cp.B_code_max));
    let execution=mul(EXECUTIONS,memory::execution(gas,code_max)?)?;let fixed=mul(EXECUTIONS,memory::fixed_heap(gas,code_max)?)?;
    items.extend([("execution/frames, code analysis, preallocations, precompiles",fixed),("execution/memory and operation classes (worst gas split)",execution.checked_sub(fixed)?)]);
    let total=add(&items.iter().map(|x|x.1).collect::<Vec<_>>())?;
    debug_assert_eq!(Some(total),add(&[mul(snapshots,snapshot_bytes)?,snapshot_bytes,code,history,side_blocks,queues,rpc,threads,execution]));
    let _=size_of::<Header>()+size_of::<Body>();
    Some(Bound{snapshots,snapshot_bytes,code,history,side_blocks,queues,rpc,threads,execution,total,items})
}
/// The share of the budget kept outside the model (D-A13-BUDGET): allocator headers, size-class
/// rounding and fragmentation are not modelled (CONDITIONS), so the model total must fit in
/// RESERVE_KEEP_EIGHTHS/8 of the budget. 7/8 keeps 12.5% (768 MiB of 6 GiB) in reserve.
pub const RESERVE_KEEP_EIGHTHS:u128=7;
/// The smallest budget that boots a bound of `total` bytes: ceil(8·total/7).
pub fn budget_required(total:u128)->Option<u128>{total.checked_mul(8).map(|x|x.div_ceil(RESERVE_KEEP_EIGHTHS))}
/// Boot check: the bound, with the reserve, must fit the node's memory budget.
pub fn check(cp:&ConsensusParams,k_hist:u32,side_max:u32,limits:&Limits,dials:usize)->Result<Bound,String>{
    let b=derive(cp,k_hist,side_max,limits,dials).ok_or_else(||"A13 memory bound: arithmetic overflow".to_string())?;
    let need=budget_required(b.total).ok_or_else(||"A13 memory bound: arithmetic overflow".to_string())?;
    if need>u128::from(limits.mem_budget){return Err(format!("A13 memory bound {} B with its 1/8 reserve needs {need} B, which exceeds the node memory budget {} B ({b:?})",b.total,limits.mem_budget))}
    Ok(b)
}
