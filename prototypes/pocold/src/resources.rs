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
];
#[derive(Clone,Debug,PartialEq,Eq)]
pub struct Bound{
    pub snapshots:u128,pub snapshot_bytes:u128,pub code:u128,pub history:u128,pub side_blocks:u128,
    pub queues:u128,pub rpc:u128,pub threads:u128,pub execution:u128,pub total:u128,
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
    let code=mul(snapshots,memory::code_bytes(u128::from(cp.CODE_CAP),accounts)?)?;
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
    let history=add(&[mul(u128::from(cp.H_END)+1,per_block)?,u128::from(cp.TXBYTES_CAP),
        mul(u128::from(cp.TX_CAP),24+24+32+RECEIPT_BASE)?,u128::from(caps::LOG_CAP)/32*33,evidence])?;
    // Side blocks: <= SIDE_BLOCKS_MAX (Chain::retain), each a full block of its own.
    let side_txs=u128::from(cp.BODY_MAX)/MIN_TX_BYTES;
    let side_block=add(&[per_block,mul(u128::from(cp.E_max),u128::from(cp.EVID_BYTES_MAX))?,u128::from(cp.BODY_MAX),mul(side_txs,24+24+32+RECEIPT_BASE)?,u128::from(caps::LOG_BLOCK_MAX)/32*33])?;
    let side_blocks=mul(chain::SIDE_BLOCKS_MAX as u128,side_block)?;
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
    let events=add(&[mul(node::EVENT_QUEUE as u128,frame+256)?,mul((1+dials) as u128,mul(net::NET_EVENT_QUEUE as u128,frame+256)?)?])?;
    let queues=add(&[pool,orphans,future,templates,seen,caches,peers,events])?;
    // RPC (rpc::conn): per connection its header buffer (HEAD_MAX+READ_CHUNK, and a lossy copy of
    // the headers as large), a body of exactly Content-Length <= REQ_BUF bytes, and a response (a
    // batch is <= BATCH_RESP_MAX plus one error item per member). A heavy body can outlive its
    // connection in the main queue: at most queued_max of them (rpc::Held). The light lane holds
    // <= conn_max bodies of <= LIGHT_BODY_MAX. The consensus thread handles one request at a
    // time: its parse tree (rpc::parse_bytes_max, enforced by JSON_VALUES_MAX) and the response
    // being built: the batch so far plus one member (its JSON tree and string, a log result
    // stopping at RESP_MAX), counted as 4 x RESP_MAX.
    let r=&limits.rpc;use crate::rpc::{REQ_BUF,HEAD_MAX,READ_CHUNK,RESP_MAX,BATCH_RESP_MAX,BATCH_MAX,LIGHT_BODY_MAX};
    let per_conn=(2*(HEAD_MAX+READ_CHUNK)+REQ_BUF+BATCH_RESP_MAX+BATCH_MAX*256) as u128;
    let rpc=add(&[mul(r.conn_max as u128,per_conn)?,mul(crate::rpc::queued_max(r) as u128,REQ_BUF as u128+256)?,mul(r.conn_max as u128,LIGHT_BODY_MAX as u128+256)?,
        crate::rpc::parse_bytes_max(REQ_BUF),(BATCH_RESP_MAX+4*RESP_MAX) as u128])?;
    // Threads: reserved stacks (an upper bound on their resident stack) and per-thread heap.
    use crate::threads::{IO_STACK,CONSENSUS_STACK};
    let io=io_threads(l.peers_max,dials,r.conn_max)?;
    let threads=add(&[mul(io,IO_STACK as u128+THREAD_HEAP)?,CONSENSUS_STACK as u128,MAIN_STACK_RESIDENT,2*THREAD_HEAP,STACK_CACHE])?;
    // EVM execution buffers, journal, transient storage and loaded state (A13 obligation 4).
    let execution=mul(EXECUTIONS,memory::execution(memory::execution_gas(cp.GAS_LIMIT),u128::from(cp.B_code_max))?)?;
    let total=add(&[mul(snapshots,snapshot_bytes)?,code,history,side_blocks,queues,rpc,threads,execution])?;
    let _=size_of::<Header>()+size_of::<Body>();
    Some(Bound{snapshots,snapshot_bytes,code,history,side_blocks,queues,rpc,threads,execution,total})
}
/// Boot check: the bound must fit the node's memory budget.
pub fn check(cp:&ConsensusParams,k_hist:u32,side_max:u32,limits:&Limits,dials:usize)->Result<Bound,String>{
    let b=derive(cp,k_hist,side_max,limits,dials).ok_or_else(||"A13 memory bound: arithmetic overflow".to_string())?;
    if b.total>u128::from(limits.mem_budget){return Err(format!("A13 memory bound {} B exceeds the node memory budget {} B ({b:?})",b.total,limits.mem_budget))}
    Ok(b)
}
