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
/// Resident bytes assumed per thread stack (pages actually touched; open obligation).
pub const STACK_RESIDENT:u128=64*1024;
/// Smallest valid transaction encoding (a signed legacy transfer exceeds it).
pub const MIN_TX_BYTES:u128=85;
/// Receipt encoding without logs: status, cumulative gas, a 256-byte bloom, list headers.
pub const RECEIPT_BASE:u128=300;
/// Longest stored rejection reason (chain::REASON_MAX) and status rejects kept (node).
pub const REASON_MAX:u128=chain::REASON_MAX as u128;

/// Largest encoded header for S_max shares: fixed fields <= 768 bytes, 9 per share nonce.
pub fn header_max(s_max:u16)->u128{768+9*u128::from(s_max)}

#[derive(Clone,Debug,PartialEq,Eq)]
pub struct Bound{
    pub snapshots:u128,pub snapshot_bytes:u128,pub code:u128,pub history:u128,pub side_blocks:u128,
    pub queues:u128,pub rpc:u128,pub threads:u128,pub total:u128,
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
    // RPC: per connection a request (<= MAX_BODY + 16 KiB headers) and a response (a batch is
    // <= BATCH_RESP_MAX plus one error item per member); the consensus thread builds one
    // response at a time: the batch so far plus one member (its JSON tree and string, a log
    // result stopping at RESP_MAX), counted as 4 x RESP_MAX.
    let r=&limits.rpc;use crate::rpc::{MAX_BODY,RESP_MAX,BATCH_RESP_MAX,BATCH_MAX};
    let rpc=add(&[mul(r.conn_max as u128,(MAX_BODY+16384+BATCH_RESP_MAX+BATCH_MAX*256) as u128)?,(BATCH_RESP_MAX+4*RESP_MAX) as u128])?;
    // Per configured peer: dialer, event forwarder, reader and writer.
    let threads=mul(add(&[2*l.peers_max as u128,4*dials as u128,r.conn_max as u128,8])?,STACK_RESIDENT)?;
    let total=add(&[mul(snapshots,snapshot_bytes)?,code,history,side_blocks,queues,rpc,threads])?;
    let _=size_of::<Header>()+size_of::<Body>();
    Some(Bound{snapshots,snapshot_bytes,code,history,side_blocks,queues,rpc,threads,total})
}
/// Boot check: the bound must fit the node's memory budget.
pub fn check(cp:&ConsensusParams,k_hist:u32,side_max:u32,limits:&Limits,dials:usize)->Result<Bound,String>{
    let b=derive(cp,k_hist,side_max,limits,dials).ok_or_else(||"A13 memory bound: arithmetic overflow".to_string())?;
    if b.total>u128::from(limits.mem_budget){return Err(format!("A13 memory bound {} B exceeds the node memory budget {} B ({b:?})",b.total,limits.mem_budget))}
    Ok(b)
}
