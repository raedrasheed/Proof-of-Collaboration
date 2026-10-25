//! A13: conservative resident-memory bound of a pocold node for an admitted profile and its
//! local limits, derived from the actual representation and the enforced caps. Every term
//! names the code that enforces its assumption; arithmetic is checked (an overflow is a
//! rejection, never a wrap). `Node::open` refuses to boot when the bound exceeds the
//! node's memory budget. Derivation and open obligations: development/audit-2026-10-22/
//! A13-DERIVATION.md.
use std::mem::size_of;
use pocol_lp4_execution::{profile::ConsensusParams,resources::memory,user_phase::caps};
use crate::{chain::{self,Entry},header::Header,net,node::{self,Limits},types::{Block,Body}};

/// Full working copies alive besides the retained ones (C-1 E3; 10 before E3). A block, production,
/// template selection, RPC simulation and the pool run on overlays (lp4 `view::Overlay`, `view::Layer`)
/// over a state they share; the engine reads through `StateRef` and PAY through the same view
/// (decision package C-2). What remains, one task at a time on the consensus thread:
/// - a block applied: its child state, merged once at the end (one copy);
/// - a rebuild's or restore's rolling re-execution: the state it holds and the next block's merged state
///   (two);
/// - after a new head, until `rebuild_pool`: the pool's base, the previous head's state, which the chain
///   no longer holds full (one; `restore_canonical` runs before `settle`, so not during a rolling
///   re-execution).
///
/// At most two.
pub const TRANSIENT_SNAPSHOTS:u128=2;
/// C-1 E3: the pool's pending state is a layer of its writes over the head (`node::Pool`). The pool admits
/// a transaction only within the caps (`PoolMeter`), and its gas is bounded only by POOL_MAX_TXS ×
/// GAS_LIMIT unless `pool_gas_max` is set (D-7: its value is not approved), so the layer is counted as a
/// whole state.
pub const POOL_LAYER_SNAPSHOTS:u128=1;
/// C-1 E3: the overlay of the block being applied (one at a time): an entry for each written account and
/// each written slot (`block_writes`), with the cleared, deleted and retained address sets, each element
/// at its inline size with hash-table growth (×2).
pub fn overlay_max(cp:&ConsensusParams)->Option<u128>{
    use revm::{db::DbAccount,primitives::{Address,U256}};let (accounts,slots)=block_writes(cp)?;
    add(&[mul(accounts,2*size_of::<(Address,DbAccount)>() as u128)?,mul(slots,2*size_of::<(U256,U256)>() as u128)?,mul(mul(accounts,3)?,2*size_of::<Address>() as u128)?])
}
/// Gas per byte of deployed runtime (EIP-170 code deposit, 200): an execution of g gas deploys at
/// most g/200 bytes.
pub const CODE_DEPOSIT:u128=200;
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
/// C-1 S3a: full states materialized from a full one through the diffs, alive at once: the parent of a
/// block being validated or an RPC tag's state (one at a time on the consensus thread), and one that
/// `ensure_state_with` keeps full until the next settle.
pub const MATERIALIZED:u128=2;
/// C-1 S3a: diffs held at once. Canonical blocks above the K_hist cut (K_hist), side states within
/// side_max, the block being imported, and during an adopting import the abandoned branch's diffs until
/// `settle` (K_hist more).
pub fn diffs_held(k_hist:u32,side_max:u32)->u128{2*u128::from(k_hist)+u128::from(side_max)+1}
/// The cheapest first write of a distinct storage slot in a transaction (EIP-2200/2929 SSTORE reset of a
/// warm slot: 2,900 gas); a slot changed between a parent's state and its child's had one in some
/// transaction of the block.
pub const SLOT_WRITE_GAS_MIN:u128=2_900;
/// The cheapest way for a transaction to add an account to the committed state: a warm touch costs 100
/// after an access-list entry of 2,400 (EIP-2930), counted at 2,400.
pub const ACCOUNT_TOUCH_GAS_MIN:u128=2_400;
/// Precompile and system addresses a block can touch at 100 gas each (warm by EIP-2929): counted at once.
pub const WARM_ADDRESSES:u128=32;
/// C-1 S3a: the largest diff of one block. USER gas is at most GAS_LIMIT and refunds return at most a fifth
/// of it (EIP-3529), so at most 5/4 GAS_LIMIT was spent. Changed slots: one first write each
/// (SLOT_WRITE_GAS_MIN) plus the SYSTEM phase's SYS_KEYS_BLOCK_MAX (apply.rs enforces it). Changed
/// accounts: three per transaction (sender, recipient, fee), one per ACCOUNT_TOUCH_GAS_MIN, the warm
/// addresses, the SYSTEM phase's SYS_ACCT_BLOCK_MAX and the escrow's issuance. A removed account keeps no
/// earlier storage in a diff: under Cancun only an account created in the same transaction is destroyed,
/// and an empty account cannot hold storage (condition `s3a-removal`). Contracts: at most one per changed
/// account. Block hashes: the 256-block window moves by one (257 entries). Each element is counted at its
/// inline size with Vec growth (×2).
pub fn diff_max(cp:&ConsensusParams)->Option<u128>{
    use std::mem::size_of;use crate::statediff::{AccountDiff,StateDiff};use revm::primitives::{Address,Bytecode,B256,U256};
    let (accounts,slots)=block_writes(cp)?;
    let vec2=|n:u128,sz:usize|mul(n,2*sz as u128);
    add(&[vec2(accounts,size_of::<(Address,AccountDiff)>())?,vec2(slots,size_of::<(U256,Option<U256>,Option<U256>)>())?,
        vec2(accounts,size_of::<(B256,Option<Bytecode>,Option<Bytecode>)>())?,vec2(257,size_of::<(U256,Option<B256>,Option<B256>)>())?,size_of::<StateDiff>() as u128+16])
}
/// The accounts and slots one block can change (diff_max's counts): (accounts, slots).
pub fn block_writes(cp:&ConsensusParams)->Option<(u128,u128)>{
    let spent=u128::from(cp.GAS_LIMIT).checked_mul(5)?/4;
    let slots=add(&[spent/SLOT_WRITE_GAS_MIN,u128::from(cp.SYS_KEYS_BLOCK_MAX)])?;
    let accounts=add(&[3*(spent/TX_GAS_MIN),spent/ACCOUNT_TOUCH_GAS_MIN,WARM_ADDRESSES,u128::from(cp.SYS_ACCT_BLOCK_MAX),1])?;
    Some((accounts,slots))
}
/// C-1 E1: one state trie (lp4 `state_trie`) of a state with these accounts and nonzero slots: a leaf per
/// account and per slot; every branch has at least two children, so a trie of n keys has at most n − 1
/// branches and 2n − 2 child pointers. A world node is a `Node<Acct>`, a storage node a `Node<U256>`, each
/// behind an Arc (`state_trie::node_bytes`); a child pointer is one word.
pub fn trie_bytes(accounts:u128,slots:u128)->Option<u128>{
    use pocol_lp4_execution::state_trie::node_bytes;
    add(&[mul(2*accounts,u128::from(node_bytes(true)))?,mul(2*slots,u128::from(node_bytes(false)))?,mul(2*(accounts+slots),size_of::<usize>() as u128)?])
}
/// C-1 E1: nodes on the path from a trie's root to a leaf, at most: a branch at each of the 64 nibbles of
/// a hashed key, and the leaf.
pub const TRIE_PATH_NODES:u128=65;
/// C-1 E1: the nodes a block's trie does not share with its parent's: the copied path of every changed
/// slot (in its account's storage trie) and of every changed account (in the world trie). An account whose
/// storage changes is one of the block's changed accounts (`block_writes`).
pub fn trie_paths(cp:&ConsensusParams)->Option<u128>{
    use pocol_lp4_execution::state_trie::node_bytes;let (accounts,slots)=block_writes(cp)?;let w=size_of::<usize>() as u128;
    add(&[mul(mul(slots,TRIE_PATH_NODES)?,u128::from(node_bytes(false))+w)?,mul(mul(accounts,TRIE_PATH_NODES)?,u128::from(node_bytes(true))+w)?])
}
/// C-1 E4 (store mode): a block's batch (`node_trie::Batch`, the new nodes of its child version until
/// `Pinned::new` commits them) is alive one at a time: validation commits it in `child_state` and a
/// rolling re-execution in `rolled` before the next block runs; production keeps no execution output
/// (`node::Production`). An inventory by inspection (CONDITIONS, `transient-snapshot-inventory`).
pub const BATCHES:u128=1;
/// The heap one decoded node holds at most (`Node::resident_bytes` of a branch with 16 children).
pub fn node_resident_max()->u128{use pocol_lp4_execution::{node_trie::{Id,Node},state_trie::Ref};(2*size_of::<usize>()+size_of::<Node>()+16*size_of::<(Id,Ref)>()) as u128}
/// The largest node serialization (`Node::encode`): a branch of 16 children, each an id and a 33-byte
/// reference, with its key and its own reference.
pub const NODE_ENC_MAX:u128=1+1+2+32+1+33+16*(32+1+33);
/// C-1 E4: one batch at most: the nodes on the copied path of every changed slot and account (as
/// `trie_paths` counts them), each decoded behind an `Arc` with its map slot (a leaf holds its key's
/// preimage, C-1 E5), and the block's write set (`state_trie::Touched`). Its code is shared with the
/// execution's.
pub fn batch_max(cp:&ConsensusParams)->Option<u128>{
    use pocol_lp4_execution::node_trie::{Id,Node};use revm::primitives::{Address,U256};let (accounts,slots)=block_writes(cp)?;
    let nodes=mul(accounts+slots,TRIE_PATH_NODES)?;let slot=|n:usize|memory::entry_bytes(n as u128);
    add(&[mul(nodes,node_resident_max()+slot(size_of::<(Id,std::sync::Arc<Node>)>()))?,
        mul(accounts,slot(size_of::<(Address,Option<Vec<U256>>)>()))?,mul(slots,memory::VEC*size_of::<U256>() as u128)?])
}
/// C-1 E4: entries that hold a stored version at once: genesis, the K_hist canonical window, side_max side
/// states, a rolling re-execution's entry, and during an adopting import, until `settle`, the abandoned
/// window (K_hist more). The pool's base and production share an entry's handle.
pub fn stored_versions(k_hist:u32,side_max:u32)->u128{2*u128::from(k_hist)+u128::from(side_max)+2}
/// One stored version's handle (`chain::Pinned` behind its `Arc`) and its BLOCKHASH window (257 entries).
pub fn pinned_bytes()->u128{size_of::<chain::Pinned>() as u128+16+257*memory::entry_bytes(64)+memory::table_bytes(64)}
/// C-1 E4.4: a checkpoint being written: its bytes (every entry at most `checkpoint::REC_MAX`, the
/// unslimmed list and the eviction FIFO), the index of entries it sorts, and redb's copy of the value in
/// its dirty pages.
pub fn checkpoint_bytes(cp:&ConsensusParams,limits:&Limits)->Option<u128>{
    let entries=add(&[u128::from(cp.H_END)+1,limits.side_cap as u128,mul(2,u128::from(limits.r_keep))?])?;
    let bytes=add(&[256,mul(entries,crate::checkpoint::REC_MAX as u128)?,mul(u128::from(cp.H_END)+1+chain::EVICTED_MAX as u128,32)?])?;
    add(&[mul(2,bytes)?,mul(entries,size_of::<usize>() as u128)?])
}
/// C-1 E4.5: the largest state.redb file, for its allocator term (A13 counts the file's allocator state
/// at one byte per 4 KiB page, as for history.redb; the file itself is disk, not memory). Nodes: the
/// head's and genesis's versions whole, and every other version that a stored entry or a checkpoint pins
/// differing from the head's by the paths of the blocks between them (a window state: K_hist blocks; a
/// side state: 2·R_keep; a checkpoint's versions: KEPT·checkpoint_every + 2·R_keep), at most a whole
/// state. Code is kept for good (storage.md): the code every block to H_END can deploy. (C-1 E5: a leaf
/// keeps its key's preimage, released with it; no preimage is kept for good.) The checkpoints' snapshots.
/// All at HISTORY_FILE_FACTOR times their bytes.
pub fn state_file_max(cp:&ConsensusParams,k_hist:u32,side_max:u32,limits:&Limits)->Option<u128>{let p=state_file_parts(cp,k_hist,side_max,limits)?;add(&p)}
/// `state_file_max`'s parts: (versions' nodes, key preimages, code, checkpoint snapshots), each at
/// HISTORY_FILE_FACTOR times its bytes.
pub fn state_file_parts(cp:&ConsensusParams,k_hist:u32,side_max:u32,limits:&Limits)->Option<[u128;4]>{
    let full=mul(2,add(&[u128::from(cp.ACCT_CAP),5,u128::from(cp.SLOT_CAP),u128::from(cp.SYS_SLOT_MAX)])?)?;
    let (wa,ws)=block_writes(cp)?;let per_block=mul(wa+ws,TRIE_PATH_NODES)?;
    let span=|blocks:u128|mul(blocks,per_block).map(|n|n.min(full));
    let (k,sm,kept)=(u128::from(k_hist),u128::from(side_max),crate::checkpoint::KEPT as u128);
    let ck_span=add(&[mul(kept,u128::from(limits.checkpoint_every.max(1)))?,mul(2,u128::from(limits.r_keep))?])?;
    let nodes=add(&[mul(2,full)?,mul(k,span(k)?)?,mul(sm,span(mul(2,u128::from(limits.r_keep))?)?)?,mul(mul(kept,k+sm+2)?,span(ck_span)?)?])?;
    let blocks=u128::from(cp.H_END)+1;
    let preimages=0;
    let code=mul(blocks,memory::execution_gas(cp.GAS_LIMIT)/CODE_DEPOSIT)?;
    let ckpts=mul(kept,checkpoint_bytes(cp,limits)?/2)?;
    Some([mul(HISTORY_FILE_FACTOR,mul(nodes,NODE_ENC_MAX+4+32)?)?,mul(HISTORY_FILE_FACTOR,preimages)?,mul(HISTORY_FILE_FACTOR,code)?,mul(HISTORY_FILE_FACTOR,ckpts)?])
}
/// Receipt encoding without logs: status, cumulative gas, a 256-byte bloom, list headers.
pub const RECEIPT_BASE:u128=300;
/// C-1 S1: history.redb's file size over the bytes it stores (receipts records, index entries, keys),
/// for its allocator term. Measured at most 4.1 (journal_measure::history_integrity_check_cost: redb
/// grows the file by regions and rounds values to page orders); counted at 8.
pub const HISTORY_FILE_FACTOR:u128=8;
/// Longest stored rejection reason (chain::REASON_MAX) and status rejects kept (node).
pub const REASON_MAX:u128=chain::REASON_MAX as u128;

/// Largest encoded header for S_max shares: fixed fields <= 768 bytes, 9 per share nonce.
pub fn header_max(s_max:u16)->u128{768+9*u128::from(s_max)}

/// What the bound does not establish (A13-DERIVATION §4). The total is the sum of requested
/// heap bytes and reserved stacks under these conditions, not an unconditional bound on the
/// resident memory of the process.
pub const CONDITIONS:&[(&str,&str)]=&[
    ("allocator-overhead","allocator per-allocation overhead and fragmentation are not modelled"),
    ("transient-snapshot-inventory","TRANSIENT_SNAPSHOTS (2, C-1 E3) and EXECUTIONS (1) are inventories by code inspection, not enforced by a counter"),
    ("main-thread","the main thread's stack is reserved by the platform; counted at 1 MiB because it only spawns and joins"),
    ("revm-representation","the execution term relies on revm 19.7 behaviour checked by source inspection (iterative frames, SharedMemory truncation, fixed stack capacity) and by measured adversarial peaks"),
    ("cpu-and-timing","CPU costs (world-root rebuild, chain scans, pool re-execution, deep-fork rebuild) are not memory terms; worst-case timing is not bounded"),
    ("s3a-removal","a diff keeps no storage for a removed account: under Cancun (revm 19.7, EIP-6780) only an account created in the same transaction is destroyed, and an account without code, nonce and balance holds no storage; by inspection, not enforced by a counter"),
    ("redb-representation","the history.redb terms rely on redb 2.6.4 behaviour checked by source inspection (cache split and write-buffer flush, allocator bitmaps) and on a measured file-size factor (HISTORY_FILE_FACTOR)"),
    ("open-replay-transient","Node::open holds the whole journal's payloads (store::open, pre-existing) and a replay index of two entries per record while replaying; this open-time transient grows with the journal and is not part of the steady-state bound. C-1 E4.4 adds to it, at open only: every record's offset and rolling hash, a decoded checkpoint snapshot and the stored versions read whole for their summaries (streamed: a node at a time, the DFS stack of node ids)"),
    ("store-inventory","store mode (C-1 E4): BATCHES (1) and stored_versions are inventories by code inspection, not enforced by a counter; the node cache is bounded by its resident-byte count (state_store::CACHE_ENTRY, Node::resident_bytes), checked by a test"),
    ("store-file-factor","the state.redb allocator term takes the largest file as HISTORY_FILE_FACTOR (measured for history.redb) times the stored bytes; for state.redb the factor is measured in evidence/c1-e4 (disk measurements), and its versions' nodes are the adversarial worst case (every version a whole state on disk)"),
];
/// The model total and its parts. `items` itemizes every group term ("group/item", bytes); the
/// group fields are the sums of their items and `total` is the sum of all items.
#[derive(Clone,Debug,PartialEq,Eq)]
pub struct Bound{
    /// Whole states counted (`snapshots` of `snapshot_bytes` each) and the snapshot group's total (with
    /// the table growth of a working copy). C-1 E4: `store` is the node store's terms (store mode).
    pub snapshots:u128,pub snapshot_bytes:u128,pub snapshot_total:u128,pub diffs:u128,pub trie:u128,pub code:u128,pub store:u128,pub history:u128,pub side_blocks:u128,
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
    // C-1 S3a: full states are the head, genesis, the side states within side_max, and the materialized
    // ones (MATERIALIZED); every other retained state is a diff (below). Before S3a: 1 + K_hist + side_max.
    let (snapshots,mut items)=if limits.state_store{
    // C-1 E4 (store mode, `Limits::state_store`): every retained state is a version pinned in state.redb,
    // read in place through hash-checked nodes (chain::Pinned, state_store): no whole state, diff or E1
    // trie is held (the checkpoint encoder refuses an entry that holds one, checkpoint::rec_of). What is in
    // memory is the caches, the work in progress and the handles.
    let code_set=memory::code_bytes(u128::from(cp.CODE_CAP),0)?;let code_entries=memory::code_bytes(0,accounts)?;
    let exec_code=memory::code_bytes(memory::execution_gas(cp.GAS_LIMIT)/CODE_DEPOSIT,0)?;
    let snapshots=POOL_LAYER_SNAPSHOTS;
    let items:Vec<(&'static str,u128)>=vec![
        ("snapshots/the pool's pending layer over the stored head (counted as a whole state)",mul(POOL_LAYER_SNAPSHOTS,snapshot_bytes)?),
        ("diffs/the overlay of the block being applied (C-1 E3)",overlay_max(cp)?),
        ("store/a block's new trie nodes before their commit (BATCHES batches)",mul(BATCHES,batch_max(cp)?)?),
        ("store/decoded-node cache (NODE_CACHE, resident bytes)",crate::state_store::NODE_CACHE as u128),
        ("store/state.redb page cache (STATE_PAGE_CACHE)",crate::state_store::STATE_PAGE_CACHE as u128),
        // redb 2.6.4 keeps, per region, a free and an allocated bitmap for every page order (buddy_allocator.rs:
        // about 4 bits per page); counted at one byte per 4 KiB page of the largest file, by its parts.
        ("store/state.redb allocator state: the versions' nodes",state_file_parts(cp,k_hist,side_max,limits)?[0]/4096),
        ("store/state.redb allocator state: code, kept for good",state_file_parts(cp,k_hist,side_max,limits)?[2]/4096),
        ("store/state.redb allocator state: the checkpoints' snapshots",state_file_parts(cp,k_hist,side_max,limits)?[3]/4096),
        ("store/stored versions' handles and BLOCKHASH windows",mul(stored_versions(k_hist,side_max),pinned_bytes())?),
        ("store/a checkpoint being written (its bytes and its entry index)",checkpoint_bytes(cp,limits)?),
        // Each account an execution loads brings its code from the store (TrieState::info): a copy per
        // loaded account, at most the logical code of every existing account (code_caps, CODE_CAP) with
        // its analysis. One execution at a time (EXECUTIONS).
        ("code/read from the store by the execution in progress (a set)",mul(EXECUTIONS,code_set)?),
        ("code/the pool's pending state (a set)",code_set),
        ("code/containers in the pool's layer",mul(snapshots,code_entries)?),("code/new runtime of the execution in progress",mul(EXECUTIONS,exec_code)?)];
    (snapshots,items)}else{
    let snapshots=add(&[1,1,u128::from(side_max),MATERIALIZED,TRANSIENT_SNAPSHOTS,POOL_LAYER_SNAPSHOTS])?;
    // Code (decision package C-1 S2). A runtime is held in refcounted buffers (revm Bytecode: Bytes and
    // an Arc jump table) that a state copy shares (journal_measure::retained_states_of_one_lineage_
    // share_their_code_buffers). Each block's state is its parent's copy plus that block's changes, and
    // under Cancun code leaves a state only within its creating transaction. So the states of one
    // lineage hold one set of buffers, at most CODE_CAP logical bytes with analysis (code_caps).
    // A separate execution of the same code makes separate buffers. Counted as a full set each:
    // - every side-branch state (unshared at worst: rebuilt from an older state);
    // - a rebuild or restore in progress, which re-creates the code it re-executes;
    // - the pool's pending state, which holds its own creates.
    // The per-copy containers (map entries, Bytecode headers) are in every snapshot, and the
    // execution in progress makes at most its gas / CODE_DEPOSIT bytes of new runtime.
    let code_set=memory::code_bytes(u128::from(cp.CODE_CAP),0)?;let code_entries=memory::code_bytes(0,accounts)?;
    let exec_code=memory::code_bytes(memory::execution_gas(cp.GAS_LIMIT)/CODE_DEPOSIT,0)?;
    let side_states=u128::from(side_max);
    let items:Vec<(&'static str,u128)>=vec![("snapshots/head state",snapshot_bytes),("snapshots/genesis state (counted as a full one)",snapshot_bytes),
        ("snapshots/side_max side-branch states",mul(side_states,snapshot_bytes)?),
        ("snapshots/materialized states (C-1 S3a: a parent or an RPC tag, and one kept until settle)",mul(MATERIALIZED,snapshot_bytes)?),
        ("snapshots/transient working copies (C-1 E3: a block's merged child, a rolling re-execution's two)",mul(TRANSIENT_SNAPSHOTS,snapshot_bytes)?),
        ("snapshots/the pool's pending layer over the head (counted as a whole state)",mul(POOL_LAYER_SNAPSHOTS,snapshot_bytes)?),
        // A table that grows in a working copy keeps its old allocation until the new one is filled:
        // one table at a time (single consensus thread), at most a whole snapshot's tables.
        ("snapshots/table growth in a working copy",snapshot_bytes),
        ("diffs/retained and side states as diffs (C-1 S3a: 2·K_hist + side_max + 1)",mul(diffs_held(k_hist,side_max),diff_max(cp)?)?),
        ("diffs/the overlay of the block being applied (C-1 E3)",overlay_max(cp)?),
        // C-1 E1: only the head keeps its state's trie after settle (chain::Chain::settle). A parent that is
        // not the head has its trie derived from the head's or built from its state, one at a time on the
        // consensus thread (validation, production, a rebuild's rolling re-execution); its distinct nodes are
        // counted as a whole trie. The block executed on it shares all but its changed paths.
        ("trie/head state trie (C-1 E1)",trie_bytes(accounts,slots)?),("trie/a parent's trie derived or built (one at a time)",trie_bytes(accounts,slots)?),
        ("trie/the changed paths of the block executed on it",trie_paths(cp)?),
        ("code/one set for the canonical lineage (its states share the buffers)",code_set),("code/side_max side-branch states (a set each)",mul(side_states,code_set)?),
        ("code/a rebuild or restore in progress (a set)",code_set),("code/the pool's pending state (a set)",code_set),
        ("code/containers in every snapshot",mul(snapshots,code_entries)?),("code/new runtime of the execution in progress",mul(EXECUTIONS,exec_code)?)];
    (snapshots,items)};
    // Per block kept in memory: the map slot (Entry inline), the canonical index, header heap
    // (encoded, ut_raw, bloom, proposer, sig, share nonces), ParentResult shares, nonce ranges
    // (members <= M_max) and evidence (E_max items <= EVID_BYTES_MAX); an empty state is shared (C-1 E5).
    let entry=size_of::<([u8;32],Entry)>() as u128;
    // C-1 E2: and its state summary (boxed; a slimmed entry drops it).
    let per_block=add(&[mul(entry+1,3)?,64,size_of::<pocol_lp4_execution::state_summary::Summary>() as u128,mul(hdr,2)?,256+20+65+64,mul(8,s)?,mul(32,s+1)?,mul(64,m)?,
        mul(u128::from(cp.E_max),24)?])?;
    // A block's transactions are bounded by its body and by its gas.
    let side_txs=(u128::from(cp.BODY_MAX)/MIN_TX_BYTES).min(u128::from(cp.GAS_LIMIT)/TX_GAS_MIN);
    let per_tx=24+24+32+RECEIPT_BASE;
    // Canonical chain (C-1 S1): <= H_END+1 blocks. The last `window` (Limits::history_window, default
    // K_hist) are resident whole; every older journaled canonical block is offloaded by Chain::retain:
    // its encoded header, body (evidence included), receipts and tx hashes are dropped and read from the
    // journal and history.redb, so its entry is the per-block term less one header and the evidence.
    // The window's content is bounded per block (BODY_MAX, E_max evidence items, side_txs receipts,
    // LOG_BLOCK_MAX log bytes encoded at most 33/32) and in total by the chain caps (TXBYTES_CAP, the
    // evidence identities, TX_CAP, LOG_CAP), so a window of the whole chain is the model before S1.
    let blocks=u128::from(cp.H_END)+1;let window=u128::from(limits.history_window.unwrap_or(u64::from(k_hist))).min(blocks);
    let offloaded_entry=per_block.checked_sub(hdr)?.checked_sub(mul(u128::from(cp.E_max),24)?)?;
    // Evidence: valid evidence tombstones its identity, and evidence against a tombstone is a host error
    // (block invalid), so the chain holds at most one item per identity ever: M_max initial records plus
    // R_max registrations per block (D86 registry rotation).
    let identities=u128::from(cp.M_max).checked_add(mul(u128::from(cp.R_max),u128::from(cp.H_END))?)?;
    let w_bodies=mul(window,u128::from(cp.BODY_MAX))?.min(u128::from(cp.TXBYTES_CAP));
    let w_evidence=mul(window,mul(u128::from(cp.E_max),u128::from(cp.EVID_BYTES_MAX))?)?.min(mul(identities,u128::from(cp.EVID_BYTES_MAX)+24)?);
    let w_receipts=mul(mul(window,side_txs)?.min(u128::from(cp.TX_CAP)),per_tx)?;
    let w_logs=mul(window,u128::from(caps::LOG_BLOCK_MAX))?.min(u128::from(caps::LOG_CAP))/32*33;
    // history.redb (crate::history): its page cache is HISTORY_CACHE (redb splits it 9:1 between reads
    // and the write buffer, and flushes the write buffer to the file past its share). Its allocator keeps
    // per page two buddy bitmaps over the page orders (about 4 bits a page, redb 2.6.4 buddy_allocator.rs),
    // counted at one byte per 4 KiB page of the file. The file holds per block a receipts record and per
    // transaction an index entry, at most HISTORY_FILE_FACTOR times their bytes (measured below 4.2,
    // evidence/c1-s1/).
    // C-1 S4: each block's nonce ranges too (owner 20 + start 16 + end 16 bytes per member, a seal).
    let payload=add(&[mul(blocks,32+32+64)?,mul(blocks,32+32+52*m)?,mul(u128::from(cp.TX_CAP),RECEIPT_BASE+4+64+4)?,u128::from(caps::LOG_CAP)/32*33])?;
    // C-1 S4: canonical journaled entries deeper than slim_depth (default 2·R_keep + E_win + 257) keep only
    // the entry, its map slot and canonical index, and an empty state; the header's heap fields, the
    // ParentResult and the nonce ranges are restored from the journal and history.redb on demand.
    let depth=u128::from(limits.slim_depth.unwrap_or(2*limits.r_keep+u64::from(cp.E_win)+257)).min(blocks);
    // C-1 E5: an entry without a state shares one empty state (chain::empty_state), counted once below.
    let slim_entry=add(&[mul(entry+1,3)?,64])?;
    let (full_old,slim_old)=(depth.saturating_sub(window),blocks-depth.max(window));
    let redb_alloc=mul(payload,HISTORY_FILE_FACTOR)?/4096;
    let hist=[("history/offloaded canonical block metadata (slim_depth − window entries)",mul(full_old,offloaded_entry)?),
        ("history/slimmed canonical block metadata (H_END+1 − slim_depth entries, C-1 S4)",mul(slim_old,slim_entry)?),
        ("history/the one empty state entries share (C-1 E5)",memory::empty_snapshot()?),("history/resident window: block entries",mul(window,per_block)?),("history/resident window: transaction bytes",w_bodies),("history/resident window: evidence",w_evidence),
        ("history/resident window: transaction hashes and receipts",w_receipts),("history/resident window: logs",w_logs),
        ("history/history.redb page cache (HISTORY_CACHE)",crate::history::HISTORY_CACHE as u128),("history/history.redb allocator state",redb_alloc)];
    let history=add(&hist.map(|x|x.1))?;items.extend(hist);
    // Side blocks (D-REORG-REDB): every journaled non-canonical block is offloaded to metadata at the
    // retain() that follows its import (Chain::retain): its encoded header and body (evidence included),
    // receipts and tx hashes are dropped, so an entry is the per-block term less one header and the
    // evidence, plus its protect-set slot. Live: <= side_cap unprotected + protect_max (2·r_keep) held
    // by a sync session. Replay: all <= side_cap + protect_max (Chain::replaying). One full block is
    // resident between its insert and that retain (or while restore_canonical re-executes it): its
    // transactions are bounded by its body and by its gas.
    let side_block=add(&[per_block,mul(u128::from(cp.E_max),u128::from(cp.EVID_BYTES_MAX))?,u128::from(cp.BODY_MAX),mul(side_txs,per_tx)?,u128::from(caps::LOG_BLOCK_MAX)/32*33])?;
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
    // LIGHT_RESP_MAX, heavy HEAVY_RESP_POOL), except small busy answers and HTTP literals (each
    // <= SMALL_REPLY_MAX, built within SMALL_REPLY_PEAK of heap: ids, answer, header and one
    // transient id parse; the round-2 term counted the answer only). A heavy body can outlive its
    // connection in the main queue: at most queued_max of them (rpc::Held). The light lane holds <= conn_max bodies of <=
    // LIGHT_BODY_MAX. The consensus thread handles one request at a time: its parse tree
    // (rpc::parse_bytes_max, enforced by JSON_VALUES_MAX) and the answer being built: the batch
    // so far (a growing String: VEC x BATCH_BYTES_HARD) plus one member (its JSON tree and
    // string, a log result stopping at RESP_MAX), counted as 4 x RESP_MAX by inspection. RpcGuard:
    // queued heavy bodies are capped at HEAVY_QUEUE (not 2·conn_max), the light lane at LIGHT_QUEUE
    // (each body is shared with its connection through an Arc, never copied; the Arc and the
    // admission state fit the +256 per body); the per-connection token bucket keeps no state. Busy
    // and rate answers on connection threads scan the members' ids without parsing a tree
    // (rpc::scan_ids) and take SMALL_REPLY_PEAK each. The SendPacer writes the answer straight from its
    // reservation (only a small response header is allocated).
    let r=&limits.rpc;use crate::rpc::{REQ_BUF,HEAD_MAX,READ_CHUNK,RESP_MAX,LIGHT_BODY_MAX,HEAVY_RESP_POOL,BATCH_BYTES_HARD,SMALL_REPLY_PEAK};
    let rq=[("rpc/connection requests (conn_max)",mul(r.conn_max as u128,(4*(HEAD_MAX+READ_CHUNK)+REQ_BUF) as u128)?),
        ("rpc/heavy response pool",HEAVY_RESP_POOL as u128),("rpc/light response pool ((conn_max+1) x LIGHT_RESP_MAX)",crate::rpc::light_pool(r) as u128),
        ("rpc/small answers outside the pools (conn_max x SMALL_REPLY_PEAK)",mul(r.conn_max as u128,SMALL_REPLY_PEAK as u128)?),
        ("rpc/queued heavy bodies (HEAVY_QUEUE)",mul(crate::rpc::queued_max(r) as u128,REQ_BUF as u128+256)?),("rpc/light lane (LIGHT_QUEUE)",mul(r.light_queue as u128,LIGHT_BODY_MAX as u128+256)?),
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
    // Each group is the sum of its items.
    let group=|g:&str|add(&items.iter().filter(|x|x.0.split('/').next()==Some(g)).map(|x|x.1).collect::<Vec<_>>());
    let (snapshot_total,diffs,trie,code,store)=(group("snapshots")?,group("diffs")?,group("trie")?,group("code")?,group("store")?);
    debug_assert_eq!(Some(total),add(&[snapshot_total,diffs,trie,code,store,history,side_blocks,queues,rpc,threads,execution]));
    let _=size_of::<Header>()+size_of::<Body>();
    Some(Bound{snapshots,snapshot_bytes,snapshot_total,diffs,trie,code,store,history,side_blocks,queues,rpc,threads,execution,total,items})
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
