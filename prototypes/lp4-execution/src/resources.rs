//! LP4 P7/P8 resource derivations for the v1 system programs (engineering
//! derivation bound to this layout; see development/lp4/p7-resources/DERIVATION.md).
//!
//! Notation: S=S_max, D, K=max(D,W_w), RRM=REG_RECORDS_MAX, M=M_max, E=E_max,
//! RET, SW=min(SWEEP_MAX,16) deletes per beginBlock, O=min(S+1,M) owners per height.
//!
//! SYS slots (state footprint, R18 SYS_SLOT_MAX):
//!   Registry 5 + 5·RRM + M   (fixed, RecArr, Rec 4 words, ActList)
//!   Ledger   K·(2·O + 2)       (K retained heights: count+owner per owner, len, total)
//!   Escrow   2 + 3·(D+1)       (burnedTotal, final marker, pending)
//!   Caps     52
//! SYS keys changed per block (R18 SYS_KEYS_BLOCK_MAX):
//!   evidence 9·E; markClose 1 (+RET+1 closing); prune 2·O+2; recordShares 3·O+2;
//!   recordResult 1; settle 4; beginBlock 2+8·SW+1 (1 when closing); closeBlock 2;
//!   final: finalize 2 + 4·(D-1)
//! SYS accounts touched per block (R18 SYS_ACCT_BLOCK_MAX):
//!   8 fixed (5 programs, PAY, SYSTEM, origin) + payees
//!   normal O+1+SW; closing O+1+RET; final min(D·(O+1), M+R_max·D+1)+RET.
use crate::profile::ConsensusParams;

#[derive(Clone,Debug,PartialEq,Eq)]
pub struct SysBounds{pub slot_min:u64,pub keys_normal:u64,pub keys_closing:u64,pub keys_final:u64,pub accts_normal:u64,pub accts_closing:u64,pub accts_final:u64}
impl SysBounds{pub fn keys_max(&self)->u64{self.keys_normal.max(self.keys_closing).max(self.keys_final)}pub fn accts_max(&self)->u64{self.accts_normal.max(self.accts_closing).max(self.accts_final)}}

pub fn derive(cp:&ConsensusParams)->SysBounds{
    let s=u64::from(cp.S_max);let d=u64::from(cp.D);let k=d.max(u64::from(cp.W_w));let rrm=u64::from(cp.REG_RECORDS_MAX);let m=u64::from(cp.M_max);
    let e=u64::from(cp.E_max);let ret=u64::from(cp.RET);let sw=u64::from(cp.SWEEP_MAX).min(16);let o=(s+1).min(m);let rmax=u64::from(cp.R_max);
    let slot_min=5+5*rrm+m + k*(2*o+2) + 2+3*(d+1) + 52;
    let common=9*e+(2*o+2)+(3*o+2)+1+4;
    let keys_normal=common+1+(2+8*sw+1)+2;
    let keys_closing=common+(1+ret+1)+1+2;
    let keys_final=common+(1+ret+1)+1+2+4*d.saturating_sub(1);
    let accts_normal=8+o+1+sw;let accts_closing=8+o+1+ret;let accts_final=8+(d*(o+1)).min(m+rmax*d+1)+ret;
    SysBounds{slot_min,keys_normal,keys_closing,keys_final,accts_normal,accts_closing,accts_final}
}
/// R18 (general, v1 layout): SYS_SLOT_MAX >= slot_min, per-block key/account caps
/// cover every phase class, and G_SYS can hold at least the per-call cap.
pub fn r18(cp:&ConsensusParams)->Result<SysBounds,Vec<String>>{
    let b=derive(cp);let mut v=Vec::new();
    if u64::from(cp.SYS_SLOT_MAX)<b.slot_min{v.push(format!("SYS_SLOT_MAX {} < {}",cp.SYS_SLOT_MAX,b.slot_min))}
    if u64::from(cp.SYS_KEYS_BLOCK_MAX)<b.keys_max(){v.push(format!("SYS_KEYS_BLOCK_MAX {} < {}",cp.SYS_KEYS_BLOCK_MAX,b.keys_max()))}
    if u64::from(cp.SYS_ACCT_BLOCK_MAX)<b.accts_max(){v.push(format!("SYS_ACCT_BLOCK_MAX {} < {}",cp.SYS_ACCT_BLOCK_MAX,b.accts_max()))}
    if cp.G_SYS<crate::apply::PER_CALL_GAS{v.push("G_SYS below per-call cap".into())}
    if v.is_empty(){Ok(b)}else{Err(v)}
}
/// Counts the actual SYS storage slots present (nonzero) in a state.
pub fn sys_slots(db:&revm::InMemoryDB)->u64{
    (0..5).map(|i|db.accounts.get(&crate::apply::program_address(i)).map(|a|a.storage.values().filter(|v|**v!=revm::primitives::U256::ZERO).count() as u64).unwrap_or(0)).sum()
}
/// R21 for snapshot-retaining nodes: retained state bytes <= (K_hist + side) x
/// bytes(state). With S_acct accounts and S_slot slots, bytes(state) <=
/// S_acct*ACCOUNT_BYTES + S_slot*SLOT_BYTES (in-memory InMemoryDB model).
pub const ACCOUNT_BYTES:u64=200;pub const SLOT_BYTES:u64=96;
pub fn r21_retained_bytes(k_hist:u64,side:u64,accounts:u64,slots:u64)->u64{(k_hist+side)*(accounts*ACCOUNT_BYTES+slots*SLOT_BYTES)}

#[cfg(test)] mod tests;

/// A13: resident bytes of one state snapshot (revm `InMemoryDB` as the node keeps it), from
/// the actual container layout. A hashbrown table of n >= 1 entries has at most
/// max(4, next_pow2(⌈8n/7⌉)) <= 6 + 16n/7 buckets (tables never shrink, so n is the peak
/// count; containers are normalized after every commit so the peak follows the live state),
/// each holding one entry and one control byte, plus a 16-byte trailing group and alignment.
/// The bound holds for every distribution of slots over accounts: each account's storage
/// table costs at most (6 + 16·s/7) buckets. Code bytes are reference-counted and shared by
/// clones, so `code_bytes` counts them separately. Checked u128 arithmetic throughout.
pub mod memory{
    use revm::{db::DbAccount,primitives::{Address,B256,Bytecode,U256}};
    pub const ACCOUNT_ENTRY:u128=std::mem::size_of::<(Address,DbAccount)>() as u128;
    pub const SLOT_ENTRY:u128=std::mem::size_of::<(U256,U256)>() as u128;
    pub const CODE_ENTRY:u128=std::mem::size_of::<(B256,Bytecode)>() as u128;
    pub const HASH_ENTRY:u128=std::mem::size_of::<(U256,B256)>() as u128;
    pub const DB:u128=std::mem::size_of::<revm::InMemoryDB>() as u128;
    /// BLOCKHASH window kept in a block's state (apply_block ancestors).
    pub const ANCESTORS:u128=256;
    /// Bytes of hashbrown tables holding `n` entries in total spread over `tables` tables.
    pub fn tables(n:u128,tables:u128,entry:u128)->Option<u128>{
        if n==0{return Some(0)}
        let buckets=n.checked_mul(16)?.div_ceil(7).checked_add(tables.checked_mul(6)?)?;
        buckets.checked_mul(entry.checked_add(1)?)?.checked_add(tables.checked_mul(32)?)
    }
    /// One snapshot with at most `accounts` accounts, `slots` storage slots and `codes`
    /// code entries; None on overflow (the caller rejects).
    pub fn snapshot(accounts:u128,slots:u128,codes:u128)->Option<u128>{
        let a=tables(accounts,1,ACCOUNT_ENTRY)?;let s=tables(slots,accounts.min(slots),SLOT_ENTRY)?;
        let c=tables(codes,1,CODE_ENTRY)?;let h=tables(ANCESTORS,1,HASH_ENTRY)?;
        a.checked_add(s)?.checked_add(c)?.checked_add(h)?.checked_add(DB)
    }
    /// A pruned (default) state: the default code entries and the empty containers.
    pub fn empty_snapshot()->Option<u128>{tables(2,1,CODE_ENTRY)?.checked_add(DB)}
    /// Code payload with its analysis (jump table of len/8 bytes plus padding) and the
    /// shared allocation headers, for `logical` code bytes in `codes` code entries.
    pub fn code_bytes(logical:u128,codes:u128)->Option<u128>{
        logical.checked_add(logical/8)?.checked_add(codes.checked_mul(33+64)?)
    }

    /// Largest gas any single EVM execution can consume: a SYSTEM call is capped at
    /// apply::PER_CALL_GAS, a transaction at GAS_LIMIT, pocold's eth_call/eth_estimateGas at
    /// the same 30M (pocold::rpc::CALL_GAS_MAX).
    pub fn execution_gas(gas_limit:u64)->u128{u128::from(gas_limit.max(crate::apply::PER_CALL_GAS))}
    /// Call frames alive at once (revm `CALL_STACK_LIMIT` + the top frame) and their sizes.
    pub const FRAMES:u128=revm::CALL_STACK_LIMIT as u128+1;
    pub const FRAME_BYTES:u128=4096;
    pub const STACK_BYTES:u128=(revm::interpreter::STACK_LIMIT*32) as u128;
    pub const JOURNAL_ENTRY:u128=std::mem::size_of::<revm::JournalEntry>() as u128;
    pub const TRANSIENT_ENTRY:u128=std::mem::size_of::<((Address,U256),U256)>() as u128;
    pub const STATE_ACCOUNT:u128=std::mem::size_of::<(Address,revm::primitives::Account)>() as u128;
    pub const STATE_SLOT:u128=std::mem::size_of::<(U256,revm::primitives::EvmStorageSlot)>() as u128;
    pub const LOG_ENTRY:u128=std::mem::size_of::<revm::primitives::Log>() as u128;
    /// Process-lifetime precompile tables (the KZG trusted setup, loaded once).
    pub const PRECOMPILE_STATIC:u128=8<<20;
    /// Memory words purchasable with `g` gas in one frame: the largest w with 3w + w²/512 <= g.
    pub fn words(g:u128)->u128{let (mut lo,mut hi)=(0u128,1u128<<40);while lo<hi{let m=(lo+hi+1)/2;if 3*m+m*m/512<=g{lo=m}else{hi=m-1}}lo}
    /// A13 obligation 4: heap of one EVM execution (revm 19.7, CANCUN) consuming at most `gas`.
    /// Every term is paid for in gas (yellow paper / EIP-2929/1153/3860 costs):
    /// - memory: at most 2·FRAMES regions are paid for at once (active frames and one returned
    ///   child per frame whose output is held); their words cost 3w + w²/512 each, from disjoint
    ///   gas, so by convexity their total is at most 2·FRAMES·words(gas/(2·FRAMES)) = W. The
    ///   shared buffer keeps at most twice its peak (Vec growth), each frame's input is a range
    ///   of its caller's memory, and each frame holds one return buffer (a returned child's
    ///   memory or a precompile output no larger than the caller's memory, +64 B): 128·W bytes;
    /// - stacks and frames: FRAMES × (STACK_LIMIT words + a 4 KiB frame);
    /// - journal: every entry-producing operation costs >= 100 gas and adds <= 2 entries, plus
    ///   two per frame; Vec growth doubles;
    /// - transient storage (TSTORE >= 100 gas per key) and loaded state (a cold account >= 2400,
    ///   a cold slot >= 1900 including access lists; +32 fixed accounts), each table at most
    ///   twice its final size while it rehashes, the loaded state also cached by the engine DB;
    /// - logs: data <= gas/8 bytes, <= gas/375 entries and topics; created code <= gas/200
    ///   bytes (code deposit) with its analysis, <= gas/32000 creations;
    /// - precompile working memory <= 8 × the largest single-frame memory, plus the static tables.
    pub fn execution(gas:u128)->Option<u128>{
        let n=2*FRAMES;let w=n.checked_mul(words(gas/n))?;
        let buffers=w.checked_mul(128)?.checked_add(FRAMES*64)?;
        let frames=FRAMES.checked_mul(STACK_BYTES+FRAME_BYTES)?;
        let journal=(gas/50+2*FRAMES).checked_mul(JOURNAL_ENTRY)?.checked_mul(2)?.checked_add(FRAMES*24)?;
        let transient=tables(gas/100,1,TRANSIENT_ENTRY)?.checked_mul(2)?;
        let accounts=gas/2400+32;let slots=gas/1900;
        let state=tables(accounts,1,STATE_ACCOUNT)?.checked_add(tables(slots,accounts.min(slots),STATE_SLOT)?)?.checked_add(tables(accounts,1,ACCOUNT_ENTRY)?)?
            .checked_add(tables(slots,accounts.min(slots),SLOT_ENTRY)?)?.checked_mul(2)?;
        let logs=(gas/8).checked_add((gas/375).checked_mul(LOG_ENTRY*2+32)?)?;
        let code=code_bytes(gas/200,gas/32000+1)?;
        let precompile=words(gas).checked_mul(32*8)?.checked_add(PRECOMPILE_STATIC)?;
        buffers.checked_add(frames)?.checked_add(journal)?.checked_add(transient)?.checked_add(state)?.checked_add(logs)?.checked_add(code)?.checked_add(precompile)
    }
}
