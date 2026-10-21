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
