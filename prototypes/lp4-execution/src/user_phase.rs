//! Transactional USER phase only. NOT PoCol block acceptance or persisted commit.
//! Context must later be bound to stored headers by P5. No system phase or final
//! header state-root comparison is claimed here. Budgets are local API bounds.
use std::collections::HashSet;
use revm::{DatabaseCommit,InMemoryDB,db::AccountState};
use revm::primitives::{Address,B256,EvmState,Log,TxEnv,U256};
use crate::{native::{self,NativeBlockContext},wire::{self,WireError},receipts,fees};
/// `DirtyAccounts`/`AcctCap`: even the halt's own nonce/fee effects would exceed the
/// limit, so the transaction cannot be included (block invalid; builders skip it).
#[derive(Debug,Clone,PartialEq,Eq)] pub enum UserError{Context,Budget,Wire(usize,WireError),Execution(usize,String),Gas,Arithmetic,Root,Commitments,DirtyAccounts(usize),AcctCap(usize)}

/// execution.md السقوف (A03): limits whose violation is an exceptional halt of the
/// transaction. All of its gas is charged, its state changes are reverted except the
/// nonce increment and the fee payment, its receipt has status 0 and no logs, and the
/// block stays valid. Log accounting follows decision LOG-ACCT-01.
pub mod caps{
    /// Per-block log bytes; one log is charged 36 + 32·|topics| + |data| (LOG-ACCT-01).
    pub const LOG_BLOCK_MAX:u64=32*1024;
    /// Logs per block (LG2: 546 succeed, 547 halt; lemma P1).
    pub const LOG_COUNT_MAX:u64=546;
    /// Aggregate charged log bytes over the canonical chain.
    pub const LOG_CAP:u64=1<<30;
    /// Distinct storage keys and distinct accounts changed by USER transactions in a block.
    pub const DIRTY_BLOCK_MAX:usize=4096;
    pub const ACCT_DIRTY_BLOCK_MAX:usize=2048;
    /// User-context SYS allowance per block: SYS_KEYS_USER_MAX keys (CP) and 16 accounts; none while closing.
    pub const USER_SYS_ACCOUNTS:usize=16;
}
/// Why a transaction halted exceptionally.
#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub enum Halt{LogCount,LogBytes,LogCap,DirtyKeys,DirtyAccounts,SlotCap,AcctCap,SysKeys,SysAccounts,SysWriteClosing}
/// LOG-ACCT-01 charge of a transaction's logs.
pub fn log_charge(logs:&[Log])->u64{logs.iter().map(|l|36+32*l.data.topics().len() as u64+l.data.data.len() as u64).sum()}
/// Block-level context of the USER phase.
#[derive(Clone,Copy,Debug,Default,PartialEq,Eq)]
pub struct UserContext{
    /// Charged log bytes of the canonical ancestors (LOG_CAP).
    pub cum_log_bytes:u64,
    /// The block executes in the closing phase (no user SYS writes).
    pub closing:bool,
}
#[derive(Clone,Debug,PartialEq,Eq)] pub struct UserCommitments{
 pub transactions_root:B256,pub receipts_root:B256,pub gas_used:u64,pub logs_bloom:[u8;256],
}
pub struct UserCandidate{state:InMemoryDB,commitments:UserCommitments,receipts:Vec<Vec<u8>>,tips:U256,log_bytes:u64,halts:Vec<(usize,Halt)>}
impl UserCandidate{
 pub fn state(&self)->&InMemoryDB{&self.state}
 /// Charged log bytes of this block (LOG-ACCT-01).
 pub fn log_bytes(&self)->u64{self.log_bytes}
 /// Transactions that halted exceptionally, by index.
 pub fn halts(&self)->&[(usize,Halt)]{&self.halts}
 pub fn commitments(&self)->&UserCommitments{&self.commitments}
 pub fn receipts(&self)->&[Vec<u8>]{&self.receipts}
 pub fn tips(&self)->U256{self.tips}
 /// Intermediate USER root, never the final PoCol header state root.
 pub fn state_root(&self,account_budget:usize,slot_budget_per_account:usize)->Result<B256,UserError>{
  let mut accounts=Vec::new();
  for (address,a) in &self.state.accounts{
   if a.account_state==AccountState::NotExisting{continue}
   if accounts.len()>=account_budget || a.storage.len()>slot_budget_per_account{return Err(UserError::Budget)}
   let number=|v:U256|crate::fixed::U256::from_be_slice(&v.to_be_bytes::<32>()).unwrap();
   let slots=a.storage.iter().map(|(k,v)|(number(*k),number(*v))).collect::<Vec<_>>();
   accounts.push(crate::trie::Account{address:address.0.0,nonce:a.info.nonce,balance:number(a.info.balance),storage_root:crate::trie::storage_root(&slots,slot_budget_per_account).map_err(|_|UserError::Root)?,code_hash:a.info.code_hash.0});
  }
  crate::trie::state_root(&accounts,account_budget).map(B256::from).map_err(|_|UserError::Root)
 }
}
/// Builds an isolated candidate. It cannot mutate the caller's snapshot.
pub fn execute_user_phase(snapshot:&InMemoryDB,raw:&[Vec<u8>],block:&NativeBlockContext,byte_budget:usize,entry_budget:usize)->Result<UserCandidate,UserError>{
 execute_user_phase_inner(snapshot,raw,block,byte_budget,entry_budget,None)
}
/// Profile-bound USER phase. Identity/schema is not ParamGate/boot acceptance.
pub fn execute_for_profile(snapshot:&InMemoryDB,raw:&[Vec<u8>],block:&NativeBlockContext,byte_budget:usize,entry_budget:usize,profile:&crate::profile::ProfileIdentity)->Result<UserCandidate,UserError>{
 execute_for_block(snapshot,raw,block,byte_budget,entry_budget,profile,UserContext::default())
}
/// Profile-bound USER phase of a block, with its log history and closing state.
pub fn execute_for_block(snapshot:&InMemoryDB,raw:&[Vec<u8>],block:&NativeBlockContext,byte_budget:usize,entry_budget:usize,profile:&crate::profile::ProfileIdentity,ctx:UserContext)->Result<UserCandidate,UserError>{
 if block.gas_limit!=U256::from(profile.cp().GAS_LIMIT){return Err(UserError::Context)}
 execute_user_phase_inner_ctx(snapshot,raw,block,byte_budget,entry_budget,Some(profile),ctx)
}

/// A13: CacheDB::commit stores every accessed slot (zero values and slots that were only
/// read) and the EIP-161 cleanup leaves NotExisting entries, so containers would grow with
/// every key ever touched. In this EmptyDB-backed state an absent slot reads 0 and an absent
/// account does not exist, exactly as those entries do, and roots ignore both; dropping them
/// keeps every container proportional to the live state that SLOT_CAP/ACCT_CAP bound.
/// Tables never shrink by themselves, so a table left oversized by such entries is shrunk:
/// every table then has at most the buckets its current entries need (resources::memory).
pub fn normalize(db:&mut InMemoryDB,touched:&[Address]){
 for a in touched{
  let gone=match db.accounts.get_mut(a){Some(x) if x.account_state==AccountState::NotExisting||x.info().is_none()=>true,
   Some(x)=>{x.storage.retain(|_,v|*v!=U256::ZERO);if x.storage.capacity()>2*x.storage.len()+8{x.storage.shrink_to_fit()}false},None=>false};
  if gone{db.accounts.remove(a);}
 }
 if db.accounts.capacity()>2*db.accounts.len()+16{db.accounts.shrink_to_fit()}
}
/// Code bytes no existing account references (A13), kept out of later snapshots.
pub fn drop_unreferenced_code(db:&mut InMemoryDB){
 let used:HashSet<B256>=db.accounts.values().filter_map(|a|a.info()).map(|i|i.code_hash).collect();
 db.contracts.retain(|h,_|used.contains(h)||*h==revm::primitives::KECCAK_EMPTY||*h==B256::ZERO);
 if db.contracts.capacity()>2*db.contracts.len()+16{db.contracts.shrink_to_fit()}
}
/// Per-block meter of the A03 limits; live counts follow the state incrementally.
struct BlockMeter{log_bytes:u64,log_count:u64,cum_log:u64,dirty_keys:HashSet<(Address,U256)>,dirty_accts:HashSet<Address>,
    sys_keys:HashSet<(Address,U256)>,sys_accts:HashSet<Address>,live_slots:u64,live_accts:u64,closing:bool,
    /// SLOT_CAP, ACCT_CAP, SYS_KEYS_USER_MAX when profile-bound.
    caps:Option<(u64,u64,u64)>}
/// Effects of one transaction's state diff on the meter, before it is committed.
#[derive(Default)]
struct Effects{keys:Vec<(Address,U256)>,accts:Vec<Address>,sys_keys:Vec<(Address,U256)>,sys_accts:Vec<Address>,d_slots:i64,d_accts:i64}
fn is_system(a:&Address)->bool{(0..5).any(|i|*a==crate::apply::program_address(i))}
/// Live (nonzero) storage slots and existing accounts of the user state (outside the five
/// system programs), counted as genesis check_caps does (D-A03-CAPS).
pub(crate) fn live_counts(db:&InMemoryDB)->(u64,u64){
 let mut slots=0u64;let mut accts=0u64;
 for (_,a) in db.accounts.iter().filter(|(k,a)|a.info().is_some()&&!is_system(k)){accts+=1;slots+=a.storage.values().filter(|v|**v!=U256::ZERO).count() as u64;}
 (slots,accts)
}
fn effects(pre:&InMemoryDB,post:&EvmState)->Effects{
 let mut e=Effects::default();
 for (a,acct) in post{
  if !acct.is_touched(){continue}
  let before=pre.accounts.get(a);let pre_info=before.and_then(|x|x.info());
  let removed=acct.is_selfdestructed()||acct.is_empty();
  let changed:Vec<U256>=if removed{vec![]}else{acct.storage.iter().filter(|(_,v)|v.is_changed()).map(|(k,_)|*k).collect()};
  let pre_slots=before.map(|x|x.storage.values().filter(|v|**v!=U256::ZERO).count() as i64).unwrap_or(0);
  let info_changed=match &pre_info{Some(i)=>removed||i.balance!=acct.info.balance||i.nonce!=acct.info.nonce||i.code_hash!=acct.info.code_hash,None=>!removed};
  if info_changed||!changed.is_empty()||(removed&&pre_slots>0){e.accts.push(*a)}
  for k in &changed{e.keys.push((*a,*k))}
  let user=!is_system(a);
  if removed{if pre_info.is_some()&&user{e.d_accts-=1;e.d_slots-=pre_slots;}
   // Removed slots of a removed account are dirty as well.
   if let Some(x)=before{for (k,v) in &x.storage{if *v!=U256::ZERO{e.keys.push((*a,*k))}}}}
  else if user{
   if pre_info.is_none(){e.d_accts+=1}
   for (_,v) in acct.storage.iter().filter(|(_,v)|v.is_changed()){
    if v.original_value()==U256::ZERO&&v.present_value()!=U256::ZERO{e.d_slots+=1}else if v.original_value()!=U256::ZERO&&v.present_value()==U256::ZERO{e.d_slots-=1}
   }
  }
  if is_system(a)&&!changed.is_empty(){e.sys_accts.push(*a);for k in &changed{e.sys_keys.push((*a,*k))}}
 }
 e
}
fn new_count<T:std::hash::Hash+Eq+Copy>(set:&HashSet<T>,items:&[T])->usize{let mut seen=HashSet::new();items.iter().filter(|x|!set.contains(x)&&seen.insert(**x)).count()}
fn add(n:u64,d:i64)->u64{if d>=0{n.saturating_add(d as u64)}else{n.saturating_sub(d.unsigned_abs())}}
impl BlockMeter{
 /// The first violated limit, if the transaction's logs and state diff were committed.
 fn check(&self,logs:&[Log],e:&Effects)->Option<Halt>{
  let n=logs.len() as u64;let charge=log_charge(logs);
  if self.log_count+n>caps::LOG_COUNT_MAX{return Some(Halt::LogCount)}
  if self.log_bytes+charge>caps::LOG_BLOCK_MAX{return Some(Halt::LogBytes)}
  if self.cum_log.saturating_add(self.log_bytes+charge)>caps::LOG_CAP{return Some(Halt::LogCap)}
  if self.dirty_keys.len()+new_count(&self.dirty_keys,&e.keys)>caps::DIRTY_BLOCK_MAX{return Some(Halt::DirtyKeys)}
  if self.dirty_accts.len()+new_count(&self.dirty_accts,&e.accts)>caps::ACCT_DIRTY_BLOCK_MAX{return Some(Halt::DirtyAccounts)}
  if let Some((slot_cap,acct_cap,sys_keys))=self.caps{
   if add(self.live_slots,e.d_slots)>slot_cap{return Some(Halt::SlotCap)}
   if add(self.live_accts,e.d_accts)>acct_cap{return Some(Halt::AcctCap)}
   if !e.sys_keys.is_empty()&&self.closing{return Some(Halt::SysWriteClosing)}
   if (self.sys_keys.len()+new_count(&self.sys_keys,&e.sys_keys)) as u64>sys_keys{return Some(Halt::SysKeys)}
   if self.sys_accts.len()+new_count(&self.sys_accts,&e.sys_accts)>caps::USER_SYS_ACCOUNTS{return Some(Halt::SysAccounts)}
  }
  None
 }
 fn commit(&mut self,logs:&[Log],e:Effects){
  self.log_count+=logs.len() as u64;self.log_bytes+=log_charge(logs);
  self.dirty_keys.extend(e.keys);self.dirty_accts.extend(e.accts);self.sys_keys.extend(e.sys_keys);self.sys_accts.extend(e.sys_accts);
  self.live_slots=add(self.live_slots,e.d_slots);self.live_accts=add(self.live_accts,e.d_accts);
 }
}
/// Exceptional halt applied to the pre-transaction state: nonce + 1, the sender pays
/// gas_limit·price, the coinbase (Escrow) receives gas_limit·tip. Nothing else changes.
fn apply_halt(state:&mut InMemoryDB,m:&mut BlockMeter,tx:&TxEnv,price:U256,tip:U256,i:usize)->Result<(),UserError>{
 let fee=price.checked_mul(U256::from(tx.gas_limit)).ok_or(UserError::Arithmetic)?;let reward=tip.checked_mul(U256::from(tx.gas_limit)).ok_or(UserError::Arithmetic)?;
 let existed=state.accounts.get(&tx.caller).and_then(|a|a.info()).is_some();
 let mut sender=state.accounts.get(&tx.caller).and_then(|a|a.info()).unwrap_or_default();
 sender.nonce=sender.nonce.checked_add(1).ok_or(UserError::Arithmetic)?;sender.balance=sender.balance.checked_sub(fee).ok_or(UserError::Arithmetic)?;
 state.insert_account_info(tx.caller,sender);
 let coinbase=crate::pay::escrow_address();
 if reward!=U256::ZERO{let mut c=state.accounts.get(&coinbase).and_then(|a|a.info()).unwrap_or_default();c.balance=c.balance.checked_add(reward).ok_or(UserError::Arithmetic)?;state.insert_account_info(coinbase,c);}
 let mut touched=vec![tx.caller];if reward!=U256::ZERO{touched.push(coinbase)}
 if m.dirty_accts.len()+new_count(&m.dirty_accts,&touched)>caps::ACCT_DIRTY_BLOCK_MAX{return Err(UserError::DirtyAccounts(i))}
 if !existed{if let Some((_,acct_cap,_))=m.caps{if m.live_accts+1>acct_cap{return Err(UserError::AcctCap(i))}}m.live_accts+=1;}
 m.dirty_accts.extend(touched);Ok(())
}
fn execute_user_phase_inner(snapshot:&InMemoryDB,raw:&[Vec<u8>],block:&NativeBlockContext,byte_budget:usize,entry_budget:usize,profile:Option<&crate::profile::ProfileIdentity>)->Result<UserCandidate,UserError>{
 execute_user_phase_inner_ctx(snapshot,raw,block,byte_budget,entry_budget,profile,UserContext::default())
}
fn execute_user_phase_inner_ctx(snapshot:&InMemoryDB,raw:&[Vec<u8>],block:&NativeBlockContext,byte_budget:usize,entry_budget:usize,profile:Option<&crate::profile::ProfileIdentity>,ctx:UserContext)->Result<UserCandidate,UserError>{
 if raw.len()>entry_budget || raw.iter().try_fold(0usize,|n,v|n.checked_add(v.len())).ok_or(UserError::Budget)?>byte_budget{return Err(UserError::Budget)}
 let limit:u64=block.gas_limit.try_into().map_err(|_|UserError::Gas)?;
 let mut state=snapshot.clone();let mut used=0u64;let mut tips=U256::ZERO;let mut encoded=Vec::new();let mut bloom=[0u8;256];
 let (live_slots,live_accts)=if profile.is_some(){live_counts(snapshot)}else{(0,0)};
 let mut meter=BlockMeter{log_bytes:0,log_count:0,cum_log:ctx.cum_log_bytes,dirty_keys:HashSet::new(),dirty_accts:HashSet::new(),sys_keys:HashSet::new(),sys_accts:HashSet::new(),
  live_slots,live_accts,closing:ctx.closing,caps:profile.map(|p|(p.cp().SLOT_CAP,p.cp().ACCT_CAP,u64::from(p.cp().SYS_KEYS_USER_MAX)))};
 let mut halts=Vec::new();
 for (i,bytes) in raw.iter().enumerate(){
  let signed=match profile{Some(p)=>wire::decode_for_profile(bytes,p),None=>wire::decode_signed(bytes,byte_budget)}.map_err(|e|UserError::Wire(i,e))?;let tx=signed.tx_env();
  // Cancun reserves declared transaction gas against remaining block gas, not
  // merely the actual post-refund gas consumption of this transaction.
  if tx.gas_limit>limit.checked_sub(used).ok_or(UserError::Gas)?{return Err(UserError::Gas)}
  let (price,tip)=fees::effective_fees(block.base_fee,tx.gas_price,tx.gas_priority_fee).map_err(|_|UserError::Arithmetic)?;
  let result=match profile{Some(p)=>native::execute_for_profile(&state,tx.clone(),block,p),None=>native::execute_in_context(&state,tx.clone(),block)}.map_err(|e|UserError::Execution(i,format!("{e:?}")))?;
  let e=effects(&state,&result.state);
  // The caps are PoCol execution: the profile-free Cancun control path stays geth-equivalent.
  if let Some(why)=profile.and_then(|_|meter.check(result.result.logs(),&e)){
   // Exceptional halt (A03): all gas, no logs, status 0; only nonce and fee remain.
   apply_halt(&mut state,&mut meter,&tx,price,tip,i)?;halts.push((i,why));
   used=used.checked_add(tx.gas_limit).ok_or(UserError::Gas)?;if used>limit{return Err(UserError::Gas)}
   tips=tips.checked_add(tip.checked_mul(U256::from(tx.gas_limit)).ok_or(UserError::Arithmetic)?).ok_or(UserError::Arithmetic)?;
   encoded.push(receipts::encode(signed.kind(),false,used,&[]).map_err(|_|UserError::Root)?);
   continue;
  }
  meter.commit(result.result.logs(),e);
  let gas=result.result.gas_used();used=used.checked_add(gas).ok_or(UserError::Gas)?;if used>limit{return Err(UserError::Gas)}
  tips=tips.checked_add(tip.checked_mul(U256::from(gas)).ok_or(UserError::Arithmetic)?).ok_or(UserError::Arithmetic)?;
  encoded.push(receipts::encode(signed.kind(),result.result.is_success(),used,result.result.logs()).map_err(|_|UserError::Root)?);
  for (a,b) in bloom.iter_mut().zip(receipts::bloom(result.result.logs())){*a|=b}
  // EIP161 cleanup, as in the existing Cancun control runner. CacheDB::commit
  // alone keeps touched empty accounts; remove them before the next transaction.
  let removed:Vec<_>=result.state.iter().filter(|(_,a)|a.is_selfdestructed()||(a.is_touched()&&a.is_empty())).map(|(a,_)|*a).collect();
  let touched:Vec<_>=result.state.iter().filter(|(_,a)|a.is_touched()).map(|(a,_)|*a).collect();
  state.commit(result.state);
  for address in removed{let a=state.accounts.entry(address).or_default();a.account_state=AccountState::NotExisting;a.storage.clear();a.info=Default::default();}
  if profile.is_some(){normalize(&mut state,&touched)}
 }
 let commitments=UserCommitments{transactions_root:receipts::ordered_root(raw,entry_budget).map_err(|_|UserError::Root)?,receipts_root:receipts::ordered_root(&encoded,entry_budget).map_err(|_|UserError::Root)?,gas_used:used,logs_bloom:bloom};
 Ok(UserCandidate{state,commitments,receipts:encoded,tips,log_bytes:meter.log_bytes,halts})
}
/// Validates USER-phase commitments only. No storage/block acceptance side effect.
pub fn validate_user_phase(snapshot:&InMemoryDB,raw:&[Vec<u8>],block:&NativeBlockContext,byte_budget:usize,entry_budget:usize,expected:&UserCommitments)->Result<UserCandidate,UserError>{
 let candidate=execute_user_phase(snapshot,raw,block,byte_budget,entry_budget)?;
 if candidate.commitments()!=expected{return Err(UserError::Commitments)}
 Ok(candidate)
}

#[cfg(test)]
mod tests{
 use super::*;
 fn meter(closing:bool,sys_keys:u64)->BlockMeter{BlockMeter{log_bytes:0,log_count:0,cum_log:0,dirty_keys:HashSet::new(),dirty_accts:HashSet::new(),sys_keys:HashSet::new(),sys_accts:HashSet::new(),
  live_slots:0,live_accts:0,closing,caps:Some((u64::MAX,u64::MAX,sys_keys))}}
 fn sys_write(n:u64)->Effects{let a=crate::apply::program_address(0);Effects{keys:(0..n).map(|k|(a,U256::from(k))).collect(),accts:vec![a],sys_keys:(0..n).map(|k|(a,U256::from(k))).collect(),sys_accts:vec![a],d_slots:0,d_accts:0}}
 #[test] fn user_context_sys_allowance_and_closing(){
  // v1 programs expose no USER-callable storage writes; the rule is enforced regardless.
  assert_eq!(meter(false,256).check(&[],&sys_write(256)),None);
  assert_eq!(meter(false,256).check(&[],&sys_write(257)),Some(Halt::SysKeys));
  assert_eq!(meter(true,256).check(&[],&sys_write(1)),Some(Halt::SysWriteClosing));
  assert_eq!(meter(true,256).check(&[],&Effects::default()),None,"no SYS write, no halt while closing");
  let mut m=meter(false,256);m.sys_accts=(0..16u8).map(|i|Address::from([i;20])).collect();
  assert_eq!(m.check(&[],&sys_write(1)),Some(Halt::SysAccounts),"a 17th system account");
 }
}
