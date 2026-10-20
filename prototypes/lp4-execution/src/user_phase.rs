//! Transactional USER phase only. NOT PoCol block acceptance or persisted commit.
//! Context must later be bound to stored headers by P5. No system phase or final
//! header state-root comparison is claimed here. Budgets are local API bounds.
use revm::{DatabaseCommit,InMemoryDB,db::AccountState};
use revm::primitives::{B256,U256};
use crate::{native::{self,NativeBlockContext},wire::{self,WireError},receipts,fees};
#[derive(Debug,Clone,PartialEq,Eq)] pub enum UserError{Context,Budget,Wire(usize,WireError),Execution(usize,String),Gas,Arithmetic,Root,Commitments}
#[derive(Clone,Debug,PartialEq,Eq)] pub struct UserCommitments{
 pub transactions_root:B256,pub receipts_root:B256,pub gas_used:u64,pub logs_bloom:[u8;256],
}
pub struct UserCandidate{state:InMemoryDB,commitments:UserCommitments,receipts:Vec<Vec<u8>>,tips:U256}
impl UserCandidate{
 pub fn state(&self)->&InMemoryDB{&self.state}
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
 if block.gas_limit!=U256::from(profile.cp().GAS_LIMIT){return Err(UserError::Context)}
 execute_user_phase_inner(snapshot,raw,block,byte_budget,entry_budget,Some(profile))
}
fn execute_user_phase_inner(snapshot:&InMemoryDB,raw:&[Vec<u8>],block:&NativeBlockContext,byte_budget:usize,entry_budget:usize,profile:Option<&crate::profile::ProfileIdentity>)->Result<UserCandidate,UserError>{
 if raw.len()>entry_budget || raw.iter().try_fold(0usize,|n,v|n.checked_add(v.len())).ok_or(UserError::Budget)?>byte_budget{return Err(UserError::Budget)}
 let limit:u64=block.gas_limit.try_into().map_err(|_|UserError::Gas)?;
 let mut state=snapshot.clone();let mut used=0u64;let mut tips=U256::ZERO;let mut encoded=Vec::new();let mut bloom=[0u8;256];
 for (i,bytes) in raw.iter().enumerate(){
  let signed=match profile{Some(p)=>wire::decode_for_profile(bytes,p),None=>wire::decode_signed(bytes,byte_budget)}.map_err(|e|UserError::Wire(i,e))?;let tx=signed.tx_env();
  // Cancun reserves declared transaction gas against remaining block gas, not
  // merely the actual post-refund gas consumption of this transaction.
  if tx.gas_limit>limit.checked_sub(used).ok_or(UserError::Gas)?{return Err(UserError::Gas)}
  let (_,tip)=fees::effective_fees(block.base_fee,tx.gas_price,tx.gas_priority_fee).map_err(|_|UserError::Arithmetic)?;
  let result=match profile{Some(p)=>native::execute_for_profile(&state,tx,block,p),None=>native::execute_in_context(&state,tx,block)}.map_err(|e|UserError::Execution(i,format!("{e:?}")))?;
  let gas=result.result.gas_used();used=used.checked_add(gas).ok_or(UserError::Gas)?;if used>limit{return Err(UserError::Gas)}
  tips=tips.checked_add(tip.checked_mul(U256::from(gas)).ok_or(UserError::Arithmetic)?).ok_or(UserError::Arithmetic)?;
  encoded.push(receipts::encode(signed.kind(),result.result.is_success(),used,result.result.logs()).map_err(|_|UserError::Root)?);
  for (a,b) in bloom.iter_mut().zip(receipts::bloom(result.result.logs())){*a|=b}
  // EIP161 cleanup, as in the existing Cancun control runner. CacheDB::commit
  // alone keeps touched empty accounts; remove them before the next transaction.
  let removed:Vec<_>=result.state.iter().filter(|(_,a)|a.is_selfdestructed()||(a.is_touched()&&a.is_empty())).map(|(a,_)|*a).collect();
  state.commit(result.state);
  for address in removed{let a=state.accounts.entry(address).or_default();a.account_state=AccountState::NotExisting;a.storage.clear();a.info=Default::default();}
 }
 let commitments=UserCommitments{transactions_root:receipts::ordered_root(raw,entry_budget).map_err(|_|UserError::Root)?,receipts_root:receipts::ordered_root(&encoded,entry_budget).map_err(|_|UserError::Root)?,gas_used:used,logs_bloom:bloom};
 Ok(UserCandidate{state,commitments,receipts:encoded,tips})
}
/// Validates USER-phase commitments only. No storage/block acceptance side effect.
pub fn validate_user_phase(snapshot:&InMemoryDB,raw:&[Vec<u8>],block:&NativeBlockContext,byte_budget:usize,entry_budget:usize,expected:&UserCommitments)->Result<UserCandidate,UserError>{
 let candidate=execute_user_phase(snapshot,raw,block,byte_budget,entry_budget)?;
 if candidate.commitments()!=expected{return Err(UserError::Commitments)}
 Ok(candidate)
}
