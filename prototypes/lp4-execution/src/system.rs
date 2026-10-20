//! LP4-SYS-01 execution primitive. Not block admission or boot authorization.
//! This module is crate-private until P5 derives its inputs from validated UT,
//! stored headers and the prescribed phase schedule. Tests cannot authorize boot.
use revm::{InMemoryDB, DatabaseCommit, FrameOrResult,
    primitives::{Address, Bytes, EvmState, TxEnv, TxKind, U256}, interpreter::CallInputs};
use crate::{native::{self, NativeBlockContext}, profile::ProfileIdentity};
pub(crate) const PER_CALL_GAS:u64=30_000_000;
pub(crate) fn system_address()->Address { let mut a=[0xff;20];a[19]=0xfe;Address::from(a) }

/// Only structural metadata validation here. Cryptographic UT admission and
/// fallback validation belong to P5; this type is not publicly constructible.
#[derive(Clone,Copy)]
pub(crate) enum Proposer { Signed(Address), Fallback }
impl Proposer {
    fn origin(self)->Result<Address,SystemError>{match self{
        Self::Signed(a) if a!=Address::ZERO=>Ok(a),Self::Fallback=>Ok(Address::ZERO),
        _=>Err(SystemError::Metadata),
    }}
    pub(crate) fn pending_word(self)->Result<U256,SystemError>{
        let origin=self.origin()?;
        Ok((U256::from_be_slice(origin.as_slice())<<8)|U256::from(matches!(self,Self::Fallback) as u64))
    }
}
#[derive(Debug,PartialEq,Eq)]
pub(crate) enum SystemError { Metadata, Context, Budget, Execution(String), UnexpectedLogs, Poisoned }
#[derive(Debug)]
pub(crate) struct Observation {pub raw_gas:u64,pub refund_counter:i64,pub output:Bytes}

/// Private candidate: no canonical storage reference or commit/public finish API.
/// Any failure poisons all prior effects; the caller cannot resume a failed block.
/// Disk persistence, USER integration and validated phase ordering remain P5/P9.
pub(crate) struct Candidate<'a> {
    state:InMemoryDB,
    profile:&'a ProfileIdentity,
    block:&'a NativeBlockContext,
    proposer:Proposer,
    used:u64,
    failed:bool,
}
impl<'a> Candidate<'a> {
    pub(crate) fn new(snapshot:&InMemoryDB,profile:&'a ProfileIdentity,block:&'a NativeBlockContext,proposer:Proposer)->Result<Self,SystemError>{
        proposer.origin()?;
        if block.height==U256::ZERO || block.gas_limit!=U256::from(profile.cp().GAS_LIMIT){return Err(SystemError::Context)}
        let limits=crate::code_caps::CodeLimits{runtime:profile.cp().B_code_max,logical:profile.cp().CODE_CAP};
        crate::code_caps::validate_snapshot(snapshot,limits).map_err(SystemError::Execution)?;
        Ok(Self{state:snapshot.clone(),profile,block,proposer,used:0,failed:false})
    }
    pub(crate) fn call(&mut self,to:Address,data:Bytes)->Result<Observation,SystemError>{
        if self.failed{return Err(SystemError::Poisoned)}
        let result=self.call_inner(to,data);
        if result.is_err(){self.failed=true;self.state=InMemoryDB::default();}
        result
    }
    fn call_inner(&mut self,to:Address,data:Bytes)->Result<Observation,SystemError>{
        let remaining=self.profile.cp().G_SYS.checked_sub(self.used).ok_or(SystemError::Budget)?;
        let allocation=remaining.min(PER_CALL_GAS);
        if allocation==0{return Err(SystemError::Budget)}
        let origin=self.proposer.origin()?;
        let limits=crate::code_caps::CodeLimits{runtime:self.profile.cp().B_code_max,logical:self.profile.cp().CODE_CAP};
        let tx=TxEnv{caller:origin,transact_to:TxKind::Call(to),gas_limit:allocation,
            gas_price:U256::ZERO,value:U256::ZERO,data,chain_id:Some(self.profile.spec().chain_id),..Default::default()};
        let mut evm=native::build_engine(&self.state,tx,self.block,self.profile.spec().chain_id,Some(limits));
        // No transact(), caller deduction, intrinsic gas or transaction post-handler.
        evm.handler.pre_execution.load_accounts(&mut evm.context).map_err(|e|SystemError::Execution(format!("{e:?}")))?;
        let precompiles=evm.handler.pre_execution.load_precompiles();
        evm.context.evm.set_precompiles(precompiles);
        for address in [system_address(),to,crate::pay::escrow_address()] {
            evm.context.evm.journaled_state.warm_preloaded_addresses.insert(address);
        }
        if origin!=Address::ZERO{evm.context.evm.journaled_state.warm_preloaded_addresses.insert(origin);}
        let mut input=CallInputs::new_boxed(&evm.context.evm.env.tx,allocation).ok_or(SystemError::Context)?;
        input.caller=system_address();
        let first=evm.handler.execution.call(&mut evm.context,input).map_err(|e|SystemError::Execution(format!("{e:?}")))?;
        let result=match first{
            FrameOrResult::Frame(frame)=>evm.run_the_loop(frame).map_err(|e|SystemError::Execution(format!("{e:?}")))?,
            FrameOrResult::Result(result)=>result,
        }.into_interpreter_result();
        if !result.result.is_ok(){return Err(SystemError::Execution(format!("{:?}",result.result)))}
        let raw=result.gas.spent();
        self.used=self.used.checked_add(raw).ok_or(SystemError::Budget)?;
        if self.used>self.profile.cp().G_SYS{return Err(SystemError::Budget)}
        let (state,logs)=evm.context.evm.journaled_state.finalize();
        // Initial approved programs emit none. A log is an error, never dropped.
        if !logs.is_empty(){return Err(SystemError::UnexpectedLogs)}
        commit_epoch(&mut self.state,state);
        crate::code_caps::validate_snapshot(&self.state,limits).map_err(SystemError::Execution)?;
        Ok(Observation{raw_gas:raw,refund_counter:result.gas.refunded(),output:result.output})
    }
    pub(crate) fn snapshot(&self)->Result<&InMemoryDB,SystemError>{if self.failed{Err(SystemError::Poisoned)}else{Ok(&self.state)}}
    pub(crate) fn used(&self)->u64{self.used}
}
fn commit_epoch(db:&mut InMemoryDB,state:EvmState){
    let removed:Vec<_>=state.iter().filter(|(_,a)|a.is_selfdestructed()||(a.is_touched()&&a.is_empty())).map(|(a,_)|*a).collect();
    db.commit(state);
    for address in removed{let a=db.accounts.entry(address).or_default();a.account_state=revm::db::AccountState::NotExisting;a.storage.clear();a.info=Default::default();}
}

#[cfg(test)] mod tests;
