//! Experimental native backend; full LP4 acceptance and boot remain disabled.
//! PAY contracts: development/LP4-PAY-APPROVAL.md and LP4-PAY-LIFECYCLE-APPROVAL.md.
//! Profile-bound code limits: development/LP4-CODE-APPROVAL.md (LP4-CODE-01).
use std::sync::Arc;
use revm::{Evm, InMemoryDB};
use revm::primitives::{Address, B256, EVMError, InvalidTransaction, ResultAndState, SpecId, TxEnv, U256};
use crate::{pay::{self,NativeContext},pay_address,CHAIN_ID};

pub fn execute(snapshot:&InMemoryDB, tx:TxEnv) -> Result<ResultAndState,EVMError<core::convert::Infallible>> {
    execute_at(snapshot,tx,U256::ZERO)
}

/// Experimental explicit NUMBER for compiled controls; not a PoCol apply context.
pub fn execute_at(snapshot:&InMemoryDB, tx:TxEnv, height:U256) -> Result<ResultAndState,EVMError<core::convert::Infallible>> {
    execute_at_time(snapshot,tx,height,U256::ZERO)
}

/// Experimental NUMBER/TIMESTAMP context, not validated PoCol block admission.
pub fn execute_at_time(snapshot:&InMemoryDB, tx:TxEnv, height:U256, timestamp:U256) -> Result<ResultAndState,EVMError<core::convert::Infallible>> {
    execute_in_context(snapshot,tx,&NativeBlockContext{height,timestamp,gas_limit:U256::from(30_000_000u64),base_fee:U256::ZERO,prevrandao:B256::ZERO})
}

/// Host-supplied fields for execution controls. This is NOT validated block apply:
/// P5 must derive these fields and the complete ancestor cache from stored headers.
/// In particular prevrandao must eventually be SHA256('PoColRandao' || seal_p).
pub struct NativeBlockContext {
    pub height:U256,
    pub timestamp:U256,
    pub gas_limit:U256,
    pub base_fee:U256,
    pub prevrandao:B256,
}

/// Execute against an immutable snapshot, including its BLOCKHASH ancestor cache.
/// No EIP-4788 system call is inserted here. Transaction/block validation and all
/// other resource ceilings remain separate obligations, never caller flags.
/// This chain-only API retains baseline Cancun code limits for old controls.
/// PoCol candidates must use execute_for_profile for approved CODE-01 limits.
pub fn execute_in_context(snapshot:&InMemoryDB, tx:TxEnv, block:&NativeBlockContext) -> Result<ResultAndState,EVMError<core::convert::Infallible>> {
    execute_on_chain(snapshot,tx,block,CHAIN_ID,None)
}
/// Bound to the same accepted LP3 identity used by signed decoding. P5 still
/// must supply validated parent/header context; no schema check authorizes boot.
pub fn execute_for_profile(snapshot:&InMemoryDB,tx:TxEnv,block:&NativeBlockContext,profile:&crate::profile::ProfileIdentity)->Result<ResultAndState,EVMError<core::convert::Infallible>>{
    let limits=crate::code_caps::CodeLimits{runtime:profile.cp().B_code_max,logical:profile.cp().CODE_CAP};
    crate::code_caps::validate_snapshot(snapshot,limits).map_err(EVMError::Custom)?;
    execute_on_chain(snapshot,tx,block,profile.spec().chain_id,Some(limits))
}
fn execute_on_chain(snapshot:&InMemoryDB,tx:TxEnv,block:&NativeBlockContext,chain_id:u64,limits:Option<crate::code_caps::CodeLimits>)->Result<ResultAndState,EVMError<core::convert::Infallible>>{
    validate_nonce(snapshot,tx.caller,tx.nonce)?;
    let mut evm=Evm::builder().with_db(snapshot.clone()).with_external_context(NativeContext::from_snapshot(snapshot))
        .with_spec_id(SpecId::CANCUN)
        .modify_cfg_env(|cfg|cfg.chain_id=chain_id)
        .modify_block_env(|b|{b.number=block.height;b.timestamp=block.timestamp;b.gas_limit=block.gas_limit;b.basefee=block.base_fee;b.prevrandao=Some(block.prevrandao);b.coinbase=pay::escrow_address();b.blob_excess_gas_and_price=Some(revm::primitives::BlobExcessGasAndPrice::new(0,false));})
        .modify_tx_env(|t|*t=tx)
        .append_handler_register(|handler|{
            let previous=handler.execution.execute_frame.clone();
            handler.execution.execute_frame=Arc::new(move |frame,memory,tables,context|{
                context.external.active_code=frame.interpreter().contract.bytecode_address;
                previous(frame,memory,tables,context)
            });
            let previous=handler.execution.call.clone();
            handler.execution.call=Arc::new(move |context,inputs|{
                if inputs.bytecode_address==pay_address() || inputs.target_address==pay_address() {
                    pay::call(context,&inputs)
                } else { previous(context,inputs) }
            });
        }).append_handler_register(crate::collision::register)
        .append_handler_register_box(Box::new(move |handler| {
            if let Some(limits)=limits {crate::code_caps::register(handler,limits);}
        })).build();
    evm.transact()
}

/// EIP-2681: maximum u64 transaction/account nonce cannot be incremented.
/// revm 19.7.0 can otherwise return a normal result for max-nonce creation.
pub fn validate_nonce(snapshot:&InMemoryDB,caller:Address,nonce:Option<u64>) -> Result<(),EVMError<core::convert::Infallible>> {
    if nonce==Some(u64::MAX) || snapshot.accounts.get(&caller).map(|a|a.info.nonce==u64::MAX).unwrap_or(false) {
        Err(EVMError::Transaction(InvalidTransaction::NonceOverflowInTransaction))
    } else {Ok(())}
}
