//! Experimental native backend; full LP4 acceptance and boot remain disabled.
//! PAY contracts: development/LP4-PAY-APPROVAL.md and LP4-PAY-LIFECYCLE-APPROVAL.md.
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
/// resource ceilings remain separate acceptance obligations, never caller flags.
pub fn execute_in_context(snapshot:&InMemoryDB, tx:TxEnv, block:&NativeBlockContext) -> Result<ResultAndState,EVMError<core::convert::Infallible>> {
    validate_nonce(snapshot,tx.caller,tx.nonce)?;
    let mut evm=Evm::builder().with_db(snapshot.clone()).with_external_context(NativeContext::from_snapshot(snapshot))
        .with_spec_id(SpecId::CANCUN)
        .modify_cfg_env(|cfg|cfg.chain_id=CHAIN_ID)
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
        }).append_handler_register(crate::collision::register).build();
    evm.transact()
}

/// EIP-2681: maximum u64 transaction/account nonce cannot be incremented.
/// revm 19.7.0 can otherwise return a normal result for max-nonce creation.
pub fn validate_nonce(snapshot:&InMemoryDB,caller:Address,nonce:Option<u64>) -> Result<(),EVMError<core::convert::Infallible>> {
    if nonce==Some(u64::MAX) || snapshot.accounts.get(&caller).map(|a|a.info.nonce==u64::MAX).unwrap_or(false) {
        Err(EVMError::Transaction(InvalidTransaction::NonceOverflowInTransaction))
    } else {Ok(())}
}
