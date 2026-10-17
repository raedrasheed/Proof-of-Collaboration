//! Native PAY boundary, LP4-PAY-01: development/LP4-PAY-APPROVAL.md.
//! Transfer primitive only. Full compiled-system policy/integration acceptance is separate.
use revm::{Context, Database, FrameOrResult, FrameResult};
use revm::primitives::{Address, Bytes, EVMError, U256};
use revm::interpreter::{CallInputs, CallOutcome, CallScheme, Gas, InstructionResult, InterpreterResult};
use crate::pay_address;

pub const PAY_GAS: u64 = 5_000;
pub fn registry_address() -> Address { Address::from_word(U256::from(0xc0c001u64).into()) }
pub fn escrow_address() -> Address { Address::from_word(U256::from(0xc0c002u64).into()) }

/// Records executing code identity independently of CALL's caller/storage identity.
/// In particular a DELEGATECALL into foreign code cannot inherit PAY authority.
#[derive(Default)]
pub struct NativeContext { pub(crate) active_code: Option<Address> }

fn outcome(inputs: &CallInputs, result: InstructionResult) -> FrameOrResult {
    let mut gas=Gas::new(inputs.gas_limit);
    if result == InstructionResult::Return { assert!(gas.record_cost(PAY_GAS)); }
    else { gas=Gas::new_spent(inputs.gas_limit); }
    FrameOrResult::Result(FrameResult::Call(CallOutcome::new(
        InterpreterResult {result, gas, output:Bytes::new()},inputs.return_memory_offset.clone())))
}

/// Called before revm's ordinary value transfer/frame creation. No PAY recipient
/// code is ever entered. All state changes use the enclosing revm journal.
pub(crate) fn call<DB: Database>(context: &mut Context<NativeContext,DB>, inputs: &CallInputs)
 -> Result<FrameOrResult,EVMError<DB::Error>> {
    let fail=|| outcome(inputs,InstructionResult::InvalidOperandOOG);
    if inputs.bytecode_address != pay_address() || inputs.target_address != pay_address()
        || inputs.scheme != CallScheme::Call || inputs.is_static || inputs.is_eof
        || inputs.call_value()!=U256::ZERO || inputs.input.len()!=64
        || inputs.input[..12].iter().any(|b|*b!=0)
        || context.evm.journaled_state.depth()==0
        || context.external.active_code!=Some(inputs.caller)
        || ![registry_address(),escrow_address()].contains(&inputs.caller)
        || inputs.gas_limit<PAY_GAS { return Ok(fail()); }
    let recipient=Address::from_slice(&inputs.input[12..32]);
    let amount=U256::from_be_slice(&inputs.input[32..64]);
    if recipient==Address::ZERO { return Ok(fail()); }
    let evm=&mut context.evm.inner;
    evm.journaled_state.load_account(inputs.caller,&mut evm.db)?;
    evm.journaled_state.load_account(recipient,&mut evm.db)?;
    let source=&evm.journaled_state.state[&inputs.caller];
    let dest=&evm.journaled_state.state[&recipient];
    // EIP-161 empty/deleted accounts are not durable recipients. A freshly created
    // nonempty account in this journal is existing; PAY itself never creates one.
    if dest.is_selfdestructed() || dest.is_empty() || source.info.balance<amount
        || (recipient!=inputs.caller && dest.info.balance.checked_add(amount).is_none()) {
        return Ok(fail());
    }
    if amount!=U256::ZERO && recipient!=inputs.caller {
        // Overflow and funding were checked BEFORE transfer: revm's helper alone
        // debits before its overflow check and must not be used as validation.
        let error=evm.journaled_state.transfer(&inputs.caller,&recipient,amount,&mut evm.db)?;
        assert!(error.is_none(),"prevalidated PAY journal transfer");
    }
    Ok(outcome(inputs,InstructionResult::Return))
}
