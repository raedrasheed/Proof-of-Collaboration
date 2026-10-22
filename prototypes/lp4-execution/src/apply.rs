//! PoCol block apply (M1 execution.md "مراحل الكتلة", D141/D142, LEDGER-01).
//!
//! apply(S_parent, ctx, body) runs, as one private candidate:
//!   phase 0: applyEvidence, markClose, pruneShares, recordShares(h-1),
//!            recordResult(h-1), settle(h-D), beginBlock (h=1 skips record*);
//!   phase 1: signed USER transactions (legacy-155/2930/1559);
//!   phase 2: subsidy issuance + closeBlock(tips), or finalize(tips) at F;
//!   phase 3: roots (state, tx, receipts, bloom, gasUsed, evidence).
//! Any error discards the whole candidate; the parent snapshot is never mutated.
//! Inputs never include the current block's nonce, owners, shares or signatures.
use revm::{InMemoryDB,DatabaseCommit,FrameOrResult,interpreter::CallInputs};
use revm::primitives::{Address,B256,Bytes,EvmState,TxEnv,TxKind,U256,keccak256};
use crate::{native::{self,NativeBlockContext},profile::ProfileIdentity,code_caps::{self,CodeLimits},pay};

pub const PER_CALL_GAS:u64=30_000_000;
pub fn system_address()->Address{let mut a=[0xff;20];a[19]=0xfe;Address::from(a)}
pub fn program_address(i:usize)->Address{Address::from_word(U256::from(0xc0c001u64+i as u64).into())}
pub fn registry()->Address{program_address(0)}
pub fn escrow()->Address{program_address(1)}
pub fn ledger()->Address{program_address(2)}
pub fn caps()->Address{program_address(3)}
pub fn chunk_factory()->Address{program_address(4)}

/// The five compiled runtime programs C0C001..C0C005, in order.
#[derive(Clone,Debug)]
pub struct SystemPrograms{pub codes:[Bytes;5]}
impl SystemPrograms{
    /// Loads `tests/data/system-v1.json` style output (compile_system_v1.cjs).
    pub fn from_compiled_json(text:&str)->Result<Self,String>{
        let v:serde_json::Value=serde_json::from_str(text).map_err(|e|e.to_string())?;
        let list=v["programs"].as_array().ok_or("programs")?;
        if list.len()!=5{return Err("five programs required".into())}
        let mut codes:[Bytes;5]=Default::default();
        for (i,p) in list.iter().enumerate(){
            let hex=p["runtime"].as_str().ok_or("runtime")?.trim_start_matches("0x");
            codes[i]=Bytes::from(decode_hex(hex)?);
            if codes[i].is_empty(){return Err("empty program".into())}
        }
        Ok(Self{codes})
    }
    pub fn v1()->Self{Self::from_compiled_json(include_str!("../tests/data/system-v1.json")).expect("bundled system-v1.json")}
    /// sysCodeHash = keccak256(RLP([code(C0C001..C0C005), 0x80 for PAY])).
    pub fn sys_code_hash(&self)->B256{crate::genesis_builder::code_hash(&self.codes)}
}
fn decode_hex(s:&str)->Result<Vec<u8>,String>{
    if s.len()%2!=0{return Err("odd hex".into())}
    (0..s.len()).step_by(2).map(|i|u8::from_str_radix(&s[i..i+2],16).map_err(|e|e.to_string())).collect()
}

#[derive(Debug,Clone,PartialEq,Eq)]
pub enum ApplyError{
    Context(&'static str), Genesis(String), System{call:&'static str,detail:String}, Budget(&'static str),
    User(String), Logs, Supply(&'static str), Root, Caps(String),
}

/// D142 ParentResult(p): {blockHash(p), winner=owner(p.nonce), shares[(n, owner(n))]}.
#[derive(Clone,Debug,PartialEq,Eq)]
pub struct ParentResult{pub block_hash:B256,pub winner:Address,pub shares:Vec<(u64,Address)>}
impl ParentResult{
    /// recordShares sequence: committed shares in nonce order, then the implicit winner once.
    pub fn owner_sequence(&self)->Vec<Address>{let mut v:Vec<Address>=self.shares.iter().map(|s|s.1).collect();v.push(self.winner);v}
}

#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum Proposer{Signed(Address),Fallback}

/// Effects of consensus-validated evidence (validity is a consensus-layer rule,
/// H-full item 15). Type 1 and type 2 both burn/tomb the accused; type 2 also
/// invalidates pot_j when it is still pending.
#[derive(Clone,Debug,PartialEq,Eq)]
pub enum EvidenceEffect{Punish{accused:Address},PunishAndInvalidate{accused:Address,j:u64}}

/// ctx = {chainId, h, ts, baseFee, gasLimit, prevrandao, coinbase=Escrow, ancestors, parentResult}.
pub struct BlockInput<'a>{
    pub height:u64,
    pub timestamp:u64,
    pub base_fee:U256,
    pub gas_limit:u64,
    /// SHA256('PoColRandao' || seal_p)
    pub prevrandao:B256,
    pub proposer:Proposer,
    pub parent_result:Option<ParentResult>,
    pub evidence:Vec<EvidenceEffect>,
    /// Raw evidence item bytes, committed by evidenceRoot.
    pub evidence_raw:&'a [Vec<u8>],
    pub transactions:&'a [Vec<u8>],
    /// (height, blockHash) for the last <=256 ancestors; BLOCKHASH(0)=genesisHash.
    pub ancestors:Vec<(u64,B256)>,
    /// Charged log bytes of the canonical ancestors (LOG_CAP, A03).
    pub cum_log_bytes:u64,
}

#[derive(Clone,Debug)]
pub struct BlockOutput{
    pub state:InMemoryDB,
    pub state_root:B256,
    pub transactions_root:B256,
    pub receipts_root:B256,
    pub evidence_root:B256,
    pub logs_bloom:[u8;256],
    pub gas_used:u64,
    pub receipts:Vec<Vec<u8>>,
    pub tips:U256,
    pub issued:U256,
    pub system_gas:u64,
    pub is_final:bool,
    pub facts:ChainFacts,
    pub meter:Meter,
    /// Charged log bytes of this block (LOG-ACCT-01); the child's cum_log_bytes adds it.
    pub log_bytes:u64,
    /// USER transactions that halted exceptionally (A03), by index.
    pub halts:Vec<(usize,crate::user_phase::Halt)>,
}

/// Parent-state facts used by consensus (finality, closing, membership).
#[derive(Clone,Copy,Debug,PartialEq,Eq,Default)]
pub struct ChainFacts{pub closing:bool,pub close_h:u64,pub cursor_done:bool,pub rec_len:u64,pub act_len:u64,pub held_total:U256,pub burned_total:U256}

fn word(db:&InMemoryDB,a:Address,slot:U256)->U256{db.accounts.get(&a).and_then(|x|x.storage.get(&slot).copied()).unwrap_or_default()}
fn bits(v:U256,shift:u32,width:u32)->U256{(v>>shift)&((U256::from(1)<<width)-U256::from(1))}
fn low_u64(v:U256)->u64{v.as_limbs()[0]}

pub fn chain_facts(db:&InMemoryDB)->ChainFacts{
    let r=registry();let c=word(db,r,U256::from(3));let len=word(db,r,U256::ZERO);
    let cursor=bits(c,90,32);
    ChainFacts{closing:bits(c,89,1)!=U256::ZERO,close_h:low_u64(bits(c,187,64)),cursor_done:cursor>=len,
        rec_len:low_u64(len),act_len:low_u64(word(db,r,U256::from(1))),held_total:word(db,r,U256::from(4)),
        burned_total:word(db,escrow(),U256::ZERO)}
}

/// One Registry record (four words, REGISTRY-LAYOUT.md).
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct MinerRecord{pub id:Address,pub status:u8,pub tomb:bool,pub bond_state:u8,pub last_share:u64,pub reward:Address,pub bond:U256,pub exit_height:u64,pub due_height:u64,pub burn_height:u64,pub grace_start:u64}
pub fn record_slot(id:Address)->U256{U256::from_be_bytes(keccak256([id.into_word().as_slice(),U256::from(7).to_be_bytes::<32>().as_slice()].concat()).0)}
fn array_slot(slot:u64)->U256{U256::from_be_bytes(keccak256(U256::from(slot).to_be_bytes::<32>()).0)}
pub fn miner_record(db:&InMemoryDB,id:Address)->Option<MinerRecord>{
    let r=registry();let s=record_slot(id);let w0=word(db,r,s);if w0==U256::ZERO{return None}
    let w1=word(db,r,s+U256::from(1));let w3=word(db,r,s+U256::from(3));
    Some(MinerRecord{id,status:low_u64(bits(w0,0,8)) as u8,tomb:bits(w0,8,8)!=U256::ZERO,bond_state:low_u64(bits(w0,16,8)) as u8,
        last_share:low_u64(bits(w0,88,64)),reward:Address::from_word(B256::from(w1)),bond:word(db,r,s+U256::from(2)),
        exit_height:low_u64(bits(w3,0,64)),due_height:low_u64(bits(w3,64,64)),burn_height:low_u64(bits(w3,128,64)),grace_start:low_u64(bits(w3,192,64))})
}
/// ActList in order (consensus §2 M_h/Act_h from the parent state).
pub fn active_list(db:&InMemoryDB)->Vec<Address>{
    let r=registry();let n=low_u64(word(db,r,U256::from(1)));let b=array_slot(6);
    (0..n).map(|i|Address::from_word(B256::from(word(db,r,b+U256::from(i))))).collect()
}
pub fn record_list(db:&InMemoryDB)->Vec<Address>{
    let r=registry();let n=low_u64(word(db,r,U256::ZERO));let b=array_slot(5);
    (0..n).map(|i|Address::from_word(B256::from(word(db,r,b+U256::from(i))))).collect()
}
fn ledger_slot_total(j:u64)->U256{U256::from_be_bytes(keccak256([U256::from(j).to_be_bytes::<32>(),U256::ZERO.to_be_bytes::<32>()].concat()).0)}
fn ledger_slot_count_base(j:u64)->U256{U256::from_be_bytes(keccak256([U256::from(j).to_be_bytes::<32>(),U256::from(1).to_be_bytes::<32>()].concat()).0)}
/// count[j][m] from the ShareLedger layout (LEDGER-01 option 1).
pub fn share_count(db:&InMemoryDB,j:u64,owner:Address)->u64{
    let n=ledger_slot_count_base(j);let slot=U256::from_be_bytes(keccak256([owner.into_word().as_slice(),n.to_be_bytes::<32>().as_slice()].concat()).0);
    low_u64(word(db,ledger(),slot))
}
pub fn share_total(db:&InMemoryDB,j:u64)->u64{low_u64(word(db,ledger(),ledger_slot_total(j)))}
pub fn pending(db:&InMemoryDB,j:u64)->(U256,U256,Address){
    let b=U256::from_be_bytes(keccak256([U256::from(j).to_be_bytes::<32>(),U256::from(3).to_be_bytes::<32>()].concat()).0);
    let e=escrow();(word(db,e,b),word(db,e,b+U256::from(1)),Address::from_word(B256::from(word(db,e,b+U256::from(2)))))
}

/// Full world-state MPT root (secure keys, nonempty accounts only).
pub fn state_root(db:&InMemoryDB)->Result<B256,ApplyError>{crate::genesis_builder::world_root(db).map_err(|_|ApplyError::Root)}

/// Built, root-checked genesis (consensus.md §0 steps 1-4).
pub struct Genesis{image:crate::genesis_builder::GenesisImage}
impl Genesis{
    /// Verifies sysCodeHash and allocRoot against the GenesisSpec; rejects nonzero
    /// alloc storage at the reserved Ledger address (LEDGER-01 clause 5).
    /// Crate-internal: outside this crate a Genesis exists only inside an `admission::Admitted`
    /// or a `devnet::Devnet` candidate, never from an unadmitted identity.
    pub(crate) fn build(alloc:&InMemoryDB,profile:&ProfileIdentity,programs:&SystemPrograms)->Result<Self,ApplyError>{
        if alloc.accounts.get(&ledger()).map(|a|a.storage.values().any(|v|*v!=U256::ZERO)).unwrap_or(false){return Err(ApplyError::Genesis("nonzero Ledger alloc storage".into()))}
        crate::genesis_builder::build(alloc,profile,&programs.codes).map(|image|Self{image}).map_err(|e|ApplyError::Genesis(format!("{e:?}")))
    }
    /// allocRoot that a GenesisSpec must commit to for this alloc/profile/programs.
    pub fn derive_root(alloc:&InMemoryDB,profile:&ProfileIdentity,programs:&SystemPrograms)->Result<B256,ApplyError>{
        crate::genesis_builder::construct_root(alloc,profile,&programs.codes).map_err(|e|ApplyError::Genesis(format!("{e:?}")))
    }
    pub fn state(&self)->&InMemoryDB{self.image.state()}
    pub fn root(&self)->B256{self.image.root()}
    pub fn initial_supply(&self)->U256{self.image.initial_supply()}
}

struct Exec<'a>{state:InMemoryDB,profile:&'a ProfileIdentity,block:NativeBlockContext,origin:Address,used:u64,limits:CodeLimits,meter:Meter}
/// CapsTracker (P7): distinct storage keys changed and accounts touched by SYSTEM
/// calls in one block, plus the largest single-call gas.
#[derive(Clone,Debug,Default)]
pub struct Meter{pub keys:std::collections::HashSet<(Address,U256)>,pub accounts:std::collections::HashSet<Address>,pub max_call_gas:u64,pub calls:u32,
    /// Gas spent by each SYSTEM call in order (measurement only; never a validity input).
    pub call_gas:Vec<(&'static str,u64)>}
impl<'a> Exec<'a>{
    fn call(&mut self,name:&'static str,to:Address,data:Vec<u8>)->Result<Bytes,ApplyError>{
        let err=|d:String|ApplyError::System{call:name,detail:d};
        let remaining=self.profile.cp().G_SYS.checked_sub(self.used).ok_or(ApplyError::Budget("G_SYS"))?;
        let allocation=remaining.min(PER_CALL_GAS);if allocation==0{return Err(ApplyError::Budget("G_SYS"))}
        let tx=TxEnv{caller:self.origin,transact_to:TxKind::Call(to),gas_limit:allocation,gas_price:U256::ZERO,value:U256::ZERO,
            data:Bytes::from(data),chain_id:Some(self.profile.spec().chain_id),..Default::default()};
        let mut evm=native::build_engine(&self.state,tx,&self.block,self.profile.spec().chain_id,Some(self.limits));
        evm.handler.pre_execution.load_accounts(&mut evm.context).map_err(|e|err(format!("{e:?}")))?;
        let precompiles=evm.handler.pre_execution.load_precompiles();evm.context.evm.set_precompiles(precompiles);
        for a in [system_address(),to,escrow()]{evm.context.evm.journaled_state.warm_preloaded_addresses.insert(a);}
        if self.origin!=Address::ZERO{evm.context.evm.journaled_state.warm_preloaded_addresses.insert(self.origin);}
        let mut input=CallInputs::new_boxed(&evm.context.evm.env.tx,allocation).ok_or(ApplyError::Context("call inputs"))?;
        input.caller=system_address();
        let first=evm.handler.execution.call(&mut evm.context,input).map_err(|e|err(format!("{e:?}")))?;
        let result=match first{FrameOrResult::Frame(f)=>evm.run_the_loop(f).map_err(|e|err(format!("{e:?}")))?,FrameOrResult::Result(r)=>r}.into_interpreter_result();
        if !result.result.is_ok(){return Err(err(format!("{:?} output={}",result.result,result.output)))}
        self.used=self.used.checked_add(result.gas.spent()).ok_or(ApplyError::Budget("G_SYS"))?;
        if self.used>self.profile.cp().G_SYS{return Err(ApplyError::Budget("G_SYS"))}
        let (state,logs)=evm.context.evm.journaled_state.finalize();
        if !logs.is_empty(){return Err(ApplyError::Logs)}
        for (a,acct) in state.iter(){ if acct.is_touched(){self.meter.accounts.insert(*a);} for (k,v) in acct.storage.iter(){ if v.is_changed(){self.meter.keys.insert((*a,*k));} } }
        self.meter.max_call_gas=self.meter.max_call_gas.max(result.gas.spent());self.meter.calls+=1;self.meter.call_gas.push((name,result.gas.spent()));
        commit_epoch(&mut self.state,state);
        code_caps::validate_snapshot(&self.state,self.limits).map_err(ApplyError::Caps)?;
        Ok(result.output)
    }
}
fn commit_epoch(db:&mut InMemoryDB,state:EvmState){
    let removed:Vec<_>=state.iter().filter(|(_,a)|a.is_selfdestructed()||(a.is_touched()&&a.is_empty())).map(|(a,_)|*a).collect();
    let touched:Vec<_>=state.iter().filter(|(_,a)|a.is_touched()).map(|(a,_)|*a).collect();
    db.commit(state);
    for address in removed{let a=db.accounts.entry(address).or_default();a.account_state=revm::db::AccountState::NotExisting;a.storage.clear();a.info=Default::default();}
    crate::user_phase::normalize(db,&touched);
}
fn selector(sig:&str)->Vec<u8>{keccak256(sig.as_bytes())[..4].to_vec()}
fn enc_u256(out:&mut Vec<u8>,v:U256){out.extend(v.to_be_bytes::<32>())}
fn enc_addr(out:&mut Vec<u8>,a:Address){out.extend(a.into_word().0)}

/// Final predicate (consensus §8) from the parent state and this block's (h, ts).
pub fn is_final_block(parent:&InMemoryDB,profile:&ProfileIdentity,h:u64,ts:u64)->bool{
    let f=chain_facts(parent);
    crate::finality_core::final_predicate(crate::finality_core::ParentFacts{closing:f.closing,close_h:f.close_h,cursor_done:f.cursor_done,is_final:false},
        h,ts,u32::from(profile.cp().D),profile.cp().H_END,profile.cp().T_END)
}

/// Executes block h on top of `parent` (never mutated). Deterministic.
pub fn apply_block(parent:&InMemoryDB,genesis:&Genesis,profile:&ProfileIdentity,input:&BlockInput<'_>)->Result<BlockOutput,ApplyError>{
    let cp=profile.cp();
    let h=input.height;
    if h==0||h>cp.H_END{return Err(ApplyError::Context("height"))}
    if input.gas_limit!=cp.GAS_LIMIT{return Err(ApplyError::Context("gasLimit"))}
    if (h==1)!=input.parent_result.is_none(){return Err(ApplyError::Context("parentResult presence"))}
    if input.transactions.len() as u64>cp.TX_CAP||input.transactions.iter().any(|t|t.len()>cp.TX_MAX as usize){return Err(ApplyError::Budget("TX_MAX"))}
    let body_bytes:usize=input.transactions.iter().chain(input.evidence_raw.iter()).map(|t|t.len()).sum();
    if body_bytes>cp.BODY_MAX as usize{return Err(ApplyError::Budget("BODY_MAX"))}
    if input.evidence_raw.len()>usize::from(cp.E_max)||input.evidence_raw.iter().any(|e|e.len()>cp.EVID_BYTES_MAX as usize){return Err(ApplyError::Budget("evidence"))}
    genesis.image.verify_candidate(parent,profile).map_err(|e|ApplyError::Genesis(format!("parent {e:?}")))?;
    let is_final=is_final_block(parent,profile,h,input.timestamp);
    let limits=CodeLimits{runtime:cp.B_code_max,logical:cp.CODE_CAP};
    let origin=match input.proposer{Proposer::Signed(a) if a!=Address::ZERO=>a,Proposer::Signed(_)=>return Err(ApplyError::Context("proposer")),Proposer::Fallback=>Address::ZERO};
    let mut state=parent.clone();
    state.block_hashes.clear();
    for (n,hash) in &input.ancestors{
        if *n>=h||h-*n>256{return Err(ApplyError::Context("ancestor window"))}
        state.block_hashes.insert(U256::from(*n),*hash);
    }
    let block=NativeBlockContext{height:U256::from(h),timestamp:U256::from(input.timestamp),gas_limit:U256::from(input.gas_limit),base_fee:input.base_fee,prevrandao:input.prevrandao};
    let mut ex=Exec{state,profile,block,origin,used:0,limits,meter:Meter::default()};

    // Phase 0.
    for e in &input.evidence{
        let (accused,j)=match e{EvidenceEffect::Punish{accused}=>(*accused,None),EvidenceEffect::PunishAndInvalidate{accused,j}=>(*accused,Some(*j))};
        if let Some(j)=j{ if pending(&ex.state,j).1!=U256::ZERO{let mut d=selector("invalidate(uint256)");enc_u256(&mut d,U256::from(j));ex.call("invalidate",escrow(),d)?;} }
        let mut d=selector("punish(address)");enc_addr(&mut d,accused);ex.call("punish",registry(),d)?;
    }
    ex.call("markClose",registry(),selector("markClose()"))?;
    ex.call("pruneShares",ledger(),selector("pruneShares()"))?;
    if let Some(pr)=&input.parent_result{
        let seq=pr.owner_sequence();
        if seq.len()>usize::from(cp.S_max)+1{return Err(ApplyError::Context("parent shares"))}
        let mut d=selector("recordShares(uint64,address[])");enc_u256(&mut d,U256::from(h-1));enc_u256(&mut d,U256::from(64));enc_u256(&mut d,U256::from(seq.len()));
        for a in &seq{enc_addr(&mut d,*a)}
        ex.call("recordShares",registry(),d)?;
        let mut d=selector("recordResult(uint256,address)");enc_u256(&mut d,U256::from(h-1));enc_addr(&mut d,pr.winner);
        ex.call("recordResult",escrow(),d)?;
    }
    if h>u64::from(cp.D){let mut d=selector("settle(uint256)");enc_u256(&mut d,U256::from(h-u64::from(cp.D)));ex.call("settle",escrow(),d)?;}
    ex.call("beginBlock",registry(),selector("beginBlock()"))?;

    // Phase 1: USER transactions.
    let budget=cp.BODY_MAX as usize;
    let ctx=crate::user_phase::UserContext{cum_log_bytes:input.cum_log_bytes,closing:chain_facts(&ex.state).closing};
    let users=crate::user_phase::execute_for_block(&ex.state,input.transactions,&ex.block,budget,budget,profile,ctx).map_err(|e|ApplyError::User(format!("{e:?}")))?;
    ex.state=users.state().clone();
    let tips=users.tips();
    code_caps::validate_snapshot(&ex.state,limits).map_err(ApplyError::Caps)?;

    // Phase 2: issuance + closeBlock, or finalize (no subsidy, tips burned).
    let mut issued=U256::ZERO;
    if !is_final{
        let subsidy=U256::from_be_bytes(profile.spec().cp[15].to_be_bytes());
        let account=ex.state.accounts.get_mut(&pay::escrow_address()).ok_or(ApplyError::Genesis("escrow".into()))?;
        account.info.balance=account.info.balance.checked_add(subsidy).ok_or(ApplyError::Supply("issuance"))?;
        issued=subsidy;
        let mut d=selector("closeBlock(uint256)");enc_u256(&mut d,tips);ex.call("closeBlock",escrow(),d)?;
    }else{
        let mut d=selector("finalize(uint256)");enc_u256(&mut d,tips);ex.call("finalize",escrow(),d)?;
        // LP4-FINAL-01: one SYSTEM call per remaining pot j in [F-D+1, F-1].
        let start=if h>u64::from(cp.D){h-u64::from(cp.D)+1}else{1};
        for j in start..h{ if pending(&ex.state,j).1!=U256::ZERO{let mut d=selector("settleFinal(uint256)");enc_u256(&mut d,U256::from(j));ex.call("settleFinal",escrow(),d)?;} }
    }
    let system_gas=ex.used;
    // R18 per-block SYS caps (CapsTracker): distinct keys and accounts.
    if ex.meter.keys.len() as u64>u64::from(cp.SYS_KEYS_BLOCK_MAX){return Err(ApplyError::Budget("SYS_KEYS_BLOCK_MAX"))}
    if ex.meter.accounts.len() as u64>u64::from(cp.SYS_ACCT_BLOCK_MAX){return Err(ApplyError::Budget("SYS_ACCT_BLOCK_MAX"))}
    let meter=ex.meter.clone();
    let mut state=ex.state;crate::user_phase::drop_unreferenced_code(&mut state);
    genesis.image.verify_candidate(&state,profile).map_err(|e|ApplyError::Genesis(format!("candidate {e:?}")))?;
    check_escrow_invariant(&state,profile,h,is_final)?;

    // Phase 3: roots.
    let c=users.commitments();
    let evidence_root=crate::trie::ordered_root(input.evidence_raw,usize::from(cp.E_max)).map(B256::from).map_err(|_|ApplyError::Root)?;
    let state_root=state_root(&state)?;
    let facts=chain_facts(&state);
    Ok(BlockOutput{state,state_root,transactions_root:c.transactions_root,receipts_root:c.receipts_root,evidence_root,logs_bloom:c.logs_bloom,gas_used:c.gas_used,
        receipts:users.receipts().to_vec(),tips,issued,system_gas,is_final,facts,meter,log_bytes:users.log_bytes(),halts:users.halts().to_vec()})
}

/// T17: Escrow surplus = balance-(Σpending+heldTotal+burnedTotal) >= 0, and
/// pending[j] exists for every j in [h-D+1,h] (non-final) with winners recorded
/// for j<h; at F no pending remains.
pub fn check_escrow_invariant(db:&InMemoryDB,profile:&ProfileIdentity,h:u64,is_final:bool)->Result<(),ApplyError>{
    let d=u64::from(profile.cp().D);let lo=h.saturating_sub(d)+1;
    let mut sum=U256::ZERO;
    for j in lo.max(1)..=h{
        let (amount,meta,winner)=pending(db,j);
        if is_final{ if meta!=U256::ZERO||amount!=U256::ZERO{return Err(ApplyError::Supply("pending after final"))} continue; }
        if meta==U256::ZERO{return Err(ApplyError::Supply("missing pending"))}
        if j<h&&winner==Address::ZERO{return Err(ApplyError::Supply("winner not recorded"))}
        if j==h&&winner!=Address::ZERO{return Err(ApplyError::Supply("current winner written"))}
        sum=sum.checked_add(amount).ok_or(ApplyError::Supply("sum"))?;
    }
    let f=chain_facts(db);
    let balance=db.accounts.get(&escrow()).map(|a|a.info.balance).unwrap_or_default();
    let need=sum.checked_add(f.held_total).and_then(|v|v.checked_add(f.burned_total)).ok_or(ApplyError::Supply("need"))?;
    if balance<need{return Err(ApplyError::Supply("escrow surplus negative"))}
    Ok(())
}

#[cfg(test)] mod tests;
