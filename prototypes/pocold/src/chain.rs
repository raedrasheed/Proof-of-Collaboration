//! Consensus state: block tree, H-pre/H-full validation (consensus.md), template
//! construction (signed / Build_fb), ParentResult (D142) and D133 fork choice.
use std::collections::{HashMap,BTreeMap};
use crate::{assignment::{self,Assignment,DrawWeights,Membership,NonceMode,ParentMember,ParentView,ShareCount},asert,hashes,header::Header,timing::AttemptWindow};
use pocol_lp4_execution::{admission::{Admitted,NodeLocal},apply::{self,BlockInput,BlockOutput,EvidenceEffect,Genesis,ParentResult,Proposer},fees,profile::ProfileIdentity,txsign::Key};
use revm::{InMemoryDB,primitives::{Address,B256,U256}};
use crate::types::*;

/// Longest stored rejection reason (A13 accounting).
pub const REASON_MAX:usize=256;
pub fn truncate(why:&str)->String{if why.len()<=REASON_MAX{return why.to_string()}let mut n=REASON_MAX;while !why.is_char_boundary(n){n-=1}why[..n].to_string()}
/// governance.md R_keep: a non-canonical block this far below the head is removed (A13).
pub const R_KEEP:u64=2048;
/// Unprotected non-canonical blocks kept as METADATA (local retention, not validity; consensus.md:29).
/// D-REORG-REDB (owner-approved): fork choice (`better`, `rebuild_canonical`, the LCA walk) reads only
/// metadata, and `retain` offloads every journaled non-canonical block's body, receipts, tx hashes and
/// encoded header (they are in the journal). R_keep entries: D118 keeps at most one non-canonical block
/// per height, so a whole window of competing blocks fits. Beyond it the lowest-work unprotected leaf is
/// evicted first; an evicted branch is re-fetched by a sync session from the fork point (locator) when a
/// peer serves a heavier chain (consensus.md §10: "fetched by sync"), and a session's blocks are
/// protected from this cap (`protect_max`). A13-DERIVATION §4 item 18.
pub const SIDE_BLOCKS_MAX:usize=R_KEEP as usize;
/// Hashes of side blocks removed by retention, remembered so that a copy received again is refused
/// before it is validated or journaled (a branch longer than SIDE_BLOCKS_MAX would otherwise be
/// re-fetched, re-executed and re-journaled every sync turn). FIFO, a cache only.
pub const EVICTED_MAX:usize=1024;
/// Bound of the invalid-block cache (A05). A forgotten entry is only re-validated.
pub const INVALID_MAX:usize=4096;

/// Immutable chain configuration: cfg = {chainId, genesisHash, ForkSchedule, CP, M_0}.
/// Constructible only from a ParamGate admission (A02): nothing boots an unadmitted profile.
pub struct Spec{admitted:Admitted}
impl Spec{
    pub fn new(admitted:Admitted)->Self{Self{admitted}}
    pub fn profile(&self)->&ProfileIdentity{self.admitted.profile()}
    pub fn genesis(&self)->&Genesis{self.admitted.genesis()}
    pub fn genesis_hash(&self)->[u8;32]{self.admitted.genesis_hash()}
    pub fn spec_bytes(&self)->&[u8]{self.admitted.spec_bytes()}
    /// The node-local timing admitted with the profile (Φ=2φ, Δ_rel, Γ).
    pub fn local(&self)->&NodeLocal{self.admitted.local()}
    pub fn admission(&self)->&Admitted{&self.admitted}
    pub fn cp(&self)->&pocol_lp4_execution::profile::ConsensusParams{self.profile().cp()}
    pub fn chain_id(&self)->u64{self.profile().spec().chain_id}
    pub fn target_g(&self)->Fixed{Fixed::from_be_slice(&self.profile().cp().target_g.to_be_bytes()).unwrap()}
    pub fn active_version(&self,h:u64)->u16{self.profile().forks().active_version(h)}
}

#[derive(Clone,Debug)]
pub struct Entry{
    pub hash:[u8;32],
    pub header:Header,
    pub body:Body,
    pub height:u64,
    pub parent:Option<[u8;32]>,
    pub total_work:U256,
    pub import_seq:u64,
    pub signed:bool,
    pub ts:u64,
    pub target:Fixed,
    pub base_fee:U256,
    pub gas_used:u64,
    pub seal:[u8;32],
    pub state:InMemoryDB,
    pub is_final:bool,
    /// ParentResult describing THIS block, consumed by its children (D142).
    pub result:Option<ParentResult>,
    pub receipts:Vec<Vec<u8>>,
    pub tx_hashes:Vec<B256>,
    pub cum_txs:u64,
    pub cum_tx_bytes:u64,
    /// Charged log bytes up to and including this block (LOG_CAP, A03).
    pub cum_log_bytes:u64,
    /// R21: state dropped outside the K_hist window; rebuilt by re-execution on demand.
    pub pruned:bool,
    /// Draw(h,0) for this block's height on its branch (evidence type 1 DrawIndex).
    pub drawn:Address,
    /// This block's nonce ranges (owner lookup for evidence without old state).
    pub ranges:Vec<(Address,u128,u128)>,
    /// D-REORG-REDB off-heap block store: the journal frame offset of this block's record, set by
    /// the node after `journal.append` (and recomputed on replay). `None` for a bare chain with no
    /// journal and for genesis (never journaled). Only a block with `body_off = Some` may be offloaded.
    pub body_off:Option<u64>,
    /// When true, `body`, `receipts`, `tx_hashes` and `header.encoded` have been dropped (empty) and
    /// are read on demand from the journal at `body_off`. State residence stays governed by `pruned`.
    pub offloaded:bool,
}

/// Source of a block's bytes for the off-heap store: given a journal frame offset (an `Entry.body_off`),
/// returns (headerBytes, bodyBytes, parentResultBytes). Implemented by the node over `store::Journal`
/// (`read_at`); a bare chain passes `None` and never offloads, so it is never called there.
pub trait BlockBytes{fn record_at(&self,off:u64)->Result<(Vec<u8>,Vec<u8>,Vec<u8>),Reject>;}
/// Drops a journaled block's bytes from memory (D-REORG-REDB): body, receipts, tx hashes and the
/// encoded header. Fork choice, child contexts and evidence ancestry read only the metadata kept.
fn offload(e:&mut Entry){e.body=Body::default();e.receipts=Vec::new();e.tx_hashes=Vec::new();e.header.encoded=Vec::new();e.offloaded=true;}
impl Entry{
    /// A copy without the executed state (an empty, pruned state), for rolling re-execution and views.
    pub fn meta_clone(&self)->Entry{
        Entry{hash:self.hash,header:self.header.clone(),body:self.body.clone(),height:self.height,parent:self.parent,total_work:self.total_work,import_seq:self.import_seq,
            signed:self.signed,ts:self.ts,target:self.target,base_fee:self.base_fee,gas_used:self.gas_used,seal:self.seal,state:InMemoryDB::default(),is_final:self.is_final,
            result:self.result.clone(),receipts:self.receipts.clone(),tx_hashes:self.tx_hashes.clone(),cum_txs:self.cum_txs,cum_tx_bytes:self.cum_tx_bytes,
            cum_log_bytes:self.cum_log_bytes,pruned:true,drawn:self.drawn,ranges:self.ranges.clone(),body_off:self.body_off,offloaded:self.offloaded}
    }
}

/// Everything a child of `p` at attempt `a` needs, derived only from p and its state.
pub struct ChildCtx{
    pub height:u64,
    pub attempt:u32,
    pub window:AttemptWindow,
    pub membership:Membership,
    pub assignment:Assignment,
    pub target:Fixed,
    pub t_share:Fixed,
    pub proposer:Address,
    pub base_fee:U256,
    pub prevrandao:B256,
    pub parent_result:Option<ParentResult>,
    pub ancestors:Vec<(u64,B256)>,
}

#[derive(Clone,Debug,PartialEq,Eq)]
pub enum Reject{
    /// Depends only on signature bytes (envReject, D129): reject this copy, not the block.
    Envelope(String),
    /// Committed-content violation (blockReject): the blockHash and descendants are invalid.
    Block(String),
    UnknownParent,
    /// Parent state outside the K_hist window: TrieRebuild, then retry.
    NeedsRebuild([u8;32]),
    Future,
    Duplicate,
    /// Removed by local retention (SIDE_BLOCKS_MAX or R_keep) and not taken again (EVICTED_MAX), or a new
    /// block at or below head-R_keep, which retention would remove at once (it cannot be canonical or win
    /// D133 there; deeper rollback is the manual checkpoint of governance.md:200). Never a validity verdict.
    Evicted,
}
fn blk<T>(s:impl Into<String>)->Result<T,Reject>{Err(Reject::Block(s.into()))}

pub struct Chain{
    pub spec:Spec,
    pub blocks:HashMap<[u8;32],Entry>,
    pub head:[u8;32],
    pub canonical:Vec<[u8;32]>,
    next_seq:u64,
    /// R21 window: full states kept for heights > head-K_hist (and genesis).
    pub k_hist:u64,
    pub rebuilds:u64,
    /// Invalid committed contents (blockReject) never re-validated.
    pub invalid:HashMap<[u8;32],String>,
    /// Insertion order of `invalid`; a cache only (never a validity input), at most INVALID_MAX.
    invalid_order:std::collections::VecDeque<[u8;32]>,
    /// tid -> (proposer, parent, h) for equivocation detection (evidence type 1).
    pub seen_templates:BTreeMap<(u64,[u8;32]),Vec<(Vec<u8>,Vec<u8>)>>,
    /// Side blocks removed by retention (EVICTED_MAX, FIFO) and how many were removed in all.
    evicted:std::collections::HashSet<[u8;32]>,evicted_order:std::collections::VecDeque<[u8;32]>,pub evicted_total:u64,
    /// Local retention parameters (consensus.md:29, governance.md:15): defaults R_KEEP and SIDE_BLOCKS_MAX.
    /// Tests lower them to exercise the boundaries quickly; they never affect validity.
    pub r_keep:u64,pub side_cap:usize,
    /// Blocks the side cap must not evict: the live sync session's fetched prefix, or (on replay) blocks
    /// that later journal records build on. Still subject to the R_keep boundary.
    pub protect:std::collections::HashSet<[u8;32]>,
    /// Journal replay: the cap then bounds ALL non-canonical blocks by side_cap + protect_max (what live
    /// could hold), since replay protects only blocks live held (Node::open).
    pub replaying:bool,
}

pub fn u256_fixed(v:&Fixed)->U256{from_fixed(v)}
pub fn work(t:&Fixed)->U256{from_fixed(&crate::fixed::work(t))}

impl Chain{
    pub fn new(spec:Spec)->Self{
        let gh=spec.genesis_hash();let cp=spec.cp();
        let mut h=blank_header();h.chain_id=spec.chain_id();h.genesis_hash=gh;h.ts=cp.g_ts;h.target=spec.target_g();
        let genesis=Entry{hash:gh,header:h,body:Body::default(),height:0,parent:None,total_work:U256::ZERO,import_seq:0,signed:false,ts:cp.g_ts,
            target:spec.target_g(),base_fee:U256::ZERO,gas_used:0,seal:seal_genesis(&gh),state:spec.genesis().state().clone(),is_final:false,result:None,
            receipts:vec![],tx_hashes:vec![],cum_txs:0,cum_tx_bytes:0,cum_log_bytes:0,pruned:false,drawn:Address::ZERO,ranges:vec![],body_off:None,offloaded:false};
        let mut blocks=HashMap::new();blocks.insert(gh,genesis);
        let k_hist=u64::from(spec.local().k_hist);
        Self{spec,blocks,head:gh,canonical:vec![gh],next_seq:1,k_hist,rebuilds:0,invalid:HashMap::new(),invalid_order:Default::default(),seen_templates:BTreeMap::new(),evicted:Default::default(),evicted_order:Default::default(),evicted_total:0,
            r_keep:R_KEEP,side_cap:SIDE_BLOCKS_MAX,protect:Default::default(),replaying:false}
    }
    pub fn head(&self)->&Entry{&self.blocks[&self.head]}
    pub fn get(&self,h:&[u8;32])->Option<&Entry>{self.blocks.get(h)}
    pub fn canonical_at(&self,height:u64)->Option<&Entry>{self.canonical.get(height as usize).and_then(|h|self.blocks.get(h))}

    // ---------------- child context ----------------
    pub fn target_for_child(&self,p:&Entry)->Result<Fixed,Reject>{
        let cp=self.spec.cp();
        asert::asert(&self.spec.target_g(),cp.g_ts as i128,cp.T_blk as i128,cp.tau as i128,p.ts as i128,p.height as i128).map(|o|o.target).ok_or_else(||Reject::Block("asert".into()))
    }
    pub fn membership(&self,p:&Entry,h:u64)->Result<Membership,Reject>{
        let cp=self.spec.cp();
        let act:Vec<ParentMember>=apply::active_list(&p.state).into_iter().map(|id|{let r=apply::miner_record(&p.state,id);
            ParentMember{id:raw_addr(id),tomb:r.map(|r|r.tomb).unwrap_or(false),last_share:r.map(|r|r.last_share).unwrap_or(0),grace_start:r.map(|r|r.grace_start).unwrap_or(0)}}).collect();
        Membership::from_parent(&ParentView{height:p.height,seal:&p.seal,act:&act},h,cp.W_act,cp.M_max).map_err(|e|Reject::Block(format!("membership {e:?}")))
    }
    pub fn draw(&self,p:&Entry,members:&Membership,h:u64)->Result<Address,Reject>{
        let cp=self.spec.cp();let lo=h.saturating_sub(1).saturating_sub(u64::from(cp.W_w)).max(1);let mut hist=Vec::new();
        if h>=2{for j in lo..=h-2{for id in members.ids(){let c=apply::share_count(&p.state,j,addr(id));if c>0{hist.push(ShareCount{height:j,id:*id,count:c});}}}}
        let w=DrawWeights::new(members,cp.W_w,&hist).map_err(|e|Reject::Block(format!("draw {e:?}")))?;
        w.draw().map(|(a,_)|addr(&a)).map_err(|e|Reject::Block(format!("draw {e:?}")))
    }
    pub fn ancestors(&self,p:&Entry)->Vec<(u64,B256)>{
        let mut out=Vec::new();let mut cur=Some(p);
        while let Some(e)=cur{ if p.height+1-e.height>256{break} out.push((e.height,B256::from(e.hash))); cur=e.parent.and_then(|x|self.blocks.get(&x)); }
        out
    }
    pub fn child_ctx(&self,p:&Entry,attempt:u32)->Result<ChildCtx,Reject>{
        let cp=self.spec.cp();let h=p.height+1;
        let window=AttemptWindow::new(p.ts,attempt,cp.D_att).map_err(|e|Reject::Block(format!("window {e:?}")))?;
        let membership=self.membership(p,h)?;
        let target=self.target_for_child(p)?;
        let mode=if cp.nonceMode==0{NonceMode::Bounded}else{NonceMode::Unbounded};
        let assignment=Assignment::new(&membership,attempt,&target,mode,cp.c).map_err(|e|Reject::Block(format!("assignment {e:?}")))?;
        let ts_share=from_fixed(&target).checked_mul(U256::from(cp.m)).unwrap_or(U256::MAX);
        let proposer=self.draw(p,&membership,h)?;
        let base_fee=if h==1{from_fixed_lp4(&cp.baseFee0)}else{fees::next_base_fee(p.base_fee,p.gas_used,p.header.gas_limit).map_err(|e|Reject::Block(format!("baseFee {e:?}")))?};
        Ok(ChildCtx{height:h,attempt,window,membership,assignment,target,t_share:to_fixed(ts_share),proposer,base_fee,prevrandao:prevrandao(&p.seal),
            parent_result:p.result.clone(),ancestors:self.ancestors(p)})
    }

    // ---------------- execution ----------------
    fn execute(&self,p:&Entry,ctx:&ChildCtx,ts:u64,proposer:Proposer,body:&Body,effects:Vec<EvidenceEffect>)->Result<BlockOutput,Reject>{
        let input=BlockInput{height:ctx.height,timestamp:ts,base_fee:ctx.base_fee,gas_limit:self.spec.cp().GAS_LIMIT,prevrandao:ctx.prevrandao,proposer,
            parent_result:ctx.parent_result.clone(),evidence:effects,evidence_raw:&body.evidence,transactions:&body.txs,ancestors:ctx.ancestors.clone(),cum_log_bytes:p.cum_log_bytes};
        apply::apply_block(&p.state,self.spec.genesis(),self.spec.profile(),&input).map_err(|e|Reject::Block(format!("apply {e:?}")))
    }
    fn fill_ut(&self,p:&Entry,ctx:&ChildCtx,ts:u64,out:&BlockOutput,proposer:&[u8])->Header{
        let mut h=blank_header();h.chain_id=self.spec.chain_id();h.genesis_hash=self.spec.genesis_hash();h.parent_hash=p.hash;h.h=ctx.height;h.a=ctx.attempt;
        h.protocol_version=self.spec.active_version(ctx.height);h.ts=ts;h.target=ctx.target;h.state_root=out.state_root.0;h.tx_root=out.transactions_root.0;
        h.receipts_root=out.receipts_root.0;h.logs_bloom=out.logs_bloom.to_vec();h.gas_limit=self.spec.cp().GAS_LIMIT;h.gas_used=out.gas_used;
        h.base_fee=to_fixed(ctx.base_fee);h.evidence_root=out.evidence_root.0;h.proposer=proposer.to_vec();reseal(&mut h);h
    }
    /// Build_fb(p, a): deterministic fallback UT with empty body (consensus §4ب).
    pub fn build_fallback(&self,p:&Entry,attempt:u32)->Result<(Header,BlockOutput,ChildCtx),Reject>{
        let ctx=self.child_ctx(p,attempt)?;
        let ts=ctx.window.fallback_timestamp(self.spec.cp().dFbWait).map_err(|e|Reject::Block(format!("fb ts {e:?}")))?;
        let out=self.execute(p,&ctx,ts,Proposer::Fallback,&Body::default(),vec![])?;
        let h=self.fill_ut(p,&ctx,ts,&out,&[]);Ok((h,out,ctx))
    }
    /// Signed template at a=0 by Draw(h,0); ts=max(L(0),C).
    pub fn build_signed(&self,p:&Entry,key:&Key,clock:u64,body:Body,effects:Vec<EvidenceEffect>)->Result<(Header,BlockOutput,ChildCtx),Reject>{
        let ctx=self.child_ctx(p,0)?;
        if key.address()!=ctx.proposer{return blk("not the drawn proposer")}
        let ts=ctx.window.proposer_timestamp(clock).map_err(|e|Reject::Block(format!("proposer ts {e:?}")))?;
        let out=self.execute(p,&ctx,ts,Proposer::Signed(key.address()),&body,effects)?;
        let mut h=self.fill_ut(p,&ctx,ts,&out,key.address().as_slice());
        let tid=template_id(&h.ut_raw);h.sig=key.sign_hash(&B256::from(hashes::sig_msg(&tid))).to_vec();reseal(&mut h);
        Ok((h,out,ctx))
    }

    /// UT bytes a valid signed template for (p, ts, proposer, body) must have.
    pub fn rebuild_signed(&self,p:&Entry,ctx:&ChildCtx,ts:u64,proposer:Address,body:&Body,effects:Vec<EvidenceEffect>)->Result<Vec<u8>,Reject>{
        let out=self.execute(p,ctx,ts,Proposer::Signed(proposer),body,effects)?;Ok(self.fill_ut(p,ctx,ts,&out,proposer.as_slice()).ut_raw)
    }

    // ---------------- validation ----------------
    /// H-pre items 1-9 (stateless with the parent header) and H-full 10-17.
    pub fn validate(&self,b:&Block,clock:Option<u64>,phi:u64)->Result<(Entry,ChildCtx),Reject>{
        let cp=self.spec.cp();let x=&b.header;let hash=b.hash();
        if self.blocks.contains_key(&hash){return Err(Reject::Duplicate)}
        if let Some(r)=self.invalid.get(&hash){return blk(format!("known invalid: {r}"))}
        // 1. sizes, 1b NetID.
        if x.encoded.len()>crate::header::HDR_MAX{return blk("1 header size")}
        if x.chain_id!=self.spec.chain_id(){return blk("netChain")}
        if x.genesis_hash!=self.spec.genesis_hash(){return blk("netGenesis")}
        if x.protocol_version!=self.spec.active_version(x.h){return blk("netVersion")}
        if !self.blocks.contains_key(&x.parent_hash){return Err(Reject::UnknownParent)}
        if let Some(r)=self.invalid.get(&x.parent_hash){return blk(format!("ancestorInvalid {r}"))}
        if self.blocks[&x.parent_hash].pruned{return Err(Reject::NeedsRebuild(x.parent_hash))}
        let p=&self.blocks[&x.parent_hash];
        // 2. linkage and H_END.
        if x.h!=p.height+1{return blk("2 height")}
        if x.h>cp.H_END{return blk("10a H_END")}
        if let Some(c)=clock{ if crate::timing::is_future(x.ts,c,phi){return Err(Reject::Future)} }
        // 3. template form. proposer and a are committed (blockReject); sig is not (envReject).
        let tid=template_id(&x.ut_raw);
        let signed=!x.proposer.is_empty();
        if signed{
            if x.proposer.len()!=20{return blk("1 proposer width")}
            if x.a!=0{return blk("3 signed requires a=0")}
            if x.sig.len()!=65{return Err(Reject::Envelope("3 signed template without signature".into()))}
            match hashes::recover_address(&hashes::sig_msg(&tid),&x.sig){Ok(a) if a[..]==x.proposer[..]=>{},_=>return Err(Reject::Envelope("3 template signature".into()))}
        }else if !x.sig.is_empty(){return Err(Reject::Envelope("3 signature without proposer".into()))}
        // 4. timing window and fallback timestamp.
        let ctx=self.child_ctx(p,x.a)?;
        if !ctx.window.contains(x.ts){return blk("4 window")}
        if !signed{let fb=ctx.window.fallback_timestamp(cp.dFbWait).map_err(|_|Reject::Block("4 fb".into()))?;if x.ts!=fb{return blk("4 fallback timestamp")}}
        // 5. ASERT target. 6/7 nonce and PoW.
        if x.target!=ctx.target{return blk("5 target")}
        if (x.nonce as u128)>=ctx.assignment.nonce_max(){return blk("6 nonce>=nMax")}
        if !le_target(&pow_hash(&tid,x.nonce),&x.target){return blk("7 pow")}
        // 8. winnerSig recoverable.
        let win=hashes::win_msg(&tid,x.nonce,&share_root(x));
        let winner=hashes::recover_address(&win,&x.winner_sig).map_err(|_|Reject::Envelope("8 winnerSig".into()))?;
        // 9. shares.
        if x.shares.len()>usize::from(cp.S_max){return blk("1 shareList size")}
        for w in x.shares.windows(2){if w[0]>=w[1]{return blk("9 shares not strictly ascending")}}
        for n in &x.shares{
            if *n==x.nonce||(*n as u128)>=ctx.assignment.nonce_max(){return blk("9 share range")}
            if !le_target(&pow_hash(&tid,*n),&ctx.t_share){return blk("9 share target")}
        }
        // 10. parent not final. 11. gas limit and base fee.
        if p.is_final{return blk("10 final parent")}
        if x.gas_limit!=cp.GAS_LIMIT{return blk("11 gasLimit")}
        if from_fixed(&x.base_fee)!=ctx.base_fee{return blk("11 baseFee")}
        // Body binding first (D129): the block hash commits the header only and the body through
        // tx_root/evidence_root. A body that does not match is another copy, not an invalid block:
        // envReject, never marked invalid. Body-content checks below run on the bound body only.
        // An uncomputable commitment (empty item) is also a copy fault: no header can commit to it (audit A01).
        let bound=crate::types::body_commitment(&b.body.txs)==Some(x.tx_root)&&crate::types::body_commitment(&b.body.evidence)==Some(x.evidence_root);
        if !bound{return Err(Reject::Envelope("15 body does not match the header roots".into()))}
        // 1 (body): sizes and evidence bounds before any evidence evaluation.
        if b.body.txs.iter().any(|t|t.len()>cp.TX_MAX as usize){return blk("1 TX_MAX")}
        // consensus.md: Body = [txs, evidence] <= BODY_MAX, the encoded body, exactly as Body::decode
        // checks it for blocks from peers (review finding: the raw item sum was checked here).
        if b.body.encode().len()>cp.BODY_MAX as usize{return blk("1 BODY_MAX")}
        if b.body.evidence.len()>usize::from(cp.E_max)||b.body.evidence.iter().any(|e|e.len()>cp.EVID_BYTES_MAX as usize){return blk("1 evidence bounds")}
        // 12. exclusive form. Fallback: body 0xc2c0c0 and UT byte-equal to Build_fb (needs apply).
        let mut fb_out=None;
        if signed{ if x.proposer[..]!=ctx.proposer[..]{return blk("12 proposer is not Draw(h,0)")} }
        else{
            if b.body.encode()!=EMPTY_BODY{return blk("12 fallback body")}
            let out=self.execute(p,&ctx,x.ts,Proposer::Fallback,&b.body,vec![])?;
            if self.fill_ut(p,&ctx,x.ts,&out,&[]).ut_raw!=x.ut_raw{return blk("12 fallback UT differs from Build_fb")}
            fb_out=Some(out);
        }
        // 13/14. ownership (winnerSig signer part is envReject).
        let owner=ctx.assignment.owner(x.nonce).ok_or_else(||Reject::Block("13 owner".into()))?;
        if owner!=winner{return Err(Reject::Envelope("13 winnerSig signer is not owner(nonce)".into()))}
        let mut shares=Vec::new();for n in &x.shares{shares.push((*n,addr(&ctx.assignment.owner(*n).ok_or_else(||Reject::Block("14 share owner".into()))?)));}
        // 15. evidence validity (roots were bound above). 16. cumulative caps.
        let effects=if signed{self.evidence_effects(p,&b.body,x.h)?}else{vec![]};
        let tx_bytes:u64=b.body.txs.iter().map(|t|t.len() as u64).sum();
        if !self.within_caps(p,&b.body.txs){return blk("16 caps")}
        // 17. apply.
        let out=match fb_out{Some(o)=>o,None=>self.execute(p,&ctx,x.ts,Proposer::Signed(Address::from_slice(&x.proposer)),&b.body,effects)?};
        if out.state_root.0!=x.state_root{return blk("17 stateRoot")}
        if out.receipts_root.0!=x.receipts_root||out.logs_bloom[..]!=x.logs_bloom[..]||out.gas_used!=x.gas_used{return blk("17 receipts/bloom/gasUsed")}
        let tx_hashes=b.body.txs.iter().map(|t|revm::primitives::keccak256(t)).collect();
        let entry=Entry{hash,header:x.clone(),body:b.body.clone(),height:x.h,parent:Some(p.hash),total_work:p.total_work.saturating_add(work(&x.target)),
            import_seq:0,signed,ts:x.ts,target:x.target,base_fee:ctx.base_fee,gas_used:x.gas_used,seal:seal(&tid,x.nonce),state:out.state,is_final:out.is_final,
            result:Some(ParentResult{block_hash:B256::from(hash),winner:addr(&owner),shares}),receipts:out.receipts,tx_hashes,
            cum_txs:p.cum_txs+b.body.txs.len() as u64,cum_tx_bytes:p.cum_tx_bytes+tx_bytes,cum_log_bytes:p.cum_log_bytes+out.log_bytes,pruned:false,drawn:ctx.proposer,
            ranges:ctx.assignment.ranges().iter().map(|r|(addr(&r.id()),r.start(),r.end_exclusive())).collect(),body_off:None,offloaded:false};
        Ok((entry,ctx))
    }

    /// Item 16 (consensus.md:170): the transaction count and raw bytes (D49: len(rawTx)) of p's branch plus
    /// `txs` within TX_CAP and TXBYTES_CAP. The one definition validation, the builder and template locking use.
    pub fn within_caps(&self,p:&Entry,txs:&[Vec<u8>])->bool{
        let cp=self.spec.cp();let bytes=txs.iter().try_fold(p.cum_tx_bytes,|n,t|n.checked_add(t.len() as u64));
        p.cum_txs.checked_add(txs.len() as u64).map_or(false,|n|n<=cp.TX_CAP)&&bytes.map_or(false,|n|n<=cp.TXBYTES_CAP)
    }
    /// What item 16 leaves for a child of p: (transactions, raw bytes).
    pub fn caps_room(&self,p:&Entry)->(u64,u64){let cp=self.spec.cp();(cp.TX_CAP.saturating_sub(p.cum_txs),cp.TXBYTES_CAP.saturating_sub(p.cum_tx_bytes))}

    /// Evidence (incentives.md "الأدلة"). Type 1: RLP([1, ST1, ST2]); type 2:
    /// RLP([2, TemplateID, nonce, shareRoot1, sig1, shareRoot2, sig2]). Invalid
    /// evidence invalidates the carrying block.
    pub fn evidence_effects(&self,p:&Entry,body:&Body,h:u64)->Result<Vec<EvidenceEffect>,Reject>{
        let cp=self.spec.cp();let mut out=Vec::new();let mut accused_seen=Vec::new();
        for raw in &body.evidence{
            let it=crate::rlp::decode(raw).map_err(|_|Reject::Block("15 evidence rlp".into()))?;let f=it.list().ok_or_else(||Reject::Block("15 evidence".into()))?;
            let kind=f.first().and_then(|k|k.bytes()).ok_or_else(||Reject::Block("15 evidence kind".into()))?;
            let (accused,j)=match kind{
                [1] if f.len()==3=>self.evidence_type1(p,&f[1],&f[2],h)?,
                [2] if f.len()==7=>self.evidence_type2(p,&f,h)?,
                _=>return blk("15 evidence form"),
            };
            if accused_seen.contains(&accused){return blk("15 duplicate accused")}
            match apply::miner_record(&p.state,accused){Some(r) if !r.tomb=>{},_=>return blk("15 accused has no live record")}
            accused_seen.push(accused);
            out.push(match j{Some(j)=>EvidenceEffect::PunishAndInvalidate{accused,j},None=>EvidenceEffect::Punish{accused}});
        }
        let _=cp;Ok(out)
    }
    fn ancestor_at<'a>(&'a self,p:&'a Entry,height:u64)->Option<&'a Entry>{let mut cur=Some(p);while let Some(e)=cur{if e.height==height{return Some(e)}if e.height<height{return None}cur=e.parent.and_then(|x|self.blocks.get(&x));}None}
    fn evidence_type1(&self,p:&Entry,a:&crate::rlp::Item<'_>,b:&crate::rlp::Item<'_>,h_incl:u64)->Result<(Address,Option<u64>),Reject>{
        // ST = [UT, sig]; reuse the strict header codec by wrapping ST in a header shell.
        let parse=|it:&crate::rlp::Item<'_>|->Result<(Header,Vec<u8>),Reject>{
            let st=it.list().ok_or_else(||Reject::Block("ev1 st".into()))?;if st.len()!=2{return blk("ev1 st")}
            let sig=st[1].bytes().ok_or_else(||Reject::Block("ev1 sig".into()))?.to_vec();
            let mut full=crate::rlp::encode(it);crate::rlp::encode_bytes(&0u64.to_be_bytes(),&mut full);full.push(0xc0);crate::rlp::encode_bytes(&[1u8;65],&mut full);
            let mut enc=Vec::new();crate::rlp::encode_list_payload(&full,&mut enc);
            let hb=crate::header::decode(&enc).map_err(|_|Reject::Block("ev1 ut decode".into()))?;Ok((hb,sig))
        };
        let (u1,s1)=parse(a)?;let (u2,s2)=parse(b)?;
        if u1.ut_raw==u2.ut_raw{return blk("ev1 identical")}
        if u1.parent_hash!=u2.parent_hash||u1.h!=u2.h||u1.a!=0||u2.a!=0||u1.chain_id!=self.spec.chain_id()||u2.chain_id!=self.spec.chain_id()||u1.genesis_hash!=self.spec.genesis_hash()||u2.genesis_hash!=self.spec.genesis_hash(){return blk("ev1 context")}
        if u1.h+u64::from(self.spec.cp().E_win)<h_incl{return blk("ev1 too old")}
        let r1=hashes::recover_address(&hashes::sig_msg(&template_id(&u1.ut_raw)),&s1).map_err(|_|Reject::Block("ev1 sig1".into()))?;
        let r2=hashes::recover_address(&hashes::sig_msg(&template_id(&u2.ut_raw)),&s2).map_err(|_|Reject::Block("ev1 sig2".into()))?;
        if r1!=r2{return blk("ev1 signers differ")}
        // Both are signed templates (§3 form): proposer present and equal to the signer.
        if u1.proposer[..]!=r1[..]||u2.proposer[..]!=r1[..]{return blk("ev1 proposer is not the signer")}
        if u1.h>h_incl{return blk("ev1 future height")}
        // DrawIndex[h mod E_win]: the proposer drawn for height u1.h on the carrying branch.
        let drawn=if u1.h==p.height+1{let m=self.membership(p,u1.h)?;self.draw(p,&m,u1.h)?}
            else{self.ancestor_at(p,u1.h).ok_or_else(||Reject::Block("ev1 height not on branch".into()))?.drawn};
        if drawn[..]!=r1[..]{return blk("ev1 signer not drawn")}
        Ok((addr(&r1),None))
    }
    fn evidence_type2(&self,p:&Entry,f:&[crate::rlp::Item<'_>],h_incl:u64)->Result<(Address,Option<u64>),Reject>{
        let b32=|i:usize|->Result<[u8;32],Reject>{let v=f[i].bytes().ok_or_else(||Reject::Block("ev2".into()))?;if v.len()!=32{return blk("ev2 len")}let mut o=[0;32];o.copy_from_slice(v);Ok(o)};
        let tid=b32(1)?;let nb=f[2].bytes().ok_or_else(||Reject::Block("ev2 nonce".into()))?;if nb.len()!=8{return blk("ev2 nonce")}
        let mut n8=[0u8;8];n8.copy_from_slice(nb);let nonce=u64::from_be_bytes(n8);
        let (r1,r2)=(b32(3)?,b32(5)?);if r1==r2{return blk("ev2 equal roots")}
        let s1=f[4].bytes().ok_or_else(||Reject::Block("ev2".into()))?;let s2=f[6].bytes().ok_or_else(||Reject::Block("ev2".into()))?;
        let a1=hashes::recover_address(&hashes::win_msg(&tid,nonce,&r1),s1).map_err(|_|Reject::Block("ev2 sig1".into()))?;
        let a2=hashes::recover_address(&hashes::win_msg(&tid,nonce,&r2),s2).map_err(|_|Reject::Block("ev2 sig2".into()))?;
        if a1!=a2{return blk("ev2 signers")}
        // An ancestor j >= h-E_win with this TemplateID; accused = owner(nonce) there.
        let mut cur=Some(p);
        while let Some(e)=cur{
            if e.height==0||e.height+u64::from(self.spec.cp().E_win)<h_incl{break}
            if template_id(&e.header.ut_raw)==tid{
                // owner(nonce) under that block's assignment (stored ranges, D142).
                let owner=e.ranges.iter().find(|(_,s0,e0)|*s0<=nonce as u128&&(nonce as u128)<*e0).map(|r|r.0).ok_or_else(||Reject::Block("ev2 nonce outside nMax".into()))?;
                if owner.0.0!=a1{return blk("ev2 signer not owner(nonce)")}
                return Ok((addr(&a1),Some(e.height)));
            }
            cur=e.parent.and_then(|x|self.blocks.get(&x));
        }
        blk("ev2 no ancestor with TemplateID")
    }

    // ---------------- import and D133 fork choice ----------------
    pub fn insert(&mut self,mut e:Entry)->bool{
        e.import_seq=self.next_seq;self.next_seq+=1;let hash=e.hash;self.blocks.insert(hash,e);
        let better=self.better(&hash,&self.head.clone());
        if better{self.head=hash;self.rebuild_canonical();}
        better
    }
    pub fn mark_invalid(&mut self,hash:[u8;32],why:String){
        if self.invalid.insert(hash,truncate(&why)).is_none(){self.invalid_order.push_back(hash);}
        while self.invalid_order.len()>INVALID_MAX{if let Some(old)=self.invalid_order.pop_front(){self.invalid.remove(&old);}}
    }
    /// R21 retention: drop states of canonical blocks at height <= head-K_hist (genesis kept).
    /// A13 side-branch bounds (local retention, never validity; consensus.md:29, D118):
    /// - a non-canonical block `r_keep` or more below the head is removed with its descendants
    ///   (adoption is owed at depth <= R_keep, network.md:144; deeper is governance.md:200);
    /// - at most `side_cap` UNPROTECTED non-canonical blocks are kept: the lowest-work unprotected
    ///   leaf goes first, repeatedly (its parent may become a leaf), so the bound holds after every
    ///   call, a reorg included. `protect` (a sync session's fetched branch, or on replay the blocks
    ///   later journal records build on) is exempt from this cap only;
    /// - every journaled non-canonical block is offloaded to metadata (D-REORG-REDB): its body,
    ///   receipts, tx hashes and encoded header are dropped and read from the journal on demand.
    ///   Canonical blocks are never offloaded here (`restore_canonical` makes adopted ones whole);
    /// - at most `side_max` non-canonical blocks keep a state (unprotected and lowest-work first
    ///   are pruned, rebuilt on demand).
    pub fn retain(&mut self){
        let head_h=self.head().height;let cut=head_h.saturating_sub(self.k_hist);
        // R21 is the canonical trie window; non-canonical states are bounded by side_max below. (Pruning
        // a side block below the window made each block of a deep competing branch rebuild its parent
        // from genesis: quadratic work for an R_keep-deep adoption.)
        let prune:Vec<[u8;32]>=self.canonical.iter().skip(1).take(cut as usize).copied().collect();
        for h in prune{if let Some(e)=self.blocks.get_mut(&h){if !e.pruned{e.state=InMemoryDB::default();e.pruned=true;}}}
        let side=|c:&Chain|->Vec<[u8;32]>{c.blocks.values().filter(|e|e.height>0&&!c.is_canonical(&e.hash)).map(|e|e.hash).collect()};
        let r_keep=self.r_keep;
        let mut gone:Vec<[u8;32]>=side(self).into_iter().filter(|h|self.blocks[h].height+r_keep<=head_h).collect();
        for h in &gone{self.blocks.remove(h);}
        // Descendants of a removed block go too (their parent is gone).
        loop{let orphaned:Vec<[u8;32]>=self.blocks.values().filter(|e|e.parent.map_or(false,|p|!self.blocks.contains_key(&p))).map(|e|e.hash).collect();
            if orphaned.is_empty(){break}for h in orphaned{self.blocks.remove(&h);gone.push(h);}}
        let side_now=side(self);
        let unprotected=side_now.iter().filter(|h|!self.protect.contains(*h)).count();
        // Live: unprotected <= side_cap (a session holds <= protect_max more). Replay: all <= their sum.
        let (count,limit)=if self.replaying{(side_now.len(),self.side_cap+self.protect_max())}else{(unprotected,self.side_cap)};
        if count>limit{
            // Children over all blocks: a block with a (protected) child is never a leaf.
            let mut children:HashMap<[u8;32],usize>=HashMap::new();
            for e in self.blocks.values(){if let Some(p)=e.parent{*children.entry(p).or_insert(0)+=1;}}
            let evictable:std::collections::HashSet<[u8;32]>=side_now.iter().filter(|h|!self.protect.contains(*h)).copied().collect();
            let key=|c:&Chain,h:&[u8;32]|{let e=&c.blocks[h];std::cmp::Reverse((e.total_work,e.import_seq,*h))};
            let mut leaves:std::collections::BinaryHeap<_>=evictable.iter().filter(|h|!children.contains_key(*h)).map(|h|key(self,h)).collect();
            let mut n=count;
            while n>limit{
                let Some(std::cmp::Reverse((_,_,h)))=leaves.pop() else{break};
                let parent=self.blocks.remove(&h).and_then(|e|e.parent);gone.push(h);n-=1;
                if let Some(p)=parent{if let Some(c)=children.get_mut(&p){*c-=1;if *c==0&&evictable.contains(&p){children.remove(&p);leaves.push(key(self,&p));}}}
            }
        }
        for h in gone{self.evicted_total+=1;if self.evicted.insert(h){self.evicted_order.push_back(h);}}
        while self.evicted_order.len()>EVICTED_MAX{if let Some(old)=self.evicted_order.pop_front(){self.evicted.remove(&old);}}
        // Live: protection is for non-canonical session blocks only (an adopted one no longer counts
        // toward protect_max). Replay keeps a canonical block protected while a later record builds on
        // it, in case a later replayed reorg makes it non-canonical again.
        let keep:Vec<[u8;32]>=self.protect.iter().filter(|h|self.blocks.contains_key(*h)&&(self.replaying||!self.is_canonical(h))).copied().collect();
        self.protect=keep.into_iter().collect();
        // Offload: the journal holds every byte dropped here (body_off is set only after a fsynced
        // append), so no crash can lose them; genesis is never journaled and never offloaded.
        let side_left=side(self);
        for h in &side_left{if let Some(e)=self.blocks.get_mut(h){if !e.offloaded&&e.body_off.is_some()&&e.height>0{offload(e);}}}
        let mut with_state:Vec<(bool,U256,u64,[u8;32])>=side_left.into_iter().filter(|h|!self.blocks[h].pruned).map(|h|{let e=&self.blocks[&h];(self.protect.contains(&h),e.total_work,e.import_seq,h)}).collect();
        let side_max=self.spec.local().side_max as usize;
        if with_state.len()>side_max{with_state.sort();let over=with_state.len()-side_max;
            let drop:Vec<[u8;32]>=with_state.into_iter().take(over).map(|x|x.3).collect();
            for h in drop{if let Some(e)=self.blocks.get_mut(&h){e.state=InMemoryDB::default();e.pruned=true;}}}
    }
    /// Height of the lowest common ancestor of two stored blocks (metadata walk).
    pub fn lca_height(&self,a:&[u8;32],b:&[u8;32])->Option<u64>{
        let (mut x,mut y)=(*a,*b);
        loop{
            if x==y{return self.blocks.get(&x).map(|e|e.height)}
            let (ex,ey)=(self.blocks.get(&x)?,self.blocks.get(&y)?);
            if ex.height>=ey.height{x=ex.parent?}else{y=ey.parent?}
        }
    }
    /// Replay of a journal record whose block is already stored (D-REORG-REDB). Live import journals
    /// a block only when it is absent, so a second record means live had removed it by retention and
    /// imported it again: consensus.md:205 gives such a block a NEW importSeq, so replay does the same
    /// (keeping live and replayed D133 keys order-equal). The head stays the D133 maximum.
    pub fn reimport(&mut self,hash:&[u8;32],header:Header,body_off:Option<u64>){
        // Live builds the re-imported entry from that copy (its envelope bytes may differ: the block hash
        // does not commit sig/winnerSig) and serves it from that record, so replay keeps the same copy.
        let Some(e)=self.blocks.get_mut(hash) else{return};e.import_seq=self.next_seq;self.next_seq+=1;
        let resident=!e.offloaded;e.header=header;if !resident{e.header.encoded=Vec::new();}if body_off.is_some(){e.body_off=body_off;}
        if self.is_canonical(hash){self.recompute_head();}
        else if self.better(hash,&self.head.clone()){self.head=*hash;self.rebuild_canonical();}
    }
    /// Head = the D133 maximum over every stored block (D133: independent of the scan order).
    fn recompute_head(&mut self){
        let all:Vec<[u8;32]>=self.blocks.keys().copied().collect();let mut best=self.canonical[0];
        for h in all{if self.better(&h,&best){best=h;}}
        self.head=best;self.rebuild_canonical();
    }
    /// Whether every canonical block holds its bytes (D-REORG-REDB invariant after an import or open).
    pub fn canonical_resident(&self)->bool{self.canonical.iter().all(|h|!self.blocks[h].offloaded)}
    /// A block's committed body: resident, or read back from the journal when offloaded.
    pub fn body_of(&self,e:&Entry,src:Option<&dyn BlockBytes>)->Result<Body,Reject>{
        if !e.offloaded{return Ok(e.body.clone())}
        let off=e.body_off.ok_or_else(||Reject::Block("offloaded block without body_off".into()))?;
        let src=src.ok_or(Reject::NeedsRebuild(e.hash))?;let (_,bb,_)=src.record_at(off)?;
        Body::decode(&bb,self.spec.cp().BODY_MAX as usize).map_err(|_|Reject::Block("offloaded body decode".into()))
    }
    /// Re-executes the stored block `e` on its parent `p` (whose state must be resident) and checks the
    /// result against the committed header and ParentResult.
    fn reexec(&self,p:&Entry,e:&Entry,body:&Body)->Result<BlockOutput,Reject>{
        let ctx=self.child_ctx(p,e.header.a)?;let effects=self.evidence_effects(p,body,e.height)?;
        let proposer=if e.signed{Proposer::Signed(Address::from_slice(&e.header.proposer))}else{Proposer::Fallback};
        let out=self.execute(p,&ctx,e.ts,proposer,body,effects)?;
        if out.state_root.0!=e.header.state_root{return blk("rebuild stateRoot mismatch")}
        // Re-derive ParentResult from the header and the rebuilt assignment (parentResultMismatch).
        let owner=|n:u64|ctx.assignment.owner(n).map(|a|addr(&a));
        let derived=ParentResult{block_hash:B256::from(e.hash),winner:owner(e.header.nonce).ok_or_else(||Reject::Block("rebuild owner".into()))?,
            shares:e.header.shares.iter().map(|n|owner(*n).map(|o|(*n,o))).collect::<Option<Vec<_>>>().ok_or_else(||Reject::Block("rebuild share owner".into()))?};
        if Some(&derived)!=e.result.as_ref(){return blk("parentResultMismatch")}
        Ok(out)
    }
    /// D-REORG-REDB restore: after an adoption (or at the end of replay) the canonical blocks above
    /// `from_h` that were offloaded while non-canonical are made whole again: header bytes and body from
    /// the journal, receipts by re-executing the adopted suffix in order from the fork point (a rolling
    /// state; state residence is unchanged), each checked against stateRoot, receiptsRoot, gasUsed and
    /// ParentResult. Canonical blocks are therefore always resident for RPC and range serving, exactly as
    /// before this change. Returns the number of blocks restored.
    pub fn restore_canonical(&mut self,from_h:u64,src:&dyn BlockBytes)->Result<usize,Reject>{
        let head_h=self.head().height;
        let off=|c:&Chain,h:u64|c.canonical_at(h).map_or(false,|e|e.offloaded);
        let Some(first)=(from_h.max(1)..=head_h).find(|h|off(self,*h)) else{return Ok(0)};
        let last=(first..=head_h).rev().find(|h|off(self,*h)).unwrap_or(first);
        let ph=self.canonical[first as usize-1];let was_pruned=self.blocks[&ph].pruned;
        self.ensure_state_with(&ph,Some(src))?;
        let mut p=self.blocks[&ph].meta_clone();p.state=self.blocks[&ph].state.clone();
        if was_pruned&&ph!=self.canonical[0]{let x=self.blocks.get_mut(&ph).unwrap();x.state=InMemoryDB::default();x.pruned=true;}
        let mut n=0;
        for hgt in first..=last{
            let hash=self.canonical[hgt as usize];let e=&self.blocks[&hash];
            let (hb,bb)=if e.offloaded{let o=e.body_off.ok_or_else(||Reject::Block("offloaded block without body_off".into()))?;let (hb,bb,_)=src.record_at(o)?;(Some(hb),Some(bb))}else{(None,None)};
            let body=match &bb{Some(bb)=>Body::decode(bb,self.spec.cp().BODY_MAX as usize).map_err(|_|Reject::Block("offloaded body decode".into()))?,None=>e.body.clone()};
            if let Some(hb)=&hb{if decode_header(hb).map(|h|block_hash(&h)).ok()!=Some(hash){return blk("restore: journal header does not hash to the block")}}
            let out=self.reexec(&p,e,&body)?;
            if out.receipts_root.0!=e.header.receipts_root||out.gas_used!=e.header.gas_used{return blk("restore: receipts mismatch")}
            let x=self.blocks.get_mut(&hash).unwrap();
            if x.offloaded{x.tx_hashes=body.txs.iter().map(|t|revm::primitives::keccak256(t)).collect();x.receipts=out.receipts;x.body=body;
                x.header.encoded=hb.unwrap_or_default();x.offloaded=false;n+=1;}
            let mut next=x.meta_clone();next.state=out.state;p=next;
        }
        Ok(n)
    }
    /// Bound of `protect` (a sync session's fetched branch): network.md:27 (sync stage R: <= 4096 headers
    /// per branch), i.e. 2·R_keep at the default R_keep.
    pub fn protect_max(&self)->usize{(2*self.r_keep) as usize}
    /// Whether retention removed this block recently (it is then not taken again).
    pub fn was_evicted(&self,hash:&[u8;32])->bool{self.evicted.contains(hash)}
    /// Non-canonical blocks, and those holding a state (A13 accounting, status).
    pub fn side_counts(&self)->(usize,usize){let side=self.blocks.values().filter(|e|e.height>0&&!self.is_canonical(&e.hash));let (mut n,mut s)=(0,0);for e in side{n+=1;if !e.pruned{s+=1}}(n,s)}
    /// TrieRebuild: re-executes from the nearest retained ancestor and checks
    /// every stateRoot against the committed header.
    pub fn ensure_state(&mut self,hash:&[u8;32])->Result<(),Reject>{self.ensure_state_with(hash,None)}
    /// As `ensure_state`, but given a `BlockBytes` source so a block whose body was offloaded
    /// (D-REORG-REDB) is re-executed from its journal record. A bare chain (nothing offloaded) passes
    /// `None`. A pruned block reached on the rebuild path that is offloaded but has no source, or no
    /// `body_off`, is an error — never a silent empty body.
    pub fn ensure_state_with(&mut self,hash:&[u8;32],src:Option<&dyn BlockBytes>)->Result<(),Reject>{
        let mut path=vec![];let mut cur=*hash;
        while self.blocks.get(&cur).map(|e|e.pruned).unwrap_or(false){path.push(cur);cur=self.blocks[&cur].parent.ok_or_else(||Reject::Block("rebuild root".into()))?;}
        if path.is_empty(){return Ok(())}
        // A13: rolling re-execution. Only the block being extended holds a state; intermediate
        // states are dropped, so a rebuild of any depth keeps at most two snapshots alive.
        let root=self.blocks.get(&cur).ok_or_else(||Reject::Block("rebuild root".into()))?;
        let mut p=root.meta_clone();p.state=root.state.clone();
        for h in path.into_iter().rev(){
            let e=self.blocks[&h].meta_clone();
            // Off-heap body: fetched and decoded from the journal when this block was offloaded.
            let body=self.body_of(&e,src)?;
            let out=self.reexec(&p,&e,&body)?;
            let mut next=e;next.state=out.state;next.pruned=false;p=next;self.rebuilds+=1;
        }
        let x=self.blocks.get_mut(hash).ok_or_else(||Reject::Block("rebuild target".into()))?;x.state=p.state;x.pruned=false;
        Ok(())
    }
    fn key(&self,h:&[u8;32])->(u8,u64,[u8;32]){let e=&self.blocks[h];(if e.signed{0}else{1},e.import_seq,e.hash)}
    /// t1 ≻ t2: greater W, or equal W and smaller key at the children of the LCA.
    pub fn better(&self,t1:&[u8;32],t2:&[u8;32])->bool{
        if t1==t2{return false}
        let (a,b)=(&self.blocks[t1],&self.blocks[t2]);
        if a.total_work!=b.total_work{return a.total_work>b.total_work}
        let (mut x,mut y)=(*t1,*t2);let (mut cx,mut cy)=(*t1,*t2);
        while self.blocks[&x].height>self.blocks[&y].height{cx=x;x=self.blocks[&x].parent.unwrap();}
        while self.blocks[&y].height>self.blocks[&x].height{cy=y;y=self.blocks[&y].parent.unwrap();}
        if x==y{ // one is an ancestor of the other with equal work: impossible since work>=1.
            return self.blocks[t1].height>self.blocks[t2].height;
        }
        while x!=y{cx=x;cy=y;x=self.blocks[&x].parent.unwrap();y=self.blocks[&y].parent.unwrap();}
        self.key(&cx)<self.key(&cy)
    }
    fn rebuild_canonical(&mut self){
        let mut path=Vec::new();let mut cur=Some(self.head);
        while let Some(h)=cur{path.push(h);cur=self.blocks[&h].parent;}
        path.reverse();self.canonical=path;
    }
    /// Whether `hash` is on the current canonical chain.
    pub fn is_canonical(&self,hash:&[u8;32])->bool{self.blocks.get(hash).map(|e|self.canonical.get(e.height as usize)==Some(hash)).unwrap_or(false)}
}
pub fn from_fixed_lp4(v:&pocol_lp4_execution::fixed::U256)->U256{U256::from_be_bytes(v.to_be_bytes())}
pub fn assignment_range(ctx:&ChildCtx,id:Address)->Option<(u64,u64)>{
    ctx.assignment.ranges().iter().find(|r|r.id()[..]==id[..]).and_then(|r|r.inclusive_end().map(|end|(r.start() as u64,end)))
}
pub fn nonce_space()->u128{assignment::NONCE_SPACE}
