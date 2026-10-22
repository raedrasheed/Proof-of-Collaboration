//! Node orchestration: one consensus thread owns the chain, journal, pool and
//! production state machine (consensus.md §4) and processes events from peers,
//! the range miner, RPC and a 50 ms tick.
use std::collections::{BTreeSet,HashMap,HashSet,VecDeque};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc,Mutex,mpsc::{self,Receiver,Sender,SyncSender}};
use std::time::{Duration,SystemTime,UNIX_EPOCH};
use crate::{hashes,header::Header};
use pocol_lp4_execution::{apply::ParentResult,txsign::Key,wire,native::{self,NativeBlockContext},user_phase::{self,PoolMeter}};
use revm::{InMemoryDB,primitives::{Address,B256,U256}};
use crate::{chain::{self,Chain,ChildCtx,Entry,Reject,Spec},miner::{self,MinerEvent,MinerHandle},net::{self,Msg,NetEvent,Peer,PeerId},store::{self,Journal},types::*};

pub struct Config{
    pub dir:PathBuf,
    pub name:String,
    pub miner:Option<Key>,
    pub listen:Option<SocketAddr>,
    pub peers:Vec<SocketAddr>,
    pub rpc:Option<SocketAddr>,
    /// Optional: stop after the canonical head reaches this height.
    pub stop_at:Option<u64>,
    pub log:bool,
    /// A05 local resource bounds (P2P and RPC separately).
    pub limits:Limits,
}
#[derive(Clone,Debug)]
pub struct Limits{pub net:net::Limits,pub rpc:crate::rpc::Limits,
    /// Node memory budget for the A13 resident bound (resources::check at open).
    pub mem_budget:u64}
impl Default for Limits{fn default()->Self{Self{net:Default::default(),rpc:Default::default(),mem_budget:MEM_BUDGET}}}
/// Default memory budget of one single-host devnet node.
pub const MEM_BUDGET:u64=6<<30;
/// Blocks waiting for their timestamp, buffered templates, equivocation observations,
/// status rejects and evidence awaiting inclusion (A13 accounting).
pub const FUTURE_MAX:usize=64;pub const TEMPLATES_MAX:usize=64;pub const SEEN_MAX:usize=4096;pub const REJECTS_MAX:usize=256;pub const EVIDENCE_POOL_MAX:usize=64;
/// Events waiting for the consensus thread (all sources); senders block when it is full.
pub const EVENT_QUEUE:usize=256;
/// Orphans (blocks whose parent is unknown): parent keys, blocks per parent and bytes, all peers together.
pub const ORPHAN_PARENTS_MAX:usize=64;pub const ORPHANS_PER_PARENT:usize=16;pub const ORPHAN_BYTES_MAX:usize=16*1024*1024;
/// Blocks walked on each side of a reorg to restore detached transactions (A11).
pub const REORG_RESTORE_MAX:usize=1024;
/// Receipt times kept for production (only recent parents matter).
pub const RECEIVED_MAX:usize=1024;

/// Rpc: request body, reply channel, and whether it carried an Origin header (a site).
pub enum Event{Net(NetEvent),Miner(MinerEvent),Rpc(Vec<u8>,Sender<String>,bool),Tick}

pub fn now_ms()->u128{SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()}
pub fn now_s()->u64{(now_ms()/1000) as u64}

struct Locked{header:Header,body:Body,tid:[u8;32],ctx:ChildCtx,fallback:bool}
/// Propose: Draw(h,0) waits until its template timestamp max(L(0),C) is not in the
/// future for receivers (C+Φ >= L(0)); with Φ=0 a template built earlier is rejected.
enum Mode{Wait{deadline_ms:u128},Locked(Box<Locked>),Idle,Propose{at_s:u64}}
struct Production{parent:[u8;32],height:u64,attempt:u32,mode:Mode,shares:BTreeSet<u64>,miner:Option<MinerHandle>,solved:bool,received_ms:u128}

/// Pending pool: transactions are kept only if they execute in order on top of
/// the head state (pending state), so several nonces per sender are allowed. The pending
/// state is normalized after every transaction and follows the block caps (`PoolMeter`), so
/// it is bounded like a snapshot (A13).
pub struct Pool{pub txs:Vec<(B256,Vec<u8>)>,pending_state:InMemoryDB,pub bytes:usize,meter:PoolMeter}
pub const POOL_MAX_BYTES:usize=64*1024*1024;
/// Local limit on pooled transactions (about ten blocks of plain transfers): every new head
/// re-executes the pool, so its length bounds that work.
pub const POOL_MAX_TXS:usize=4096;

pub struct Node{
    pub cfg:Config,
    pub chain:Chain,
    journal:Journal,
    peers:HashMap<PeerId,Peer>,
    /// Range sync: the height each peer announced (Hello) or relayed, our head height and when it
    /// last changed, and when a range was last requested.
    peer_heights:HashMap<PeerId,u64>,sync_mark:(u64,u128),sync_ask_ms:u128,sync_turn:usize,
    outbound:Arc<Mutex<HashSet<String>>>,
    pub tx:SyncSender<Event>,
    rx:Receiver<Event>,
    miner_tx:Sender<MinerEvent>,
    prod:Option<Production>,
    orphans:HashMap<[u8;32],Vec<Block>>,
    /// Orphan parent keys, oldest first, and the bytes their blocks hold.
    orphan_order:VecDeque<[u8;32]>,orphan_bytes:usize,
    pub net:net::Net,
    future:Vec<Block>,
    /// Own sealed blocks waiting in `future` for their timestamp (Φ=2φ may be 0 on one host).
    own_future:HashSet<[u8;32]>,
    templates:HashMap<[u8;32],(Header,Body,u128)>,
    received:HashMap<[u8;32],u128>,
    pub pool:Pool,
    pub rejects:VecDeque<(String,String)>,
    pub stats:Stats,
    pub stopped:bool,
    /// Equivocation observations and evidence awaiting inclusion (incentives.md الأدلة).
    seen_templates:HashMap<([u8;32],u64),(Vec<u8>,Vec<u8>,Vec<u8>)>,
    seen_wins:HashMap<([u8;32],u64),([u8;32],[u8;65])>,
    pub evidence_pool:Vec<Vec<u8>>,
}
#[derive(Default,Clone,Debug)]
pub struct Stats{pub imported:u64,pub mined:u64,pub signed_templates:u64,pub fallback_templates:u64,pub shares_seen:u64,pub hashes:u64,pub reorgs:u64}

fn orphan_size(b:&Block)->usize{b.header.encoded.len()+b.body.txs.iter().chain(b.body.evidence.iter()).map(|x|x.len()).sum::<usize>()}
fn result_bytes(r:&Option<ParentResult>)->Vec<u8>{
    let mut p=Vec::new();
    if let Some(r)=r{crate::rlp::encode_bytes(r.winner.as_slice(),&mut p);let mut l=Vec::new();for (n,o) in &r.shares{let mut q=Vec::new();crate::rlp::encode_bytes(&n.to_be_bytes(),&mut q);crate::rlp::encode_bytes(o.as_slice(),&mut q);crate::rlp::encode_list_payload(&q,&mut l);}
        crate::rlp::encode_list_payload(&l,&mut p);}
    let mut o=Vec::new();crate::rlp::encode_list_payload(&p,&mut o);o
}

impl Node{
    /// Opens the journal, replays and re-executes every committed block.
    pub fn open(cfg:Config,spec:Spec)->Result<Self,String>{
        // A13: the resident bound of this profile with these limits must fit the budget.
        crate::resources::check(spec.cp(),spec.local().k_hist,spec.local().side_max,&cfg.limits,cfg.peers.len())?;
        let binding=spec.genesis_hash();
        let rec=store::open(&cfg.dir,&binding).map_err(|e|format!("store: {e:?}"))?;
        let mut chain=Chain::new(spec);
        for (i,payload) in rec.payloads.iter().enumerate(){
            let (hb,bb,rb)=store::decode_record(payload).map_err(|e|format!("record {i}: {e}"))?;
            let header=decode_header(&hb).map_err(|e|format!("record {i}: {e}"))?;
            let body=Body::decode(&bb,chain.spec.cp().BODY_MAX as usize).map_err(|e|format!("record {i}: {e}"))?;
            let block=Block{header,body};
            // Same rules as live import: a journaled fork child of a block below the K_hist window
            // needs the TrieRebuild that import performed before journaling it.
            let (entry,_)=match chain.validate(&block,None,0){
                Err(Reject::NeedsRebuild(p))=>{chain.ensure_state(&p).map_err(|e|format!("replay {i}: rebuild {e:?}"))?;chain.validate(&block,None,0).map_err(|e|format!("replay {i}: {e:?}"))?}
                r=>r.map_err(|e|format!("replay {i}: {e:?}"))?,
            };
            if result_bytes(&entry.result)!=rb{return Err(format!("parentResultMismatch at record {i}"))}
            chain.insert(entry);
            if i%64==63{chain.retain();}
        }
        chain.retain();
        let (tx,rx)=mpsc::sync_channel(EVENT_QUEUE);let (miner_tx,miner_rx)=mpsc::channel::<MinerEvent>();
        let fwd=tx.clone();std::thread::spawn(move||{for e in miner_rx{if fwd.send(Event::Miner(e)).is_err(){break}}});
        let head_state=chain.head().state.clone();let meter=PoolMeter::of(&head_state,chain.spec.profile());
        let net=net::Net::new(cfg.limits.net.clone());
        let mut node=Self{cfg,chain,net,orphan_order:VecDeque::new(),orphan_bytes:0,journal:rec.journal,peers:HashMap::new(),peer_heights:HashMap::new(),sync_mark:(0,0),sync_ask_ms:0,sync_turn:0,outbound:Arc::new(Mutex::new(HashSet::new())),tx,rx,miner_tx,prod:None,
            orphans:HashMap::new(),future:Vec::new(),own_future:HashSet::new(),templates:HashMap::new(),received:HashMap::new(),
            pool:Pool{txs:vec![],pending_state:head_state,bytes:0,meter},rejects:VecDeque::new(),stats:Stats::default(),stopped:false,seen_templates:HashMap::new(),seen_wins:HashMap::new(),evidence_pool:Vec::new()};
        node.stats.imported=rec.payloads.len() as u64;
        if rec.torn_tail{node.log("recovered torn journal tail into a new journal");}
        if rec.migrated_v1{node.log("migrated a fully verified v1 journal to format v2 (original kept as blocks.journal.v1-n)");}
        Ok(node)
    }
    pub fn log(&self,m:&str){if self.cfg.log{eprintln!("[{} {}] {m}",self.cfg.name,now_ms()%100_000_000);}}

    pub fn start_network(&mut self)->Result<(),String>{
        if let Some(a)=self.cfg.listen{let l=std::net::TcpListener::bind(a).map_err(|e|format!("listen {a}: {e}"))?;
            let tx=self.tx.clone();let (ntx,nrx)=mpsc::sync_channel(net::NET_EVENT_QUEUE);std::thread::spawn(move||{for e in nrx{if tx.send(Event::Net(e)).is_err(){break}}});
            net::listen(l,ntx,self.net.clone());}
        for a in self.cfg.peers.clone(){let tx=self.tx.clone();let (ntx,nrx)=mpsc::sync_channel(net::NET_EVENT_QUEUE);std::thread::spawn(move||{for e in nrx{if tx.send(Event::Net(e)).is_err(){break}}});
            net::dial(a,ntx,self.outbound.clone(),self.net.clone());}
        if let Some(a)=self.cfg.rpc{crate::rpc::serve(a,self.tx.clone(),self.cfg.limits.rpc.clone())?;}
        let t=self.tx.clone();std::thread::spawn(move||loop{std::thread::sleep(Duration::from_millis(50));if t.send(Event::Tick).is_err(){break}});
        Ok(())
    }
    /// Runs until stop_at or channel closure.
    pub fn run(&mut self){
        self.restart_production();
        while !self.stopped{
            let ev=match self.rx.recv_timeout(Duration::from_millis(200)){Ok(e)=>e,Err(mpsc::RecvTimeoutError::Timeout)=>Event::Tick,Err(_)=>break};
            self.handle(ev);
        }
        if let Some(p)=&self.prod{if let Some(m)=&p.miner{m.stop();}}
    }
    pub fn handle(&mut self,ev:Event){
        match ev{
            Event::Tick=>self.tick(),
            Event::Miner(m)=>self.on_miner(m),
            Event::Rpc(body,reply,site)=>{let r=crate::rpc::handle_with(self,&body,site);let _=reply.send(r);}
            Event::Net(NetEvent::Connected(id,peer))=>{let hello=self.hello();peer.send(&hello);self.peers.insert(id,peer);}
            Event::Net(NetEvent::Closed(id))=>{self.peer_heights.remove(&id);if let Some(p)=self.peers.remove(&id){if p.outbound{if let Ok(mut s)=self.outbound.lock(){s.remove(&p.addr);}}}}
            Event::Net(NetEvent::Message(id,m))=>self.on_msg(id,m),
        }
    }
    /// Φ = 2φ from the admitted local parameters (future-timestamp slack).
    fn capital_phi(&self)->u64{u64::from(self.chain.spec.local().capital_phi())}
    fn hello(&self)->Msg{let h=self.chain.head();Msg::Hello{chain_id:self.chain.spec.chain_id(),genesis:self.chain.spec.genesis_hash(),head:h.hash,height:h.height,node:self.cfg.name.clone()}}
    fn broadcast(&self,m:&Msg,except:Option<PeerId>){for (id,p) in &self.peers{if Some(*id)!=except{p.send(m);}}}

    // ---------------- import ----------------
    /// Validates, journals (fsync) and inserts a block. Returns Ok(true) if new head.
    pub fn import(&mut self,b:Block,from:Option<PeerId>)->Result<bool,Reject>{
        let hash=b.hash();
        let mut res=self.chain.validate(&b,Some(now_s()),self.capital_phi());
        if let Err(Reject::NeedsRebuild(p))=&res{let p=*p;self.log("TrieRebuild for a fork below the K_hist window");
            if let Err(e)=self.chain.ensure_state(&p){return Err(e)}res=self.chain.validate(&b,Some(now_s()),self.capital_phi());}
        let (entry,_)=match res{
            Ok(v)=>v,
            Err(Reject::UnknownParent)=>{
                let parent=b.header.parent_hash;
                self.add_orphan(parent,b);
                if let Some(id)=from{if let Some(p)=self.peers.get(&id){p.send(&Msg::GetBlock{hash:parent});}}
                return Err(Reject::UnknownParent);
            }
            Err(Reject::Future)=>{if self.future.len()<FUTURE_MAX{self.future.push(b);}return Err(Reject::Future)}
            Err(Reject::Block(why))=>{self.chain.mark_invalid(hash,why.clone());self.reject(hash,&why);return Err(Reject::Block(why))}
            Err(e)=>{if let Reject::Envelope(w)=&e{self.reject(hash,w);}return Err(e)}
        };
        self.observe_template(&b.header);self.observe_win(&b.header);
        let record=store::encode_record(&b.header.encoded,&b.body.encode(),&result_bytes(&entry.result));
        if let Err(e)=self.journal.append(&record){self.log(&format!("FATAL journal append: {e:?}"));std::process::exit(70);}
        self.received.insert(hash,now_ms());
        if self.received.len()>RECEIVED_MAX{let keep=self.chain.head().height.saturating_sub(8);let blocks=&self.chain.blocks;self.received.retain(|h,_|blocks.get(h).map_or(false,|e|e.height>=keep));}
        let old_head=self.chain.head;
        let new_head=self.chain.insert(entry);self.stats.imported+=1;
        // A11: the detached transactions are read before retain() may prune the abandoned branch.
        let detached=if new_head{self.detached_txs(old_head)}else{vec![]};
        self.chain.retain();
        self.broadcast(&Msg::Block{header:b.header.encoded.clone(),body:b.body.encode()},from);
        if new_head{
            if self.chain.get(&self.chain.head).and_then(|e|e.parent)!=Some(old_head){self.stats.reorgs+=1;}
            self.log(&format!("head h={} {} signed={} txs={}",self.chain.head().height,&hex(&hash)[..14],self.chain.head().signed,b.body.txs.len()));
            self.on_new_head(detached);
        }
        // Orphans waiting for this block.
        // A copy whose body does not match its header is only an envelope fault: ask the peers for
        // the real block under that hash (the junk copy may have taken its orphan slot).
        if let Some(children)=self.take_orphans(&hash){for c in children{let h=c.hash();if matches!(self.import(c,None),Err(Reject::Envelope(_))){self.broadcast(&Msg::GetBlock{hash:h},None);}}}
        Ok(new_head)
    }
    /// Bounded orphan store (A05): per parent, parent keys and bytes; the oldest parent goes first.
    fn add_orphan(&mut self,parent:[u8;32],b:Block){
        let hash=b.hash();let size=b.header.encoded.len()+b.body.txs.iter().chain(b.body.evidence.iter()).map(|x|x.len()).sum::<usize>();
        // Duplicates are the same header AND body: a copy with a foreign body (an envelope fault once
        // the parent arrives) must not keep the real block out (review finding, A01-adjacent).
        if self.orphans.get(&parent).map_or(false,|l|l.len()>=ORPHANS_PER_PARENT||l.iter().any(|x|x.hash()==hash&&x.body==b.body)){return}
        if size>ORPHAN_BYTES_MAX{return}
        if !self.orphans.contains_key(&parent){self.orphan_order.push_back(parent);}
        self.orphans.entry(parent).or_default().push(b);self.orphan_bytes+=size;
        while self.orphan_order.len()>ORPHAN_PARENTS_MAX||self.orphan_bytes>ORPHAN_BYTES_MAX{
            let Some(old)=self.orphan_order.pop_front() else{break};
            if let Some(l)=self.orphans.remove(&old){self.orphan_bytes-=l.iter().map(orphan_size).sum::<usize>();}
        }
    }
    fn take_orphans(&mut self,parent:&[u8;32])->Option<Vec<Block>>{
        let l=self.orphans.remove(parent)?;self.orphan_order.retain(|k|k!=parent);self.orphan_bytes-=l.iter().map(orphan_size).sum::<usize>();Some(l)
    }
    pub fn orphan_stats(&self)->(usize,usize,usize){(self.orphans.len(),self.orphans.values().map(|l|l.len()).sum(),self.orphan_bytes)}
    fn reject(&mut self,hash:[u8;32],why:&str){self.rejects.push_back((hex(&hash),chain::truncate(why)));if self.rejects.len()>REJECTS_MAX{self.rejects.pop_front();}self.log(&format!("reject {}: {why}",&hex(&hash)[..14]));}
    fn on_new_head(&mut self,detached:Vec<Vec<u8>>){
        self.rebuild_pool(detached);
        if let Some(s)=self.cfg.stop_at{if self.chain.head().height>=s{self.stopped=true;return}}
        self.restart_production();
    }

    // ---------------- pool ----------------
    fn next_block_ctx(&self)->NativeBlockContext{
        let h=self.chain.head();let cp=self.chain.spec.cp();
        let base=if h.height==0{chain::from_fixed_lp4(&cp.baseFee0)}else{pocol_lp4_execution::fees::next_base_fee(h.base_fee,h.gas_used,h.header.gas_limit).unwrap_or(U256::MAX)};
        NativeBlockContext{height:U256::from(h.height+1),timestamp:U256::from(now_s().max(h.ts+1)),gas_limit:U256::from(cp.GAS_LIMIT),base_fee:base,prevrandao:B256::ZERO}
    }
    pub fn submit_tx(&mut self,raw:Vec<u8>,relay:bool)->Result<B256,String>{
        let cp=self.chain.spec.cp();
        if raw.len()>cp.TX_MAX as usize{return Err("-32014 oversized".into())}
        let env=wire::decode_for_profile(&raw,self.chain.spec.profile()).map_err(|e|format!("{} {e:?}",e.specified_pool_code().unwrap_or(-32000)))?;
        let hash=env.hash();
        if self.pool.txs.iter().any(|(h,_)|*h==hash){return Ok(hash)}
        if self.pool.bytes+raw.len()>POOL_MAX_BYTES||self.pool.txs.len()>=POOL_MAX_TXS{return Err("-32016 pool full".into())}
        let ctx=self.next_block_ctx();
        let r=native::execute_for_profile(&self.pool.pending_state,env.tx_env(),&ctx,self.chain.spec.profile()).map_err(|e|format!("-32000 {e:?}"))?;
        // A13: the effects must stay within the caps a block enforces; then only live entries are kept.
        self.pool.meter.admit(&self.pool.pending_state,&r.state).map_err(|h|format!("-32000 pending state would exceed a cap ({h:?})"))?;
        // The same commit as a block's USER phase (EIP-161 cleanup, normalization), so the meter
        // follows the pending state exactly (second review: touched empty accounts were kept).
        user_phase::commit_tx(&mut self.pool.pending_state,r.state,true);user_phase::drop_unreferenced_code(&mut self.pool.pending_state);
        self.pool.bytes+=raw.len();self.pool.txs.push((hash,raw.clone()));
        if relay{self.broadcast(&Msg::Tx{raw},None);}
        Ok(hash)
    }
    /// Transactions of the blocks that left the canonical chain (from `old` back to the common
    /// ancestor with the new head), oldest block first and in block order, minus those that the
    /// new canonical branch includes (A11). At most REORG_RESTORE_MAX blocks are walked per side.
    fn detached_txs(&self,old:[u8;32])->Vec<Vec<u8>>{
        let height=|x:&[u8;32]|self.chain.get(x).map(|e|e.height);
        let (mut a,mut b)=(old,self.chain.head);let mut gone=Vec::new();let mut kept=HashSet::new();
        for _ in 0..2*REORG_RESTORE_MAX{
            if a==b{break}
            let (Some(ha),Some(hb))=(height(&a),height(&b)) else{break};
            if ha>=hb{let Some(e)=self.chain.get(&a) else{break};gone.push(a);match e.parent{Some(p)=>a=p,None=>break}}
            else{let Some(e)=self.chain.get(&b) else{break};kept.extend(e.tx_hashes.iter().copied());match e.parent{Some(p)=>b=p,None=>break}}
        }
        gone.iter().rev().filter_map(|h|self.chain.get(h)).flat_map(|e|e.body.txs.iter().zip(e.tx_hashes.iter()))
            .filter(|(_,h)|!kept.contains(*h)).map(|(raw,_)|raw.clone()).collect()
    }
    fn rebuild_pool(&mut self,detached:Vec<Vec<u8>>){
        let old=std::mem::take(&mut self.pool.txs);self.pool.bytes=0;self.pool.pending_state=self.chain.head().state.clone();
        self.pool.meter=PoolMeter::of(&self.pool.pending_state,self.chain.spec.profile());
        // Transactions in abandoned blocks return to the pool (consensus §10), before the previous
        // pool; each is re-executed on the new head (nonce, balance, fee) and duplicates are skipped.
        for raw in detached{let _=self.submit_tx(raw,false);}
        for (_,raw) in old{let _=self.submit_tx(raw,false);}
    }
    /// Pool transactions that still execute in order (for a signed template).
    fn template_txs(&self)->Vec<Vec<u8>>{
        let cp=self.chain.spec.cp();let mut out=Vec::new();let mut gas=0u64;let mut bytes=0usize;
        // Encoded item length (RLP string header included); the three list headers take <= 12 bytes.
        let enc=|n:usize|n+1+if n<56{0}else if n<256{1}else if n<65536{2}else{3};
        for (_,raw) in &self.pool.txs{
            let Ok(env)=wire::decode_for_profile(raw,self.chain.spec.profile()) else{continue};let g=env.tx_env().gas_limit;
            if gas+g>cp.GAS_LIMIT||bytes+enc(raw.len())>cp.BODY_MAX as usize-12{break}
            gas+=g;bytes+=enc(raw.len());out.push(raw.clone());
        }
        out
    }

    // ---------------- production (consensus §4) ----------------
    fn restart_production(&mut self){
        if let Some(p)=self.prod.take(){if let Some(m)=p.miner{m.stop();}}
        let head=self.chain.head().clone_light();
        if head.is_final{self.log("chain is final; no production");return}
        let received_ms=*self.received.get(&head.hash).unwrap_or(&now_ms());
        self.prod=Some(Production{parent:head.hash,height:head.height+1,attempt:0,mode:Mode::Idle,shares:BTreeSet::new(),miner:None,solved:false,received_ms});
        self.begin_attempt(0);
    }
    fn begin_attempt(&mut self,a:u32){
        let parent_hash=match &self.prod{Some(p)=>p.parent,None=>return};
        let p=self.chain.get(&parent_hash).unwrap().clone();
        if let Some(pr)=&mut self.prod{pr.attempt=a;pr.shares.clear();pr.solved=false;if let Some(m)=pr.miner.take(){m.stop();}}
        if a==0{
            let ctx=match self.chain.child_ctx(&p,0){Ok(c)=>c,Err(e)=>{self.log(&format!("ctx error {e:?}"));return}};
            let me=self.cfg.miner.as_ref().map(|k|k.address());
            if me==Some(ctx.proposer){
                let phi=self.capital_phi();
                if now_s().saturating_add(phi)<ctx.window.lower(){if let Some(pr)=&mut self.prod{pr.mode=Mode::Propose{at_s:ctx.window.lower()-phi};}return;}
                let txs=self.template_txs();
                if let Some(t)=self.build_signed_template(&p,txs){
                    self.stats.signed_templates+=1;
                    let shell=t.0.encoded.clone();self.broadcast(&Msg::Template{shell,body:t.1.encode()},None);
                    self.lock(t.0,t.1,false);return;
                }
            }
            let received=self.prod.as_ref().unwrap().received_ms;
            let deadline=ctx.window.deadline_ms(received,u64::from(self.chain.spec.local().delta_rel),self.chain.spec.cp().dFbWait).unwrap_or(0);
            if let Some(pr)=&mut self.prod{pr.mode=Mode::Wait{deadline_ms:deadline};}
            // A signed template may already have arrived for this parent.
            if let Some((h,b,arr))=self.templates.remove(&parent_hash){if arr<=deadline{self.try_lock_signed(h,b);}}
        }else{
            self.lock_fallback(&p,a);
        }
    }
    fn build_signed_template(&mut self,p:&Entry,mut txs:Vec<Vec<u8>>)->Option<(Header,Body)>{
        self.cfg.miner.as_ref()?;
        let evidence=self.includable_evidence(p);
        let key=self.cfg.miner.as_ref()?;
        for _ in 0..8{
            let body=Body{txs:txs.clone(),evidence:evidence.clone()};
            let effects=match self.chain.evidence_effects(p,&body,p.height+1){Ok(e)=>e,Err(_)=>vec![]};
            let mut body=if effects.len()==body.evidence.len(){body}else{Body{txs:txs.clone(),evidence:vec![]}};
            // Evidence shares BODY_MAX with the transactions: drop transactions until the encoded body fits.
            while body.encode().len()>self.chain.spec.cp().BODY_MAX as usize&&!body.txs.is_empty(){body.txs.pop();}txs=body.txs.clone();
            // Evidence alone over BODY_MAX (not reachable with E_max·EVID_BYTES_MAX < BODY_MAX): build without it.
            let effects=if body.encode().len()>self.chain.spec.cp().BODY_MAX as usize{body.evidence.clear();vec![]}else{effects};
            match self.chain.build_signed(p,key,now_s(),body.clone(),effects){
                Ok((h,_,_))=>return Some((h,body)),
                Err(Reject::Block(why))=>{
                    self.log(&format!("signed template failed: {why}"));
                    // Drop the offending user transaction (USER phase reports its index) and retry.
                    let idx=why.split("User(").nth(1).and_then(|s|s.split(|c:char|!c.is_ascii_digit()).find(|x|!x.is_empty())).and_then(|n|n.parse::<usize>().ok());
                    match idx{Some(i) if i<txs.len()=>{txs.remove(i);}_=>{if txs.is_empty(){return None}txs.clear();}}
                }
                Err(_)=>return None,
            }
        }
        None
    }
    fn lock_fallback(&mut self,p:&Entry,a:u32){
        match self.chain.build_fallback(p,a){
            Ok((h,_,_))=>{self.stats.fallback_templates+=1;self.lock(h,Body::default(),true)}
            Err(e)=>{self.log(&format!("fallback build failed a={a}: {e:?}"));if let Some(pr)=&mut self.prod{pr.mode=Mode::Idle;}}
        }
    }
    fn lock(&mut self,header:Header,body:Body,fallback:bool){
        let parent=match &self.prod{Some(p)=>p.parent,None=>return};
        let p=self.chain.get(&parent).unwrap().clone_light();
        let ctx=match self.chain.child_ctx(&p,header.a){Ok(c)=>c,Err(_)=>return};
        let tid=template_id(&header.ut_raw);
        self.log(&format!("lock h={} a={} {} tid={}",header.h,header.a,if fallback{"FB"}else{"PROP"},&hex(&tid)[..12]));
        let miner=self.cfg.miner.as_ref().and_then(|k|chain::assignment_range(&ctx,k.address())).map(|(s,e)|
            miner::start(tid,s,e,ctx.target,ctx.t_share,usize::from(self.chain.spec.cp().S_max),self.miner_tx.clone()));
        if let Some(pr)=&mut self.prod{pr.mode=Mode::Locked(Box::new(Locked{header,body,tid,ctx,fallback}));pr.miner=miner;}
    }
    /// Validates a received signed template for the current parent: signature,
    /// proposer = Draw(h,0), a=0, window, and UT equal to the template rebuilt
    /// from apply(parent, body) (1b independence). Locks on success.
    fn try_lock_signed(&mut self,shell:Header,body:Body)->bool{
        let parent=match &self.prod{Some(p)=>p.parent,None=>return false};
        if shell.parent_hash!=parent||shell.a!=0||shell.proposer.len()!=20{return false}
        let p=self.chain.get(&parent).unwrap().clone_light();
        let ctx=match self.chain.child_ctx(&p,0){Ok(c)=>c,Err(_)=>return false};
        let tid=template_id(&shell.ut_raw);
        let ok_sig=matches!(hashes::recover_address(&hashes::sig_msg(&tid),&shell.sig),Ok(a) if a[..]==shell.proposer[..]);
        if !ok_sig||shell.proposer[..]!=ctx.proposer[..]||!ctx.window.contains(shell.ts)||crate::timing::is_future(shell.ts,now_s(),self.capital_phi()){return false}
        let Ok(effects)=self.chain.evidence_effects(&p,&body,shell.h) else{return false};
        let rebuilt=self.chain.rebuild_signed(&p,&ctx,shell.ts,Address::from_slice(&shell.proposer),&body,effects);
        match rebuilt{Ok(ut) if ut==shell.ut_raw=>{self.lock(shell,body,false);true},_=>false}
    }
    /// Range responses stop when the requester's queue is half full (Peer::offer). A head that has
    /// not moved for a second while a peer announced a higher block asks that peer for the next
    /// range, at most once a second (review finding: the rest used to come only by orphan walk-back).
    fn sync_ranges(&mut self,now:u128){
        let ours=self.chain.head().height;
        if ours!=self.sync_mark.0{self.sync_mark=(ours,now);return}
        if now.saturating_sub(self.sync_mark.1)<1000||now.saturating_sub(self.sync_ask_ms)<1000{return}
        // Peers announcing more blocks are asked in turn, so one that lies about its height (Hello
        // heights are unverified) gets only its share of the requests.
        let mut ahead:Vec<(PeerId,u64)>=self.peer_heights.iter().filter(|(_,h)|**h>ours).map(|(i,h)|(*i,*h)).collect();ahead.sort();
        if ahead.is_empty(){return}
        let (id,h)=ahead[self.sync_turn%ahead.len()];self.sync_turn=self.sync_turn.wrapping_add(1);
        if let Some(p)=self.peers.get(&id){p.send(&Msg::GetRange{start:ours+1,count:(h-ours).min(512)});self.sync_ask_ms=now;}
    }
    fn tick(&mut self){
        self.sync_ranges(now_ms());
        // Retry future blocks.
        if !self.future.is_empty(){let f=std::mem::take(&mut self.future);for b in f{let h=b.hash();if self.import(b,None).is_ok()&&self.own_future.remove(&h){self.stats.mined+=1;}}
            let waiting:HashSet<[u8;32]>=self.future.iter().map(|b|b.hash()).collect();self.own_future.retain(|h|waiting.contains(h));}
        let now=now_ms();
        let Some(pr)=&self.prod else{return};
        let parent=pr.parent;let a=pr.attempt;
        match &pr.mode{
            Mode::Propose{at_s} if now_s()>=*at_s=>{self.begin_attempt(0);}
            Mode::Wait{deadline_ms} if now>*deadline_ms=>{
                // FB is sticky for (parent, h, 0).
                let p=self.chain.get(&parent).unwrap().clone_light();self.lock_fallback(&p,0);
            }
            Mode::Locked(_)|Mode::Idle|Mode::Wait{..}|Mode::Propose{..}=>{
                let p=self.chain.get(&parent).unwrap();
                if let Ok(w)=crate::timing::AttemptWindow::new(p.ts,a,self.chain.spec.cp().D_att){
                    if w.advance_due(now_s(),u64::from(self.chain.spec.local().gamma)){self.log(&format!("attempt {} expired; advancing",a));self.begin_attempt(a+1);}
                }
            }
        }
    }
    fn on_miner(&mut self,m:MinerEvent){
        let Some(pr)=&mut self.prod else{return};
        let Mode::Locked(l)=&pr.mode else{return};
        match m{
            MinerEvent::Share{tid,nonce} if tid==l.tid=>{pr.shares.insert(nonce);self.stats.shares_seen+=1;self.broadcast(&Msg::Share{tid,nonce},None);}
            MinerEvent::Exhausted{tid,hashes} if tid==l.tid=>{self.stats.hashes+=hashes;pr.miner=None;self.log("range exhausted; idle until next template");}
            MinerEvent::Solution{tid,nonce} if tid==l.tid&&!pr.solved=>{
                pr.solved=true;
                let s_max=usize::from(self.chain.spec.cp().S_max);
                let shares:Vec<u64>=pr.shares.iter().copied().filter(|n|*n!=nonce).take(s_max).collect();
                let mut h=l.header.clone();h.nonce=nonce;h.shares=shares;reseal(&mut h);
                let key=self.cfg.miner.as_ref().unwrap();
                h.winner_sig=key.sign_hash(&B256::from(hashes::win_msg(&tid,nonce,&share_root(&h))));reseal(&mut h);
                let b=Block{header:h,body:l.body.clone()};
                let hash=b.hash();
                match self.import(b,None){Ok(_)=>{self.stats.mined+=1;}
                    Err(Reject::Future)=>{self.own_future.insert(hash);self.log("own block waits for its timestamp");}
                    Err(e)=>self.log(&format!("own block rejected: {e:?}"))}
            }
            _=>{}
        }
    }
    fn on_msg(&mut self,from:PeerId,m:Msg){
        match m{
            Msg::Hello{chain_id,genesis,head,height,node}=>{
                if chain_id!=self.chain.spec.chain_id()||genesis!=self.chain.spec.genesis_hash(){
                    self.log(&format!("peer {node}: wrong network; closing"));if let Some(p)=self.peers.get(&from){p.close();}return;
                }
                self.peer_heights.insert(from,height);
                if !self.chain.blocks.contains_key(&head)&&height>0{
                    let ours=self.chain.head().height;
                    if let Some(p)=self.peers.get(&from){
                        if height>ours{p.send(&Msg::GetRange{start:ours+1,count:(height-ours).min(512)});}
                        p.send(&Msg::GetBlock{hash:head});
                    }
                }
            }
            Msg::Block{header,body}=>{
                let Ok(h)=decode_header(&header) else{return};
                let Ok(b)=Body::decode(&body,self.chain.spec.cp().BODY_MAX as usize) else{return};
                // Relayed heights are unverified (a block ahead of us is an orphan here); sync_ranges
                // asks the peers in turn, so an inflated height cannot monopolize the requests.
                if let Some(x)=self.peer_heights.get_mut(&from){*x=(*x).max(h.h);}
                let _=self.import(Block{header:h,body:b},Some(from));
            }
            Msg::Template{shell,body}=>{
                let Ok(h)=decode_header(&shell) else{return};
                let Ok(b)=Body::decode(&body,self.chain.spec.cp().BODY_MAX as usize) else{return};
                let arrival=now_ms();
                let equivocated=self.observe_template(&h);
                let waiting=matches!(&self.prod,Some(p) if p.parent==h.parent_hash&&p.attempt==0&&matches!(p.mode,Mode::Wait{deadline_ms} if arrival<=deadline_ms));
                if equivocated{
                    // Second template from the same proposer: evidence type 1, then sticky FB.
                    if matches!(&self.prod,Some(p) if p.parent==h.parent_hash&&p.attempt==0){let p=self.chain.get(&h.parent_hash).unwrap().clone();self.lock_fallback(&p,0);}
                }else if waiting{self.try_lock_signed(h,b);}
                else if !self.chain.blocks.contains_key(&h.parent_hash)||self.prod.as_ref().map(|p|p.parent!=h.parent_hash).unwrap_or(true){
                    if self.templates.len()>TEMPLATES_MAX{self.templates.clear();}self.templates.insert(h.parent_hash,(h,b,now_ms()));
                }
            }
            Msg::Share{tid,nonce}=>{
                let Some(pr)=&mut self.prod else{return};let Mode::Locked(l)=&pr.mode else{return};
                if tid!=l.tid||(nonce as u128)>=l.ctx.assignment.nonce_max()||pr.shares.contains(&nonce){return}
                if !le_target(&pow_hash(&tid,nonce),&l.ctx.t_share){return}
                pr.shares.insert(nonce);self.stats.shares_seen+=1;
            }
            Msg::GetBlock{hash}=>{if let Some(e)=self.chain.get(&hash){if e.height>0{if let Some(p)=self.peers.get(&from){p.send(&Msg::Block{header:e.header.encoded.clone(),body:e.body.encode()});}}}}
            Msg::GetRange{start,count}=>{
                let Some(p)=self.peers.get(&from) else{return};
                // Responses stop when the peer's queue is half full (offer); the peer asks again.
                for hgt in start..start.saturating_add(count.min(512)){match self.chain.canonical_at(hgt){Some(e) if e.height>0=>{if !p.offer(&Msg::Block{header:e.header.encoded.clone(),body:e.body.encode()}){break}}_=>break}}
            }
            Msg::Tx{raw}=>{let _=self.submit_tx(raw,true);}
        }
    }
}
impl Node{
    pub fn pool_state(&self)->&InMemoryDB{&self.pool.pending_state}
    /// The pool meter's (user slots, user accounts, system slots).
    pub fn pool_live(&self)->(u64,u64,u64){self.pool.meter.live()}
    pub fn peer_count(&self)->usize{self.peers.len()}
    pub fn status_json(&self)->serde_json::Value{
        let h=self.chain.head();
        let mode=match &self.prod{None=>"none".to_string(),Some(p)=>match &p.mode{Mode::Idle=>"idle".into(),Mode::Wait{..}=>format!("wait a={}",p.attempt),Mode::Propose{at_s}=>format!("propose at {at_s}"),
            Mode::Locked(l)=>format!("{} h={} a={} shares={} mining={}",if l.fallback{"FB"}else{"PROP"},p.height,p.attempt,p.shares.len(),p.miner.is_some())}};
        serde_json::json!({"name":self.cfg.name,"chainId":self.chain.spec.chain_id(),"genesisHash":hex(&self.chain.spec.genesis_hash()),"head":{"height":h.height,"hash":hex(&h.hash),"ts":h.ts,"signed":h.signed,"final":h.is_final,"totalWork":format!("{:#x}",h.total_work)},
            "peers":self.peers.values().map(|p|p.addr.clone()).collect::<Vec<_>>(),"production":mode,"miner":self.cfg.miner.as_ref().map(|k|format!("{:#x}",k.address())),
            "pool":self.pool.txs.len(),"journalRecords":self.journal_records(),"blocksKnown":self.chain.blocks.len(),"invalidKnown":self.chain.invalid.len(),
            "stats":{"imported":self.stats.imported,"mined":self.stats.mined,"signedTemplates":self.stats.signed_templates,"fallbackTemplates":self.stats.fallback_templates,"sharesSeen":self.stats.shares_seen,"hashesInExhaustedRanges":self.stats.hashes,"reorgs":self.stats.reorgs}})
    }
    pub fn template_json(&self)->serde_json::Value{
        match &self.prod{Some(Production{mode:Mode::Locked(l),..})=>serde_json::json!({"templateId":hex(&l.tid),"header":hex(&l.header.encoded),"fallback":l.fallback,"nonceMax":l.ctx.assignment.nonce_max().to_string()}),_=>serde_json::Value::Null}
    }
    pub fn journal_records(&self)->u64{self.journal.records}
}
impl Node{
    fn st_bytes(h:&Header)->Vec<u8>{let mut p=h.ut_raw.clone();crate::rlp::encode_bytes(&h.sig,&mut p);let mut o=Vec::new();crate::rlp::encode_list_payload(&p,&mut o);o}
    /// Records a signed template; returns true when it equivocates (evidence type 1 created).
    fn observe_template(&mut self,h:&Header)->bool{
        if h.proposer.len()!=20||h.sig.len()!=65||h.a!=0{return false}
        let tid=template_id(&h.ut_raw);
        if !matches!(hashes::recover_address(&hashes::sig_msg(&tid),&h.sig),Ok(a) if a[..]==h.proposer[..]){return false}
        let key=(h.parent_hash,h.h);let st=Self::st_bytes(h);
        match self.seen_templates.get(&key){
            None=>{if self.seen_templates.len()>SEEN_MAX{self.seen_templates.clear();}self.seen_templates.insert(key,(h.ut_raw.clone(),st,h.proposer.clone()));false}
            Some((ut,first,prop)) if *ut!=h.ut_raw&&*prop==h.proposer=>{
                let mut p=Vec::new();crate::rlp::encode_bytes(&[1],&mut p);p.extend(first.clone());p.extend(st);let mut ev=Vec::new();crate::rlp::encode_list_payload(&p,&mut ev);
                if !self.evidence_pool.contains(&ev)&&self.evidence_pool.len()<EVIDENCE_POOL_MAX{self.log(&format!("equivocation (type 1) by proposer of h={}",h.h));self.evidence_pool.push(ev);}true}
            _=>false,
        }
    }
    /// Records winner signatures per (TemplateID, nonce); a second share root creates evidence type 2.
    fn observe_win(&mut self,h:&Header){
        let tid=template_id(&h.ut_raw);let root=share_root(h);
        match self.seen_wins.get(&(tid,h.nonce)){
            None=>{if self.seen_wins.len()>SEEN_MAX{self.seen_wins.clear();}self.seen_wins.insert((tid,h.nonce),(root,h.winner_sig));}
            Some((r,sig)) if *r!=root=>{
                let mut p=Vec::new();crate::rlp::encode_bytes(&[2],&mut p);crate::rlp::encode_bytes(&tid,&mut p);crate::rlp::encode_bytes(&h.nonce.to_be_bytes(),&mut p);
                crate::rlp::encode_bytes(r,&mut p);crate::rlp::encode_bytes(sig,&mut p);crate::rlp::encode_bytes(&root,&mut p);crate::rlp::encode_bytes(&h.winner_sig,&mut p);
                let mut ev=Vec::new();crate::rlp::encode_list_payload(&p,&mut ev);
                if !self.evidence_pool.contains(&ev)&&self.evidence_pool.len()<EVIDENCE_POOL_MAX{self.log(&format!("equivocation (type 2) on h={}",h.h));self.evidence_pool.push(ev);}
            }
            _=>{}
        }
    }
    /// Evidence still valid on top of `p`, at most E_max, one per accused.
    fn includable_evidence(&mut self,p:&Entry)->Vec<Vec<u8>>{
        let e_max=usize::from(self.chain.spec.cp().E_max);let mut out:Vec<Vec<u8>>=Vec::new();let mut keep=Vec::new();
        for ev in std::mem::take(&mut self.evidence_pool){
            let one=Body{txs:vec![],evidence:vec![ev.clone()]};
            match self.chain.evidence_effects(p,&one,p.height+1){
                Ok(_)=>{let mut trial=out.clone();trial.push(ev.clone());
                    if out.len()<e_max&&self.chain.evidence_effects(p,&Body{txs:vec![],evidence:trial},p.height+1).is_ok(){out.push(ev.clone());}keep.push(ev);}
                Err(_)=>{} // already applied on this branch (accused tomb) or no longer provable: drop
            }
        }
        self.evidence_pool=keep;out
    }
}
trait Light{fn clone_light(&self)->Entry;}
impl Light for Entry{fn clone_light(&self)->Entry{self.clone()}}
