//! Node orchestration: one consensus thread owns the chain, journal, pool and
//! production state machine (consensus.md §4) and processes events from peers,
//! the range miner, RPC and a 50 ms tick.
use std::collections::{BTreeSet,HashMap,HashSet,VecDeque};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc,Mutex,mpsc::{self,Receiver,Sender}};
use std::time::{Duration,SystemTime,UNIX_EPOCH};
use crate::{hashes,header::Header};
use pocol_lp4_execution::{apply::ParentResult,txsign::Key,wire,native::{self,NativeBlockContext}};
use revm::{InMemoryDB,DatabaseCommit,primitives::{Address,B256,U256}};
use crate::{chain::{self,Chain,ChildCtx,Entry,Reject,Spec},miner::{self,MinerEvent,MinerHandle},net::{self,Msg,NetEvent,Peer,PeerId},store::{self,Journal},types::*};

pub struct Config{
    pub dir:PathBuf,
    pub name:String,
    pub miner:Option<Key>,
    pub listen:Option<SocketAddr>,
    pub peers:Vec<SocketAddr>,
    pub rpc:Option<SocketAddr>,
    /// Local timing parameters (not consensus): Δ_rel, Φ (future slack), Γ.
    pub delta_rel:u64,pub phi:u64,pub gamma:u64,
    /// Optional: stop after the canonical head reaches this height.
    pub stop_at:Option<u64>,
    pub log:bool,
}

pub enum Event{Net(NetEvent),Miner(MinerEvent),Rpc(Vec<u8>,Sender<String>),Tick}

pub fn now_ms()->u128{SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()}
pub fn now_s()->u64{(now_ms()/1000) as u64}

struct Locked{header:Header,body:Body,tid:[u8;32],ctx:ChildCtx,fallback:bool}
enum Mode{Wait{deadline_ms:u128},Locked(Box<Locked>),Idle}
struct Production{parent:[u8;32],height:u64,attempt:u32,mode:Mode,shares:BTreeSet<u64>,miner:Option<MinerHandle>,solved:bool,received_ms:u128}

/// Pending pool: transactions are kept only if they execute in order on top of
/// the head state (pending state), so several nonces per sender are allowed.
pub struct Pool{pub txs:Vec<(B256,Vec<u8>)>,pending_state:InMemoryDB,pub bytes:usize}
pub const POOL_MAX_BYTES:usize=64*1024*1024;

pub struct Node{
    pub cfg:Config,
    pub chain:Chain,
    journal:Journal,
    peers:HashMap<PeerId,Peer>,
    outbound:Arc<Mutex<HashSet<String>>>,
    pub tx:Sender<Event>,
    rx:Receiver<Event>,
    miner_tx:Sender<MinerEvent>,
    prod:Option<Production>,
    orphans:HashMap<[u8;32],Vec<Block>>,
    future:Vec<Block>,
    templates:HashMap<[u8;32],(Header,Body,u128)>,
    received:HashMap<[u8;32],u128>,
    pub pool:Pool,
    pub rejects:VecDeque<(String,String)>,
    pub stats:Stats,
    pub stopped:bool,
}
#[derive(Default,Clone,Debug)]
pub struct Stats{pub imported:u64,pub mined:u64,pub signed_templates:u64,pub fallback_templates:u64,pub shares_seen:u64,pub hashes:u64,pub reorgs:u64}

fn result_bytes(r:&Option<ParentResult>)->Vec<u8>{
    let mut p=Vec::new();
    if let Some(r)=r{crate::rlp::encode_bytes(r.winner.as_slice(),&mut p);let mut l=Vec::new();for (n,o) in &r.shares{let mut q=Vec::new();crate::rlp::encode_bytes(&n.to_be_bytes(),&mut q);crate::rlp::encode_bytes(o.as_slice(),&mut q);crate::rlp::encode_list_payload(&q,&mut l);}
        crate::rlp::encode_list_payload(&l,&mut p);}
    let mut o=Vec::new();crate::rlp::encode_list_payload(&p,&mut o);o
}

impl Node{
    /// Opens the journal, replays and re-executes every committed block.
    pub fn open(cfg:Config,spec:Spec)->Result<Self,String>{
        let binding=spec.genesis_hash;
        let rec=store::open(&cfg.dir,&binding).map_err(|e|format!("store: {e:?}"))?;
        let mut chain=Chain::new(spec);
        for (i,payload) in rec.payloads.iter().enumerate(){
            let (hb,bb,rb)=store::decode_record(payload).map_err(|e|format!("record {i}: {e}"))?;
            let header=decode_header(&hb).map_err(|e|format!("record {i}: {e}"))?;
            let body=Body::decode(&bb,chain.spec.cp().BODY_MAX as usize).map_err(|e|format!("record {i}: {e}"))?;
            let block=Block{header,body};
            let (entry,_)=chain.validate(&block,None,0).map_err(|e|format!("replay {i}: {e:?}"))?;
            if result_bytes(&entry.result)!=rb{return Err(format!("parentResultMismatch at record {i}"))}
            chain.insert(entry);
        }
        let (tx,rx)=mpsc::channel();let (miner_tx,miner_rx)=mpsc::channel::<MinerEvent>();
        let fwd=tx.clone();std::thread::spawn(move||{for e in miner_rx{if fwd.send(Event::Miner(e)).is_err(){break}}});
        let head_state=chain.head().state.clone();
        let mut node=Self{cfg,chain,journal:rec.journal,peers:HashMap::new(),outbound:Arc::new(Mutex::new(HashSet::new())),tx,rx,miner_tx,prod:None,
            orphans:HashMap::new(),future:Vec::new(),templates:HashMap::new(),received:HashMap::new(),
            pool:Pool{txs:vec![],pending_state:head_state,bytes:0},rejects:VecDeque::new(),stats:Stats::default(),stopped:false};
        node.stats.imported=rec.payloads.len() as u64;
        if rec.torn_tail{node.log("recovered torn journal tail into a new journal");}
        Ok(node)
    }
    pub fn log(&self,m:&str){if self.cfg.log{eprintln!("[{} {}] {m}",self.cfg.name,now_ms()%100_000_000);}}

    pub fn start_network(&mut self)->Result<(),String>{
        if let Some(a)=self.cfg.listen{let l=std::net::TcpListener::bind(a).map_err(|e|format!("listen {a}: {e}"))?;
            let tx=self.tx.clone();let (ntx,nrx)=mpsc::channel();std::thread::spawn(move||{for e in nrx{if tx.send(Event::Net(e)).is_err(){break}}});
            net::listen(l,ntx);}
        for a in self.cfg.peers.clone(){let tx=self.tx.clone();let (ntx,nrx)=mpsc::channel();std::thread::spawn(move||{for e in nrx{if tx.send(Event::Net(e)).is_err(){break}}});
            net::dial(a,ntx,self.outbound.clone());}
        if let Some(a)=self.cfg.rpc{crate::rpc::serve(a,self.tx.clone())?;}
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
            Event::Rpc(body,reply)=>{let r=crate::rpc::handle(self,&body);let _=reply.send(r);}
            Event::Net(NetEvent::Connected(id,peer))=>{let hello=self.hello();peer.send(&hello);self.peers.insert(id,peer);}
            Event::Net(NetEvent::Closed(id))=>{if let Some(p)=self.peers.remove(&id){if p.outbound{if let Ok(mut s)=self.outbound.lock(){s.remove(&p.addr);}}}}
            Event::Net(NetEvent::Message(id,m))=>self.on_msg(id,m),
        }
    }
    fn hello(&self)->Msg{let h=self.chain.head();Msg::Hello{chain_id:self.chain.spec.chain_id(),genesis:self.chain.spec.genesis_hash,head:h.hash,height:h.height,node:self.cfg.name.clone()}}
    fn broadcast(&self,m:&Msg,except:Option<PeerId>){for (id,p) in &self.peers{if Some(*id)!=except{p.send(m);}}}

    // ---------------- import ----------------
    /// Validates, journals (fsync) and inserts a block. Returns Ok(true) if new head.
    pub fn import(&mut self,b:Block,from:Option<PeerId>)->Result<bool,Reject>{
        let hash=b.hash();
        let mut res=self.chain.validate(&b,Some(now_s()),self.cfg.phi);
        if let Err(Reject::NeedsRebuild(p))=&res{let p=*p;self.log("TrieRebuild for a fork below the K_hist window");
            if let Err(e)=self.chain.ensure_state(&p){return Err(e)}res=self.chain.validate(&b,Some(now_s()),self.cfg.phi);}
        let (entry,_)=match res{
            Ok(v)=>v,
            Err(Reject::UnknownParent)=>{
                let parent=b.header.parent_hash;
                let list=self.orphans.entry(parent).or_default();if list.len()<16&&!list.iter().any(|x|x.hash()==hash){list.push(b);}
                if let Some(id)=from{if let Some(p)=self.peers.get(&id){p.send(&Msg::GetBlock{hash:parent});}}
                return Err(Reject::UnknownParent);
            }
            Err(Reject::Future)=>{if self.future.len()<64{self.future.push(b);}return Err(Reject::Future)}
            Err(Reject::Block(why))=>{self.chain.mark_invalid(hash,why.clone());self.reject(hash,&why);return Err(Reject::Block(why))}
            Err(e)=>{if let Reject::Envelope(w)=&e{self.reject(hash,w);}return Err(e)}
        };
        let record=store::encode_record(&b.header.encoded,&b.body.encode(),&result_bytes(&entry.result));
        if let Err(e)=self.journal.append(&record){self.log(&format!("FATAL journal append: {e:?}"));std::process::exit(70);}
        self.received.insert(hash,now_ms());
        let old_head=self.chain.head;
        let new_head=self.chain.insert(entry);self.stats.imported+=1;self.chain.retain();
        self.broadcast(&Msg::Block{header:b.header.encoded.clone(),body:b.body.encode()},from);
        if new_head{
            if self.chain.get(&self.chain.head).and_then(|e|e.parent)!=Some(old_head){self.stats.reorgs+=1;}
            self.log(&format!("head h={} {} signed={} txs={}",self.chain.head().height,&hex(&hash)[..14],self.chain.head().signed,b.body.txs.len()));
            self.on_new_head();
        }
        // Orphans waiting for this block.
        if let Some(children)=self.orphans.remove(&hash){for c in children{let _=self.import(c,None);}}
        Ok(new_head)
    }
    fn reject(&mut self,hash:[u8;32],why:&str){self.rejects.push_back((hex(&hash),why.to_string()));if self.rejects.len()>256{self.rejects.pop_front();}self.log(&format!("reject {}: {why}",&hex(&hash)[..14]));}
    fn on_new_head(&mut self){
        self.rebuild_pool();
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
        let env=wire::decode_for_profile(&raw,&self.chain.spec.profile).map_err(|e|format!("{} {e:?}",e.specified_pool_code().unwrap_or(-32000)))?;
        let hash=env.hash();
        if self.pool.txs.iter().any(|(h,_)|*h==hash){return Ok(hash)}
        if self.pool.bytes+raw.len()>POOL_MAX_BYTES{return Err("-32016 pool full".into())}
        let ctx=self.next_block_ctx();
        let r=native::execute_for_profile(&self.pool.pending_state,env.tx_env(),&ctx,&self.chain.spec.profile).map_err(|e|format!("-32000 {e:?}"))?;
        self.pool.pending_state.commit(r.state);
        self.pool.bytes+=raw.len();self.pool.txs.push((hash,raw.clone()));
        if relay{self.broadcast(&Msg::Tx{raw},None);}
        Ok(hash)
    }
    fn rebuild_pool(&mut self){
        let old=std::mem::take(&mut self.pool.txs);self.pool.bytes=0;self.pool.pending_state=self.chain.head().state.clone();
        // Transactions in abandoned blocks return to the pool (consensus §10).
        for (_,raw) in old{let _=self.submit_tx(raw,false);}
    }
    /// Pool transactions that still execute in order (for a signed template).
    fn template_txs(&self)->Vec<Vec<u8>>{
        let cp=self.chain.spec.cp();let mut out=Vec::new();let mut gas=0u64;let mut bytes=0usize;
        for (_,raw) in &self.pool.txs{
            let Ok(env)=wire::decode_for_profile(raw,&self.chain.spec.profile) else{continue};let g=env.tx_env().gas_limit;
            if gas+g>cp.GAS_LIMIT||bytes+raw.len()>cp.BODY_MAX as usize-1024{break}
            gas+=g;bytes+=raw.len();out.push(raw.clone());
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
                let txs=self.template_txs();
                if let Some(t)=self.build_signed_template(&p,txs){
                    self.stats.signed_templates+=1;
                    let shell=t.0.encoded.clone();self.broadcast(&Msg::Template{shell,body:t.1.encode()},None);
                    self.lock(t.0,t.1,false);return;
                }
            }
            let received=self.prod.as_ref().unwrap().received_ms;
            let deadline=ctx.window.deadline_ms(received,self.cfg.delta_rel,self.chain.spec.cp().dFbWait).unwrap_or(0);
            if let Some(pr)=&mut self.prod{pr.mode=Mode::Wait{deadline_ms:deadline};}
            // A signed template may already have arrived for this parent.
            if let Some((h,b,arr))=self.templates.remove(&parent_hash){if arr<=deadline{self.try_lock_signed(h,b);}}
        }else{
            self.lock_fallback(&p,a);
        }
    }
    fn build_signed_template(&mut self,p:&Entry,mut txs:Vec<Vec<u8>>)->Option<(Header,Body)>{
        let key=self.cfg.miner.as_ref()?;
        for _ in 0..8{
            let body=Body{txs:txs.clone(),evidence:vec![]};
            match self.chain.build_signed(p,key,now_s(),body.clone(),vec![]){
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
            Err(e)=>self.log(&format!("fallback build failed a={a}: {e:?}")),
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
        if !ok_sig||shell.proposer[..]!=ctx.proposer[..]||!ctx.window.contains(shell.ts)||crate::timing::is_future(shell.ts,now_s(),self.cfg.phi){return false}
        let Ok(effects)=self.chain.evidence_effects(&p,&body,shell.h) else{return false};
        let rebuilt=self.chain.rebuild_signed(&p,&ctx,shell.ts,Address::from_slice(&shell.proposer),&body,effects);
        match rebuilt{Ok(ut) if ut==shell.ut_raw=>{self.lock(shell,body,false);true},_=>false}
    }
    fn tick(&mut self){
        // Retry future blocks.
        if !self.future.is_empty(){let f=std::mem::take(&mut self.future);for b in f{let _=self.import(b,None);}}
        let now=now_ms();
        let Some(pr)=&self.prod else{return};
        let parent=pr.parent;let a=pr.attempt;
        match &pr.mode{
            Mode::Wait{deadline_ms} if now>=*deadline_ms=>{
                // FB is sticky for (parent, h, 0).
                let p=self.chain.get(&parent).unwrap().clone_light();self.lock_fallback(&p,0);
            }
            Mode::Locked(_)|Mode::Idle|Mode::Wait{..}=>{
                let p=self.chain.get(&parent).unwrap();
                if let Ok(w)=crate::timing::AttemptWindow::new(p.ts,a,self.chain.spec.cp().D_att){
                    if w.advance_due(now_s(),self.cfg.gamma){self.log(&format!("attempt {} expired; advancing",a));self.begin_attempt(a+1);}
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
                match self.import(b,None){Ok(_)=>{self.stats.mined+=1;}Err(e)=>self.log(&format!("own block rejected: {e:?}"))}
            }
            _=>{}
        }
    }
    fn on_msg(&mut self,from:PeerId,m:Msg){
        match m{
            Msg::Hello{chain_id,genesis,head,height,node}=>{
                if chain_id!=self.chain.spec.chain_id()||genesis!=self.chain.spec.genesis_hash{
                    self.log(&format!("peer {node}: wrong network; closing"));if let Some(p)=self.peers.get(&from){p.close();}return;
                }
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
                let _=self.import(Block{header:h,body:b},Some(from));
            }
            Msg::Template{shell,body}=>{
                let Ok(h)=decode_header(&shell) else{return};
                let Ok(b)=Body::decode(&body,self.chain.spec.cp().BODY_MAX as usize) else{return};
                let waiting=matches!(&self.prod,Some(p) if p.parent==h.parent_hash&&p.attempt==0&&matches!(p.mode,Mode::Wait{..}));
                if waiting{self.try_lock_signed(h,b);}
                else if !self.chain.blocks.contains_key(&h.parent_hash)||self.prod.as_ref().map(|p|p.parent!=h.parent_hash).unwrap_or(true){
                    if self.templates.len()>64{self.templates.clear();}self.templates.insert(h.parent_hash,(h,b,now_ms()));
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
                for hgt in start..start.saturating_add(count.min(512)){match self.chain.canonical_at(hgt){Some(e) if e.height>0=>{p.send(&Msg::Block{header:e.header.encoded.clone(),body:e.body.encode()});}_=>break}}
            }
            Msg::Tx{raw}=>{let _=self.submit_tx(raw,true);}
        }
    }
}
impl Node{
    pub fn pool_state(&self)->&InMemoryDB{&self.pool.pending_state}
    pub fn peer_count(&self)->usize{self.peers.len()}
    pub fn status_json(&self)->serde_json::Value{
        let h=self.chain.head();
        let mode=match &self.prod{None=>"none".to_string(),Some(p)=>match &p.mode{Mode::Idle=>"idle".into(),Mode::Wait{..}=>format!("wait a={}",p.attempt),
            Mode::Locked(l)=>format!("{} h={} a={} shares={} mining={}",if l.fallback{"FB"}else{"PROP"},p.height,p.attempt,p.shares.len(),p.miner.is_some())}};
        serde_json::json!({"name":self.cfg.name,"chainId":self.chain.spec.chain_id(),"genesisHash":hex(&self.chain.spec.genesis_hash),"head":{"height":h.height,"hash":hex(&h.hash),"ts":h.ts,"signed":h.signed,"final":h.is_final,"totalWork":format!("{:#x}",h.total_work)},
            "peers":self.peers.values().map(|p|p.addr.clone()).collect::<Vec<_>>(),"production":mode,"miner":self.cfg.miner.as_ref().map(|k|format!("{:#x}",k.address())),
            "pool":self.pool.txs.len(),"journalRecords":self.journal_records(),"blocksKnown":self.chain.blocks.len(),"invalidKnown":self.chain.invalid.len(),
            "stats":{"imported":self.stats.imported,"mined":self.stats.mined,"signedTemplates":self.stats.signed_templates,"fallbackTemplates":self.stats.fallback_templates,"sharesSeen":self.stats.shares_seen,"hashesInExhaustedRanges":self.stats.hashes,"reorgs":self.stats.reorgs}})
    }
    pub fn template_json(&self)->serde_json::Value{
        match &self.prod{Some(Production{mode:Mode::Locked(l),..})=>serde_json::json!({"templateId":hex(&l.tid),"header":hex(&l.header.encoded),"fallback":l.fallback,"nonceMax":l.ctx.assignment.nonce_max().to_string()}),_=>serde_json::Value::Null}
    }
    pub fn journal_records(&self)->u64{self.journal.records}
}
trait Light{fn clone_light(&self)->Entry;}
impl Light for Entry{fn clone_light(&self)->Entry{self.clone()}}
