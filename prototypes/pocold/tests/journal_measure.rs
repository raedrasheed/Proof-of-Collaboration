//! TRACK journal (audit-2026-10-22): measurement of the on-disk journal growth and the cost of
//! re-execution from genesis (open replay, deep-fork rebuild, restore), with peak RSS. This test
//! only MEASURES the existing code (store::encode_record/encode_frame, Node::open replay,
//! Chain::ensure_state, Chain::restore_canonical); it does not change behaviour and does not attack.
//! It prints machine-readable `JM-*` lines consumed by development/audit-2026-10-22/JOURNAL-GROWTH-
//! AND-REPLAY.md. The heavy variants are `#[ignore]` and run in release:
//!   flock <cpu.lock> cargo test --release --test journal_measure -- --ignored --nocapture
//! See each test for scope. Facts used: a journal record is RLP([headerBytes, bodyBytes,
//! parentResultBytes]) (store::encode_record) framed with OVERHEAD = 41 B (store::OVERHEAD);
//! receipts/logs are NOT stored, they are re-derived on replay (store.rs doc, chain::validate).
use pocold::{chain::{Chain,Spec},store,types::*};
use pocold::header::Header;
use pocold::node::{Config,Limits,Node};
use pocol_lp4_execution::{devnet::{self,DevnetConfig},txsign::{Key,Tx}};
use revm::primitives::{Address,B256,U256};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Instant;

// ---- harness (self-contained; test files are separate crates, nothing imports consensus.rs) ----
fn cfg()->DevnetConfig{let mut c=DevnetConfig::new(777910,1_700_000_000,&["a","b","c"]);c.hash_rate=1024;c.d_att=73;c.tau=40;c.c=8;c}
fn admitted()->Spec{let c=cfg();let d=devnet::build(&c).unwrap();Spec::new(d.admit(&pocold::single_host_local()).unwrap_or_else(|e|panic!("{e}")).0)}
struct Net{chain:Chain,keys:HashMap<Address,Key>}
fn net()->Net{let c=cfg();let d=devnet::build(&c).unwrap();let mut keys=HashMap::new();
    for m in &d.miners{keys.insert(m.id,Key::from_secret(&m.key.secret()).unwrap());}
    Net{chain:Chain::new(admitted()),keys}}
fn try_seal(n:&Net,mut h:Header,body:Body,attempt:u32,start:u64)->Option<Block>{
    let p=n.chain.get(&h.parent_hash).unwrap().clone();let ctx=n.chain.child_ctx(&p,attempt).unwrap();
    let tid=template_id(&h.ut_raw);let mut shares=vec![];let mut x=start;
    loop{if (x as u128)>=ctx.assignment.nonce_max(){return None}let ph=pow_hash(&tid,x);if le_target(&ph,&ctx.t_share){if le_target(&ph,&ctx.target){break}shares.push(x);}x+=1;}
    let owner=addr(&ctx.assignment.owner(x).unwrap());
    h.nonce=x;shares.truncate(256);h.shares=shares;reseal(&mut h);
    h.winner_sig=n.keys[&owner].sign_hash(&B256::from(pocold::hashes::win_msg(&tid,x,&share_root(&h))));reseal(&mut h);
    Some(Block{header:h,body})}
fn fallback(n:&Net,parent:[u8;32],a:u32)->Block{let p=n.chain.get(&parent).unwrap().clone();
    for a in a..a+16{let (h,_,_)=n.chain.build_fallback(&p,a).unwrap();if let Some(b)=try_seal(n,h,Body::default(),a,0){return b}}panic!("no fallback solution")}
fn signed(n:&Net,parent:[u8;32],body:Body)->Block{
    let p=n.chain.get(&parent).unwrap().clone();let ctx=n.chain.child_ctx(&p,0).unwrap();
    for off in 0..u64::from(n.chain.spec.cp().D_att){let (h,_,_)=n.chain.build_signed(&p,&n.keys[&ctx.proposer],ctx.window.lower()+off,body.clone(),vec![]).unwrap_or_else(|e|panic!("build_signed: {e:?}"));
        if let Some(b)=try_seal(n,h,body.clone(),0,0){return b}}panic!("no signed solution")}
fn import(n:&mut Net,b:&Block){let (e,_)=n.chain.validate(b,None,0).unwrap_or_else(|e|panic!("h={} {e:?}",b.header.h));n.chain.insert(e);n.chain.retain();}

// max_fee is set very high (1e15 wei) so a chain of full blocks, whose EIP-1559 base fee rises ~12.5%
// per full block, never outruns it within the measured runs.
fn pay(key:&Key,nonce:u64)->Vec<u8>{Tx{chain_id:777910,nonce,max_priority:U256::from(1_000_000_000u64),max_fee:U256::from(1_000_000_000_000_000u64),gas:21000,to:Some(devnet::account_key("bob").address()),value:U256::from(1u64),data:Default::default()}.sign_1559(key)}
/// A call with `len` zero calldata bytes to an EOA (no code runs): fills body bytes cheaply (zero
/// calldata gas) up to TX_MAX. Two of them reach BODY_MAX; each reserves GAS_LIMIT/2-50k so the pair
/// stays under GAS_LIMIT (calldata of this length costs far less than that reservation).
fn big_call(key:&Key,nonce:u64,len:usize)->Vec<u8>{Tx{chain_id:777910,nonce,max_priority:U256::from(1u64),max_fee:U256::from(1_000_000_000_000_000u64),gas:3_950_000,to:Some(devnet::account_key("bob").address()),value:U256::ZERO,data:vec![0u8;len].into()}.sign_1559(key)}
/// The most 21000-gas transfers build_signed accepts on `head` (a full-gas transfer block), found by
/// re-execution only (no PoW), then returned so the caller seals once.
fn pack_transfers(n:&Net,head:[u8;32],alice:&Key)->Vec<Vec<u8>>{
    let p=n.chain.get(&head).unwrap().clone();
    let (mut lo,mut hi)=(1usize,400usize);
    let ok=|k:usize|{let txs:Vec<Vec<u8>>=(0..k as u64).map(|i|pay(alice,i)).collect();
        n.chain.build_signed(&p,&n.keys[&n.chain.child_ctx(&p,0).unwrap().proposer],n.chain.child_ctx(&p,0).unwrap().window.lower(),Body{txs,evidence:vec![]},vec![]).is_ok()};
    assert!(ok(lo),"a single 21000-gas transfer must build");
    while lo<hi{let mid=(lo+hi+1)/2;if ok(mid){lo=mid}else{hi=mid-1}}
    (0..lo as u64).map(|i|pay(alice,i)).collect()
}
/// Init code: a loop of LOG0(0 bytes) `n` times then STOP (same shape as the eth_getLogs test). At
/// n=546 it hits LOG_COUNT_MAX; a log-heavy block's receipts are large but its JOURNAL record is not.
fn log_deploy(key:&Key,nonce:u64,n:u16)->Vec<u8>{
    let mut init=vec![0x61,(n>>8) as u8,(n&0xff) as u8,0x5b];// PUSH2 n; JUMPDEST(3)
    init.extend([0x5f,0x5f,0xa0,0x60,0x01,0x90,0x03,0x80,0x60,0x03,0x57,0x00]);// PUSH0 PUSH0 LOG0; PUSH1 1 SWAP1 SUB; DUP1 PUSH1 3 JUMPI; STOP
    Tx{chain_id:777910,nonce,max_priority:U256::from(1u64),max_fee:U256::from(1_000_000_000_000_000u64),gas:8_000_000,to:None,value:U256::ZERO,data:init.into()}.sign_1559(key)}

#[cfg(target_os="linux")]
fn rss_bytes()->i64{let s=std::fs::read_to_string("/proc/self/statm").unwrap();s.split_whitespace().nth(1).unwrap().parse::<i64>().unwrap()*4096}
#[cfg(not(target_os="linux"))]
fn rss_bytes()->i64{-1}
#[cfg(target_os="linux")]
fn vmhwm_bytes()->i64{std::fs::read_to_string("/proc/self/status").unwrap().lines().find(|l|l.starts_with("VmHWM:")).map(|l|l.split_whitespace().nth(1).unwrap().parse::<i64>().unwrap()*1024).unwrap_or(-1)}
#[cfg(not(target_os="linux"))]
fn vmhwm_bytes()->i64{-1}

fn tmp(name:&str)->PathBuf{let d=std::env::temp_dir().join(format!("pocold-jm-{name}-{}",std::process::id()));let _=std::fs::remove_dir_all(&d);d}
fn disk_bytes(dir:&std::path::Path)->u64{std::fs::read(dir.join("blocks.journal")).map(|b|b.len() as u64).unwrap_or(0)}

/// The exact on-disk record size of a built block: encode_record (RLP of header/body/result),
/// framed with OVERHEAD. `result` is the parentResult the node stores; we take it from validate().
fn record_bytes(chain:&Chain,b:&Block)->usize{
    let (e,_)=chain.validate(b,None,0).unwrap();
    let rb=result_bytes(&e);
    store::encode_frame(&store::encode_record(&b.header.encoded,&b.body.encode(),&rb)).len()
}
/// Re-derive the stored parentResult bytes (node.rs result_bytes), via the public Entry.result.
fn result_bytes(e:&pocold::chain::Entry)->Vec<u8>{
    use pocold::rlp;let mut p=Vec::new();
    if let Some(r)=&e.result{rlp::encode_bytes(r.winner.as_slice(),&mut p);let mut l=Vec::new();
        for (n,o) in &r.shares{let mut q=Vec::new();rlp::encode_bytes(&n.to_be_bytes(),&mut q);rlp::encode_bytes(o.as_slice(),&mut q);rlp::encode_list_payload(&q,&mut l);}
        rlp::encode_list_payload(&l,&mut p);}
    let mut o=Vec::new();rlp::encode_list_payload(&p,&mut o);o
}

fn mnode(tag:&str)->(Node,PathBuf,impl Fn()->Config){
    let dir=tmp(tag);let d=dir.clone();
    let conf=move||Config{dir:d.clone(),name:"jm".into(),miner:None,listen:None,peers:vec![],rpc:None,stop_at:None,log:false,limits:Limits::default()};
    (Node::open(conf(),admitted()).unwrap(),dir,conf)
}

// ============================ (a1) journal bytes per record ============================
/// Bytes a single journal record occupies for each block kind. Fast; runs in all builds.
#[test]
fn jm_journal_bytes_per_record(){
    let mut n=net();let g=n.chain.head;let alice=devnet::account_key("alice");
    // one real parent so signed templates have a drawn proposer and base fee
    let p0=fallback(&n,g,0);import(&mut n,&p0);let head=n.chain.head;
    let empty=fallback(&n,head,1);
    let transfers=pack_transfers(&n,head,&alice); // the most 21000-gas transfers a block holds (~full gas)
    let full_gas=signed(&n,head,Body{txs:transfers,evidence:vec![]});
    let logheavy=signed(&n,head,Body{txs:vec![log_deploy(&alice,0,546)],evidence:vec![]});
    // Pack body to just under BODY_MAX with two big zero-calldata calls.
    let max=n.chain.spec.cp().BODY_MAX as usize;let mut len=max/2-200;
    loop{let body=Body{txs:vec![big_call(&alice,0,len),big_call(&alice,1,len)],evidence:vec![]};
        if body.encode().len()>max{len-=64;}else if (Body{txs:vec![big_call(&alice,0,len+64),big_call(&alice,1,len+64)],evidence:vec![]}).encode().len()<=max{len+=64;}else{break}}
    let body_max=signed(&n,head,Body{txs:vec![big_call(&alice,0,len),big_call(&alice,1,len)],evidence:vec![]});
    let kinds=[("empty",&empty),("full_gas_transfers",&full_gas),("log_heavy_546",&logheavy),("full_body_max",&body_max)];
    let mut out=serde_json::Map::new();
    for (k,b) in kinds{
        let rec=record_bytes(&n.chain,b);
        let body=b.body.encode().len();let hdr=b.header.encoded.len();let txs=b.body.txs.len();
        let (e,_)=n.chain.validate(b,None,0).unwrap();let receipts:usize=e.receipts.iter().map(|r|r.len()).sum();
        let result=result_bytes(&e).len();let shares=b.header.shares.len();
        out.insert(k.into(),serde_json::json!({"recordBytes":rec,"headerBytes":hdr,"bodyBytes":body,"resultBytes":result,"powShares":shares,"txs":txs,"receiptBytesNotStored":receipts,"gasUsed":e.gas_used,"cumLogBytes":e.cum_log_bytes}));
    }
    println!("JM-BYTES {}",serde_json::Value::Object(out));
    println!("JM-CONST {}",serde_json::json!({"OVERHEAD":store::OVERHEAD,"MAX_RECORD":store::MAX_RECORD,"BODY_MAX":n.chain.spec.cp().BODY_MAX,"TX_MAX":n.chain.spec.cp().TX_MAX,"GAS_LIMIT":n.chain.spec.cp().GAS_LIMIT}));
}

// ============================ (a2) replay-at-open + RSS, empty blocks ============================
/// Builds up to `JM_HEIGHT` empty (fallback) blocks into an on-disk journal, snapshots the data dir
/// at the devnet checkpoints, then reopens each snapshot and times the replay-at-open (every record
/// re-executed from genesis) and records VmHWM across the largest replay. Demonstrates replay time is
/// linear in the record count, giving the per-block cost used to extrapolate to the network H_END.
/// Release only. `JM_HEIGHT` env overrides the max height (default 20000 = devnet H_END).
#[test]
#[ignore="measurement: run in release with --ignored --nocapture"]
fn jm_replay_empty_blocks(){
    let h_max:u64=std::env::var("JM_HEIGHT").ok().and_then(|s|s.parse().ok()).unwrap_or(20_000);
    let checkpoints:Vec<u64>=[1000u64,5000,20000].into_iter().filter(|c|*c<=h_max).collect();
    let (mut n,dir,_)=mnode("replay");
    let mut harness=net();let mut parent=harness.chain.head;
    let t_build=Instant::now();let mut snaps:Vec<(u64,PathBuf)>=vec![];
    for h in 1..=h_max{
        let b=fallback(&harness,parent,0);import(&mut harness,&b);parent=b.hash();
        n.import(b,None).unwrap();
        if checkpoints.contains(&h){
            let snap=tmp(&format!("snap{h}"));std::fs::create_dir_all(&snap).unwrap();
            for f in ["blocks.journal","blocks.commit","retention.rkeep"]{let s=dir.join(f);if s.exists(){std::fs::copy(&s,snap.join(f)).unwrap();}}
            snaps.push((h,snap));
        }
        if h%2000==0{eprintln!("  built {h}/{h_max} ({:.0}s)",t_build.elapsed().as_secs_f64());}
    }
    let build_s=t_build.elapsed().as_secs_f64();
    let final_disk=disk_bytes(&dir);let final_records=n.journal_records();
    drop(n);drop(harness);
    for (h,snap) in &snaps{
        let before=vmhwm_bytes();let rss0=rss_bytes();
        let t=Instant::now();
        let conf=Config{dir:snap.clone(),name:"jm".into(),miner:None,listen:None,peers:vec![],rpc:None,stop_at:None,log:false,limits:Limits::default()};
        let r=Node::open(conf,admitted()).unwrap();
        let open_s=t.elapsed().as_secs_f64();
        let after=vmhwm_bytes();let rss1=rss_bytes();
        let records=r.journal_records();assert_eq!(records,*h,"replayed {} records at checkpoint {h}",records);
        let dbytes=disk_bytes(snap);
        println!("JM-REPLAY {}",serde_json::json!({"height":h,"records":records,"journalDiskBytes":dbytes,"openSeconds":open_s,"perRecordMicros":open_s*1e6/(*h as f64),"vmHwmBeforeBytes":before,"vmHwmAfterBytes":after,"rssBeforeBytes":rss0,"rssAfterBytes":rss1}));
        drop(r);let _=std::fs::remove_dir_all(snap);
    }
    println!("JM-BUILD {}",serde_json::json!({"hMax":h_max,"buildSeconds":build_s,"finalJournalDiskBytes":final_disk,"finalRecords":final_records,"bytesPerRecordAvg":final_disk as f64/final_records.max(1) as f64}));
    let _=std::fs::remove_dir_all(&dir);
}

// ============================ (a3) per-block replay cost by block kind ============================
/// Per-record replay cost for each heavy block kind, from a modest run (building 20k full blocks is
/// infeasible: each full block executes ~380 transactions). Replay re-executes each record on its
/// parent independently, so the open time at height H is H * perRecord + a small constant; the report
/// uses these per-record figures to project the 1k/5k/20k/129600 totals for the full/log/body-max
/// profiles. Release only.
#[test]
#[ignore="measurement: run in release with --ignored --nocapture"]
fn jm_replay_by_kind(){
    let count:u64=std::env::var("JM_KIND_COUNT").ok().and_then(|s|s.parse().ok()).unwrap_or(40);
    for kind in ["empty","full_gas_transfers","log_heavy_546","full_body_max"]{
        let (mut n,dir,_)=mnode(&format!("kind-{kind}"));
        let mut harness=net();let mut parent=harness.chain.head;
        // alice funds 380 transfers per block across `count` blocks; give each block its own sender set
        // by using distinct accounts is unnecessary — nonces simply continue.
        let alice=devnet::account_key("alice");let mut nonce=0u64;
        let bodymax_len={let max=n.chain.spec.cp().BODY_MAX as usize;let mut len=max/2-200;
            loop{let e=(Body{txs:vec![big_call(&alice,0,len),big_call(&alice,1,len)],evidence:vec![]}).encode().len();
                if e>max{len-=64;}else if (Body{txs:vec![big_call(&alice,0,len+64),big_call(&alice,1,len+64)],evidence:vec![]}).encode().len()<=max{len+=64;}else{break}}len};
        // The per-block transfer count is fixed (constant gas limit); compute once from the first parent.
        let transfers_k=if kind=="full_gas_transfers"{pack_transfers(&harness,parent,&alice).len() as u64}else{0};
        let t_build=Instant::now();
        for _ in 0..count{
            let b=match kind{
                "empty"=>fallback(&harness,parent,0),
                "full_gas_transfers"=>{let txs:Vec<Vec<u8>>=(0..transfers_k).map(|i|pay(&alice,nonce+i)).collect();nonce+=transfers_k;signed(&harness,parent,Body{txs,evidence:vec![]})}
                "log_heavy_546"=>{let b=signed(&harness,parent,Body{txs:vec![log_deploy(&alice,nonce,546)],evidence:vec![]});nonce+=1;b}
                "full_body_max"=>{let b=signed(&harness,parent,Body{txs:vec![big_call(&alice,nonce,bodymax_len),big_call(&alice,nonce+1,bodymax_len)],evidence:vec![]});nonce+=2;b}
                _=>unreachable!(),
            };
            import(&mut harness,&b);parent=b.hash();n.import(b,None).unwrap();
        }
        let build_s=t_build.elapsed().as_secs_f64();
        let disk=disk_bytes(&dir);let records=n.journal_records();
        drop(n);drop(harness);
        let t=Instant::now();
        let conf=Config{dir:dir.clone(),name:"jm".into(),miner:None,listen:None,peers:vec![],rpc:None,stop_at:None,log:false,limits:Limits::default()};
        let r=Node::open(conf,admitted()).unwrap();
        let open_s=t.elapsed().as_secs_f64();
        assert_eq!(r.journal_records(),records);
        println!("JM-KIND {}",serde_json::json!({"kind":kind,"blocks":count,"records":records,"journalDiskBytes":disk,"bytesPerRecord":disk as f64/records.max(1) as f64,"buildSeconds":build_s,"openSeconds":open_s,"perRecordMillis":open_s*1e3/records.max(1) as f64}));
        drop(r);let _=std::fs::remove_dir_all(&dir);
    }
}

// ============================ (a4) deep-fork rebuild vs fork-point height ============================
/// A fork point below the K_hist window has a pruned state; a rebuild (ensure_state) re-executes from
/// the nearest retained ancestor, which below the window is genesis — there are no reverse diffs
/// (storage.md:70 expects them for 2048 blocks). This times ensure_state for several fork-point
/// heights, showing the rebuild cost scales with the fork-point height (linear in height, not depth).
/// Release only.
#[test]
#[ignore="measurement: run in release with --ignored --nocapture"]
fn jm_deep_fork_rebuild_vs_height(){
    let h_max:u64=std::env::var("JM_REBUILD_HEIGHT").ok().and_then(|s|s.parse().ok()).unwrap_or(5000);
    let mut harness=net();let mut parent=harness.chain.head;let blocks:Vec<Block>={
        let mut v=vec![];for _ in 0..h_max{let b=fallback(&harness,parent,0);import(&mut harness,&b);parent=b.hash();v.push(b);}v};
    // A chain that keeps ALL canonical states resident (k_hist huge) so we can prune on demand and
    // measure the rebuild of one target from genesis.
    let mut chain=Chain::new(admitted());chain.k_hist=u64::MAX;chain.side_cap=h_max as usize+8;
    for b in &blocks{let (e,_)=chain.validate(b,None,0).unwrap();chain.insert(e);}
    let fps:Vec<u64>=[100u64,500,1000,2048,3000,h_max].into_iter().filter(|f|*f<=h_max).collect();
    for f in fps{
        let hash=chain.canonical_at(f).unwrap().hash;
        // Prune every canonical state except genesis, forcing a full rebuild from genesis to f.
        let hs:Vec<[u8;32]>=chain.canonical.iter().skip(1).copied().collect();
        for h in hs{let e=chain.blocks.get_mut(&h).unwrap();e.state=revm::InMemoryDB::default();e.pruned=true;}
        let before=chain.rebuilds;let t=Instant::now();
        chain.ensure_state(&hash).unwrap();
        let s=t.elapsed().as_secs_f64();
        println!("JM-REBUILD {}",serde_json::json!({"forkPointHeight":f,"reExecutions":chain.rebuilds-before,"seconds":s,"perBlockMillis":s*1e3/f as f64}));
    }
}

// ============================ (a5) restore cost after an adoption ============================
/// After adopting a heavier branch, restore_canonical re-executes the adopted suffix from the fork
/// point to make offloaded blocks whole. This times the restore for a given adoption depth. Fast-ish;
/// uses a small R_keep so the eviction/offload path runs. Release recommended.
#[test]
#[ignore="measurement: run in release with --ignored --nocapture"]
fn jm_restore_cost(){
    let depth:usize=std::env::var("JM_RESTORE_DEPTH").ok().and_then(|s|s.parse().ok()).unwrap_or(400);
    // Our lighter branch (attempt 1, less work/block); theirs heavier, delivered unsolicited to be
    // offloaded as side blocks, then adopted — restore re-executes the suffix.
    let mut a=net();let g=a.chain.head;let mut p=g;let mut ours=vec![];
    for _ in 0..depth+1{let b=fallback(&a,p,1);import(&mut a,&b);p=b.hash();ours.push(b);}
    let target=a.chain.head().total_work;
    let mut b=net();let mut p=g;let mut theirs=vec![];
    while b.chain.get(&p).unwrap().total_work<=target{let x=fallback(&b,p,0);import(&mut b,&x);p=x.hash();theirs.push(x);}
    for _ in 0..1{let x=fallback(&b,p,0);import(&mut b,&x);p=x.hash();theirs.push(x);}
    let dir=tmp("restore");let d=dir.clone();
    let conf=move||Config{dir:d.clone(),name:"jm".into(),miner:None,listen:None,peers:vec![],rpc:None,stop_at:None,log:false,limits:Limits{r_keep:depth as u64+16,side_cap:depth+16,..Default::default()}};
    let mut n=Node::open(conf(),admitted()).unwrap();
    for x in &ours[..depth]{n.import(x.clone(),None).unwrap();}
    let restored0=n.stats.restored;
    let t=Instant::now();
    for x in &theirs{n.import(x.clone(),None).unwrap();}
    let adopt_s=t.elapsed().as_secs_f64();
    let restored=n.stats.restored-restored0;
    assert_eq!(n.chain.head,theirs.last().unwrap().hash());
    println!("JM-RESTORE {}",serde_json::json!({"adoptionDepth":depth,"theirBlocks":theirs.len(),"restoredBlocks":restored,"adoptSeconds":adopt_s}));
    drop(n);let _=std::fs::remove_dir_all(&dir);
}
