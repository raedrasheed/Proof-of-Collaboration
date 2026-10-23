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
/// `gas` is the tx gas limit (so a log-heavy tx can be packed beside a compute filler in one block).
fn log_deploy_gas(key:&Key,nonce:u64,n:u16,gas:u64)->Vec<u8>{
    let mut init=vec![0x61,(n>>8) as u8,(n&0xff) as u8,0x5b];// PUSH2 n; JUMPDEST(3)
    init.extend([0x5f,0x5f,0xa0,0x60,0x01,0x90,0x03,0x80,0x60,0x03,0x57,0x00]);// PUSH0 PUSH0 LOG0; PUSH1 1 SWAP1 SUB; DUP1 PUSH1 3 JUMPI; STOP
    Tx{chain_id:777910,nonce,max_priority:U256::from(1u64),max_fee:U256::from(1_000_000_000_000_000u64),gas,to:None,value:U256::ZERO,data:init.into()}.sign_1559(key)}
fn log_deploy(key:&Key,nonce:u64,n:u16)->Vec<u8>{log_deploy_gas(key,nonce,n,8_000_000)}
/// A single compute-heavy tx that burns its whole gas limit: init code `JUMPDEST PUSH1 0 JUMP` is a
/// tight infinite loop, so creation runs out of gas (status 0, gas_used = gas limit, no logs). One per
/// block gives a FULL-GAS block that is bounded by neither TX_CAP (1 tx) nor TXBYTES_CAP (tiny body),
/// so H_END of them is reachable: the per-block replay worst case (J-V6). `gas` <= GAS_LIMIT headroom.
fn compute_oog(key:&Key,nonce:u64,gas:u64)->Vec<u8>{
    Tx{chain_id:777910,nonce,max_priority:U256::from(1u64),max_fee:U256::from(1_000_000_000_000_000u64),gas,to:None,value:U256::ZERO,data:vec![0x5b,0x60,0x00,0x56].into()}.sign_1559(key)}

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
    // Full-gas compute block (1 tx, ~8M gas OOG loop): the open-time worst case, bounded by no cap.
    let fg_compute=signed(&n,head,Body{txs:vec![compute_oog(&alice,0,7_950_000)],evidence:vec![]});
    // Full-gas LOG-heavy block (546 logs then a compute filler to ~8M gas): the task's "8M gas of a
    // log-heavy contract". Shows the journal record stays small while receipts/logs are large.
    let fg_logs=signed(&n,head,Body{txs:vec![log_deploy_gas(&alice,0,546,300_000),compute_oog(&alice,1,7_650_000)],evidence:vec![]});
    let kinds=[("empty",&empty),("full_gas_transfers",&full_gas),("log_heavy_546",&logheavy),("full_body_max",&body_max),("full_gas_compute",&fg_compute),("full_gas_logs",&fg_logs)];
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
    for kind in ["empty","full_gas_transfers","log_heavy_546","full_body_max","full_gas_compute"]{
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
                "full_gas_compute"=>{let b=signed(&harness,parent,Body{txs:vec![compute_oog(&alice,nonce,7_950_000)],evidence:vec![]});nonce+=1;b}
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
    let mut fps:Vec<u64>=[100u64,500,1000,2048,3000,h_max].into_iter().filter(|f|*f<=h_max).collect();fps.sort_unstable();fps.dedup();
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

// ============================ (a5) deep-reorg latency: rebuild + restore ============================
/// A legal deep reorg whose fork point is below the K_hist window pays the genesis rebuild TWICE on the
/// single consensus thread (J-V1): once when the first competing block is validated (its parent, the
/// canonical fork point, has a pruned state -> NeedsRebuild -> ensure_state_with from genesis), and
/// again inside restore_canonical when the branch is adopted (import_with runs retain() BEFORE
/// restore_canonical, and retain re-prunes the still-canonical fork point, so restore's ensure_state_with
/// rebuilds it from genesis a second time). Plus d re-executions to validate the suffix and d to restore
/// it. This measures each phase so the report can state latency ~= 2*rebuild(f) + 2*d*a, not
/// rebuild(f) + d*a. The resulting journal is then reopened to show open replay re-pays both rebuilds.
/// Release only. JM_REORG_HEIGHT sets the canonical height (fork point = half of it).
#[test]
#[ignore="measurement: run in release with --ignored --nocapture"]
fn jm_deep_reorg_latency(){
    let n_c:u64=std::env::var("JM_REORG_HEIGHT").ok().and_then(|s|s.parse().ok()).unwrap_or(600);let f=n_c/2;
    // Builder keeps every state resident (k_hist=MAX, side_cap huge) so both branches build cleanly.
    let mut h=net();h.chain.k_hist=u64::MAX;h.chain.side_cap=n_c as usize*4+64;
    let mut c=vec![];let mut p=h.chain.head;for _ in 0..n_c{let b=fallback(&h,p,0);import(&mut h,&b);p=b.hash();c.push(b);}
    let fp=c[f as usize-1].hash(); // canonical block at height f
    // Competing branch T from the fork point: a signed first block (distinct from C's fallback
    // continuation, so no duplicate) whose PATH is still lighter than C until T grows past it, then
    // fallback(a=0) until strictly heavier (T is adopted only then; its path work, not per-height work,
    // decides D133). Grown in the all-states-resident builder.
    let cw=h.chain.get(&c.last().unwrap().hash()).unwrap().total_work;
    let t0=signed(&h,fp,Body::default());import(&mut h,&t0);let mut p=t0.hash();let mut t=vec![t0];
    while h.chain.get(&p).unwrap().total_work<=cw{let b=fallback(&h,p,0);import(&mut h,&b);p=b.hash();t.push(b);}
    let b=fallback(&h,p,0);import(&mut h,&b);t.push(b); // one past the crossover: a clean strict margin
    assert!(h.chain.get(&t.last().unwrap().hash()).unwrap().total_work>cw,"T must be heavier");
    drop(h);
    // Node under test: default single-host limits (k_hist=32, side_max=8, side_cap=2048).
    let (mut n,dir,_)=mnode("reorg");
    for b in &c{n.import(b.clone(),None).unwrap();}
    assert!(f+n.chain.k_hist<n.chain.head().height,"fork point must be below the K_hist window");
    let r0=n.chain.rebuilds;
    let (mut first,mut adopt)=(None,None);let t_all=Instant::now();
    for (i,b) in t.iter().enumerate(){
        let (rb,rs)=(n.chain.rebuilds,n.stats.restored);let ti=Instant::now();let nh=n.import(b.clone(),None).unwrap();
        let (dt,dr)=(ti.elapsed().as_secs_f64(),n.chain.rebuilds-rb);
        if i==0{first=Some((dt,dr));}
        if nh&&adopt.is_none()&&n.chain.head==b.hash(){adopt=Some((i,dt,dr,n.stats.restored-rs));}
    }
    let (total_s,total_rebuilds)=(t_all.elapsed().as_secs_f64(),n.chain.rebuilds-r0);
    assert_eq!(n.chain.head,t.last().unwrap().hash(),"T adopted");
    let (fi,fr)=first.unwrap();let (ai,at,ar,arest)=adopt.unwrap();
    println!("JM-REORG {}",serde_json::json!({"canonicalHeight":n_c,"forkPointHeight":f,"kHist":n.chain.k_hist,"reorgDepth":n_c-f,"theirBlocks":t.len(),
        "firstSideImport":{"seconds":fi,"rebuilds":fr},"adoptingImport":{"index":ai,"seconds":at,"rebuilds":ar,"restoredBlocks":arest},
        "allImports":{"seconds":total_s,"rebuilds":total_rebuilds},"stageAModelRebuilds":f,"actualRebuilds":total_rebuilds}));
    drop(n);
    // Reopen: replay re-imports T as a side branch then adopts, re-paying both rebuilds.
    let conf=Config{dir:dir.clone(),name:"jm".into(),miner:None,listen:None,peers:vec![],rpc:None,stop_at:None,log:false,limits:Limits::default()};
    let t=Instant::now();let r=Node::open(conf,admitted()).unwrap();let open_s=t.elapsed().as_secs_f64();
    println!("JM-REORG-OPEN {}",serde_json::json!({"records":r.journal_records(),"openSeconds":open_s,"rebuildsDuringOpen":r.chain.rebuilds}));
    drop(r);let _=std::fs::remove_dir_all(&dir);
}

// ============================ (a6) open-time memory transient (fresh process) ============================
/// Peak RSS of Node::open ALONE, in a fresh process (J-V4, J-V5). store::open reads the whole journal
/// into memory (read_to_end) and parse_v2 copies each payload, so the whole journal and the sum of
/// payloads coexist: the open transient is ~2x the journal. The stage-A VmHWM (237 MB) was the
/// process-lifetime peak of the in-process BUILD phase, not the open; measuring in a child process that
/// only opens (VmHWM reset via /proc/self/clear_refs, or counted from process start) isolates the open
/// peak. JM_MEM_OPEN=<dir> makes this process OPEN that dir only and print; absent, it builds a
/// full-BODY_MAX journal up to the devnet TXBYTES_CAP and reopens with VmHWM reset. Release only.
#[test]
#[ignore="measurement: run in release with --ignored --nocapture"]
fn jm_open_memory(){
    fn vmrss()->i64{std::fs::read_to_string("/proc/self/status").ok().and_then(|s|s.lines().find(|l|l.starts_with("VmRSS:")).and_then(|l|l.split_whitespace().nth(1).and_then(|x|x.parse().ok()))).map(|k:i64|k*1024).unwrap_or(-1)}
    if let Ok(d)=std::env::var("JM_MEM_OPEN"){
        let dir=PathBuf::from(d);let jbytes=disk_bytes(&dir);
        let (rss0,hwm0)=(vmrss(),vmhwm_bytes());let t=Instant::now();
        let r=Node::open(Config{dir:dir.clone(),name:"jm".into(),miner:None,listen:None,peers:vec![],rpc:None,stop_at:None,log:false,limits:Limits::default()},admitted()).unwrap();
        let open_s=t.elapsed().as_secs_f64();let (rss1,hwm1)=(vmrss(),vmhwm_bytes());
        println!("JM-OPENMEM-FRESH {}",serde_json::json!({"records":r.journal_records(),"journalBytes":jbytes,"openSeconds":open_s,
            "rssBeforeBytes":rss0,"vmHwmBeforeBytes":hwm0,"vmHwmAfterBytes":hwm1,"rssAfterBytes":rss1,
            "peakAboveBaselineBytes":(hwm1-rss0),"peakOverJournal":(hwm1-rss0) as f64/jbytes.max(1) as f64}));
        return
    }
    // JM_MEM_DIR builds into a persistent dir (not removed) so a second process can open it fresh
    // (the only sound way to measure the open peak, J-V5); absent, build+open in one process (which
    // UNDER-counts: the allocator reuses the build's freed memory).
    let persist=std::env::var("JM_MEM_DIR").ok();
    let dir=persist.clone().map(PathBuf::from).unwrap_or_else(||tmp("openmem"));let _=std::fs::remove_dir_all(&dir);
    let mut n=Node::open(Config{dir:dir.clone(),name:"jm".into(),miner:None,listen:None,peers:vec![],rpc:None,stop_at:None,log:false,limits:Limits::default()},admitted()).unwrap();
    let mut harness=net();let mut parent=harness.chain.head;let alice=devnet::account_key("alice");
    let max=n.chain.spec.cp().BODY_MAX as usize;let mut len=max/2-200;
    loop{let e=(Body{txs:vec![big_call(&alice,0,len),big_call(&alice,1,len)],evidence:vec![]}).encode().len();
        if e>max{len-=64;}else if (Body{txs:vec![big_call(&alice,0,len+64),big_call(&alice,1,len+64)],evidence:vec![]}).encode().len()<=max{len+=64;}else{break}}
    let (mut nonce,mut blocks)=(0u64,0u64);
    loop{let body=Body{txs:vec![big_call(&alice,nonce,len),big_call(&alice,nonce+1,len)],evidence:vec![]};
        let pe=harness.chain.get(&parent).unwrap().clone();
        if pe.cum_tx_bytes+body.txs.iter().map(|t|t.len() as u64).sum::<u64>()>harness.chain.spec.cp().TXBYTES_CAP{break}
        let b=signed(&harness,parent,body);import(&mut harness,&b);parent=b.hash();n.import(b,None).unwrap();nonce+=2;blocks+=1;}
    let jbytes=disk_bytes(&dir);drop(n);drop(harness);
    std::fs::write("/proc/self/clear_refs","5").unwrap();
    let (rss0,hwm0)=(vmrss(),vmhwm_bytes());let t=Instant::now();
    let r=Node::open(Config{dir:dir.clone(),name:"jm".into(),miner:None,listen:None,peers:vec![],rpc:None,stop_at:None,log:false,limits:Limits::default()},admitted()).unwrap();
    let open_s=t.elapsed().as_secs_f64();let (rss1,hwm1)=(vmrss(),vmhwm_bytes());
    println!("JM-OPENMEM {}",serde_json::json!({"blocks":blocks,"records":r.journal_records(),"journalBytes":jbytes,"openSeconds":open_s,"inProcessUndercounts":true,
        "rssBeforeBytes":rss0,"vmHwmAfterResetBytes":hwm0,"vmHwmAfterOpenBytes":hwm1,"rssAfterBytes":rss1,
        "peakAboveBaselineBytes":(hwm1-rss0),"peakOverJournal":(hwm1-rss0) as f64/jbytes.max(1) as f64}));
    drop(r);if persist.is_none(){let _=std::fs::remove_dir_all(&dir);}
}

// ============================ (a7) open replay cost by component ============================
/// Splits replay cost per record into validate / insert / retain, bucketed by height, to attribute the
/// super-linear open (J-V10): both Chain::retain (scans all resident blocks per record) and
/// Chain::insert -> rebuild_canonical (walks head->genesis on every head change) grow O(H) per record,
/// so the per-record cost is validate (flat) + insert (O(H)) + retain (O(H)). Mirrors Node::open's loop
/// on a bare Chain (replaying=true). Release only. JM_SPLIT_N sets the chain length.
#[test]
#[ignore="measurement: run in release with --ignored --nocapture"]
fn jm_replay_component_split(){
    let n_c:u64=std::env::var("JM_SPLIT_N").ok().and_then(|s|s.parse().ok()).unwrap_or(6000);
    let mut harness=net();harness.chain.k_hist=u64::MAX;harness.chain.side_cap=n_c as usize+64;
    let mut cb=vec![];let mut p=harness.chain.head;for _ in 0..n_c{let b=fallback(&harness,p,0);import(&mut harness,&b);p=b.hash();cb.push(b);}
    drop(harness);
    let mut c=Chain::new(admitted());c.replaying=true;
    let bucket=1000usize;let mut acc=vec![(0f64,0f64,0f64);cb.len().div_ceil(bucket)];
    for (i,b) in cb.iter().enumerate(){
        let t0=Instant::now();let (e,_)=c.validate(b,None,0).unwrap();let t1=Instant::now();c.insert(e);let t2=Instant::now();c.retain();let t3=Instant::now();
        let a=&mut acc[i/bucket];a.0+=(t1-t0).as_secs_f64();a.1+=(t2-t1).as_secs_f64();a.2+=(t3-t2).as_secs_f64();
    }
    for (k,(v,ins,ret)) in acc.iter().enumerate(){let m=bucket as f64;
        println!("JM-SPLIT {}",serde_json::json!({"heights":format!("{}..{}",k*bucket+1,(k+1)*bucket),"validateMs":v*1e3/m,"insertMs":ins*1e3/m,"retainMs":ret*1e3/m}));}
}
