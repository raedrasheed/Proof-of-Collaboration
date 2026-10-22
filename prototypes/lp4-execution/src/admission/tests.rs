//! A02 corrected behaviour: the full gate runs on the real artifacts, every reproduced
//! violation is rejected with its rule, each rule has a boundary case, approved profiles
//! are admitted, and results are deterministic. Rule lists are asserted exactly.
use super::*;
use crate::{devnet::{self,Devnet,DevnetConfig},fixed};

fn cfg()->DevnetConfig{DevnetConfig::new(777920,1_800_000_000,&["a","b","c"])}
fn net(c:&DevnetConfig)->Devnet{devnet::build(c).expect("candidate")}
/// Timing measured once for the base profile, rebound to `bytes` so that rule
/// attribution tests isolate the rule under test (R14/R19 have their own tests).
fn rebound(t:&Timing,bytes:&[u8])->Timing{Timing{genesis_hash:gs::genesis_hash(bytes),..t.clone()}}
fn base()->(Devnet,Timing){let n=net(&cfg());let t=measure(&n.spec_bytes,&n.alloc,1).expect("measure");(n,t)}
fn run(n:&Devnet,t:&Timing,local:&NodeLocal)->Result<Admitted,Rejection>{let t=rebound(t,&n.spec_bytes);admit(&n.request(local,Some(&t)))}
fn rules(r:Result<Admitted,Rejection>)->Vec<String>{match r{Ok(_)=>vec![],Err(e)=>e.rules}}
fn v(x:&[&str])->Vec<String>{x.iter().map(|s|s.to_string()).collect()}
/// The candidate's spec with CP edits and the allocRoot re-derived for them, as a
/// careful operator would; the gate, not a stale root, must catch the edit.
fn edited(n:&Devnet,edits:&[(usize,u64)])->Vec<u8>{
    let mut spec=gs::decode(&n.spec_bytes).unwrap();for (i,x) in edits{spec.cp[*i]=fixed::U256::from_u64(*x)}
    let b=gs::encode(&spec);
    if let Ok(p)=fact_identity(&b,&gs::genesis_hash(&b),spec.chain_id){if let Ok(r)=Genesis::derive_root(&n.alloc,&p,&SystemPrograms::v1()){spec.alloc_root=r.0}}
    gs::encode(&spec)
}
fn run_bytes(n:&Devnet,t:&Timing,bytes:&[u8],local:&NodeLocal)->Vec<String>{let t=rebound(t,bytes);rules(admit(&Request{spec_bytes:bytes,..n.request(local,Some(&t))}))}
fn sh()->NodeLocal{NodeLocal::single_host()}

#[test] fn approved_single_host_devnet_is_admitted_with_reported_provenance(){
    let (n,t)=base();let a=admit(&n.request(&sh(),Some(&t))).unwrap_or_else(|e|panic!("{e}"));
    assert_eq!(a.genesis_hash(),n.profile.genesis_hash());assert_eq!(a.genesis().root(),n.genesis.root());
    let r=a.report();assert_eq!(r.calibration_class,Some(FactClass::SyntheticFixture));assert_eq!(r.resource_class,Some(FactClass::Measurement));
    // D-A13-PROFILE: the retained-state bound fits HIST_TRIE_BUDGET; no R21 exception is used.
    assert!(!r.r21_exception&&r.historical_bytes<=HIST_TRIE_BUDGET,"{} {:?}",r.historical_bytes,r.notes);
    let a=admit(&n.request(&NodeLocal{retention_stress:false,..sh()},Some(&t)));assert!(a.is_ok(),"admitted without retentionStress");
    assert!(t.phase_ms.iter().all(|ms|*ms<=1000),"t_exec=1 s must cover every measured phase: {t:?}");
}
#[test] fn approved_p11_timing_profile_is_admitted(){
    // P11: T_blk=10, tau=600, c=2, D_att=60, dFbWait=6 with P11 local timing.
    let mut c=cfg();c.t_blk=10;c.tau=600;c.c=2;c.d_att=60;c.d_fb_wait=6;c.hash_rate=1<<14;
    let n=net(&c);let t=measure(&n.spec_bytes,&n.alloc,1).unwrap();
    admit(&n.request(&NodeLocal::p11(),Some(&t))).unwrap_or_else(|e|panic!("{e}"));
}
#[test] fn audit_reproductions_are_rejected_with_their_rules(){
    let (_,t)=base();
    let mut c=cfg();c.s_max=1;assert_eq!(rules(run(&net(&c),&t,&sh())),v(&["R9"]),"A02-R9 S_max=1");
    let mut c=cfg();c.h_close=c.h_end;assert_eq!(rules(run(&net(&c),&t,&sh())),v(&["R13"]),"A02-R13 H_CLOSE=H_END");
    // As audited: R_max=2 (the audited devnet default), so the genesis holds 69 system slots.
    let mut c=cfg();c.r_max=2;c.sys_slot_max=1;let n=net(&c);
    let e=run(&n,&t,&sh()).err().expect("SYS_SLOT_MAX=1 must be rejected");assert_eq!(e.rules,v(&["R18"]));
    let g=Genesis::build(&n.alloc,&n.profile,&SystemPrograms::v1()).unwrap();assert_eq!(resources::sys_slots(g.state()),69,"genesis needs 69 system slots");
}
#[test] fn timing_rules_r1_to_r7_at_their_boundaries(){
    let (n,t)=base();
    assert_eq!(rules(run(&n,&t,&NodeLocal{delta_rel:4,..sh()})),v(&["R2"]));
    assert!(run(&n,&t,&NodeLocal{delta_rel:5,..sh()}).is_ok());
    let mut c=cfg();c.d_fb_wait=2;assert_eq!(rules(run(&net(&c),&t,&sh())),v(&["R3"]));
    assert_eq!(rules(run(&n,&t,&NodeLocal{phi:2,..sh()})),v(&["R2","R3","R4","R7"]),"Φ=4 ≥ Δ_fb_wait=3");
    let mut c=cfg();c.d_att=8;assert_eq!(rules(run(&net(&c),&t,&sh())),v(&["R5","R7"]));
    let mut c=cfg();c.d_att=24;assert_eq!(rules(run(&net(&c),&t,&sh())),v(&["R7"]));
    let mut c=cfg();c.d_att=25;assert!(run(&net(&c),&t,&sh()).is_ok());
    assert!(rules(run(&n,&t,&NodeLocal{phi:u32::MAX,..sh()})).contains(&"R1".to_string()),"an overflowing Φ=2φ fails R1");
}
#[test] fn size_membership_and_end_rules_r8_to_r13(){
    let (n,t)=base();
    let mut c=cfg();c.u=19;assert_eq!(rules(run(&net(&c),&t,&sh())),v(&["R8"]),"U < E_win+D");
    let mut c=cfg();c.e_win=2049;c.u=2053;assert_eq!(rules(run(&net(&c),&t,&sh())),v(&["R8"]),"E_win > R_keep");
    // Genesis construction itself refuses B_code_max < 24577 (code_caps), so the identity
    // facts are absent as well; the note names the construction failure.
    assert_eq!(run_bytes(&n,&t,&edited(&n,&[(34,24576)]),&sh()),v(&["R9","R23","R24"]),"B_code_max");
    assert!(run_bytes(&n,&t,&edited(&n,&[(34,24577)]),&sh()).is_empty());
    assert_eq!(run_bytes(&n,&t,&edited(&n,&[(32,196608-16384+1)]),&sh()),v(&["R10"]));
    assert!(run_bytes(&n,&t,&edited(&n,&[(32,196608-16384)]),&sh()).is_empty());
    assert_eq!(rules(run(&n,&t,&NodeLocal{k_hist:12,..sh()})),v(&["R11"]),"k_view < K_hist");
    let r=run_bytes(&n,&t,&edited(&n,&[(18,2)]),&sh());assert_eq!(r.first().map(|s|s.as_str()),Some("R12"),"M_max < |M_0|: {r:?}");
    let mut c=cfg();c.t_close_offset=c.t_end_offset+1;assert_eq!(rules(run(&net(&c),&t,&sh())),v(&["R13"]),"T_CLOSE > T_END");
    let mut c=cfg();c.h_close=c.h_end-160;assert!(run(&net(&c),&t,&sh()).is_ok(),"H_CLOSE+Z_close = H_END");
}
#[test] fn resource_rules_r14_to_r21(){
    let (n,t)=base();
    assert_eq!(rules(admit(&n.request(&sh(),None))),v(&["R14","R19"]),"no timing measurement");
    let other=Timing{genesis_hash:[7;32],..t.clone()};assert_eq!(rules(admit(&n.request(&sh(),Some(&other)))),v(&["R14","R19"]),"measured for another genesis");
    let slow=Timing{phase_ms:[10,10,1001],..t.clone()};assert_eq!(rules(run(&n,&slow,&sh())),v(&["R14","R19"]),"final phase above t_exec");
    let mut g=DEFAULT_GOSSIP;g[1]=196608+685; // template = BODY_MAX + 686-byte envelope
    assert_eq!(rules(run(&n,&t,&NodeLocal{gossip:g,..sh()})),v(&["R15"]));
    // R16 with R_max=2: M_max + R_max*(Lmax+LAG) = 64 + 2*(max(40, 2*16+4+1)+2048) = 4240.
    let mut c=cfg();c.r_max=2;c.reg_records_max=4239;assert_eq!(rules(run(&net(&c),&t,&sh())),v(&["R16"]));
    let mut c=cfg();c.r_max=2;c.reg_records_max=4240;assert!(run(&net(&c),&t,&sh()).is_ok());
    // R16 with the devnet's R_max=0: REG_RECORDS_MAX >= M_max = 64.
    let mut c=cfg();c.reg_records_max=63;assert_eq!(rules(run(&net(&c),&t,&sh())),v(&["R16"]));
    assert_eq!(run_bytes(&n,&t,&edited(&n,&[(21,3)]),&sh()),v(&["R17"]),"SWEEP_MAX < R_max+E_max = 4");
    assert!(run_bytes(&n,&t,&edited(&n,&[(21,4)]),&sh()).is_empty());
    let b=resources::derive(n.profile.cp());
    let mut c=cfg();c.sys_slot_max=b.slot_min as u32-1;assert_eq!(rules(run(&net(&c),&t,&sh())),v(&["R18"]));
    let mut c=cfg();c.sys_slot_max=b.slot_min as u32;assert!(run(&net(&c),&t,&sh()).is_ok());
    let keys=(b.keys_normal+u64::from(n.profile.cp().SYS_KEYS_USER_MAX)).max(b.keys_closing).max(b.keys_final);
    assert_eq!(run_bytes(&n,&t,&edited(&n,&[(41,keys-1)]),&sh()),v(&["R18"]),"system+user keys above SYS_KEYS_BLOCK_MAX");
    assert!(run_bytes(&n,&t,&edited(&n,&[(41,keys)]),&sh()).is_empty());
    assert_eq!(run_bytes(&n,&t,&edited(&n,&[(44,30_000_000)]),&sh()),v(&["R18"]),"phase gas above G_SYS");
    // R20: Z_close >= ceil(8192/128)+P2+D+1 = 71.
    assert_eq!(run_bytes(&n,&t,&edited(&n,&[(49,70)]),&sh()),v(&["R20"]));
    assert!(run_bytes(&n,&t,&edited(&n,&[(49,71)]),&sh()).is_empty());
    // R21 at network-scale caps: pocold's full snapshots exceed HIST_TRIE_BUDGET; only the
    // simnet retentionStress exception admits it, and a node never gets that exception.
    let mut c=cfg();c.slot_cap=4_000_000;c.acct_cap=1_000_000;let big=net(&c);
    assert_eq!(rules(run(&big,&t,&NodeLocal{retention_stress:false,..sh()})),v(&["R21"]));
    let a=run(&big,&t,&sh()).unwrap();assert!(a.report().r21_exception&&a.report().notes.iter().any(|x|x.contains("retentionStress")));
    // Outside the measured SYS gas domain the gas facts are absent: R18, never assumed.
    let mut c=cfg();c.d=17;c.u=41;assert_eq!(rules(run(&net(&c),&t,&sh())),v(&["R18"]),"D=17 outside the gas domain");
}
#[test] fn identity_rules_r22_to_r26(){
    let (n,t)=base();let tt=rebound(&t,&n.spec_bytes);
    assert_eq!(rules(admit(&Request{node:NodeKind::Node,..n.request(&sh(),Some(&tt))})),v(&["R22"]),"simnet profile on a node: [R22] (governance.md)");
    assert_eq!(rules(admit(&Request{forks:&[(1,0),(2,50)],..n.request(&sh(),Some(&tt))})),v(&["R24"]),"TestFork-v2 is not implemented");
    let mut alloc=n.alloc.clone();let a=devnet::account_key("alice").address();alloc.accounts.get_mut(&a).unwrap().info.balance+=revm::primitives::U256::from(1);
    assert_eq!(rules(admit(&Request{alloc:&alloc,..n.request(&sh(),Some(&tt))})),v(&["R24"]),"alloc does not match allocRoot");
    let mut big=n.alloc.clone();big.accounts.get_mut(&a).unwrap().info.balance=revm::primitives::U256::from(1)<<127;
    let r=rules(admit(&Request{alloc:&big,..n.request(&sh(),Some(&tt))}));assert!(r.contains(&"R23".to_string()),"{r:?}");
    assert_eq!(rules(admit(&Request{calibration:Some((n.hash_rate+1,FactClass::SyntheticFixture)),..n.request(&sh(),Some(&tt))})),v(&["R25"]),"target_g is not the calibrated value");
    let e=admit(&Request{calibration:None,..n.request(&sh(),Some(&tt))}).err().unwrap();assert_eq!(e.rules,v(&["R25"]));assert!(!e.missing.is_empty());
    let mut rpc=RpcLimits::default();rpc.conn_max=1000;assert_eq!(rules(run(&n,&t,&NodeLocal{rpc,..sh()})),v(&["R26"]));
    let mut bytes=n.spec_bytes.clone();bytes.pop();assert_eq!(rules(admit(&Request{spec_bytes:&bytes,..n.request(&sh(),Some(&tt))})),v(&["R24"]),"undecodable GenesisSpec");
}
#[test] fn rejections_are_deterministic_and_name_their_causes(){
    let (_,t)=base();let mut c=cfg();c.s_max=1;c.h_close=c.h_end;c.d_att=8;let n=net(&c);
    let a=run(&n,&t,&sh()).err().unwrap();let b=run(&n,&t,&sh()).err().unwrap();
    assert_eq!(a,b);assert_eq!(a.rules,v(&["R5","R7","R9","R13"]));
    assert!(a.to_string().starts_with("-32018 ParamGate rejected [R5, R7, R9, R13]"),"{a}");
}
