//! A13 at the network profile (governance.md genesis parameters, profileKind=network): the model the
//! 6 GiB gate checks, itemized, for the decision package. pocold refuses to boot this profile; this
//! test records by how much and which terms carry it. It asserts nothing about admission.
use pocol_lp4_execution::devnet::{self,DevnetConfig};

fn network()->DevnetConfig{
    let labels:Vec<String>=(0..4).map(|i|format!("m{i}")).collect();let refs:Vec<&str>=labels.iter().map(|s|s.as_str()).collect();
    let mut c=DevnetConfig::new(777920,1_800_000_000,&refs);
    // chainId 777920: devnet::build refuses the network chainId 777001; chainId does not enter any A13 term.
    // governance.md: T_blk 60, tau 3600, c 2, D_att 300, dFbWait 25; m 32, kappa 2, S_max 256, D 16, W_w 64;
    // R_max 2, M_max 256, REG_RECORDS_MAX 16384; W_act 128, Theta_inact 1024; E_win 2048, U 2200;
    // caps; SYS_SLOT_MAX 131072; H_END 129600, H_CLOSE 129440, Z_close 160, RET 128, P2 2.
    c.t_blk=60;c.tau=3600;c.c=2;c.d_att=300;c.d_fb_wait=25;c.m=32;c.kappa=2;c.s_max=256;c.d=16;c.w_w=64;
    c.r_max=2;c.m_max=256;c.reg_records_max=16384;c.w_act=128;c.theta_inact=1024;c.e_win=2048;c.u=2200;
    c.code_cap=1<<30;c.txbytes_cap=1<<33;c.tx_cap=10_000_000;c.slot_cap=4_000_000;c.acct_cap=1_000_000;c.sys_slot_max=131072;
    c.h_end=129_600;c.h_close=129_440;c.t_end_offset=10_368_000;c.t_close_offset=10_368_000-9_600;c.z_close=160;c.ret=128;c.p2=2;c
}
fn print(tag:&str,b:&pocold::resources::Bound){
    let gib=|x:u128|x as f64/(1u128<<30) as f64;
    let need=pocold::resources::budget_required(b.total).unwrap();
    println!("{tag} {}",serde_json::json!({"total":b.total.to_string(),"totalGiB":gib(b.total),"budgetRequiredGiB":gib(need),"budgetGiB":6,
        "snapshotGiB":gib(b.snapshot_bytes),"snapshots":b.snapshots.to_string(),
        "groupsGiB":{"snapshots":gib(b.snapshot_total),"diffs":gib(b.diffs),"trie":gib(b.trie),"code":gib(b.code),"store":gib(b.store),"history":gib(b.history),"side":gib(b.side_blocks),"queues":gib(b.queues),"rpc":gib(b.rpc),"threads":gib(b.threads),"execution":gib(b.execution)},
        "items":b.items.iter().map(|(k,v)|serde_json::json!([k,v.to_string(),gib(*v)])).collect::<Vec<_>>()}));
}
/// C-1 E4.5: the same profile with the states in state.redb (`Limits::state_store`), with the pool's gas
/// unbounded (D-7: its value is not approved), as pocold would boot it.
#[test] fn a13_store_model_at_the_network_profile(){
    let d=devnet::build(&network()).expect("network-profile candidate");let cp=d.profile.cp().clone();
    let l=pocold::single_host_local();
    let b=pocold::resources::derive(&cp,32,l.side_max,&pocold::node::Limits{state_store:true,..Default::default()},2).expect("no overflow");
    print("A13-NETWORK-STORE",&b);
}
#[test] fn a13_model_at_the_network_profile(){
    let d=devnet::build(&network()).expect("network-profile candidate");let cp=d.profile.cp().clone();
    let l=pocold::single_host_local();
    // K_hist = 32 at the network profile (governance.md, local retention); side_max as pocold boots.
    let b=pocold::resources::derive(&cp,32,l.side_max,&pocold::node::Limits::default(),2).expect("no overflow");print("A13-NETWORK",&b);
    let need=pocold::resources::budget_required(b.total).unwrap();
    assert!(need>u128::from(pocold::node::MEM_BUDGET),"the network profile does not fit 6 GiB today (if this fails, the model changed: update the decision package)");
}

/// C-1 E4.5: the devnet profile pocold boots, whole-state and store mode with the default limits: both pass
/// the boot gate. Store mode is not the smaller bound here: the devnet's states are small, and its fixed
/// caches and worst-case batch and file terms outweigh them.
#[test] fn a13_store_model_at_the_devnet_profile(){
    let c=DevnetConfig::new(777910,1_700_000_000,&["a","b","c"]);let d=devnet::build(&c).unwrap();let cp=d.profile.cp().clone();let l=pocold::single_host_local();
    let (m,s)=(pocold::node::Limits::default(),pocold::node::Limits{state_store:true,..Default::default()});
    let bm=pocold::resources::check(&cp,l.k_hist,l.side_max,&m,0).expect("whole-state mode boots");let bs=pocold::resources::check(&cp,l.k_hist,l.side_max,&s,0).expect("store mode boots");
    print("A13-DEVNET-MEM",&bm);print("A13-DEVNET-STORE",&bs);
}
