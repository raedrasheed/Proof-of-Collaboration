use super::*;
use crate::{apply::{self,BlockInput,EvidenceEffect,ParentResult,Proposer},devnet::{self,DevnetConfig}};
use revm::primitives::{Address,B256,U256};

fn network_like(miners:usize,h_close:u64,h_end:u64)->DevnetConfig{
    let labels:Vec<String>=(0..miners).map(|i|format!("m{i}")).collect();let refs:Vec<&str>=labels.iter().map(|s|s.as_str()).collect();
    let mut c=DevnetConfig::new(777920,1_800_000_000,&refs);
    c.d=16;c.w_w=64;c.s_max=256;c.m_max=256;c.h_close=h_close;c.h_end=h_end;c.ret=128;c.e_win=2048;c.u=2200;c.w_act=128;c.theta_inact=1024;c
}

#[test] fn r18_network_values_and_caps64_minimum_boundary(){
    let net=devnet::build(&network_like(4,1000,2000)).unwrap();let cp=net.profile.cp().clone();
    let b=r18(&cp).unwrap();
    // Network-like CP: S=256, M=256, RRM=8192 (devnet), K=64, D=16, E=4, RET=128.
    assert_eq!(b.slot_min,5+5*8192+256+64*(2*256+2)+2+3*17+52);
    assert!(b.keys_max()<=2048&&b.accts_max()<=512,"{b:?}");
    // caps64 minimum: SYS_SLOT_MAX = slot_min passes, slot_min-1 fails R18.
    let mut m=cp.clone();m.SYS_SLOT_MAX=b.slot_min as u32;assert!(r18(&m).is_ok());
    m.SYS_SLOT_MAX=b.slot_min as u32-1;assert!(r18(&m).unwrap_err()[0].starts_with("SYS_SLOT_MAX"));
    let mut m=cp.clone();m.SYS_KEYS_BLOCK_MAX=b.keys_max() as u32-1;assert!(r18(&m).is_err());
    let mut m=cp.clone();m.SYS_ACCT_BLOCK_MAX=b.accts_max() as u32-1;assert!(r18(&m).is_err());
    println!("R18-DERIVED {}",serde_json::json!({"slotMin":b.slot_min,"keys":[b.keys_normal,b.keys_closing,b.keys_final],"accounts":[b.accts_normal,b.accts_closing,b.accts_final]}));
}

/// Worst-case stress: 256 identities (M_max), every height carries S_max shares
/// so 256 distinct owners per height, four evidence punishments in one block,
/// closing cursor over 256 records with RET=128, finalization at H_END.
#[test] fn measured_worst_case_stays_within_derived_bounds_and_caps(){
    let net=devnet::build(&network_like(256,60,80)).unwrap();let cp=net.profile.cp().clone();let b=derive(&cp);
    let ids:Vec<Address>=net.miners.iter().map(|m|m.id).collect();
    let mut state=net.genesis.state().clone();let mut prev:Option<ParentResult>=None;let mut base=U256::from(1_000_000_000u64);
    let (mut kn,mut kc,mut kf,mut an,mut ac,mut af,mut gas,mut call)=(0usize,0usize,0usize,0usize,0usize,0usize,0u64,0u64);let mut final_seen=false;
    for h in 1..=80u64{
        let evidence=if h==30{(0..4).map(|i|EvidenceEffect::Punish{accused:ids[200+i]}).collect()}else{vec![]};
        let input=BlockInput{height:h,timestamp:1_800_000_000+60*h,base_fee:base,gas_limit:8_000_000,prevrandao:B256::ZERO,
            proposer:if h%2==0{Proposer::Signed(ids[(h as usize*7)%256])}else{Proposer::Fallback},parent_result:prev.clone(),evidence,evidence_raw:&[],transactions:&[],ancestors:vec![]};
        let o=apply::apply_block(&state,&net.genesis,&net.profile,&input).unwrap_or_else(|e|panic!("h={h} {e:?}"));
        base=crate::fees::next_base_fee(base,o.gas_used,8_000_000).unwrap();
        let (k,a)=(o.meter.keys.len(),o.meter.accounts.len());
        if o.is_final{kf=kf.max(k);af=af.max(a);final_seen=true}else if o.facts.closing{kc=kc.max(k);ac=ac.max(a)}else{kn=kn.max(k);an=an.max(a)}
        gas=gas.max(o.system_gas);call=call.max(o.meter.max_call_gas);if h%10==0||o.facts.closing{println!("GAS h={h} sys={} maxcall={} calls={} keys={k} accts={a}",o.system_gas,o.meter.max_call_gas,o.meter.calls);}
        assert!(sys_slots(&o.state)<=b.slot_min,"slots {} > {}",sys_slots(&o.state),b.slot_min);
        state=o.state.clone();
        let w=ids[h as usize%256];let shares:Vec<(u64,Address)>=(0..256u64).map(|i|(i*3+1,ids[((h+i) as usize)%256])).collect();
        prev=Some(ParentResult{block_hash:B256::from(U256::from(h)),winner:w,shares});
        if o.is_final{break}
    }
    assert!(final_seen,"final block reached");
    assert!(kn as u64<=b.keys_normal&&kc as u64<=b.keys_closing&&kf as u64<=b.keys_final,"keys {kn}/{kc}/{kf} vs {b:?}");
    assert!(an as u64<=b.accts_normal&&ac as u64<=b.accts_closing&&af as u64<=b.accts_final,"accounts {an}/{ac}/{af} vs {b:?}");
    assert!(call<=apply::PER_CALL_GAS&&gas<=cp.G_SYS,"gas call={call} block={gas}");
    println!("R18-MEASURED {}",serde_json::json!({"keysMax":[kn,kc,kf],"accountsMax":[an,ac,af],"maxBlockSysGas":gas,"maxCallGas":call,"G_SYS":cp.G_SYS}));
}

#[test] fn r21_retention_formula(){assert_eq!(r21_retained_bytes(32,2,100,1000),34*(100*ACCOUNT_BYTES+1000*SLOT_BYTES));}
