//! A02 boot path: `init-devnet` and `load_spec` (used by `run` and `status`) run the full
//! ParamGate on the real files and refuse every violation with its rules (-32018). Timing
//! facts are measured on the booting machine.
use pocol_lp4_execution::devnet::{self,DevnetConfig};
use std::path::{Path,PathBuf};

fn tmp(tag:&str)->PathBuf{let d=std::env::temp_dir().join(format!("pocold-adm-{tag}-{}",std::process::id()));let _=std::fs::remove_dir_all(&d);d}
/// Writes a candidate's published files exactly as init-devnet does, with or without
/// its calibration and timing records.
fn publish(c:&DevnetConfig,dir:&Path,timing:bool){
    let n=devnet::build(c).unwrap();std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join("genesis.spec.hex"),pocold::types::hex(&n.spec_bytes)).unwrap();
    std::fs::write(dir.join("alloc.json"),devnet::alloc_to_json(&n.alloc).to_string()).unwrap();
    let mut info=serde_json::json!({"calibration":{"hashesPerSecond":n.hash_rate}});
    // As init-devnet: a profile whose blocks cannot be applied has no timing record.
    if timing{if let Ok(t)=pocol_lp4_execution::admission::measure(&n.spec_bytes,&n.alloc,1){info["timing"]=t.to_json();}}
    std::fs::write(dir.join("devnet.json"),info.to_string()).unwrap();
}
fn load(dir:&Path)->Result<(),String>{pocold::load_spec(dir,&pocold::single_host_local()).map(|_|())}
fn base()->DevnetConfig{DevnetConfig::new(777930,1_700_000_000,&["a","b","c"])}

#[test] fn load_refuses_the_audited_profiles_and_admits_the_valid_one(){
    let d=tmp("load");
    for (name,edit,rule) in [("s_max",(|c:&mut DevnetConfig|c.s_max=1) as fn(&mut DevnetConfig),"[R9]"),
        ("h_close",|c|c.h_close=c.h_end,"[R13]"),
        // Its genesis already exceeds SYS_SLOT_MAX, so no block applies and no timing exists.
        ("sys_slot_max",|c|c.sys_slot_max=1,"[R14, R18, R19]")]{
        let mut c=base();edit(&mut c);let dir=d.join(name);publish(&c,&dir,true);
        let e=load(&dir).expect_err(name);assert!(e.starts_with(&format!("-32018 ParamGate rejected {rule}")),"{name}: {e}");
    }
    let dir=d.join("ok");publish(&base(),&dir,true);load(&dir).unwrap();
    // R14/R19 use a measurement taken at load on this machine (review finding): a devnet.json
    // without a timing record still boots, and a forged record changes nothing.
    let dir=d.join("untimed");publish(&base(),&dir,false);load(&dir).unwrap();
    let dir=d.join("forged");publish(&base(),&dir,true);
    let mut info:serde_json::Value=serde_json::from_str(&std::fs::read_to_string(dir.join("devnet.json")).unwrap()).unwrap();
    info["timing"]["phaseMs"]=serde_json::json!([3_600_000,3_600_000,3_600_000]);std::fs::write(dir.join("devnet.json"),info.to_string()).unwrap();
    load(&dir).unwrap();
    let _=std::fs::remove_dir_all(&d);
}
#[test] fn init_devnet_refuses_gate_invalid_timing_and_writes_nothing(){
    let d=tmp("init");let out=d.join("net");
    let o=std::process::Command::new(env!("CARGO_BIN_EXE_pocold")).args(["init-devnet","--out",out.to_str().unwrap(),"--miners","a,b,c","--genesis-time","1700000000",
        "--t-blk","1","--d-att","4","--fb-wait","1","--work-bits","15"]).output().unwrap();
    // The old LP5-LP10 e2e flags: Δ_fb_wait=1 < Φ+Δ+2t_exec=3 (R3); 4+5 < 2(7+2·1) (R7).
    let err=String::from_utf8_lossy(&o.stderr);
    assert!(!o.status.success()&&err.contains("-32018 ParamGate rejected [R3, R7]"),"{err}");
    assert!(!out.exists(),"nothing is written for a rejected profile");
    let o=std::process::Command::new(env!("CARGO_BIN_EXE_pocold")).args(["init-devnet","--out",out.to_str().unwrap(),"--miners","a,b,c","--genesis-time","1700000000"]).output().unwrap();
    assert!(o.status.success(),"{}",String::from_utf8_lossy(&o.stderr));load(&out).unwrap();
    // A node whose local timing breaks the gate refuses to boot the same files.
    let e=pocold::load_spec(&out,&pocol_lp4_execution::admission::NodeLocal{delta_rel:4,..pocold::single_host_local()}).map(|_|()).unwrap_err();
    assert!(e.starts_with("-32018 ParamGate rejected [R2]"),"{e}");
    let _=std::fs::remove_dir_all(&d);
}
/// D-A02-SCOPE: pocold boots only an experimental-devnet admission. Its R26 facts name only the
/// RpcGuard limits it enforces; the unimplemented mechanisms are absent (0 in the gate), waived
/// and reported, never nominal. The same files under the specification scope are refused.
#[test] fn pocold_admission_is_an_experimental_devnet_with_absent_rpc_mechanisms(){
    use pocol_lp4_execution::admission::{self,Request,Scope};
    let d=tmp("scope");let dir=d.join("ok");publish(&base(),&dir,true);
    let spec=pocold::load_spec(&dir,&pocold::single_host_local()).unwrap();let a=spec.admission();
    assert_eq!(a.scope(),Scope::ExperimentalDevnet);assert!(!a.specification_compliant());
    let f=&a.local().rpc;assert_eq!(f.absent().len(),22);assert!(!f.is_fixture());
    for x in pocold::RPC_ENFORCED{assert!(!f.absent().contains(&x),"{x} is enforced")}
    assert_eq!((f.values().heavy_resp_mem,f.values().rate,f.values().min_send_rate),(0,0,0),"absent fields are not nominal");
    assert_eq!(f.values().req_buf,pocold::rpc::REQ_BUF as u64);
    let w=&a.report().waivers;assert_eq!(w.len(),1);assert_eq!(w[0].checked.len(),4);
    let j=pocold::admission_json(a);assert_eq!(j["scope"],"experimental-devnet");assert_eq!(j["specificationCompliant"],false);
    assert!(j["conditions"].as_array().unwrap().iter().any(|c|c["id"]=="rpc-absent"));
    // Specification scope on the same artifacts and local facts.
    let n=devnet::build(&base()).unwrap();let t=admission::measure(&n.spec_bytes,&n.alloc,1).unwrap();let local=pocold::single_host_local();
    let e=admission::admit(&Request{scope:Scope::Specification,..n.request(&local,Some(&t))}).err().expect("not specification compliance");
    assert!(e.missing.contains(&"specification:rpc-absent".to_string()),"{e}");
    let _=std::fs::remove_dir_all(&d);
}
