//! pocold — PoCol local development node library (simnet devnets only).
// Accepted LP1 consensus sources, shared byte-for-byte (not copied).
#[path="../../lp1-node/src/fixed.rs"] #[allow(dead_code)] pub mod fixed;
#[path="../../lp1-node/src/rlp.rs"] #[allow(dead_code)] pub mod rlp;
#[path="../../lp1-node/src/hex.rs"] #[allow(dead_code)] pub mod hex;
#[path="../../lp1-node/src/hashes.rs"] #[allow(dead_code)] pub mod hashes;
#[path="../../lp1-node/src/decimal.rs"] #[allow(dead_code)] pub mod decimal;
#[path="../../lp1-node/src/genesis.rs"] #[allow(dead_code)] pub mod genesis;
#[path="../../lp1-node/src/genesis_spec.rs"] #[allow(dead_code)] pub mod genesis_spec;
#[path="../../lp1-node/src/header.rs"] #[allow(dead_code)] pub mod header;
#[path="../../lp1-node/src/asert.rs"] #[allow(dead_code)] pub mod asert;
#[path="../../lp1-node/src/assignment.rs"] #[allow(dead_code)] pub mod assignment;
#[path="../../lp1-node/src/timing.rs"] #[allow(dead_code)] pub mod timing;
pub mod site;
pub mod secp_backend;
/// A13 obligation 3 (enforced): every pocold thread is created here with an explicit stack
/// reservation, and its resident stack cannot exceed that reservation (an overflow hits the
/// guard page and aborts). The thread inventory is in `resources::threads`.
pub mod threads{
    /// Network, RPC connection, forwarding, timer and miner threads.
    pub const IO_STACK:usize=256*1024;
    /// The consensus thread: admission, journal replay, block execution, RPC methods.
    pub const CONSENSUS_STACK:usize=16<<20;
    pub fn spawn<F,T>(name:impl Into<String>,stack:usize,f:F)->std::io::Result<std::thread::JoinHandle<T>>
    where F:FnOnce()->T+Send+'static,T:Send+'static{std::thread::Builder::new().name(name.into()).stack_size(stack).spawn(f)}
    /// Joins the finished threads among `hs` and drops their handles. A thread whose function
    /// has returned only has to exit, so the join is prompt; a caller that counts `hs` after
    /// this counts running and exiting threads together (A13 thread inventory).
    pub fn reap(hs:&mut Vec<std::thread::JoinHandle<()>>){
        let mut i=0;while i<hs.len(){if hs[i].is_finished(){let _=hs.swap_remove(i).join();}else{i+=1}}
    }
}
pub mod types;pub mod chain;pub mod store;pub mod miner;pub mod net;pub mod node;pub mod rpc;pub mod resources;

use pocol_lp4_execution::{admission::{self,NodeLocal,Request},devnet,gate::FactClass,profile::{NodeKind,ProfileKind}};

/// The node-local parameters of a single-host devnet node, with pocold's actual
/// gossip frame limit (net::MAX_FRAME) for every message type and its RPC limits.
pub fn single_host_local()->NodeLocal{NodeLocal{gossip:[net::MAX_FRAME as u32;6],rpc:rpc_facts(&rpc::Limits::default()),..NodeLocal::single_host()}}
/// R26 facts (D-A02-SCOPE): only the RpcGuard limits pocold enforces, taken from its code and
/// its running limits. The other RpcGuard mechanisms (HEAVY/LIGHT classes and their response
/// memory, scratch, queues, pacing, rate buckets, send watchdog, timers) are not implemented,
/// so their fields are absent, never nominal; admission reports them and can only be an
/// experimental-devnet admission.
pub const RPC_ENFORCED:[&str;7]=["conn_max","req_buf","resp_max","batch_resp_max","batch_max","logs_count_max","logs_scan_bytes"];
pub fn rpc_facts(l:&rpc::Limits)->admission::RpcFacts{
    let v=[l.conn_max,rpc::REQ_BUF,rpc::RESP_MAX,rpc::BATCH_RESP_MAX,rpc::BATCH_MAX,rpc::LOGS_COUNT_MAX,rpc::LOGS_SCAN_BYTES];
    let present:Vec<(&str,u64)>=RPC_ENFORCED.iter().zip(v).map(|(k,x)|(*k,x as u64)).collect();
    admission::RpcFacts::enforced(&present).expect("RPC_ENFORCED names RpcGuard fields")
}

/// The admission scope, waivers and conditions, for devnet.json and status (D-A02-SCOPE).
pub fn admission_json(a:&admission::Admitted)->serde_json::Value{
    let r=a.report();
    serde_json::json!({"scope":r.scope.name(),"specificationCompliant":a.specification_compliant(),"binding":types::hex(&r.binding),
        "waivers":r.waivers.iter().map(|w|serde_json::json!({"rule":w.rule,"absent":w.absent,"waived":w.waived,"checked":w.checked})).collect::<Vec<_>>(),
        "conditions":r.conditions.iter().map(|c|serde_json::json!({"id":c.id,"rules":c.rules,"detail":c.detail})).collect::<Vec<_>>(),
        "notes":r.notes,"deferred":r.deferred})
}

/// Loads a devnet's published files and runs the full ParamGate admission (A02): the
/// GenesisSpec, alloc, the declared calibration (devnet.json), a timing measurement taken now on
/// this machine and this node's local parameters. Boot is refused with every violated rule.
/// The timing recorded by init-devnet is informational only (review finding: a recorded value
/// could come from another machine or be edited).
pub fn load_spec(dir:&std::path::Path,local:&NodeLocal)->Result<chain::Spec,String>{
    let hexs=std::fs::read_to_string(dir.join("genesis.spec.hex")).map_err(|e|format!("genesis.spec.hex: {e}"))?;
    let spec_bytes=types::unhex(hexs.trim())?;
    let alloc:serde_json::Value=serde_json::from_str(&std::fs::read_to_string(dir.join("alloc.json")).map_err(|e|format!("alloc.json: {e}"))?).map_err(|e|e.to_string())?;
    let alloc=devnet::alloc_from_json(&alloc)?;
    let info:serde_json::Value=std::fs::read_to_string(dir.join("devnet.json")).ok().and_then(|t|serde_json::from_str(&t).ok()).unwrap_or_default();
    let calibration=info["calibration"]["hashesPerSecond"].as_u64().map(|r|(r,FactClass::SyntheticFixture));
    let measured=admission::measure(&spec_bytes,&alloc,1);
    let req=Request{spec_bytes:&spec_bytes,alloc:&alloc,forks:&[(1,0)],kind:ProfileKind::Simnet,node:NodeKind::Simnet,local,calibration,timing:measured.as_ref().ok(),scope:admission::Scope::ExperimentalDevnet};
    admission::admit(&req).map(chain::Spec::new).map_err(|e|match &measured{Err(why)=>format!("{e}; timing: {why}"),Ok(_)=>e.to_string()})
}
