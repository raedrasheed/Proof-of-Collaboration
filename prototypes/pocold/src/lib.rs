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
pub mod types;pub mod chain;pub mod store;pub mod miner;pub mod net;pub mod node;pub mod rpc;pub mod resources;

use pocol_lp4_execution::{admission::{self,NodeLocal,Request},devnet,gate::FactClass,profile::{NodeKind,ProfileKind}};

/// The node-local parameters of a single-host devnet node, with pocold's actual
/// gossip frame limit (net::MAX_FRAME) for every message type and its RPC limits.
pub fn single_host_local()->NodeLocal{NodeLocal{gossip:[net::MAX_FRAME as u32;6],rpc:rpc_facts(&rpc::Limits::default()),..NodeLocal::single_host()}}
/// R26 facts: the RpcGuard values pocold implements are taken from its code (connection cap,
/// request size, RESP_MAX, batch limits, log limits). The remaining RpcGuard fields (HEAVY/LIGHT
/// response memory, scratch, pacing, rate buckets) are not implemented by pocold and keep their
/// nominal values (open obligation, development/audit-2026-10-22/A13-DERIVATION.md).
pub fn rpc_facts(l:&rpc::Limits)->pocol_lp4_execution::param_gate::RpcLimits{
    pocol_lp4_execution::param_gate::RpcLimits{conn_max:l.conn_max as u64,req_buf:rpc::MAX_BODY as u64,resp_max:rpc::RESP_MAX as u64,batch_resp_max:rpc::BATCH_RESP_MAX as u64,
        batch_max:rpc::BATCH_MAX as u64,logs_count_max:rpc::LOGS_COUNT_MAX as u64,logs_scan_bytes:rpc::LOGS_SCAN_BYTES as u64,..Default::default()}
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
    let req=Request{spec_bytes:&spec_bytes,alloc:&alloc,forks:&[(1,0)],kind:ProfileKind::Simnet,node:NodeKind::Simnet,local,calibration,timing:measured.as_ref().ok()};
    admission::admit(&req).map(chain::Spec::new).map_err(|e|match &measured{Err(why)=>format!("{e}; timing: {why}"),Ok(_)=>e.to_string()})
}
