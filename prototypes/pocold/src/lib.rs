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

use pocol_lp4_execution::{admission::{self,NodeLocal,Request,Timing},devnet,gate::FactClass,profile::{NodeKind,ProfileKind}};

/// The node-local parameters of a single-host devnet node, with pocold's actual
/// gossip frame limit (net::MAX_FRAME) for every message type.
pub fn single_host_local()->NodeLocal{NodeLocal{gossip:[net::MAX_FRAME as u32;6],..NodeLocal::single_host()}}

/// Loads a devnet's published files and runs the full ParamGate admission (A02): the
/// GenesisSpec, alloc, the recorded calibration and timing measurement (devnet.json)
/// and this node's local parameters. Boot is refused with every violated rule.
pub fn load_spec(dir:&std::path::Path,local:&NodeLocal)->Result<chain::Spec,String>{
    let hexs=std::fs::read_to_string(dir.join("genesis.spec.hex")).map_err(|e|format!("genesis.spec.hex: {e}"))?;
    let spec_bytes=types::unhex(hexs.trim())?;
    let alloc:serde_json::Value=serde_json::from_str(&std::fs::read_to_string(dir.join("alloc.json")).map_err(|e|format!("alloc.json: {e}"))?).map_err(|e|e.to_string())?;
    let alloc=devnet::alloc_from_json(&alloc)?;
    let info:serde_json::Value=std::fs::read_to_string(dir.join("devnet.json")).ok().and_then(|t|serde_json::from_str(&t).ok()).unwrap_or_default();
    let calibration=info["calibration"]["hashesPerSecond"].as_u64().map(|r|(r,FactClass::SyntheticFixture));
    let timing=Timing::from_json(&info["timing"]);
    let req=Request{spec_bytes:&spec_bytes,alloc:&alloc,forks:&[(1,0)],kind:ProfileKind::Simnet,node:NodeKind::Simnet,local,calibration,timing:timing.as_ref()};
    admission::admit(&req).map(chain::Spec::new).map_err(|e|e.to_string())
}
