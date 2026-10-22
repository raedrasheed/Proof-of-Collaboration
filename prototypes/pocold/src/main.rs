//! pocold — PoCol local development node (simnet devnets only).
use pocold::{node,types,load_spec,single_host_local};
use pocol_lp4_execution::admission::NodeLocal;
use std::path::PathBuf;
use pocol_lp4_execution::devnet;

fn arg(args:&[String],k:&str)->Option<String>{args.iter().position(|a|a==k).and_then(|i|args.get(i+1)).cloned()}
fn args_all(args:&[String],k:&str)->Vec<String>{args.windows(2).filter(|w|w[0]==k).map(|w|w[1].clone()).collect()}
fn num<T:std::str::FromStr>(args:&[String],k:&str,d:T)->T{arg(args,k).and_then(|v|v.parse().ok()).unwrap_or(d)}

fn main(){
    let args:Vec<String>=std::env::args().collect();
    let cmd=args.get(1).map(|s|s.as_str()).unwrap_or("help");
    let r=match cmd{
        "init-devnet"=>init(&args),
        "run"=>run(&args),
        "status"=>status(&args),
        _=>{eprintln!("usage:\n  pocold init-devnet --out DIR --miners a,b,c [--chain-id N] [--genesis-time S] [--t-blk S] [--tau S] [--d-att S] [--fb-wait S] [--c N] [--work-bits N] [--h-end N] [--h-close N] [--accounts x,y] [LOCAL]\n  pocold run --network DIR --data DIR --name N [--miner LABEL] [--listen ADDR] [--peer ADDR]... [--rpc ADDR] [--stop-at H] [--log] [LOCAL]\n  pocold status --network DIR --data DIR [LOCAL]\nLOCAL (ParamGate local timing, whole seconds; default single host): [--delta S] [--phi S] [--t-exec S] [--delta-rel S] [--gamma S]\nEvery profile is admitted by the full ParamGate (R1-R26) before boot; a rejection lists the violated rules (-32018).");Ok(())}
    };
    if let Err(e)=r{eprintln!("error: {e}");std::process::exit(1);}
}
/// Node-local ParamGate inputs: the single-host defaults with optional overrides.
fn local(args:&[String])->NodeLocal{
    let d=single_host_local();
    NodeLocal{delta:num(args,"--delta",d.delta),phi:num(args,"--phi",d.phi),t_exec:num(args,"--t-exec",d.t_exec),delta_rel:num(args,"--delta-rel",d.delta_rel),gamma:num(args,"--gamma",d.gamma),..d}
}
fn init(args:&[String])->Result<(),String>{
    let out=PathBuf::from(arg(args,"--out").ok_or("--out")?);
    let miners:Vec<String>=arg(args,"--miners").ok_or("--miners")?.split(',').map(|s|s.to_string()).collect();
    let refs:Vec<&str>=miners.iter().map(|s|s.as_str()).collect();
    let g_ts=num(args,"--genesis-time",node::now_s());
    let mut cfg=devnet::DevnetConfig::new(num(args,"--chain-id",777900u64),g_ts,&refs);
    cfg.t_blk=num(args,"--t-blk",cfg.t_blk);cfg.tau=num(args,"--tau",cfg.tau);cfg.d_att=num(args,"--d-att",cfg.d_att);cfg.d_fb_wait=num(args,"--fb-wait",cfg.d_fb_wait);cfg.c=num(args,"--c",cfg.c);
    cfg.h_end=num(args,"--h-end",cfg.h_end);cfg.h_close=num(args,"--h-close",cfg.h_close);cfg.d=num(args,"--d",cfg.d);cfg.w_w=num(args,"--w-w",cfg.w_w);
    // About 2^bits hashes per block: H_cal = 2^bits / T_blk (R25d calibration, synthetic for a devnet).
    let bits:u32=num(args,"--work-bits",18);cfg.hash_rate=(1u64<<bits.min(63))/u64::from(cfg.t_blk.max(1));
    if let Some(a)=arg(args,"--accounts"){cfg.accounts=a.split(',').map(|l|(l.to_string(),revm::primitives::U256::from(10u128.pow(24)))).collect();}
    let net=devnet::build(&cfg)?;
    // A02: measure this profile's timing, then run the full gate; nothing is written on rejection.
    let (admitted,timing)=net.admit(&local(args))?;
    std::fs::create_dir_all(&out).map_err(|e|e.to_string())?;
    std::fs::write(out.join("genesis.spec.hex"),types::hex(&net.spec_bytes)).map_err(|e|e.to_string())?;
    std::fs::write(out.join("alloc.json"),serde_json::to_string_pretty(&devnet::alloc_to_json(&net.alloc)).unwrap()).map_err(|e|e.to_string())?;
    let info=serde_json::json!({"chainId":cfg.chain_id,"genesisHash":types::hex(&net.genesis_hash.0),"genesisTime":g_ts,"forks":[[1,0]],"profileKind":"simnet",
        "note":"Local devnet only. Keys are deterministic disposable devnet keys derived from labels (pocol_lp4_execution::txsign::Key::devnet).",
        "miners":net.miners.iter().map(|m|serde_json::json!({"label":m.label,"id":format!("{:#x}",m.id),"reward":format!("{:#x}",m.reward)})).collect::<Vec<_>>(),
        "accounts":cfg.accounts.iter().map(|(l,w)|serde_json::json!({"label":l,"address":format!("{:#x}",devnet::account_key(l).address()),"wei":w.to_string()})).collect::<Vec<_>>(),
        "calibration":{"hashesPerSecond":cfg.hash_rate,"class":"synthetic-fixture","note":"devnet difficulty chosen with --work-bits, not a measured hash rate"},
        "timing":timing.to_json(),
        "admission":{"binding":types::hex(&admitted.report().binding),"notes":admitted.report().notes,"deferred":admitted.report().deferred}});
    std::fs::write(out.join("devnet.json"),serde_json::to_string_pretty(&info).unwrap()).map_err(|e|e.to_string())?;
    println!("{}",serde_json::to_string_pretty(&info).unwrap());Ok(())
}
fn run(args:&[String])->Result<(),String>{
    let net=PathBuf::from(arg(args,"--network").ok_or("--network")?);
    let spec=load_spec(&net,&local(args))?;
    let name=arg(args,"--name").unwrap_or_else(||"node".into());
    let miner=arg(args,"--miner").map(|l|devnet::miner_identity(&l).key);
    let parse=|s:&str|s.parse::<std::net::SocketAddr>().map_err(|e|format!("{s}: {e}"));
    let cfg=node::Config{dir:PathBuf::from(arg(args,"--data").ok_or("--data")?),name,miner,
        listen:arg(args,"--listen").map(|s|parse(&s)).transpose()?,peers:args_all(args,"--peer").iter().map(|s|parse(s)).collect::<Result<_,_>>()?,
        rpc:arg(args,"--rpc").map(|s|parse(&s)).transpose()?,
        stop_at:arg(args,"--stop-at").and_then(|s|s.parse().ok()),log:args.iter().any(|a|a=="--log")};
    let mut n=node::Node::open(cfg,spec)?;
    n.log(&format!("opened: head h={} records={}",n.chain.head().height,n.journal_records()));
    n.start_network()?;n.run();
    println!("{}",n.status_json());Ok(())
}
fn status(args:&[String])->Result<(),String>{
    let net=PathBuf::from(arg(args,"--network").ok_or("--network")?);let spec=load_spec(&net,&local(args))?;
    let cfg=node::Config{dir:PathBuf::from(arg(args,"--data").ok_or("--data")?),name:"status".into(),miner:None,listen:None,peers:vec![],rpc:None,stop_at:None,log:false};
    let n=node::Node::open(cfg,spec)?;println!("{}",n.status_json());Ok(())
}
