//! Loopback JSON-RPC over HTTP/1.1 (one request per connection). The HTTP
//! threads only parse/forward; every method runs on the consensus thread over
//! an immutable head snapshot. RPC never affects validity (consensus §13).
use std::io::{Read,Write};
use std::net::{SocketAddr,TcpListener,TcpStream};
use std::sync::{Arc,atomic::{AtomicUsize,Ordering},mpsc::{self,SyncSender}};
use std::time::{Duration,Instant};
use serde_json::{json,Value};
use revm::primitives::{Address,B256,Bytes,TxEnv,TxKind,U256,keccak256,ExecutionResult};
use pocol_lp4_execution::{native::{self,NativeBlockContext},wire,apply};
use crate::{node::{Event,Node},types::*,chain::{self,Entry}};

pub const MAX_BODY:usize=1024*1024;
/// RpcGuard RESP_MAX and LOGS_SCAN_BYTES (governance.md): a larger response is replaced
/// by -32008; eth_getLogs stops after scanning this many log data bytes, or once its result
/// would exceed RESP_MAX or LOGS_COUNT_MAX logs (-32005), so it never builds more.
pub const RESP_MAX:usize=8*1024*1024;pub const LOGS_SCAN_BYTES:usize=32*1024*1024;pub const LOGS_COUNT_MAX:usize=10000;
/// Batches (network.md): at most BATCH_MAX members; the member that makes the delivered bytes
/// exceed BATCH_RESP_MAX, and every later one, is answered -32020 {batchBytes} without running.
pub const BATCH_MAX:usize=20;pub const BATCH_RESP_MAX:usize=16*1024*1024;
/// ORIGIN_DENY (governance.md): local mining interfaces are never reachable from a site.
pub const ORIGIN_DENY:[&str;2]=["pocol_submitShare","pocol_getTemplate"];

/// A05 RPC bounds (local; distinct from the P2P limits). RPC_CONN_MAX and
/// REQ_READ_DEADLINE are governance.md RpcGuard values.
#[derive(Clone,Debug,PartialEq,Eq)]
pub struct Limits{
    /// Concurrent connections; an excess connection gets 503 and is closed without being read
    /// (network.md RPC_CONN_MAX).
    pub conn_max:usize,
    /// Whole request (headers and body), one response write, and the node's answer.
    pub read_deadline:Duration,pub write_deadline:Duration,pub work_deadline:Duration,
}
impl Default for Limits{
    fn default()->Self{Self{conn_max:32,read_deadline:Duration::from_secs(10),write_deadline:Duration::from_secs(10),work_deadline:Duration::from_secs(30)}}
}
/// Connection counters, for status and tests.
#[derive(Debug,Default)]
pub struct RpcCounters{pub refused:AtomicUsize}
pub static COUNTERS:RpcCounters=RpcCounters{refused:AtomicUsize::new(0)};

pub fn serve(addr:SocketAddr,node:SyncSender<Event>,limits:Limits)->Result<(),String>{
    if !addr.ip().is_loopback(){return Err("RPC binds loopback only".into())}
    let l=TcpListener::bind(addr).map_err(|e|format!("rpc bind {addr}: {e}"))?;
    let live=Arc::new(AtomicUsize::new(0));
    std::thread::Builder::new().name("rpc".into()).spawn(move||{
        let mut next=0u64;
        for s in l.incoming(){
            let Ok(mut s)=s else{continue};next+=1;let id=next;
            if live.fetch_add(1,Ordering::SeqCst)>=limits.conn_max{
                live.fetch_sub(1,Ordering::SeqCst);COUNTERS.refused.fetch_add(1,Ordering::SeqCst);
                let _=s.set_write_timeout(Some(Duration::from_millis(100)));let _=respond(&mut s,503,"{}");continue
            }
            let (n,lim,lv)=(node.clone(),limits.clone(),live.clone());
            if std::thread::Builder::new().name(format!("rpc-{id}")).spawn(move||{let _=conn(s,n,&lim);lv.fetch_sub(1,Ordering::SeqCst);}).is_err(){
                live.fetch_sub(1,Ordering::SeqCst);
            }
        }
    }).map_err(|e|e.to_string())?;
    Ok(())
}
/// Reads into `buf` before `deadline`; Ok(0) at EOF.
fn read_until(s:&mut TcpStream,tmp:&mut [u8],deadline:Instant)->std::io::Result<usize>{
    let left=deadline.saturating_duration_since(Instant::now());
    if left.is_zero(){return Err(std::io::Error::new(std::io::ErrorKind::TimedOut,"request deadline"))}
    s.set_read_timeout(Some(left.max(Duration::from_millis(1))))?;s.read(tmp)
}
fn conn(mut s:TcpStream,node:SyncSender<Event>,l:&Limits)->std::io::Result<()>{
    let deadline=Instant::now()+l.read_deadline;s.set_write_timeout(Some(l.write_deadline))?;
    let mut buf=Vec::new();let mut tmp=[0u8;8192];let head_end;
    loop{let n=read_until(&mut s,&mut tmp,deadline)?;if n==0{return Ok(())}buf.extend_from_slice(&tmp[..n]);
        if let Some(i)=buf.windows(4).position(|w|w==b"\r\n\r\n"){head_end=i+4;break}if buf.len()>16384{return respond(&mut s,431,"{}")}}
    let head=String::from_utf8_lossy(&buf[..head_end]).to_string();
    let mut lines=head.split("\r\n");let first=lines.next().unwrap_or("");
    let mut len=0usize;let mut origin=None;
    for l in lines{let mut kv=l.splitn(2,':');let k=kv.next().unwrap_or("").trim().to_ascii_lowercase();let v=kv.next().unwrap_or("").trim().to_string();
        if k=="content-length"{len=v.parse().unwrap_or(usize::MAX)}if k=="origin"{origin=Some(v)}}
    if first.starts_with("OPTIONS"){return respond(&mut s,204,"")}
    if !first.starts_with("POST"){return respond(&mut s,405,"{}")}
    if len>MAX_BODY{return respond(&mut s,413,"{}")}
    while buf.len()<head_end+len{let n=read_until(&mut s,&mut tmp,deadline)?;if n==0{break}buf.extend_from_slice(&tmp[..n]);}
    let body=buf[head_end..(head_end+len).min(buf.len())].to_vec();
    // A10: with an Origin header ORIGIN_DENY applies to the request and to every batch member,
    // inside the consensus thread before any member executes.
    let (tx,rx)=mpsc::channel();if node.send(Event::Rpc(body,tx,origin.is_some())).is_err(){return respond(&mut s,503,"{}")}
    match rx.recv_timeout(l.work_deadline){Ok(r)=>respond(&mut s,200,&r),Err(_)=>respond(&mut s,504,"{}")}
}
fn respond(s:&mut TcpStream,code:u16,body:&str)->std::io::Result<()>{
    let reason=match code{200=>"OK",204=>"No Content",405=>"Method Not Allowed",413=>"Payload Too Large",431=>"Request Header Fields Too Large",503=>"Service Unavailable",_=>"Error"};
    write!(s,"HTTP/1.1 {code} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Headers: content-type\r\nConnection: close\r\n\r\n{body}",body.len())?;s.flush()
}

fn qty(v:u64)->String{format!("0x{v:x}")}
fn qty256(v:U256)->String{format!("0x{v:x}")}
fn err(id:&Value,code:i64,m:&str)->Value{json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":m}})}
fn parse_u64(v:&Value)->Option<u64>{v.as_str().and_then(|s|u64::from_str_radix(s.trim_start_matches("0x"),16).ok())}
fn parse_addr(v:&Value)->Option<Address>{v.as_str()?.parse().ok()}
fn parse_u256(v:&Value)->Option<U256>{v.as_str().and_then(|s|U256::from_str_radix(s.trim_start_matches("0x"),16).ok())}

pub fn handle(n:&mut Node,body:&[u8])->String{handle_with(n,body,false)}
/// One response, or -32008 with the request's id when it exceeds RESP_MAX.
fn capped(v:Value,id:&Value)->String{let s=v.to_string();if s.len()<=RESP_MAX{s}else{err(id,-32008,"response too large").to_string()}}
fn id_of(v:&Value)->Value{v.get("id").cloned().unwrap_or(Value::Null)}
/// `site`: the request carried an Origin header. ORIGIN_DENY is decided for the request
/// and for every batch member before any member executes; a denied member is answered
/// -32601 and never reaches its method; malformed members are -32600 (A10).
pub fn handle_with(n:&mut Node,body:&[u8],site:bool)->String{
    let v:Value=match serde_json::from_slice(body){Ok(v)=>v,Err(_)=>return err(&Value::Null,-32700,"parse error").to_string()};
    let denied=|i:&Value|site&&i.get("method").and_then(|m|m.as_str()).map_or(false,|m|ORIGIN_DENY.contains(&m));
    let site_err=|i:&Value|err(&i.get("id").cloned().unwrap_or(Value::Null),-32601,"method not available to sites");
    if let Value::Array(items)=&v{
        if items.is_empty()||items.len()>BATCH_MAX{return err(&Value::Null,-32600,"batch").to_string()}
        let deny:Vec<bool>=items.iter().map(|i|denied(i)).collect();
        return batch(items,BATCH_RESP_MAX,|k,i|if deny[k]{site_err(i).to_string()}else{capped(one(n,i),&id_of(i))});
    }
    if denied(&v){return site_err(&v).to_string()}
    let id=id_of(&v);capped(one(n,&v),&id)
}
/// Batch members run and are serialized one at a time, so a batch holds at most `limit` bytes
/// of answers plus the member being built (A13). The member that makes the delivered bytes
/// exceed `limit`, and every later one, is answered -32020 {batchBytes} without running.
fn batch(items:&[Value],limit:usize,mut run:impl FnMut(usize,&Value)->String)->String{
    let mut out=String::from("[");let mut sent=0usize;let mut over=false;
    for (k,i) in items.iter().enumerate(){
        let mut s=if over{String::new()}else{run(k,i)};
        if over||sent+s.len()>limit{over=true;s=json!({"jsonrpc":"2.0","id":id_of(i),"error":{"code":-32020,"message":"batch response limit","data":{"reason":"batchBytes"}}}).to_string();}
        sent+=s.len();if k>0{out.push(',');}out.push_str(&s);
    }
    out.push(']');out
}
fn one(n:&mut Node,v:&Value)->Value{
    if !v.is_object(){return err(&Value::Null,-32600,"invalid request")}
    let id=v["id"].clone();let p=v["params"].as_array().cloned().unwrap_or_default();
    let m=match v["method"].as_str(){Some(m)=>m,None=>return err(&id,-32600,"invalid request")};
    match call(n,m,&p){Ok(r)=>json!({"jsonrpc":"2.0","id":id,"result":r}),Err((c,msg))=>err(&id,c,&msg)}
}
type R=Result<Value,(i64,String)>;
fn bad(m:&str)->(i64,String){(-32602,m.to_string())}

fn block_by_tag<'a>(n:&'a Node,tag:&Value)->Option<&'a Entry>{
    match tag.as_str(){
        None|Some("latest")|Some("pending")|Some("safe")|Some("finalized")=>{
            let h=n.chain.head();let k=match tag.as_str(){Some("safe")=>6,Some("finalized")=>60,_=>0};n.chain.canonical_at(h.height.saturating_sub(k))
        }
        Some("earliest")=>n.chain.canonical_at(0),
        Some(_)=>parse_u64(tag).and_then(|x|n.chain.canonical_at(x)),
    }
}
fn state_for<'a>(n:&'a Node,tag:&Value)->Result<&'a revm::InMemoryDB,(i64,String)>{
    if tag.as_str()==Some("pending"){return Ok(&n.pool_state())}
    let e=block_by_tag(n,tag).ok_or((-32001,"unknown block".to_string()))?;
    if e.pruned{return Err((-32017,"state outside the retained trie window (K_hist)".into()))}
    Ok(&e.state)
}
fn call(n:&mut Node,m:&str,p:&[Value])->R{
    let cp=n.chain.spec.cp();
    match m{
        "web3_clientVersion"=>Ok(json!("pocold/0.1.0 (PoCol local devnet)")),
        "net_version"=>Ok(json!(n.chain.spec.chain_id().to_string())),
        "net_listening"=>Ok(json!(true)),
        "net_peerCount"=>Ok(json!(qty(n.peer_count() as u64))),
        "eth_chainId"=>Ok(json!(qty(n.chain.spec.chain_id()))),
        "eth_syncing"=>Ok(json!(false)),
        "eth_mining"=>Ok(json!(n.cfg.miner.is_some())),
        "eth_accounts"=>Ok(json!([])),
        "eth_blockNumber"=>Ok(json!(qty(n.chain.head().height))),
        "eth_gasPrice"=>{let b=next_base(n);Ok(json!(qty256(b+U256::from(1_000_000_000u64))))}
        "eth_maxPriorityFeePerGas"=>Ok(json!(qty(1_000_000_000))),
        "eth_feeHistory"=>{
            let count=p.first().and_then(|x|x.as_u64().or_else(||parse_u64(x))).unwrap_or(1).clamp(1,128);let h=n.chain.head().height;
            let start=h.saturating_sub(count-1).max(1);let mut fees=vec![];let mut ratio=vec![];
            for x in start..=h{if let Some(e)=n.chain.canonical_at(x){fees.push(qty256(e.base_fee));ratio.push(json!(e.gas_used as f64/cp.GAS_LIMIT as f64));}}
            fees.push(qty256(next_base(n)));Ok(json!({"oldestBlock":qty(start),"baseFeePerGas":fees,"gasUsedRatio":ratio,"reward":[]}))
        }
        "eth_getBalance"=>{let a=p.first().and_then(parse_addr).ok_or(bad("address"))?;let s=state_for(n,p.get(1).unwrap_or(&Value::Null))?;
            Ok(json!(qty256(s.accounts.get(&a).map(|x|x.info.balance).unwrap_or_default())))}
        "eth_getTransactionCount"=>{let a=p.first().and_then(parse_addr).ok_or(bad("address"))?;let s=state_for(n,p.get(1).unwrap_or(&Value::Null))?;
            Ok(json!(qty(s.accounts.get(&a).map(|x|x.info.nonce).unwrap_or(0))))}
        "eth_getCode"=>{let a=p.first().and_then(parse_addr).ok_or(bad("address"))?;let s=state_for(n,p.get(1).unwrap_or(&Value::Null))?;
            Ok(json!(hex(&s.accounts.get(&a).and_then(|x|x.info.code.as_ref()).map(|c|c.original_bytes().to_vec()).unwrap_or_default())))}
        "eth_getStorageAt"=>{let a=p.first().and_then(parse_addr).ok_or(bad("address"))?;let k=p.get(1).and_then(parse_u256).ok_or(bad("slot"))?;
            let s=state_for(n,p.get(2).unwrap_or(&Value::Null))?;let v=s.accounts.get(&a).and_then(|x|x.storage.get(&k).copied()).unwrap_or_default();
            Ok(json!(hex(&v.to_be_bytes::<32>())))}
        "eth_call"=>{let o=p.first().ok_or(bad("call"))?;let r=simulate(n,o,p.get(1).unwrap_or(&Value::Null),None)?;
            match r{ExecutionResult::Success{output,..}=>Ok(json!(hex(output.data()))),ExecutionResult::Revert{output,..}=>Err((3,format!("execution reverted:{}",hex(&output)))),ExecutionResult::Halt{reason,..}=>Err((-32000,format!("halt {reason:?}")))}}
        "eth_estimateGas"=>{
            let o=p.first().ok_or(bad("call"))?;let tag=Value::String("latest".into());
            let first=simulate(n,o,&tag,Some(cp.GAS_LIMIT))?;
            let used=match first{ExecutionResult::Success{gas_used,..}=>gas_used,ExecutionResult::Revert{output,..}=>return Err((3,format!("execution reverted:{}",hex(&output)))),ExecutionResult::Halt{reason,..}=>return Err((-32000,format!("halt {reason:?}")))};
            let (mut lo,mut hi)=(used,cp.GAS_LIMIT);
            while lo+1000<hi{let mid=(lo+hi)/2;match simulate(n,o,&tag,Some(mid)){Ok(ExecutionResult::Success{..})=>hi=mid,_=>lo=mid}}
            Ok(json!(qty(hi)))
        }
        "eth_sendRawTransaction"=>{let raw=p.first().and_then(|x|x.as_str()).and_then(|s|unhex(s).ok()).ok_or(bad("raw"))?;
            n.submit_tx(raw,true).map(|h|json!(format!("{h}"))).map_err(|e|{let code=e.split(' ').next().and_then(|c|c.parse().ok()).unwrap_or(-32000);(code,e)})}
        "eth_getBlockByNumber"=>{let e=block_by_tag(n,p.first().unwrap_or(&Value::Null));Ok(e.map(|e|block_json(n,e,p.get(1).and_then(|x|x.as_bool()).unwrap_or(false))).unwrap_or(Value::Null))}
        "eth_getBlockByHash"=>{let h=p.first().and_then(|x|x.as_str()).and_then(|s|unhex(s).ok()).ok_or(bad("hash"))?;
            Ok(h.try_into().ok().and_then(|h:[u8;32]|n.chain.get(&h)).map(|e|block_json(n,e,p.get(1).and_then(|x|x.as_bool()).unwrap_or(false))).unwrap_or(Value::Null))}
        "eth_getTransactionByHash"=>{let h=p.first().and_then(|x|x.as_str()).and_then(|s|s.parse::<B256>().ok()).ok_or(bad("hash"))?;
            Ok(find_tx(n,&h).map(|(e,i)|tx_json(n,e,i)).unwrap_or(Value::Null))}
        "eth_getTransactionReceipt"=>{let h=p.first().and_then(|x|x.as_str()).and_then(|s|s.parse::<B256>().ok()).ok_or(bad("hash"))?;
            Ok(find_tx(n,&h).map(|(e,i)|receipt_json(n,e,i)).unwrap_or(Value::Null))}
        "eth_getLogs"=>logs(n,p.first().unwrap_or(&Value::Null)),
        // LogClient endpoint (browser.md BR10): numeric range of at most 1024 blocks, or one blockHash.
        "pocol_getLogs"=>{let f=p.first().unwrap_or(&Value::Null);
            if let Some(h)=f.get("blockHash"){let h=h.as_str().and_then(|s|unhex(s).ok()).ok_or(bad("blockHash"))?;
                let h:[u8;32]=h.try_into().map_err(|_|bad("blockHash"))?;
                let e=n.chain.get(&h).filter(|e|n.chain.canonical_at(e.height).map(|c|c.hash==e.hash).unwrap_or(false)).ok_or((-32001,"unknown or non-canonical block".to_string()))?;let mut g=f.clone();g["fromBlock"]=json!(qty(e.height));g["toBlock"]=json!(qty(e.height));
                if let Some(o)=g.as_object_mut(){o.remove("blockHash");}
                return logs(n,&g)}
            if f["fromBlock"].as_str().map(|s|!s.starts_with("0x")).unwrap_or(true)||f["toBlock"].as_str().map(|s|!s.starts_with("0x")).unwrap_or(true){return Err(bad("numeric fromBlock/toBlock"))}
            logs(n,f)}
        "pocol_status"=>Ok(n.status_json()),
        "pocol_getRejects"=>Ok(json!(n.rejects.iter().map(|(h,w)|json!({"hash":h,"reason":w})).collect::<Vec<_>>())),
        "pocol_getHeaders"=>{let from=p.first().and_then(|x|x.as_u64().or_else(||parse_u64(x))).ok_or(bad("from"))?;let count=p.get(1).and_then(|x|x.as_u64().or_else(||parse_u64(x))).ok_or(bad("count"))?;
            if count==0||count>512{return Err(bad("count 1..512"))}
            let mut out=vec![];for h in from..from+count{if let Some(e)=n.chain.canonical_at(h){if h>0{out.push(hex(&e.header.encoded));}}else{break}}Ok(json!(out))}
        "pocol_getBlockRlp"=>{let e=block_by_tag(n,p.first().unwrap_or(&Value::Null)).ok_or((-32001,"unknown block".to_string()))?;
            Ok(json!({"header":hex(&e.header.encoded),"body":hex(&e.body.encode())}))}
        "pocol_getMiners"=>{let s=&n.chain.head().state;Ok(json!(apply::record_list(s).iter().map(|id|{let r=apply::miner_record(s,*id).unwrap();
            json!({"id":format!("{id:#x}"),"status":r.status,"tomb":r.tomb,"bondState":r.bond_state,"lastShare":r.last_share,"reward":format!("{:#x}",r.reward),"rewardBalance":qty256(s.accounts.get(&r.reward).map(|a|a.info.balance).unwrap_or_default())})}).collect::<Vec<_>>()))}
        "pocol_getTemplate"=>Ok(n.template_json()),
        _=>Err((-32601,format!("method {m} not found"))),
    }
}
fn next_base(n:&Node)->U256{let h=n.chain.head();if h.height==0{chain::from_fixed_lp4(&n.chain.spec.cp().baseFee0)}else{pocol_lp4_execution::fees::next_base_fee(h.base_fee,h.gas_used,h.header.gas_limit).unwrap_or(h.base_fee)}}
fn simulate(n:&Node,o:&Value,tag:&Value,gas:Option<u64>)->Result<ExecutionResult,(i64,String)>{
    let cp=n.chain.spec.cp();let e=block_by_tag(n,tag).ok_or((-32001,"unknown block".to_string()))?;
    let to=o["to"].as_str().and_then(|s|s.parse::<Address>().ok());
    let data=o.get("data").or_else(||o.get("input")).and_then(|x|x.as_str()).map(|s|unhex(s)).transpose().map_err(|_|bad("data"))?.unwrap_or_default();
    let tx=TxEnv{caller:o["from"].as_str().and_then(|s|s.parse().ok()).unwrap_or(Address::ZERO),transact_to:to.map(TxKind::Call).unwrap_or(TxKind::Create),
        gas_limit:gas.or_else(||parse_u64(&o["gas"])).unwrap_or(30_000_000).min(30_000_000),gas_price:U256::ZERO,value:parse_u256(&o["value"]).unwrap_or_default(),
        data:Bytes::from(data),nonce:None,chain_id:Some(n.chain.spec.chain_id()),..Default::default()};
    let ctx=NativeBlockContext{height:U256::from(e.height+1),timestamp:U256::from(e.ts+1),gas_limit:U256::from(cp.GAS_LIMIT.max(30_000_000)),base_fee:U256::ZERO,prevrandao:B256::ZERO};
    let mut st=e.state.clone();
    // eth_call simulation: fund the caller for value transfers, never committed.
    if let Some(a)=st.accounts.get_mut(&tx.caller){a.info.balance=a.info.balance.max(tx.value);}
    native::execute_for_profile(&st,tx,&ctx,n.chain.spec.profile()).map(|r|r.result).map_err(|e|(-32000,format!("{e:?}")))
}
fn find_tx<'a>(n:&'a Node,h:&B256)->Option<(&'a Entry,usize)>{
    for x in n.chain.canonical.iter().rev(){let e=&n.chain.blocks[x];if let Some(i)=e.tx_hashes.iter().position(|t|t==h){return Some((e,i))}}None
}
fn block_json(n:&Node,e:&Entry,full:bool)->Value{
    let x=&e.header;let winner=e.result.as_ref().map(|r|format!("{:#x}",r.winner)).unwrap_or(format!("{:#x}",Address::ZERO));
    let txs:Vec<Value>=if full{(0..e.tx_hashes.len()).map(|i|tx_json(n,e,i)).collect()}else{e.tx_hashes.iter().map(|h|json!(format!("{h}"))).collect()};
    json!({"number":qty(e.height),"hash":hex(&e.hash),"parentHash":hex(&x.parent_hash),"nonce":hex(&x.nonce.to_be_bytes()),"sha3Uncles":"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
        "logsBloom":hex(&x.logs_bloom),"transactionsRoot":hex(&x.tx_root),"stateRoot":hex(&x.state_root),"receiptsRoot":hex(&x.receipts_root),"miner":winner,
        "difficulty":qty256(chain::work(&x.target)),"totalDifficulty":qty256(e.total_work),"extraData":"0x","size":qty(x.encoded.len() as u64),"gasLimit":qty(x.gas_limit),"gasUsed":qty(x.gas_used),
        "timestamp":qty(x.ts),"transactions":txs,"uncles":[],"baseFeePerGas":qty256(e.base_fee),"mixHash":hex(&[0u8;32]),
        "pocol":{"attempt":x.a,"signed":e.signed,"proposer":hex(&x.proposer),"shares":x.shares.len(),"templateId":hex(&template_id(&x.ut_raw)),"final":e.is_final}})
}
fn tx_json(n:&Node,e:&Entry,i:usize)->Value{
    let raw=&e.body.txs[i];let env=wire::decode_for_profile(raw,n.chain.spec.profile());
    let mut v=json!({"hash":format!("{}",e.tx_hashes[i]),"blockHash":hex(&e.hash),"blockNumber":qty(e.height),"transactionIndex":qty(i as u64),"raw":hex(raw)});
    if let Ok(env)=env{let t=env.tx_env();v["from"]=json!(format!("{:#x}",env.sender()));v["to"]=t.transact_to.to().map(|a|json!(format!("{a:#x}"))).unwrap_or(Value::Null);
        v["nonce"]=json!(qty(t.nonce.unwrap_or(0)));v["gas"]=json!(qty(t.gas_limit));v["value"]=json!(qty256(t.value));v["input"]=json!(hex(&t.data));v["type"]=json!(qty(env.kind() as u64));
        v["gasPrice"]=json!(qty256(t.gas_price));if let Some(pf)=t.gas_priority_fee{v["maxPriorityFeePerGas"]=json!(qty256(pf));v["maxFeePerGas"]=json!(qty256(t.gas_price));}v["chainId"]=json!(qty(n.chain.spec.chain_id()));}
    v
}
fn decode_receipt(r:&[u8])->Option<(bool,u64,Vec<(Address,Vec<B256>,Vec<u8>)>)>{
    let body=if r.first().map(|b|*b<0x7f).unwrap_or(false){&r[1..]}else{r};
    let it=crate::rlp::decode(body).ok()?;let f=it.list()?;
    let status=f[0].bytes()?==[1];let cum=f[1].bytes()?.iter().fold(0u64,|a,b|(a<<8)|*b as u64);
    let mut logs=vec![];for l in f[3].list()?{let lf=l.list()?;let a=Address::from_slice(lf[0].bytes()?);let topics=lf[1].list()?.iter().map(|t|B256::from_slice(t.bytes().unwrap())).collect();logs.push((a,topics,lf[2].bytes()?.to_vec()));}
    Some((status,cum,logs))
}
fn receipt_json(n:&Node,e:&Entry,i:usize)->Value{
    let Some((status,cum,logs))=decode_receipt(&e.receipts[i]) else{return Value::Null};
    let prev=if i==0{0}else{decode_receipt(&e.receipts[i-1]).map(|r|r.1).unwrap_or(0)};
    let env=wire::decode_for_profile(&e.body.txs[i],n.chain.spec.profile()).ok();
    let (from,to,contract,price)=match &env{Some(env)=>{let t=env.tx_env();let from=env.sender();
        let created=if t.transact_to.is_create(){let mut p=Vec::new();crate::rlp::encode_bytes(from.as_slice(),&mut p);let nb=t.nonce.unwrap_or(0).to_be_bytes();let f=nb.iter().position(|x|*x!=0).unwrap_or(8);crate::rlp::encode_bytes(&nb[f..],&mut p);let mut o=Vec::new();crate::rlp::encode_list_payload(&p,&mut o);
            Some(Address::from_slice(&keccak256(&o)[12..]))}else{None};
        let tip=t.gas_priority_fee.map(|pf|pf.min(t.gas_price-e.base_fee)).unwrap_or(t.gas_price-e.base_fee);
        (json!(format!("{from:#x}")),t.transact_to.to().map(|a|json!(format!("{a:#x}"))).unwrap_or(Value::Null),created.map(|a|json!(format!("{a:#x}"))).unwrap_or(Value::Null),e.base_fee+tip)}
        None=>(Value::Null,Value::Null,Value::Null,e.base_fee)};
    let base_index:usize=(0..i).map(|k|decode_receipt(&e.receipts[k]).map(|r|r.2.len()).unwrap_or(0)).sum();
    let logs:Vec<Value>=logs.iter().enumerate().map(|(k,(a,t,d))|json!({"address":format!("{a:#x}"),"topics":t.iter().map(|x|format!("{x}")).collect::<Vec<_>>(),"data":hex(d),
        "blockNumber":qty(e.height),"blockHash":hex(&e.hash),"transactionHash":format!("{}",e.tx_hashes[i]),"transactionIndex":qty(i as u64),"logIndex":qty((base_index+k) as u64),"removed":false})).collect();
    let bloom=pocol_lp4_execution::receipts::bloom(&[]);let _=bloom;
    json!({"transactionHash":format!("{}",e.tx_hashes[i]),"transactionIndex":qty(i as u64),"blockHash":hex(&e.hash),"blockNumber":qty(e.height),"from":from,"to":to,
        "cumulativeGasUsed":qty(cum),"gasUsed":qty(cum-prev),"contractAddress":contract,"logs":logs,"logsBloom":hex(&e.header.logs_bloom),"status":qty(status as u64),
        "effectiveGasPrice":qty256(price),"type":qty(env.map(|x|x.kind() as u64).unwrap_or(0))})
}
fn logs(n:&Node,f:&Value)->R{
    let head=n.chain.head().height;
    let from=match f["fromBlock"].as_str(){None|Some("latest")=>head,Some("earliest")=>0,Some(_)=>parse_u64(&f["fromBlock"]).ok_or(bad("fromBlock"))?};
    let to=match f["toBlock"].as_str(){None|Some("latest")=>head,Some(_)=>parse_u64(&f["toBlock"]).ok_or(bad("toBlock"))?};
    if to<from||to-from+1>1024{return Err((-32020,"range > 1024 blocks".into()))}
    let addrs:Vec<Address>=match &f["address"]{Value::String(s)=>s.parse().ok().into_iter().collect(),Value::Array(a)=>a.iter().filter_map(parse_addr).collect(),_=>vec![]};
    let topics:Vec<Option<Vec<B256>>>=f["topics"].as_array().map(|t|t.iter().map(|x|match x{Value::Null=>None,Value::String(s)=>s.parse().ok().map(|b|vec![b]),Value::Array(a)=>Some(a.iter().filter_map(|y|y.as_str()?.parse().ok()).collect()),_=>None}).collect()).unwrap_or_default();
    let mut out=vec![];let mut scanned=0usize;let mut bytes=2usize;
    for h in from..=to{let Some(e)=n.chain.canonical_at(h) else{break};
        scanned+=e.receipts.iter().map(|r|r.len()).sum::<usize>();if scanned>LOGS_SCAN_BYTES{return Err((-32005,"log scan limit".into()))}
        for i in 0..e.receipts.len(){let r=receipt_json(n,e,i);for l in r["logs"].as_array().cloned().unwrap_or_default(){
            let a:Address=l["address"].as_str().unwrap().parse().unwrap();if !addrs.is_empty()&&!addrs.contains(&a){continue}
            let lt:Vec<B256>=l["topics"].as_array().unwrap().iter().map(|x|x.as_str().unwrap().parse().unwrap()).collect();
            if topics.iter().enumerate().any(|(k,want)|match want{None=>false,Some(w)=>lt.get(k).map(|t|!w.contains(t)).unwrap_or(true)}){continue}
            bytes+=l.to_string().len()+1;if bytes>RESP_MAX-1024{return Err((-32005,"log response limit".into()))}
            out.push(l);if out.len()>LOGS_COUNT_MAX{return Err((-32005,"too many logs".into()))}}}}
    Ok(Value::Array(out))
}

#[cfg(test)]
mod tests{
    #[test] fn responses_above_resp_max_become_an_error(){
        let id=serde_json::json!(7);
        let small=super::capped(serde_json::json!({"jsonrpc":"2.0","id":7,"result":"0x1"}),&id);assert!(small.contains("\"result\""));
        let big=super::capped(serde_json::json!({"jsonrpc":"2.0","id":7,"result":"a".repeat(super::RESP_MAX)}),&id);
        assert!(big.contains("-32008")&&big.len()<200,"{}",&big[..big.len().min(200)]);
        // The error answers the request (A14 clients require the request id).
        let v:serde_json::Value=serde_json::from_str(&big).unwrap();assert_eq!(v["id"],7);
    }
    #[test] fn batch_members_beyond_the_byte_limit_are_not_run(){
        let items:Vec<serde_json::Value>=(0..5).map(|i|serde_json::json!({"jsonrpc":"2.0","id":i,"method":"m"})).collect();let mut ran=vec![];
        let out=super::batch(&items,1000,|k,_|{ran.push(k);serde_json::json!({"jsonrpc":"2.0","id":k,"result":"a".repeat(380)}).to_string()});
        let v:serde_json::Value=serde_json::from_str(&out).unwrap();let a=v.as_array().unwrap();
        assert_eq!(ran,vec![0,1,2],"members after the one that crossed the limit never run");
        assert!(a[0]["result"].is_string()&&a[1]["result"].is_string());
        for (k,x) in a.iter().enumerate().skip(2){assert_eq!(x["error"]["code"],-32020);assert_eq!(x["error"]["data"]["reason"],"batchBytes");assert_eq!(x["id"],k as u64);}
    }
}
