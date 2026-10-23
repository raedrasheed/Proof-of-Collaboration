//! Loopback JSON-RPC over HTTP/1.1 (one request per connection). The HTTP
//! threads only parse/forward; every method runs on the consensus thread over
//! an immutable head snapshot. RPC never affects validity (consensus §13).
use std::io::{Read,Write};
use std::net::{SocketAddr,TcpListener,TcpStream};
use std::sync::{Arc,atomic::{AtomicBool,AtomicUsize,Ordering},mpsc::{self,Sender,SyncSender}};
use std::time::{Duration,Instant};
use serde_json::{json,Value};
use revm::primitives::{Address,B256,Bytes,TxEnv,TxKind,U256,keccak256,ExecutionResult};
use pocol_lp4_execution::{native::{self,NativeBlockContext},wire,apply};
use crate::{node::{Event,Node},types::*,chain::{self,Entry}};

/// RpcGuard REQ_BUF (network.md:221/229): request line, headers and body together; headers alone
/// stop at HEAD_MAX.
pub const REQ_BUF:usize=1024*1024;pub const HEAD_MAX:usize=16384;
/// One socket read. The header buffer is allocated once at HEAD_MAX+READ_CHUNK; the body gets a
/// buffer of exactly Content-Length bytes and its reads stop there (A13 rpc term).
pub const READ_CHUNK:usize=8192;
/// JSON values in one request (members, parameters and keys together). Counted on the raw body
/// before parsing, so a request's parse tree stays within `parse_bytes_max` (A13; local limit,
/// D-A13-RPC). A larger request is -32600 without being parsed.
pub const JSON_VALUES_MAX:usize=4096;
/// RpcGuard RESP_MAX and LOGS_SCAN_BYTES (governance.md): a larger response is replaced
/// by -32008; eth_getLogs stops after scanning this many log data bytes, or once its result
/// would exceed RESP_MAX or LOGS_COUNT_MAX logs: -32020 {reason, fromBlock, lastCompleteBlock,
/// nextFromBlock} (network.md:298), so it never builds more.
pub const RESP_MAX:usize=8*1024*1024;pub const LOGS_SCAN_BYTES:usize=32*1024*1024;pub const LOGS_COUNT_MAX:usize=10000;
/// Batches (network.md): at most BATCH_MAX members; the member that makes the delivered bytes
/// exceed BATCH_RESP_MAX, and every later one, is answered -32020 {batchBytes} without running.
pub const BATCH_MAX:usize=20;pub const BATCH_RESP_MAX:usize=16*1024*1024;
/// ORIGIN_DENY (governance.md): local mining interfaces are never reachable from a site.
/// eth_call/eth_estimateGas gas cap. It must not exceed the largest per-execution gas of the
/// A13 execution model (`memory::execution_gas`), checked at compile time in resources.rs.
pub const CALL_GAS_MAX:u64=30_000_000;
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
/// Connection and work counters, for status and tests: connections refused at the cap,
/// connection threads alive, requests skipped because their work deadline had passed before
/// the consensus thread reached them, and batch members not run for the same reason.
/// Also: heavy requests refused because QUEUED_MAX bodies were already waiting, requests
/// refused by JSON_VALUES_MAX, and requests answered busy because the heavy pool was full.
#[derive(Debug,Default)]
/// Gauges: heavy bodies queued now (all servers of the process), Wake events sent for the light
/// lane, and light requests pushed into it.
pub struct RpcCounters{pub refused:AtomicUsize,pub active:AtomicUsize,pub expired:AtomicUsize,pub expired_members:AtomicUsize,pub queue_full:AtomicUsize,pub too_complex:AtomicUsize,pub busy:AtomicUsize,
    pub queued:AtomicUsize,pub wakes:AtomicUsize,pub light_pushed:AtomicUsize}
pub static COUNTERS:RpcCounters=RpcCounters{refused:AtomicUsize::new(0),active:AtomicUsize::new(0),expired:AtomicUsize::new(0),expired_members:AtomicUsize::new(0),
    queue_full:AtomicUsize::new(0),too_complex:AtomicUsize::new(0),busy:AtomicUsize::new(0),queued:AtomicUsize::new(0),wakes:AtomicUsize::new(0),light_pushed:AtomicUsize::new(0)};

/// Heavy request bodies waiting in the main queue, per server: the body of a request whose
/// connection already answered 504 stays there until the node dequeues it, so the connection
/// cap alone does not bound them (A13 rpc term). A further heavy request is 503.
pub fn queued_max(l:&Limits)->usize{2*l.conn_max.max(1)}
/// One queued heavy body; dropping it (when the node has handled or skipped the request)
/// frees its place.
pub struct Held(Arc<AtomicUsize>);
impl Drop for Held{fn drop(&mut self){self.0.fetch_sub(1,Ordering::SeqCst);COUNTERS.queued.fetch_sub(1,Ordering::SeqCst);}}
fn hold(c:&Arc<AtomicUsize>,max:usize)->Option<Held>{
    if c.fetch_add(1,Ordering::SeqCst)>=max{c.fetch_sub(1,Ordering::SeqCst);return None}
    COUNTERS.queued.fetch_add(1,Ordering::SeqCst);Some(Held(c.clone()))
}
/// A request for the consensus thread: body, reply, whether it carried an Origin header (a
/// site), the instant after which nobody waits for the answer, its lane, and its queue place
/// (heavy only; the light lane is bounded by its own capacity).
pub struct Request{pub body:Vec<u8>,pub reply:Sender<Reply>,pub site:bool,pub deadline:Instant,pub light:bool,pub held:Option<Held>}

/// Response memory (local; after RpcGuard LIGHT_RESP_MAX, HEAVY_RESP_MEM and LIGHT_RESP_MEM,
/// network.md (ج)). Before a request runs, the consensus thread reserves its class maximum:
/// LIGHT_RESP_MAX for a light request, RESP_MAX for a heavy one, BATCH_BYTES_HARD for a batch.
/// After it runs, the reservation shrinks to the response's allocation, and it is released when
/// the connection has written the response or failed (the Reply is dropped). So answers waiting
/// on slow readers hold at most the pools, whatever conn_max is (A13 rpc term).
/// - Light: (conn_max + 1) x LIGHT_RESP_MAX, one per connection plus the one being computed for a
///   connection that already left, so a light reservation never fails (network.md S1). A light
///   response larger than LIGHT_RESP_MAX is answered -32008.
/// - Heavy: HEAVY_RESP_POOL. A full pool answers -32021 {busy, retryAfterMs} before anything
///   runs (each batch member gets its own busy item), so a state-changing call never loses its
///   answer. pocold does not queue the request (no QUEUE_WAIT): it answers busy at once.
/// These pools are not the RpcGuard permit mechanism (no HEAVY_ACTIVE/LIGHT_ACTIVE permits, no
/// SendPacer, batches are not streamed), so the RpcGuard fields stay absent in admission.
pub const LIGHT_RESP_MAX:usize=512*1024;
pub const HEAVY_RESP_POOL:usize=48<<20;
pub const ERR_ITEM_MAX:usize=256;
/// The largest batch answer: BATCH_RESP_MAX of answers plus one error item per member.
pub const BATCH_BYTES_HARD:usize=BATCH_RESP_MAX+BATCH_MAX*ERR_ITEM_MAX+64;
/// Answers outside the pools: a busy answer (<= BATCH_MAX error items) and the HTTP literals.
pub const SMALL_REPLY_MAX:usize=BATCH_MAX*ERR_ITEM_MAX+64;
pub fn light_pool(l:&Limits)->usize{(l.conn_max+1)*LIGHT_RESP_MAX}
type Pool=(Arc<AtomicUsize>,usize);
#[derive(Clone)]
pub struct RespPools{heavy:Pool,light:Pool}
impl RespPools{
    pub fn new(l:&Limits)->Self{Self{heavy:(Arc::new(AtomicUsize::new(0)),HEAVY_RESP_POOL),light:(Arc::new(AtomicUsize::new(0)),light_pool(l))}}
    fn take(p:&Pool,n:usize)->Option<Resv>{
        let mut cur=p.0.load(Ordering::SeqCst);
        loop{if cur+n>p.1{return None}match p.0.compare_exchange(cur,cur+n,Ordering::SeqCst,Ordering::SeqCst){Ok(_)=>return Some(Resv{pool:p.0.clone(),n}),Err(c)=>cur=c}}
    }
    /// Reserved bytes (heavy, light), for status and tests.
    pub fn in_use(&self)->(usize,usize){(self.heavy.0.load(Ordering::SeqCst),self.light.0.load(Ordering::SeqCst))}
    /// Reserves `n` heavy bytes directly (tests hold the pool full with it).
    pub fn hold_heavy(&self,n:usize)->Option<Resv>{Self::take(&self.heavy,n)}
}
pub struct Resv{pool:Arc<AtomicUsize>,n:usize}
impl Resv{fn shrink(&mut self,to:usize){if to<self.n{self.pool.fetch_sub(self.n-to,Ordering::SeqCst);self.n=to;}}}
impl Drop for Resv{fn drop(&mut self){self.pool.fetch_sub(self.n,Ordering::SeqCst);}}
/// An answer and the reservation that covers it until the connection drops it.
pub struct Reply{pub body:String,_resv:Option<Resv>}
/// Runs one request under the response pools (see LIGHT_RESP_MAX).
pub fn answer(n:&mut Node,q:&Request)->Reply{
    let batch=q.body.iter().find(|b|!b.is_ascii_whitespace())==Some(&b'[');
    let pools=n.resp_pools();
    let (pool,need)=if q.light{(&pools.light,LIGHT_RESP_MAX)}else if batch{(&pools.heavy,BATCH_BYTES_HARD)}else{(&pools.heavy,RESP_MAX)};
    let Some(mut resv)=RespPools::take(pool,need) else{COUNTERS.busy.fetch_add(1,Ordering::SeqCst);return Reply{body:busy(&q.body),_resv:None}};
    let mut body=handle_until(n,&q.body,q.site,Some(q.deadline));
    if body.len()>need{body=err(&request_id(&q.body),-32008,"response too large").to_string();}
    body.shrink_to_fit();resv.shrink(body.capacity());
    Reply{body,_resv:Some(resv)}
}
fn request_id(body:&[u8])->Value{
    if json_values(body)>JSON_VALUES_MAX{return Value::Null}
    serde_json::from_slice::<Value>(body).ok().map(|v|id_of(&v)).map(|id|if id.to_string().len()<=128{id}else{Value::Null}).unwrap_or(Value::Null)
}
/// -32021 {busy, retryAfterMs}: one error object, or one item per batch member; nothing runs.
fn busy(body:&[u8])->String{
    let e=|i:&Value|{let id=id_of(i);let id=if id.to_string().len()<=128{id}else{Value::Null};
        json!({"jsonrpc":"2.0","id":id,"error":{"code":-32021,"message":"busy","data":{"reason":"busy","retryAfterMs":250}}}).to_string()};
    // Parsed only within JSON_VALUES_MAX, like any request (the parse-tree term).
    if json_values(body)>JSON_VALUES_MAX{return e(&Value::Null)}
    match serde_json::from_slice::<Value>(body){
        Ok(Value::Array(items)) if !items.is_empty()&&items.len()<=BATCH_MAX=>format!("[{}]",items.iter().map(e).collect::<Vec<_>>().join(",")),
        Ok(v)=>e(&v),Err(_)=>e(&Value::Null),
    }
}

/// The light lane: conn_max places and a wake flag, so the main queue holds at most one Wake
/// for it at a time, whatever the light request rate.
#[derive(Clone)]
pub struct LightLane{pub tx:SyncSender<Event>,pub wake:Arc<AtomicBool>}
impl LightLane{
    pub fn new(cap:usize)->(Self,mpsc::Receiver<Event>){let (tx,rx)=mpsc::sync_channel(cap.max(1));(Self{tx,wake:Arc::new(AtomicBool::new(false))},rx)}
    /// Asks the node to drain the lane unless a Wake is already pending. A full main queue
    /// needs none: the node drains the lane before every event it takes.
    pub fn wake(&self,node:&SyncSender<Event>){
        if !self.wake.swap(true,Ordering::SeqCst){
            if node.try_send(Event::Wake).is_ok(){COUNTERS.wakes.fetch_add(1,Ordering::SeqCst);}else{self.wake.store(false,Ordering::SeqCst);}
        }
    }
}

/// Methods the network.md classification table makes light unconditionally (worst encoded
/// response <= LIGHT_RESP_MAX). Conditional entries (pocol_getHeaders by count, eth_getBlockBy*
/// by the full flag), unlisted methods and batches are scheduled as heavy.
pub const LIGHT_METHODS:&[&str]=&["eth_chainId","net_version","web3_clientVersion","eth_blockNumber","eth_gasPrice","eth_maxPriorityFeePerGas","eth_getBalance",
    "eth_getStorageAt","eth_getTransactionCount","eth_sendRawTransaction","pocol_getTiming","pocol_getTarget","pocol_getCaps","pocol_syncStatus","pocol_getPot",
    "pocol_getSettlement","pocol_getBurnTotals","pocol_getEscrow","pocol_getRetention","pocol_getClosing","pocol_getRpcStats","pocol_submitShare","eth_getCode",
    "eth_getTransactionByHash","eth_getTransactionReceipt","pocol_getParams","pocol_getAssignment","pocol_getMinerSet","pocol_getTemplate"];
/// A light request is a single object of at most LIGHT_BODY_MAX bytes whose method is listed.
/// The probe borrows the method name and skips every other field, so classification allocates
/// nothing in proportion to the body (A13); any parse error (duplicate keys included) is heavy.
pub const LIGHT_BODY_MAX:usize=4096;
pub fn is_light(body:&[u8])->bool{
    #[derive(serde::Deserialize)] struct Probe<'a>{#[serde(borrow,default)] method:Option<std::borrow::Cow<'a,str>>}
    if body.len()>LIGHT_BODY_MAX||body.iter().find(|b|!b.is_ascii_whitespace())!=Some(&b'{'){return false}
    matches!(serde_json::from_slice::<Probe>(body),Ok(Probe{method:Some(m)}) if LIGHT_METHODS.contains(&m.as_ref()))
}
/// Connection threads are joined by the acceptor before their slot is reused, so at most
/// conn_max connection threads exist, exiting ones included (A13 thread inventory).
pub fn serve(addr:SocketAddr,node:SyncSender<Event>,light:LightLane,limits:Limits)->Result<(),String>{
    if !addr.ip().is_loopback(){return Err("RPC binds loopback only".into())}
    let l=TcpListener::bind(addr).map_err(|e|format!("rpc bind {addr}: {e}"))?;
    let queued=Arc::new(AtomicUsize::new(0));
    crate::threads::spawn("rpc",crate::threads::IO_STACK,move||{
        let mut next=0u64;let mut conns:Vec<std::thread::JoinHandle<()>>=Vec::new();
        for s in l.incoming(){
            let Ok(mut s)=s else{continue};next+=1;let id=next;
            crate::threads::reap(&mut conns);
            if conns.len()>=limits.conn_max{
                COUNTERS.refused.fetch_add(1,Ordering::SeqCst);
                let _=s.set_write_timeout(Some(Duration::from_millis(100)));let _=respond(&mut s,503,"{}");continue
            }
            let (n,lt,lim,q)=(node.clone(),light.clone(),limits.clone(),queued.clone());
            COUNTERS.active.fetch_add(1,Ordering::SeqCst);
            match crate::threads::spawn(format!("rpc-{id}"),crate::threads::IO_STACK,move||{let _=conn(s,n,lt,&lim,&q);COUNTERS.active.fetch_sub(1,Ordering::SeqCst);}){
                Ok(h)=>conns.push(h),Err(_)=>{COUNTERS.active.fetch_sub(1,Ordering::SeqCst);}
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
fn conn(mut s:TcpStream,node:SyncSender<Event>,light:LightLane,l:&Limits,queued:&Arc<AtomicUsize>)->std::io::Result<()>{
    let deadline=Instant::now()+l.read_deadline;s.set_write_timeout(Some(l.write_deadline))?;
    // Request memory (A13 rpc term): this header buffer, never reallocated (it stops past
    // HEAD_MAX, at most one read later), then a body buffer of exactly Content-Length bytes.
    let mut buf=Vec::with_capacity(HEAD_MAX+READ_CHUNK);let mut tmp=[0u8;READ_CHUNK];let head_end;
    loop{let n=read_until(&mut s,&mut tmp,deadline)?;if n==0{return Ok(())}buf.extend_from_slice(&tmp[..n]);
        if let Some(i)=buf.windows(4).position(|w|w==b"\r\n\r\n"){head_end=i+4;break}if buf.len()>HEAD_MAX{return respond(&mut s,431,"{}")}}
    let (method,len,site)={
        let head=String::from_utf8_lossy(&buf[..head_end]);
        let mut lines=head.split("\r\n");let first=lines.next().unwrap_or("");
        let mut len=0usize;let mut site=false;
        for l in lines{let mut kv=l.splitn(2,':');let k=kv.next().unwrap_or("").trim().to_ascii_lowercase();
            if k=="content-length"{len=kv.next().unwrap_or("").trim().parse().unwrap_or(usize::MAX)}if k=="origin"{site=true}}
        (if first.starts_with("OPTIONS"){0}else if first.starts_with("POST"){1}else{2},len,site)
    };
    if method==0{return respond(&mut s,204,"")}
    if method==2{return respond(&mut s,405,"{}")}
    if len>REQ_BUF.saturating_sub(head_end){
        // Closing with unread input makes the kernel reset the connection, which can discard the
        // 413 before the client reads it: shut down the write side and drain at most REQ_BUF more
        // bytes within the read deadline first.
        respond(&mut s,413,"{}")?;let _=s.shutdown(std::net::Shutdown::Write);
        let mut left=REQ_BUF;while left>0{match read_until(&mut s,&mut tmp,deadline){Ok(0)|Err(_)=>break,Ok(n)=>left=left.saturating_sub(n)}}
        return Ok(())
    }
    let mut body=Vec::with_capacity(len);body.extend_from_slice(&buf[head_end..buf.len().min(head_end+len)]);drop(buf);
    while body.len()<len{let want=(len-body.len()).min(READ_CHUNK);let n=read_until(&mut s,&mut tmp[..want],deadline)?;if n==0{break}body.extend_from_slice(&tmp[..n]);}
    // A10: with an Origin header ORIGIN_DENY applies to the request and to every batch member,
    // inside the consensus thread before any member executes.
    // The work deadline runs from here; the node skips the request, or stops a batch between
    // members, once it has passed (nobody waits for that answer any more).
    let work_by=Instant::now()+l.work_deadline;
    let (tx,rx)=mpsc::channel();
    if is_light(&body){
        // The lane holds one request per connection; a full lane (expired requests not yet
        // skipped) is 503.
        if light.tx.try_send(Event::Rpc(Request{body,reply:tx,site,deadline:work_by,light:true,held:None})).is_err(){return respond(&mut s,503,"{}")}
        COUNTERS.light_pushed.fetch_add(1,Ordering::SeqCst);
        light.wake(&node);
    }else{
        let Some(held)=hold(queued,queued_max(l)) else{COUNTERS.queue_full.fetch_add(1,Ordering::SeqCst);return respond(&mut s,503,"{}")};
        if node.send(Event::Rpc(Request{body,reply:tx,site,deadline:work_by,light:false,held:Some(held)})).is_err(){return respond(&mut s,503,"{}")}
    }
    // The reservation in the Reply is released when it drops, after the write or its failure.
    match rx.recv_timeout(work_by.saturating_duration_since(Instant::now())){Ok(r)=>respond(&mut s,200,&r.body),Err(_)=>respond(&mut s,504,"{}")}
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

pub fn handle(n:&mut Node,body:&[u8])->String{handle_until(n,body,false,None)}
/// One response, or -32008 with the request's id when it exceeds RESP_MAX.
fn capped(v:Value,id:&Value)->String{let s=v.to_string();if s.len()<=RESP_MAX{s}else{err(id,-32008,"response too large").to_string()}}
fn id_of(v:&Value)->Value{v.get("id").cloned().unwrap_or(Value::Null)}
/// `site`: the request carried an Origin header. ORIGIN_DENY is decided for the request
/// and for every batch member before any member executes; a denied member is answered
/// -32601 and never reaches its method; malformed members are -32600 (A10).
pub fn handle_with(n:&mut Node,body:&[u8],site:bool)->String{handle_until(n,body,site,None)}
/// As `handle_with`; batch members are not started after `deadline`: each is answered
/// -32020 {deadline} without running (network.md:235, 363).
pub fn handle_until(n:&mut Node,body:&[u8],site:bool,deadline:Option<Instant>)->String{
    if json_values(body)>JSON_VALUES_MAX{COUNTERS.too_complex.fetch_add(1,Ordering::SeqCst);return err(&Value::Null,-32600,"request has too many JSON values").to_string()}
    let v:Value=match serde_json::from_slice(body){Ok(v)=>v,Err(_)=>return err(&Value::Null,-32700,"parse error").to_string()};
    let denied=|i:&Value|site&&i.get("method").and_then(|m|m.as_str()).map_or(false,|m|ORIGIN_DENY.contains(&m));
    let site_err=|i:&Value|err(&i.get("id").cloned().unwrap_or(Value::Null),-32601,"method not available to sites");
    if let Value::Array(items)=&v{
        if items.is_empty()||items.len()>BATCH_MAX{return err(&Value::Null,-32600,"batch").to_string()}
        let deny:Vec<bool>=items.iter().map(|i|denied(i)).collect();
        // Light requests waiting in their lane run between members.
        return batch(items,BATCH_RESP_MAX,|k,i|{
            if k>0{n.drain_light()}
            if deny[k]{site_err(i).to_string()}
            else if deadline.is_some_and(|d|Instant::now()>=d){COUNTERS.expired_members.fetch_add(1,Ordering::SeqCst);item_err(i,-32020,"work deadline","deadline")}
            else{capped(one(n,i),&id_of(i))}
        });
    }
    if denied(&v){return site_err(&v).to_string()}
    let id=id_of(&v);capped(one(n,&v),&id)
}
/// An upper bound on the JSON values serde_json can build from `body`, counted without
/// allocating: every value is the top-level one, or a member of a container that is its first
/// member or follows a comma, so values <= 1 + containers + commas outside strings (an object
/// member's key counts again: x2). A prefix serde_json accepts before an error has no more.
pub fn json_values(body:&[u8])->usize{
    let (mut n,mut in_str,mut esc)=(0usize,false,false);
    for &b in body{
        if in_str{if esc{esc=false}else if b==b'\\'{esc=true}else if b==b'"'{in_str=false}continue}
        match b{b'"'=>in_str=true,b'{'|b'['|b','=>n+=1,_=>{}}
    }
    2*(n+1)
}
/// The parse tree of a request within JSON_VALUES_MAX (A13 rpc term), serde_json 1.0 with
/// BTreeMap objects: per value one 32-byte slot in a Vec grown by doubling (<= 2 slots) and at
/// most one B-tree node (<= 1 KiB: 11 keys and values plus edges); array buffers of at least 4
/// slots; strings and the escape scratch buffer <= 3 x the body; decoded parameters <= the body.
pub fn parse_bytes_max(body_max:usize)->u128{(JSON_VALUES_MAX as u128)*(64+1024+128)+4*(body_max as u128)}
/// Batch members run and are serialized one at a time, so a batch holds at most `limit` bytes
/// of answers plus the member being built (A13). The member that makes the delivered bytes
/// exceed `limit`, and every later one, is answered -32020 {batchBytes} without running.
fn batch(items:&[Value],limit:usize,mut run:impl FnMut(usize,&Value)->String)->String{
    // Every delivered byte counts (brackets and separators included). An error item echoes the
    // request id only while it stays within ERR_ITEM_MAX.
    let mut out=String::from("[");let mut over=false;
    for (k,i) in items.iter().enumerate(){
        let mut s=if over{String::new()}else{run(k,i)};
        if over||out.len()+1+s.len()+1>limit{
            over=true;s=item_err(i,-32020,"batch response limit","batchBytes");
        }
        if k>0{out.push(',');}out.push_str(&s);
    }
    out.push(']');out
}
/// An error item that echoes the request id only while it stays within ERR_ITEM_MAX (256 B).
fn item_err(i:&Value,code:i64,m:&str,reason:&str)->String{
    let id=id_of(i);let id=if id.to_string().len()<=128{id}else{Value::Null};
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":m,"data":{"reason":reason}}}).to_string()
}
fn one(n:&mut Node,v:&Value)->Value{
    if !v.is_object(){return err(&Value::Null,-32600,"invalid request")}
    let id=v["id"].clone();let p=v["params"].as_array().cloned().unwrap_or_default();
    let m=match v["method"].as_str(){Some(m)=>m,None=>return err(&id,-32600,"invalid request")};
    match call(n,m,&p){Ok(r)=>json!({"jsonrpc":"2.0","id":id,"result":r}),Err(f)=>fail_json(&id,f)}
}
/// An RPC error with optional data (network.md: −32020 carries {reason, fromBlock, …}).
struct Fail(i64,String,Option<Value>);
impl From<(i64,String)> for Fail{fn from((c,m):(i64,String))->Self{Fail(c,m,None)}}
type R=Result<Value,Fail>;
fn fail_json(id:&Value,f:Fail)->Value{match f.2{None=>err(id,f.0,&f.1),Some(d)=>json!({"jsonrpc":"2.0","id":id,"error":{"code":f.0,"message":f.1,"data":d}})}}
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
            match r{ExecutionResult::Success{output,..}=>Ok(json!(hex(output.data()))),ExecutionResult::Revert{output,..}=>Err(Fail::from((3,format!("execution reverted:{}",hex(&output))))),ExecutionResult::Halt{reason,..}=>Err(Fail::from((-32000,format!("halt {reason:?}"))))}}
        "eth_estimateGas"=>{
            let o=p.first().ok_or(bad("call"))?;let tag=Value::String("latest".into());
            let first=simulate(n,o,&tag,Some(cp.GAS_LIMIT))?;
            let used=match first{ExecutionResult::Success{gas_used,..}=>gas_used,ExecutionResult::Revert{output,..}=>return Err(Fail::from((3,format!("execution reverted:{}",hex(&output))))),ExecutionResult::Halt{reason,..}=>return Err(Fail::from((-32000,format!("halt {reason:?}"))))};
            let (mut lo,mut hi)=(used,cp.GAS_LIMIT);
            while lo+1000<hi{let mid=(lo+hi)/2;match simulate(n,o,&tag,Some(mid)){Ok(ExecutionResult::Success{..})=>hi=mid,_=>lo=mid}}
            Ok(json!(qty(hi)))
        }
        "eth_sendRawTransaction"=>{let raw=p.first().and_then(|x|x.as_str()).and_then(|s|unhex(s).ok()).ok_or(bad("raw"))?;
            n.submit_tx(raw,true).map(|h|json!(format!("{h}"))).map_err(|e|{let code=e.split(' ').next().and_then(|c|c.parse().ok()).unwrap_or(-32000);Fail(code,e,None)})}
        "eth_getBlockByNumber"=>{let e=block_by_tag(n,p.first().unwrap_or(&Value::Null));Ok(e.map(|e|block_json(n,e,p.get(1).and_then(|x|x.as_bool()).unwrap_or(false))).unwrap_or(Value::Null))}
        "eth_getBlockByHash"=>{let h=p.first().and_then(|x|x.as_str()).and_then(|s|unhex(s).ok()).ok_or(bad("hash"))?;
            Ok(h.try_into().ok().and_then(|h:[u8;32]|n.block_view(&h)).map(|e|block_json(n,&e,p.get(1).and_then(|x|x.as_bool()).unwrap_or(false))).unwrap_or(Value::Null))}
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
            if f["fromBlock"].as_str().map(|s|!s.starts_with("0x")).unwrap_or(true)||f["toBlock"].as_str().map(|s|!s.starts_with("0x")).unwrap_or(true){return Err(bad("numeric fromBlock/toBlock").into())}
            logs(n,f)}
        "pocol_status"=>Ok(n.status_json()),
        // pocold's own RPC counters and gauges (process-wide). Not the RpcGuard pocol_getRpcStats
        // record of network.md, which pocold does not implement (that method stays unavailable).
        "pocold_rpcCounters"=>{let c=&COUNTERS;let g=|a:&AtomicUsize|a.load(Ordering::SeqCst);let (h,l)=n.resp_pools().in_use();
            Ok(json!({"refused":g(&c.refused),"active":g(&c.active),"expired":g(&c.expired),"expiredMembers":g(&c.expired_members),"queueFull":g(&c.queue_full),
                "tooComplex":g(&c.too_complex),"busy":g(&c.busy),"queued":g(&c.queued),"wakes":g(&c.wakes),"lightPushed":g(&c.light_pushed),"heavyReserved":h,"lightReserved":l}))}
        "pocol_getRejects"=>Ok(json!(n.rejects.iter().map(|(h,w)|json!({"hash":h,"reason":w})).collect::<Vec<_>>())),
        "pocol_getHeaders"=>{let from=p.first().and_then(|x|x.as_u64().or_else(||parse_u64(x))).ok_or(bad("from"))?;let count=p.get(1).and_then(|x|x.as_u64().or_else(||parse_u64(x))).ok_or(bad("count"))?;
            if count==0||count>512{return Err(bad("count 1..512").into())}
            let mut out=vec![];for h in from..from+count{if let Some(e)=n.chain.canonical_at(h){if h>0{out.push(hex(&e.header.encoded));}}else{break}}Ok(json!(out))}
        "pocol_getBlockRlp"=>{let e=block_by_tag(n,p.first().unwrap_or(&Value::Null)).ok_or((-32001,"unknown block".to_string()))?;
            Ok(json!({"header":hex(&e.header.encoded),"body":hex(&e.body.encode())}))}
        "pocol_getMiners"=>{let s=&n.chain.head().state;Ok(json!(apply::record_list(s).iter().map(|id|{let r=apply::miner_record(s,*id).unwrap();
            json!({"id":format!("{id:#x}"),"status":r.status,"tomb":r.tomb,"bondState":r.bond_state,"lastShare":r.last_share,"reward":format!("{:#x}",r.reward),"rewardBalance":qty256(s.accounts.get(&r.reward).map(|a|a.info.balance).unwrap_or_default())})}).collect::<Vec<_>>()))}
        "pocol_getTemplate"=>Ok(n.template_json()),
        _=>Err(Fail::from((-32601,format!("method {m} not found")))),
    }
}
fn next_base(n:&Node)->U256{let h=n.chain.head();if h.height==0{chain::from_fixed_lp4(&n.chain.spec.cp().baseFee0)}else{pocol_lp4_execution::fees::next_base_fee(h.base_fee,h.gas_used,h.header.gas_limit).unwrap_or(h.base_fee)}}
fn simulate(n:&Node,o:&Value,tag:&Value,gas:Option<u64>)->Result<ExecutionResult,(i64,String)>{
    let cp=n.chain.spec.cp();let e=block_by_tag(n,tag).ok_or((-32001,"unknown block".to_string()))?;
    // As state_for: a pruned state (outside the trie window, or a block adopted after its state was
    // pruned as a side block) is -32017 (consensus.md §10), never a simulation on an empty state.
    if e.pruned{return Err((-32017,"state outside the retained trie window (K_hist)".into()))}
    let to=o["to"].as_str().and_then(|s|s.parse::<Address>().ok());
    let data=o.get("data").or_else(||o.get("input")).and_then(|x|x.as_str()).map(|s|unhex(s)).transpose().map_err(|_|bad("data"))?.unwrap_or_default();
    let tx=TxEnv{caller:o["from"].as_str().and_then(|s|s.parse().ok()).unwrap_or(Address::ZERO),transact_to:to.map(TxKind::Call).unwrap_or(TxKind::Create),
        gas_limit:gas.or_else(||parse_u64(&o["gas"])).unwrap_or(CALL_GAS_MAX).min(CALL_GAS_MAX),gas_price:U256::ZERO,value:parse_u256(&o["value"]).unwrap_or_default(),
        data:Bytes::from(data),nonce:None,chain_id:Some(n.chain.spec.chain_id()),..Default::default()};
    let ctx=NativeBlockContext{height:U256::from(e.height+1),timestamp:U256::from(e.ts+1),gas_limit:U256::from(cp.GAS_LIMIT.max(CALL_GAS_MAX)),base_fee:U256::ZERO,prevrandao:B256::ZERO};
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
    // The standard fields; `raw` only when the transaction does not decode (then there is no
    // `input`), so an answer stays within network.md's 2·TX_MAX + 2 KiB and LIGHT_RESP_MAX.
    let mut v=json!({"hash":format!("{}",e.tx_hashes[i]),"blockHash":hex(&e.hash),"blockNumber":qty(e.height),"transactionIndex":qty(i as u64)});
    if env.is_err(){v["raw"]=json!(hex(raw));}
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
    if to<from||to-from+1>1024{return Err(Fail::from((-32020,"range > 1024 blocks".into())))}
    let addrs:Vec<Address>=match &f["address"]{Value::String(s)=>s.parse().ok().into_iter().collect(),Value::Array(a)=>a.iter().filter_map(parse_addr).collect(),_=>vec![]};
    let topics:Vec<Option<Vec<B256>>>=f["topics"].as_array().map(|t|t.iter().map(|x|match x{Value::Null=>None,Value::String(s)=>s.parse().ok().map(|b|vec![b]),Value::Array(a)=>Some(a.iter().filter_map(|y|y.as_str()?.parse().ok()).collect()),_=>None}).collect()).unwrap_or_default();
    // network.md:298: the block x whose logs would pass a limit is not returned; the client resumes from x.
    let stop=|reason:&str,x:u64|Fail(-32020,format!("log query limit ({reason})"),Some(json!({"reason":reason,"fromBlock":qty(from),"lastCompleteBlock":if x>from{Value::from(qty(x-1))}else{Value::Null},"nextFromBlock":qty(x)})));
    let mut out=vec![];let mut scanned=0usize;let mut bytes=2usize;
    for h in from..=to{let Some(e)=n.chain.canonical_at(h) else{break};
        scanned+=e.receipts.iter().map(|r|r.len()).sum::<usize>();if scanned>LOGS_SCAN_BYTES{return Err(stop("scanBytes",h))}
        for i in 0..e.receipts.len(){let r=receipt_json(n,e,i);for l in r["logs"].as_array().cloned().unwrap_or_default(){
            let a:Address=l["address"].as_str().unwrap().parse().unwrap();if !addrs.is_empty()&&!addrs.contains(&a){continue}
            let lt:Vec<B256>=l["topics"].as_array().unwrap().iter().map(|x|x.as_str().unwrap().parse().unwrap()).collect();
            if topics.iter().enumerate().any(|(k,want)|match want{None=>false,Some(w)=>lt.get(k).map(|t|!w.contains(t)).unwrap_or(true)}){continue}
            bytes+=l.to_string().len()+1;if bytes>RESP_MAX-1024{return Err(stop("resultBytes",h))}
            out.push(l);if out.len()>LOGS_COUNT_MAX{return Err(stop("resultCount",h))}}}}
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
    /// Response pools: a reservation is refused once the pool would exceed its size; shrinking
    /// returns the difference; dropping returns the rest; light holds conn_max+1 class maxima.
    /// Second review: a busy answer to a body over JSON_VALUES_MAX is built without parsing it, so
    /// its heap stays far below the parse-tree term (the body itself is the caller's).
    #[test] fn a_busy_answer_does_not_parse_an_over_limit_body(){
        let body=format!("[{}0]","0,".repeat(400_000));assert!(super::json_values(body.as_bytes())>super::JSON_VALUES_MAX);
        let (a,peak)=crate::alloc_meter::peak(||super::busy(body.as_bytes()));
        assert!(a.contains("-32021")&&a.contains("\"id\":null"),"{a}");
        assert!(peak<64*1024,"the busy path requested {peak} B for an unparsed body");
    }
    #[test] fn response_pools_reserve_shrink_and_release(){
        let l=super::Limits{conn_max:3,..Default::default()};let p=super::RespPools::new(&l);
        let a=p.hold_heavy(super::HEAVY_RESP_POOL-10).unwrap();assert!(p.hold_heavy(11).is_none());let mut b=p.hold_heavy(10).unwrap();
        assert_eq!(p.in_use().0,super::HEAVY_RESP_POOL);b.shrink(4);assert_eq!(p.in_use().0,super::HEAVY_RESP_POOL-6);drop(a);assert_eq!(p.in_use().0,4);drop(b);assert_eq!(p.in_use().0,0);
        let lights:Vec<_>=(0..4).map(|_|super::RespPools::take(&p.light,super::LIGHT_RESP_MAX).expect("a light reservation never fails within conn_max+1")).collect();
        assert!(super::RespPools::take(&p.light,1).is_none());drop(lights);assert_eq!(p.in_use().1,0);
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
