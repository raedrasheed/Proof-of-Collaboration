//! Loopback JSON-RPC over HTTP/1.1 (one request per connection). The HTTP
//! threads only parse/forward; every method runs on the consensus thread over
//! an immutable head snapshot. RPC never affects validity (consensus §13).
use std::io::{Read,Write};
use std::net::{SocketAddr,TcpListener,TcpStream};
use std::sync::{Arc,Mutex,atomic::{AtomicBool,AtomicUsize,Ordering},mpsc::{self,Sender,SyncSender}};
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

/// RpcGuard local service policy (network.md:182-330). These are hypotheses for testing, exposed
/// in pocol_getParams.rpcLimits; none is a validity rule (D87, consensus.md §13). Within pocold's
/// architecture (one consensus thread plus a light lane, HTTP/1.1 one request per connection that
/// closes after its response) some mechanisms are enforced exactly, some by an equivalent or
/// stronger bound, and some are not enforced; development/audit-2026-10-22/RPCGUARD.md has the
/// per-item status, test and mutant. Every field here is configurable so tests reach the bounds.
#[derive(Clone,Debug,PartialEq,Eq)]
pub struct Limits{
    /// RPC_CONN_MAX: concurrent connections; an excess connection gets 503 and is closed without
    /// being read (network.md:213).
    pub conn_max:usize,
    /// REQ_READ_DEADLINE (whole request: line, headers and body), one response write, and the
    /// node's answer (the nobody-waits work deadline: a request whose caller already left is not run).
    pub read_deadline:Duration,pub write_deadline:Duration,pub work_deadline:Duration,
    /// Heavy admission queue depth and the wait before a full-for-this-long queue answers busy
    /// (network.md:223, :230: HEAVY_QUEUE, QUEUE_WAIT). The light lane's capacity (LIGHT_QUEUE).
    pub heavy_queue:usize,pub light_queue:usize,pub queue_wait:Duration,
    /// Per-source token bucket (network.md:224): rate tokens per second, capacity bucket_cap. The
    /// spec's bucket is per connection; pocold closes after one request, so a faithful per-connection
    /// bucket is vacuous (≤ bucket_cap tokens per connection ⇒ never fires). The equivalent is a
    /// per-source-IP bucket; its DEFAULT is deliberately loose, because on loopback a 20/s bucket
    /// keyed by IP would throttle the node's own local tooling (the site publisher/fetcher burst far
    /// above 20/s in legitimate use). The exact spec values (20/s, cap 20) are enforced whenever
    /// configured and are demonstrated by `rpc_rate_bucket_limits_a_source` (RPCGUARD.md).
    pub rate:u32,pub bucket_cap:u32,
    /// SCRATCH budgets (network.md:228): the working bytes a heavy / light handler may allocate
    /// beyond its response, threaded through eth_getLogs/pocol_getLogs and eth_call.
    pub scratch_heavy:usize,pub scratch_light:usize,
    /// COMPUTE_DEADLINE (network.md:235): from acceptance, including encoding, 5 s heavy, 500 ms light.
    pub compute_heavy:Duration,pub compute_light:Duration,
    /// SendPacer (network.md:244-248): MIN_SEND_RATE B/s, GRACE, ENFORCE_SLACK, backstop re-check.
    pub min_send_rate:u64,pub grace:Duration,pub enforce_slack:Duration,pub pacer_backstop:Duration,
    /// BATCH_WALL (network.md:263): the backstop from read-end to sendDone.
    pub batch_wall:Duration,
    /// SO_SNDBUF and CONN_BUF (network.md:189, :229); SEND_SOCK_BUF enters no criterion (D93).
    pub send_sock_buf:usize,pub conn_buf:usize,
}
impl Default for Limits{
    fn default()->Self{Self{conn_max:32,read_deadline:Duration::from_secs(10),write_deadline:Duration::from_secs(10),work_deadline:Duration::from_secs(30),
        heavy_queue:16,light_queue:32,queue_wait:Duration::from_secs(2),rate:10_000,bucket_cap:10_000,
        scratch_heavy:16<<20,scratch_light:1<<20,compute_heavy:Duration::from_secs(5),compute_light:Duration::from_millis(500),
        min_send_rate:65536,grace:Duration::from_secs(2),enforce_slack:Duration::from_millis(200),pacer_backstop:Duration::from_millis(50),
        batch_wall:Duration::from_secs(420),send_sock_buf:32*1024,conn_buf:64*1024}}
}
/// SEND_MAX(size) = GRACE + size/R + ENFORCE_SLACK, the longest a response of `size` bytes may hold
/// its reservation before the SendPacer closes (network.md:252). ms, saturating.
pub fn send_max_ms(l:&Limits,size:u64)->u128{
    let r=l.min_send_rate.max(1) as u128;
    l.grace.as_millis()+(size as u128*1000)/r+l.enforce_slack.as_millis()
}
/// Connection and work counters, for status and tests: connections refused at the cap,
/// connection threads alive, requests skipped because their work deadline had passed before
/// the consensus thread reached them, and batch members not run for the same reason.
/// Also: heavy requests refused because QUEUED_MAX bodies were already waiting, requests
/// refused by JSON_VALUES_MAX, and requests answered busy because the heavy pool was full.
#[derive(Debug,Default)]
/// Gauges: heavy bodies queued now (all servers of the process), Wake events sent for the light
/// lane, and light requests pushed into it. RpcGuard (round 2): rate-limited requests, SendPacer
/// closes and the largest pacer lateness seen (ms), COMPUTE_DEADLINE hits, BATCH_WALL hits,
/// sendDone events, and the largest heavy/light SCRATCH high-water mark (bytes).
pub struct RpcCounters{pub refused:AtomicUsize,pub active:AtomicUsize,pub expired:AtomicUsize,pub expired_members:AtomicUsize,pub queue_full:AtomicUsize,pub too_complex:AtomicUsize,pub busy:AtomicUsize,
    pub queued:AtomicUsize,pub wakes:AtomicUsize,pub light_pushed:AtomicUsize,
    pub rate:AtomicUsize,pub pacer_closed:AtomicUsize,pub pacer_late_max_ms:AtomicUsize,pub deadline_hits:AtomicUsize,pub scratch_hits:AtomicUsize,
    pub batch_wall_hits:AtomicUsize,pub send_done:AtomicUsize,pub scratch_heavy_max:AtomicUsize,pub scratch_light_max:AtomicUsize}
pub static COUNTERS:RpcCounters=RpcCounters{refused:AtomicUsize::new(0),active:AtomicUsize::new(0),expired:AtomicUsize::new(0),expired_members:AtomicUsize::new(0),
    queue_full:AtomicUsize::new(0),too_complex:AtomicUsize::new(0),busy:AtomicUsize::new(0),queued:AtomicUsize::new(0),wakes:AtomicUsize::new(0),light_pushed:AtomicUsize::new(0),
    rate:AtomicUsize::new(0),pacer_closed:AtomicUsize::new(0),pacer_late_max_ms:AtomicUsize::new(0),deadline_hits:AtomicUsize::new(0),scratch_hits:AtomicUsize::new(0),
    batch_wall_hits:AtomicUsize::new(0),send_done:AtomicUsize::new(0),scratch_heavy_max:AtomicUsize::new(0),scratch_light_max:AtomicUsize::new(0)};
fn bump_max(a:&AtomicUsize,v:usize){let mut cur=a.load(Ordering::SeqCst);while v>cur{match a.compare_exchange(cur,v,Ordering::SeqCst,Ordering::SeqCst){Ok(_)=>break,Err(c)=>cur=c}}}

/// Heavy request bodies waiting in the admission queue, per server: the body of a request whose
/// connection already answered 504 stays there until the node dequeues it, so the connection cap
/// alone does not bound them (A13 rpc term). HEAVY_QUEUE places; a further heavy request waits up
/// to QUEUE_WAIT and then is -32021 {busy} (network.md:223, :230).
pub fn queued_max(l:&Limits)->usize{l.heavy_queue.max(1)}
/// One queued heavy body; dropping it (when the node has handled or skipped the request)
/// frees its place.
pub struct Held(Arc<AtomicUsize>);
impl Drop for Held{fn drop(&mut self){self.0.fetch_sub(1,Ordering::SeqCst);COUNTERS.queued.fetch_sub(1,Ordering::SeqCst);}}
fn hold(c:&Arc<AtomicUsize>,max:usize)->Option<Held>{
    if c.fetch_add(1,Ordering::SeqCst)>=max{c.fetch_sub(1,Ordering::SeqCst);return None}
    COUNTERS.queued.fetch_add(1,Ordering::SeqCst);Some(Held(c.clone()))
}
/// A request for the consensus thread: body, reply, whether it carried an Origin header (a
/// site), the instant after which nobody waits for the answer, when it was accepted (the
/// COMPUTE_DEADLINE runs from here), its lane, and its queue place (heavy only; the light lane
/// is bounded by its own capacity).
pub struct Request{pub body:Vec<u8>,pub reply:Sender<Reply>,pub site:bool,pub deadline:Instant,pub accepted:Instant,pub light:bool,pub held:Option<Held>}
/// COMPUTE_DEADLINE and SCRATCH, threaded through a heavy or light handler (network.md:228, :235).
/// A handler checks the deadline inside long loops (eth_getLogs every 16 blocks and every 1 MiB;
/// eth_call per loop body through the simulation stop hook) and charges its working allocations
/// against the scratch budget; either overflow is -32020 {deadline|scratch}. CANCEL_MAX is the gap
/// between checks, which releases resources within ≤ one block scan / one loop body.
pub struct Budget{pub compute_by:Instant,pub scratch_max:usize,pub scratch_used:usize,pub light:bool}
impl Budget{
    pub fn expired(&self)->bool{Instant::now()>=self.compute_by}
    /// Charges `n` scratch bytes; true if the budget still holds. Records the high-water mark.
    pub fn charge(&mut self,n:usize)->bool{
        self.scratch_used=self.scratch_used.saturating_add(n);
        bump_max(if self.light{&COUNTERS.scratch_light_max}else{&COUNTERS.scratch_heavy_max},self.scratch_used);
        self.scratch_used<=self.scratch_max
    }
}
/// A per-source-IP token bucket (network.md:224). pocold closes a connection after one response,
/// so a token bucket keyed by the connection object can never bound one client across its many
/// connections; keyed by the connection's remote IP it gives the per-client bound the spec intends
/// (≤ bucket_cap burst, then `rate`/s) and is testable: the 21st request within one second from one
/// client is -32021 {rate}. Millitokens, refilled continuously.
pub struct Buckets{map:Mutex<std::collections::HashMap<std::net::IpAddr,(u64,Instant)>>,rate:u32,cap:u32}
impl Buckets{
    pub fn new(rate:u32,cap:u32)->Self{Self{map:Mutex::new(std::collections::HashMap::new()),rate:rate.max(1),cap:cap.max(1)}}
    /// Takes `k` tokens for `ip`; on success None, else Some(retryAfterMs) without taking any.
    pub fn take(&self,ip:std::net::IpAddr,k:u32)->Option<u64>{
        let (rate,cap)=(self.rate as u64,self.cap as u64*1000);let need=k as u64*1000;
        let mut m=self.map.lock().unwrap_or_else(|e|e.into_inner());
        if m.len()>4096{m.clear();}// bound the map (loopback holds one or two entries)
        let now=Instant::now();let e=m.entry(ip).or_insert((cap,now));
        let refill=(now.saturating_duration_since(e.1).as_millis() as u64).saturating_mul(rate);
        e.0=(e.0+refill).min(cap);e.1=now;
        if e.0>=need{e.0-=need;None}else{Some(((need-e.0)*1000).div_ceil(rate*1000).max(1))}
    }
}
/// SendPacer (network.md:244-256). The server writes the response in chunks; A is the bytes the
/// socket has accepted, size the response length, sendTime the wall time since the first byte while
/// A < size (the server is always pending until sendDone, since P jumps to size at once). The one
/// binding rule: close if sendTime > GRACE and A < MIN_SEND_RATE·sendTime. Re-checked after every
/// partial write and at least every `pacer_backstop` (a write timeout), so the close lateness is
/// ≤ ENFORCE_SLACK. On A = size it is sendDone: the reservation (in `Reply`) drops at return. A full
/// response of `size` bytes cannot hold its reservation longer than SEND_MAX(size).
fn pace_write(s:&mut TcpStream,body:&[u8],l:&Limits)->std::io::Result<()>{
    let (r,grace)=(l.min_send_rate.max(1) as u128,l.grace.as_secs_f64());
    // The answer is written straight from its reservation-backed String; only the small header is
    // allocated here (no second copy of the body, so an in-flight answer stays one reservation).
    let hdr=format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Headers: content-type\r\nConnection: close\r\n\r\n",body.len());
    let parts:[&[u8];2]=[hdr.as_bytes(),body];let size=hdr.len()+body.len();
    let (t0,mut a,mut pi,mut off)=(Instant::now(),0usize,0usize,0usize);
    while a<size{
        // Re-check the rule at least every backstop: a bounded write timeout makes a stalled write
        // return WouldBlock/TimedOut so the loop can evaluate the rule and the backstop.
        s.set_write_timeout(Some(l.pacer_backstop.max(Duration::from_millis(1))))?;
        while pi<2&&off>=parts[pi].len(){pi+=1;off=0;}
        if pi<2{match s.write(&parts[pi][off..]){
            Ok(0)=>return Err(std::io::Error::new(std::io::ErrorKind::WriteZero,"peer closed")),
            Ok(n)=>{a+=n;off+=n;}
            Err(e) if e.kind()==std::io::ErrorKind::WouldBlock||e.kind()==std::io::ErrorKind::TimedOut=>{},
            Err(e)=>return Err(e),
        }}
        let st=t0.elapsed().as_secs_f64();
        if st>grace && (a as f64)<(r as f64)*st{
            // s_v = max(GRACE, A/R); the enforcement lateness is sendTime − s_v.
            let s_v=grace.max(a as f64/r as f64);let late_ms=((st-s_v)*1000.0).max(0.0) as usize;
            COUNTERS.pacer_closed.fetch_add(1,Ordering::SeqCst);bump_max(&COUNTERS.pacer_late_max_ms,late_ms);
            return Err(std::io::Error::new(std::io::ErrorKind::TimedOut,"send pacer: below MIN_SEND_RATE after GRACE"));
        }
    }
    COUNTERS.send_done.fetch_add(1,Ordering::SeqCst);s.flush()
}

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
/// Runs one request under the response pools (see LIGHT_RESP_MAX), the COMPUTE_DEADLINE and the
/// SCRATCH budget of its class. The deadline runs from acceptance (network.md:235, including
/// encoding), so a heavy request that is admitted, waits in the queue and then runs still has at
/// most COMPUTE_DEADLINE of total compute.
pub fn answer(n:&mut Node,q:&Request)->Reply{
    let batch=q.body.iter().find(|b|!b.is_ascii_whitespace())==Some(&b'[');
    let (pool,need)=if q.light{(&n.resp_pools().light,LIGHT_RESP_MAX)}else if batch{(&n.resp_pools().heavy,BATCH_BYTES_HARD)}else{(&n.resp_pools().heavy,RESP_MAX)};
    let (pool,need)=(pool.clone(),need);
    let Some(mut resv)=RespPools::take(&pool,need) else{COUNTERS.busy.fetch_add(1,Ordering::SeqCst);return Reply{body:busy(&q.body),_resv:None}};
    let lr=&n.cfg.limits.rpc;
    let mut budget=Budget{compute_by:q.accepted+if q.light{lr.compute_light}else{lr.compute_heavy},
        scratch_max:if q.light{lr.scratch_light}else{lr.scratch_heavy},scratch_used:0,light:q.light};
    let mut body=handle_until_budgeted(n,&q.body,q.site,Some(q.deadline),&mut budget);
    if body.len()>need{body=err(&request_id(&q.body),-32008,"response too large").to_string();}
    body.shrink_to_fit();resv.shrink(body.capacity());
    Reply{body,_resv:Some(resv)}
}
fn request_id(body:&[u8])->Value{
    if json_values(body)>JSON_VALUES_MAX{return Value::Null}
    serde_json::from_slice::<Value>(body).ok().map(|v|id_of(&v)).map(|id|if id.to_string().len()<=128{id}else{Value::Null}).unwrap_or(Value::Null)
}
/// -32021 {busy, retryAfterMs}: one error object, or one item per batch member; nothing runs.
fn busy(body:&[u8])->String{reply_32021(body,"busy",250)}
/// -32021 {reason, retryAfterMs}: one error object (singleton) or one item per batch member, each
/// echoing the member id; nothing runs. The reason is "busy" (a full pool or heavy queue, or a
/// QUEUE_WAIT timeout) or "rate" (the per-source token bucket).
fn reply_32021(body:&[u8],reason:&'static str,retry:u64)->String{
    let e=|i:&Value|{let id=id_of(i);let id=if id.to_string().len()<=128{id}else{Value::Null};
        json!({"jsonrpc":"2.0","id":id,"error":{"code":-32021,"message":reason,"data":{"reason":reason,"retryAfterMs":retry}}}).to_string()};
    // Parsed only within JSON_VALUES_MAX, like any request (the parse-tree term). A batch's k error
    // items are written from CONN_BUF (network.md:225).
    if json_values(body)>JSON_VALUES_MAX{return e(&Value::Null)}
    match serde_json::from_slice::<Value>(body){
        Ok(Value::Array(items)) if !items.is_empty()&&items.len()<=BATCH_MAX=>format!("[{}]",items.iter().map(e).collect::<Vec<_>>().join(",")),
        Ok(v)=>e(&v),Err(_)=>e(&Value::Null),
    }
}
/// The token cost of a request without parsing a tree: 1 for a singleton, else the number of
/// top-level array members (network.md:224, "k tokens at parse"), capped at BATCH_MAX+1 (a larger
/// batch is rejected later). A cheap depth/quote scan, allocation-free like `json_values`.
pub fn request_tokens(body:&[u8])->u32{
    let first=body.iter().find(|b|!b.is_ascii_whitespace());
    if first!=Some(&b'['){return 1}
    let (mut depth,mut members,mut in_str,mut esc,mut saw)=(0i32,0u32,false,false,false);
    for &c in body{
        if in_str{if esc{esc=false}else if c==b'\\'{esc=true}else if c==b'"'{in_str=false}continue}
        match c{
            b'"'=>{in_str=true;if depth==1{saw=true}}
            b'{'|b'['=>{depth+=1;if depth==2{saw=true}}
            b'}'|b']'=>depth-=1,
            b',' if depth==1=>members+=1,
            _ if depth==1&&!c.is_ascii_whitespace()=>saw=true,
            _=>{}
        }
        if members>=BATCH_MAX as u32{break}
    }
    (if saw{members+1}else{0}).clamp(1,BATCH_MAX as u32+1)
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
/// Shared across one server's connections: the heavy admission queue depth (an abandoned heavy
/// body stays here until the node dequeues it) and the per-source token bucket.
pub struct Server{pub queued:Arc<AtomicUsize>,pub buckets:Arc<Buckets>}
/// Connection threads are joined by the acceptor before their slot is reused, so at most
/// conn_max connection threads exist, exiting ones included (A13 thread inventory).
pub fn serve(addr:SocketAddr,node:SyncSender<Event>,light:LightLane,limits:Limits)->Result<(),String>{
    if !addr.ip().is_loopback(){return Err("RPC binds loopback only".into())}
    let l=TcpListener::bind(addr).map_err(|e|format!("rpc bind {addr}: {e}"))?;
    let srv=Arc::new(Server{queued:Arc::new(AtomicUsize::new(0)),buckets:Arc::new(Buckets::new(limits.rate,limits.bucket_cap))});
    crate::threads::spawn("rpc",crate::threads::IO_STACK,move||{
        let mut next=0u64;let mut conns:Vec<std::thread::JoinHandle<()>>=Vec::new();
        for s in l.incoming(){
            let Ok(mut s)=s else{continue};next+=1;let id=next;
            crate::threads::reap(&mut conns);
            if conns.len()>=limits.conn_max{
                COUNTERS.refused.fetch_add(1,Ordering::SeqCst);
                let _=s.set_write_timeout(Some(Duration::from_millis(100)));let _=respond(&mut s,503,"{}");continue
            }
            let (n,lt,lim,srv)=(node.clone(),light.clone(),limits.clone(),srv.clone());
            COUNTERS.active.fetch_add(1,Ordering::SeqCst);
            match crate::threads::spawn(format!("rpc-{id}"),crate::threads::IO_STACK,move||{let _=conn(s,n,lt,&lim,&srv);COUNTERS.active.fetch_sub(1,Ordering::SeqCst);}){
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
fn conn(mut s:TcpStream,node:SyncSender<Event>,light:LightLane,l:&Limits,srv:&Server)->std::io::Result<()>{
    // SO_SNDBUF: std::net exposes no portable setsockopt, and per D93 it enters no criterion (it only
    // shapes the accept/read gap for measurement); the binding SendPacer rule (`pace_write`) holds
    // regardless of the send buffer size. Left unset to keep the socket layer portable to Windows.
    let ip=s.peer_addr().map(|a|a.ip()).unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
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
    // Per-source token bucket (network.md:224): k tokens at parse (1 singleton, k batch). Insufficient
    // is -32021 {rate, retryAfterMs} without admission, snapshot or run (a batch writes k error items).
    if let Some(retry)=srv.buckets.take(ip,request_tokens(&body)){
        COUNTERS.rate.fetch_add(1,Ordering::SeqCst);return respond(&mut s,200,&reply_32021(&body,"rate",retry));
    }
    // A10: with an Origin header ORIGIN_DENY applies to the request and to every batch member,
    // inside the consensus thread before any member executes.
    // The work deadline runs from here; the node skips the request, or stops a batch between
    // members, once it has passed (nobody waits for that answer any more). `accepted` is the
    // instant the COMPUTE_DEADLINE runs from.
    let accepted=Instant::now();let work_by=accepted+l.work_deadline;
    let (tx,rx)=mpsc::channel();
    if is_light(&body){
        // LIGHT_QUEUE places; a full lane (requests that expired behind heavy work, not yet skipped)
        // is -32021 {busy} (network.md:223). On a full lane the body is recovered from the send error.
        if let Err(mpsc::TrySendError::Full(Event::Rpc(q))|mpsc::TrySendError::Disconnected(Event::Rpc(q)))=light.tx.try_send(Event::Rpc(Request{body,reply:tx,site,deadline:work_by,accepted,light:true,held:None})){
            COUNTERS.busy.fetch_add(1,Ordering::SeqCst);return respond(&mut s,200,&busy(&q.body));
        }
        COUNTERS.light_pushed.fetch_add(1,Ordering::SeqCst);
        light.wake(&node);
    }else{
        // HEAVY_QUEUE admission with QUEUE_WAIT (network.md:223,:230): reserve a queue place, waiting
        // up to QUEUE_WAIT for one; a queue full for that long is -32021 {busy, retryAfterMs}. The
        // single consensus thread makes active heavy work ≤ 1 ≤ HEAVY_ACTIVE.
        let Some(held)=reserve_heavy(&srv.queued,l.heavy_queue,l.queue_wait) else{COUNTERS.queue_full.fetch_add(1,Ordering::SeqCst);COUNTERS.busy.fetch_add(1,Ordering::SeqCst);return respond(&mut s,200,&busy(&body))};
        if node.send(Event::Rpc(Request{body,reply:tx,site,deadline:work_by,accepted,light:false,held:Some(held)})).is_err(){return respond(&mut s,503,"{}")}
    }
    // The reservation in the Reply is released when it drops, after the write or its failure. The
    // 200 answer is written under the SendPacer (`pace_write`), so a slow reader cannot hold its
    // reservation beyond SEND_MAX(size); `r` stays alive across the write, holding the reservation.
    match rx.recv_timeout(work_by.saturating_duration_since(Instant::now())){Ok(r)=>pace_write(&mut s,r.body.as_bytes(),l),Err(_)=>respond(&mut s,504,"{}")}
}
/// Reserves one HEAVY_QUEUE place, waiting up to QUEUE_WAIT for one if the queue is full
/// (network.md:230). The place is released when the node dequeues the request (`Held` drop).
fn reserve_heavy(c:&Arc<AtomicUsize>,max:usize,wait:Duration)->Option<Held>{
    let until=Instant::now()+wait;
    loop{
        if let Some(h)=hold(c,max){return Some(h)}
        if Instant::now()>=until{return None}
        std::thread::sleep(Duration::from_millis(5).min(wait));
    }
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

/// An unbounded budget: no COMPUTE_DEADLINE and effectively unlimited SCRATCH (for `handle`,
/// used where the caller is a test or an in-process consumer, not a network client).
fn unbounded()->Budget{Budget{compute_by:Instant::now()+Duration::from_secs(365*24*3600),scratch_max:usize::MAX,scratch_used:0,light:false}}
pub fn handle(n:&mut Node,body:&[u8])->String{handle_until_budgeted(n,body,false,None,&mut unbounded())}
/// One response, or -32008 with the request's id when it exceeds RESP_MAX.
fn capped(v:Value,id:&Value)->String{let s=v.to_string();if s.len()<=RESP_MAX{s}else{err(id,-32008,"response too large").to_string()}}
fn id_of(v:&Value)->Value{v.get("id").cloned().unwrap_or(Value::Null)}
/// `site`: the request carried an Origin header. ORIGIN_DENY is decided for the request
/// and for every batch member before any member executes; a denied member is answered
/// -32601 and never reaches its method; malformed members are -32600 (A10).
pub fn handle_with(n:&mut Node,body:&[u8],site:bool)->String{handle_until_budgeted(n,body,site,None,&mut unbounded())}
/// As `handle_with`, under a COMPUTE_DEADLINE and SCRATCH budget (`Budget`). Batch members are not
/// started after `deadline` (the nobody-waits work deadline: each is answered -32020 {deadline}
/// without running, network.md:235, :363); each member that does run gets its own COMPUTE_DEADLINE
/// (reset to COMPUTE_HEAVY from when it starts) and SCRATCH budget, and the whole batch is bounded
/// by BATCH_WALL from read-end to sendDone (network.md:263): once it passes, the remaining members
/// are closed with batchWallHits.
pub fn handle_until_budgeted(n:&mut Node,body:&[u8],site:bool,deadline:Option<Instant>,budget:&mut Budget)->String{
    if json_values(body)>JSON_VALUES_MAX{COUNTERS.too_complex.fetch_add(1,Ordering::SeqCst);return err(&Value::Null,-32600,"request has too many JSON values").to_string()}
    let v:Value=match serde_json::from_slice(body){Ok(v)=>v,Err(_)=>return err(&Value::Null,-32700,"parse error").to_string()};
    let denied=|i:&Value|site&&i.get("method").and_then(|m|m.as_str()).map_or(false,|m|ORIGIN_DENY.contains(&m));
    let site_err=|i:&Value|err(&i.get("id").cloned().unwrap_or(Value::Null),-32601,"method not available to sites");
    if let Value::Array(items)=&v{
        if items.is_empty()||items.len()>BATCH_MAX{return err(&Value::Null,-32600,"batch").to_string()}
        let deny:Vec<bool>=items.iter().map(|i|denied(i)).collect();
        let (lr_compute,lr_wall)=(n.cfg.limits.rpc.compute_heavy,n.cfg.limits.rpc.batch_wall);
        let wall_by=Instant::now()+lr_wall;
        // Light requests waiting in their lane run between members.
        return batch(items,BATCH_RESP_MAX,|k,i|{
            if k>0{n.drain_light()}
            if Instant::now()>=wall_by{COUNTERS.batch_wall_hits.fetch_add(1,Ordering::SeqCst);return item_err(i,-32020,"batch wall","batchWall")}
            if deny[k]{site_err(i).to_string()}
            else if deadline.is_some_and(|d|Instant::now()>=d){COUNTERS.expired_members.fetch_add(1,Ordering::SeqCst);item_err(i,-32020,"work deadline","deadline")}
            else{budget.compute_by=(Instant::now()+lr_compute).min(wall_by);budget.scratch_used=0;capped(one(n,i,budget),&id_of(i))}
        });
    }
    if denied(&v){return site_err(&v).to_string()}
    let id=id_of(&v);capped(one(n,&v,budget),&id)
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
fn one(n:&mut Node,v:&Value,b:&mut Budget)->Value{
    if !v.is_object(){return err(&Value::Null,-32600,"invalid request")}
    let id=v["id"].clone();let p=v["params"].as_array().cloned().unwrap_or_default();
    let m=match v["method"].as_str(){Some(m)=>m,None=>return err(&id,-32600,"invalid request")};
    // COMPUTE_DEADLINE checked at the handler entry too, so the light deadline is enforced for a
    // light method whose body work is O(1): a light request accepted past its 500 ms budget is
    // -32020 {deadline} (network.md:235). Heavy loops check it again inside (eth_getLogs, eth_call).
    if b.expired(){COUNTERS.deadline_hits.fetch_add(1,Ordering::SeqCst);return fail_json(&id,Fail(-32020,"compute deadline".into(),Some(json!({"reason":"deadline"}))));}
    match call(n,m,&p,b){Ok(r)=>json!({"jsonrpc":"2.0","id":id,"result":r}),Err(f)=>fail_json(&id,f)}
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
fn call(n:&mut Node,m:&str,p:&[Value],b:&mut Budget)->R{
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
        "eth_call"=>{let o=p.first().ok_or(bad("call"))?;let r=simulate(n,o,p.get(1).unwrap_or(&Value::Null),None,b)?;
            match r{ExecutionResult::Success{output,..}=>Ok(json!(hex(output.data()))),ExecutionResult::Revert{output,..}=>Err(Fail::from((3,format!("execution reverted:{}",hex(&output))))),ExecutionResult::Halt{reason,..}=>Err(Fail::from((-32000,format!("halt {reason:?}"))))}}
        "eth_estimateGas"=>{
            let o=p.first().ok_or(bad("call"))?;let tag=Value::String("latest".into());
            let first=simulate(n,o,&tag,Some(cp.GAS_LIMIT),b)?;
            let used=match first{ExecutionResult::Success{gas_used,..}=>gas_used,ExecutionResult::Revert{output,..}=>return Err(Fail::from((3,format!("execution reverted:{}",hex(&output))))),ExecutionResult::Halt{reason,..}=>return Err(Fail::from((-32000,format!("halt {reason:?}"))))};
            let (mut lo,mut hi)=(used,cp.GAS_LIMIT);
            while lo+1000<hi{let mid=(lo+hi)/2;match simulate(n,o,&tag,Some(mid),b){Ok(ExecutionResult::Success{..})=>hi=mid,Err(f) if f.0==-32020=>return Err(f),_=>lo=mid}}
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
        "eth_getLogs"=>logs(n,p.first().unwrap_or(&Value::Null),b),
        // LogClient endpoint (browser.md BR10): numeric range of at most 1024 blocks, or one blockHash.
        "pocol_getLogs"=>{let f=p.first().unwrap_or(&Value::Null);
            if let Some(h)=f.get("blockHash"){let h=h.as_str().and_then(|s|unhex(s).ok()).ok_or(bad("blockHash"))?;
                let h:[u8;32]=h.try_into().map_err(|_|bad("blockHash"))?;
                let e=n.chain.get(&h).filter(|e|n.chain.canonical_at(e.height).map(|c|c.hash==e.hash).unwrap_or(false)).ok_or((-32001,"unknown or non-canonical block".to_string()))?;let mut g=f.clone();g["fromBlock"]=json!(qty(e.height));g["toBlock"]=json!(qty(e.height));
                if let Some(o)=g.as_object_mut(){o.remove("blockHash");}
                return logs(n,&g,b)}
            if f["fromBlock"].as_str().map(|s|!s.starts_with("0x")).unwrap_or(true)||f["toBlock"].as_str().map(|s|!s.starts_with("0x")).unwrap_or(true){return Err(bad("numeric fromBlock/toBlock").into())}
            logs(n,f,b)}
        "pocol_status"=>Ok(n.status_json()),
        // pocold's own RPC counters and gauges (process-wide), a superset of pocol_getRpcStats.
        "pocold_rpcCounters"=>Ok(rpc_stats(n)),
        // network.md pocol_getRpcStats: the subset of the RpcGuard record pocold tracks. The fields
        // for mechanisms pocold does not enforce (per-permit active/queued gauges, snapshotsOpen,
        // anchorRejects, PacerTrace) are reported as the bounds pocold does guarantee or omitted;
        // RPCGUARD.md maps every field.
        "pocol_getRpcStats"=>Ok(rpc_stats(n)),
        "pocol_getParams"=>{let sp=&n.chain.spec;let l=&n.cfg.limits.rpc;
            Ok(json!({"profileKind":format!("{:?}",sp.profile().kind()),"nodeKind":format!("{:?}",sp.profile().node_kind()),"nonceMode":sp.cp().nonceMode,
                "chainId":sp.chain_id(),"genesisHash":hex(&sp.genesis_hash()),"genesisPre":hex(sp.spec_bytes()),
                "activeVersion":sp.active_version(n.chain.head().height),"rpcLimits":rpc_limits_json(l)}))}
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
/// pocol_getParams.rpcLimits: the running RpcGuard limits (network.md:184). Byte and ms integers.
fn rpc_limits_json(l:&Limits)->Value{
    json!({"connMax":l.conn_max,"reqBuf":REQ_BUF,"connBuf":l.conn_buf,"sendSockBuf":l.send_sock_buf,
        "heavyActive":1,"lightActive":1,"heavyQueue":l.heavy_queue,"lightQueue":l.light_queue,"queueWaitMs":l.queue_wait.as_millis() as u64,
        "heavyRespMem":HEAVY_RESP_POOL,"lightRespMem":light_pool(l),"respMax":RESP_MAX,"lightRespMax":LIGHT_RESP_MAX,"batchRespMax":BATCH_RESP_MAX,
        "scratchHeavy":l.scratch_heavy,"scratchLight":l.scratch_light,"batchMax":BATCH_MAX,"errItemMax":ERR_ITEM_MAX,
        "logsCountMax":LOGS_COUNT_MAX,"logsScanBytes":LOGS_SCAN_BYTES,"rate":l.rate,"bucketCap":l.bucket_cap,
        "computeHeavyMs":l.compute_heavy.as_millis() as u64,"computeLightMs":l.compute_light.as_millis() as u64,"reqReadDeadlineMs":l.read_deadline.as_millis() as u64,
        "minSendRate":l.min_send_rate,"graceMs":l.grace.as_millis() as u64,"enforceSlackMs":l.enforce_slack.as_millis() as u64,"batchWallMs":l.batch_wall.as_millis() as u64})
}
/// pocol_getRpcStats / pocold_rpcCounters: the RpcGuard stat record pocold tracks (network.md:333).
fn rpc_stats(n:&Node)->Value{
    let c=&COUNTERS;let g=|a:&AtomicUsize|a.load(Ordering::SeqCst);let (h,l)=n.resp_pools().in_use();
    json!({"conns":g(&c.active),"heavyResv":h,"lightResv":l,"maxResPerConn":1,"busyCount":g(&c.busy),"rateCount":g(&c.rate),
        "scratchHeavyMax":g(&c.scratch_heavy_max),"scratchLightMax":g(&c.scratch_light_max),"cancelled":g(&c.deadline_hits)+g(&c.scratch_hits),
        "pacerClosed":g(&c.pacer_closed),"pacerLateMaxMs":g(&c.pacer_late_max_ms),"sendDoneCount":g(&c.send_done),"batchWallHits":g(&c.batch_wall_hits),
        "refused":g(&c.refused),"active":g(&c.active),"expired":g(&c.expired),"expiredMembers":g(&c.expired_members),"queueFull":g(&c.queue_full),
        "tooComplex":g(&c.too_complex),"busy":g(&c.busy),"queued":g(&c.queued),"wakes":g(&c.wakes),"lightPushed":g(&c.light_pushed),"heavyReserved":h,"lightReserved":l,
        "deadlineHits":g(&c.deadline_hits),"scratchHits":g(&c.scratch_hits)})
}
fn simulate(n:&Node,o:&Value,tag:&Value,gas:Option<u64>,b:&Budget)->Result<ExecutionResult,Fail>{
    let cp=n.chain.spec.cp();let e=block_by_tag(n,tag).ok_or(Fail::from((-32001,"unknown block".to_string())))?;
    // As state_for: a pruned state (outside the trie window, or a block adopted after its state was
    // pruned as a side block) is -32017 (consensus.md §10), never a simulation on an empty state.
    if e.pruned{return Err(Fail::from((-32017,"state outside the retained trie window (K_hist)".into())))}
    let to=o["to"].as_str().and_then(|s|s.parse::<Address>().ok());
    let data=o.get("data").or_else(||o.get("input")).and_then(|x|x.as_str()).map(|s|unhex(s)).transpose().map_err(|_|Fail::from(bad("data")))?.unwrap_or_default();
    let tx=TxEnv{caller:o["from"].as_str().and_then(|s|s.parse().ok()).unwrap_or(Address::ZERO),transact_to:to.map(TxKind::Call).unwrap_or(TxKind::Create),
        gas_limit:gas.or_else(||parse_u64(&o["gas"])).unwrap_or(CALL_GAS_MAX).min(CALL_GAS_MAX),gas_price:U256::ZERO,value:parse_u256(&o["value"]).unwrap_or_default(),
        data:Bytes::from(data),nonce:None,chain_id:Some(n.chain.spec.chain_id()),..Default::default()};
    let ctx=NativeBlockContext{height:U256::from(e.height+1),timestamp:U256::from(e.ts+1),gas_limit:U256::from(cp.GAS_LIMIT.max(CALL_GAS_MAX)),base_fee:U256::ZERO,prevrandao:B256::ZERO};
    let mut st=e.state.clone();
    // eth_call simulation: fund the caller for value transfers, never committed.
    if let Some(a)=st.accounts.get_mut(&tx.caller){a.info.balance=a.info.balance.max(tx.value);}
    // COMPUTE_DEADLINE (network.md:235,(و)): the simulation's stop hook is polled per loop body and
    // per call/create frame; when the deadline passes the execution ends and eth_call is -32020
    // {deadline} (the gap between checks is CANCEL_MAX, well under one block scan).
    let by=b.compute_by;let stop:std::rc::Rc<dyn Fn()->bool>=std::rc::Rc::new(move||Instant::now()>=by);
    match native::simulate_for_profile(&st,tx,&ctx,n.chain.spec.profile(),stop){
        Ok(r)=>Ok(r.result),
        Err(revm::primitives::EVMError::Custom(m)) if m==native::SIMULATION_STOPPED=>{COUNTERS.deadline_hits.fetch_add(1,Ordering::SeqCst);Err(Fail(-32020,"compute deadline".into(),Some(json!({"reason":"deadline"}))))}
        Err(e)=>Err(Fail::from((-32000,format!("{e:?}")))),
    }
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
fn logs(n:&Node,f:&Value,b:&mut Budget)->R{
    let head=n.chain.head().height;
    let from=match f["fromBlock"].as_str(){None|Some("latest")=>head,Some("earliest")=>0,Some(_)=>parse_u64(&f["fromBlock"]).ok_or(bad("fromBlock"))?};
    let to=match f["toBlock"].as_str(){None|Some("latest")=>head,Some(_)=>parse_u64(&f["toBlock"]).ok_or(bad("toBlock"))?};
    if to<from||to-from+1>1024{return Err(Fail::from((-32020,"range > 1024 blocks".into())))}
    let addrs:Vec<Address>=match &f["address"]{Value::String(s)=>s.parse().ok().into_iter().collect(),Value::Array(a)=>a.iter().filter_map(parse_addr).collect(),_=>vec![]};
    let topics:Vec<Option<Vec<B256>>>=f["topics"].as_array().map(|t|t.iter().map(|x|match x{Value::Null=>None,Value::String(s)=>s.parse().ok().map(|b|vec![b]),Value::Array(a)=>Some(a.iter().filter_map(|y|y.as_str()?.parse().ok()).collect()),_=>None}).collect()).unwrap_or_default();
    // network.md:298: the block x whose logs would pass a limit is not returned; the client resumes from x.
    // -32020 for a per-block limit, a COMPUTE_DEADLINE or a SCRATCH overflow all carry the same resume
    // data {reason, fromBlock, lastCompleteBlock, nextFromBlock} (network.md (ز)).
    let stop=|reason:&str,x:u64|Fail(-32020,format!("log query limit ({reason})"),Some(json!({"reason":reason,"fromBlock":qty(from),"lastCompleteBlock":if x>from{Value::from(qty(x-1))}else{Value::Null},"nextFromBlock":qty(x)})));
    let mut out=vec![];let mut scanned=0usize;let mut bytes=2usize;
    for h in from..=to{let Some(e)=n.chain.canonical_at(h) else{break};
        // Cancellation checks (network.md (و)): the COMPUTE_DEADLINE every 16 blocks scanned (the
        // scratch budget is charged every matched log, so the 1 MiB / deadline check is tight).
        if (h-from)%16==0&&b.expired(){COUNTERS.deadline_hits.fetch_add(1,Ordering::SeqCst);return Err(stop("deadline",h))}
        scanned+=e.receipts.iter().map(|r|r.len()).sum::<usize>();if scanned>LOGS_SCAN_BYTES{return Err(stop("scanBytes",h))}
        for i in 0..e.receipts.len(){let r=receipt_json(n,e,i);for l in r["logs"].as_array().cloned().unwrap_or_default(){
            let a:Address=l["address"].as_str().unwrap().parse().unwrap();if !addrs.is_empty()&&!addrs.contains(&a){continue}
            let lt:Vec<B256>=l["topics"].as_array().unwrap().iter().map(|x|x.as_str().unwrap().parse().unwrap()).collect();
            if topics.iter().enumerate().any(|(k,want)|match want{None=>false,Some(w)=>lt.get(k).map(|t|!w.contains(t)).unwrap_or(true)}){continue}
            let sz=l.to_string().len()+1;
            // SCRATCH (network.md:228): the working bytes this heavy handler materializes; overflow is
            // -32020 {scratch} with the same resume data. A partial result is dropped entirely.
            if !b.charge(sz){COUNTERS.scratch_hits.fetch_add(1,Ordering::SeqCst);return Err(stop("scratch",h))}
            bytes+=sz;if bytes>RESP_MAX-1024{return Err(stop("resultBytes",h))}
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
