//! A05 resource bounds (P2P and RPC, separately) and A10 ORIGIN_DENY per batch member,
//! on a real node over loopback sockets. Limits are shrunk so every case stays small.
use std::io::{Read,Write};
use std::net::{TcpListener,TcpStream};
use std::sync::{Arc,atomic::{AtomicBool,Ordering}};
use std::time::{Duration,Instant};
use pocold::{chain::Spec,net::{self,Msg},node::{Config,Limits,Node}};
use pocol_lp4_execution::{devnet::{self,DevnetConfig},txsign::Tx};
use revm::primitives::U256;

/// Thread counts are process-wide: these tests run one at a time.
static SERIAL:std::sync::Mutex<()>=std::sync::Mutex::new(());
fn serial()->std::sync::MutexGuard<'static,()>{SERIAL.lock().unwrap_or_else(|e|e.into_inner())}
fn free_port()->u16{TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()}
/// One devnet per test binary: its genesis is now (with a genesis in the past every node's
/// production attempts are overdue, and each tick builds a fallback template, so the nodes the
/// earlier tests leave running would saturate the CPU), and its timing is measured once
/// (R14/R19 are measured on this host and fail closed under CPU contention).
fn spec()->Spec{
    static GENESIS:std::sync::OnceLock<u64>=std::sync::OnceLock::new();
    static TIMING:std::sync::OnceLock<pocol_lp4_execution::admission::Timing>=std::sync::OnceLock::new();
    let n=devnet::build(&DevnetConfig::new(777940,*GENESIS.get_or_init(pocold::node::now_s),&["a","b","c"])).unwrap();
    let t=TIMING.get_or_init(||pocol_lp4_execution::admission::measure(&n.spec_bytes,&n.alloc,1).unwrap());
    Spec::new(pocol_lp4_execution::admission::admit(&n.request(&pocold::single_host_local(),Some(t))).unwrap_or_else(|e|panic!("{e}")))
}
struct Running{p2p:u16,rpc:u16,net:net::Net,chain_id:u64,genesis:[u8;32]}
fn start(tag:&str,limits:Limits)->Running{start_with(tag,limits,vec![])}
fn start_with(tag:&str,limits:Limits,peers:Vec<std::net::SocketAddr>)->Running{
    let (p2p,rpc)=(free_port(),free_port());let spec=spec();let (chain_id,genesis)=(spec.chain_id(),spec.genesis_hash());
    let dir=std::env::temp_dir().join(format!("pocold-net-{tag}-{}",std::process::id()));let _=std::fs::remove_dir_all(&dir);
    let cfg=Config{dir,name:tag.into(),miner:None,listen:Some(format!("127.0.0.1:{p2p}").parse().unwrap()),peers,rpc:Some(format!("127.0.0.1:{rpc}").parse().unwrap()),stop_at:None,log:false,limits};
    let mut node=Node::open(cfg,spec).unwrap();let net=node.net.clone();
    node.start_network().unwrap();std::thread::spawn(move||node.run());
    std::thread::sleep(Duration::from_millis(100));
    Running{p2p,rpc,net,chain_id,genesis}
}
fn frame(m:&Msg)->Vec<u8>{let b=m.encode();let mut f=(b.len() as u32).to_be_bytes().to_vec();f.extend(b);f}
fn hello(r:&Running,name:&str)->Vec<u8>{frame(&Msg::Hello{chain_id:r.chain_id,genesis:r.genesis,head:r.genesis,height:0,node:name.into()})}
fn connect(r:&Running)->TcpStream{let s=TcpStream::connect(("127.0.0.1",r.p2p)).unwrap();s.set_read_timeout(Some(Duration::from_millis(3000))).unwrap();s}
/// True if the node closed the connection (EOF or reset) within the read timeout.
fn closed(s:&mut TcpStream)->bool{let mut b=[0u8;4096];loop{match s.read(&mut b){Ok(0)=>return true,Ok(_)=>continue,Err(e)=>return e.kind()!=std::io::ErrorKind::WouldBlock&&e.kind()!=std::io::ErrorKind::TimedOut}}}
fn live(r:&Running)->usize{r.net.counters.live.load(Ordering::SeqCst)}
/// Process threads (Linux /proc). Elsewhere thread counts are not measured: 0, and every
/// thread-count assertion holds vacuously; the notice lets a platform run report that.
fn threads()->usize{
    #[cfg(target_os="linux")]{std::fs::read_to_string("/proc/self/status").unwrap().lines().find(|l|l.starts_with("Threads:")).unwrap()[8..].trim().parse().unwrap()}
    #[cfg(not(target_os="linux"))]{eprintln!("THREADS-NOT-MEASURED");0}
}
fn wait_until(ms:u64,f:impl Fn()->bool)->bool{let t=Instant::now();while t.elapsed()<Duration::from_millis(ms){if f(){return true}std::thread::sleep(Duration::from_millis(20));}f()}
fn rpc(port:u16,body:&str,origin:bool)->(u16,String){
    let mut s=TcpStream::connect(("127.0.0.1",port)).unwrap();s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let o=if origin{"Origin: https://site.example\r\n"}else{""};
    // A refused connection is closed unread (RPC_CONN_MAX): the write or the read may then see a reset (code 0).
    let _=write!(s,"POST / HTTP/1.1\r\nHost: x\r\n{o}Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",body.len());
    let mut out=String::new();let _=s.read_to_string(&mut out);
    let code=out.get(9..12).and_then(|c|c.parse().ok()).unwrap_or(0);(code,out.split("\r\n\r\n").nth(1).unwrap_or("").to_string())
}
fn small()->Limits{
    let mut l=Limits::default();
    l.net=net::Limits{peers_max:6,handshaking_max:3,hello_deadline:Duration::from_millis(500),frame_deadline:Duration::from_millis(500),
        idle_deadline:Duration::from_secs(60),queue_bytes_max:512*1024,write_deadline:Duration::from_millis(500)};
    l
}

#[test] fn idle_peers_without_hello_are_bounded_and_expire(){let _g=serial();
    let r=start("idle",small());let base=threads();
    let mut idle:Vec<TcpStream>=(0..10).map(|_|connect(&r)).collect();
    assert!(wait_until(500,||r.net.counters.refused.load(Ordering::SeqCst)>=7),"only 3 handshake slots: refused={}",r.net.counters.refused.load(Ordering::SeqCst));
    assert!(live(&r)<=3,"live={}",live(&r));
    assert!(threads()<=base+3*2,"two threads per admitted connection only: {} vs {base}",threads());
    // The Hello deadline (500 ms) closes every admitted idle connection.
    assert!(wait_until(2000,||live(&r)==0),"live={}",live(&r));
    assert!(idle.iter_mut().all(closed),"every idle connection is closed");
    // A legitimate peer is served afterwards: its Hello is accepted and answered.
    let mut s=connect(&r);s.write_all(&hello(&r,"legit")).unwrap();
    let mut len=[0u8;4];s.read_exact(&mut len).unwrap();let mut b=vec![0u8;u32::from_be_bytes(len) as usize];s.read_exact(&mut b).unwrap();
    assert!(matches!(Msg::decode(&b).unwrap(),Msg::Hello{..}));assert!(wait_until(500,||live(&r)==1));
    std::thread::sleep(Duration::from_millis(700));assert_eq!(live(&r),1,"an established peer is not subject to the Hello deadline");
}
#[test] fn only_a_hello_is_accepted_before_the_handshake(){let _g=serial();
    let r=start("prehello",small());
    let mut s=connect(&r);s.write_all(&frame(&Msg::GetRange{start:1,count:512})).unwrap();
    assert!(closed(&mut s),"a non-Hello first frame closes the connection");assert!(wait_until(500,||live(&r)==0));
}
#[test] fn oversized_and_stalled_frames_close_the_peer(){let _g=serial();
    let r=start("frames",small());
    let mut s=connect(&r);s.write_all(&hello(&r,"big")).unwrap();s.write_all(&((net::MAX_FRAME+1) as u32).to_be_bytes()).unwrap();
    assert!(closed(&mut s),"a length above MAX_FRAME closes before any allocation");
    let mut s=connect(&r);s.write_all(&hello(&r,"slow")).unwrap();std::thread::sleep(Duration::from_millis(100));
    s.write_all(&1000u32.to_be_bytes()).unwrap();s.write_all(&[0u8;10]).unwrap();
    let t=Instant::now();assert!(closed(&mut s));assert!(t.elapsed()<Duration::from_millis(2500),"the frame deadline (500 ms) closes a stalled frame");
    assert!(wait_until(1000,||live(&r)==0));
}
#[test] fn a_peer_that_stops_reading_is_dropped_and_consensus_keeps_serving(){let _g=serial();
    let r=start("slow",small());
    // The slow peer completes the handshake and never reads again.
    let mut slow=connect(&r);slow.write_all(&hello(&r,"slow")).unwrap();assert!(wait_until(500,||live(&r)==1));
    // Large valid transactions are relayed to every peer (about 100 KiB each).
    let alice=devnet::account_key("alice");let t0=Instant::now();let mut worst=Duration::ZERO;
    for nonce in 0..120u64{
        let tx=Tx{chain_id:r.chain_id,nonce,max_priority:U256::from(1u64),max_fee:U256::from(10_000_000_000u64),gas:2_000_000,to:Some(alice.address()),value:U256::ZERO,data:vec![1u8;100_000].into()}.sign_1559(&alice);
        let body=format!(r#"{{"jsonrpc":"2.0","id":{nonce},"method":"eth_sendRawTransaction","params":["0x{}"]}}"#,pocold::types::hex(&tx).trim_start_matches("0x"));
        let t=Instant::now();let (code,_)=rpc(r.rpc,&body,false);worst=worst.max(t.elapsed());assert_eq!(code,200);
        if r.net.counters.dropped_slow.load(Ordering::SeqCst)>0{break}
    }
    assert!(r.net.counters.dropped_slow.load(Ordering::SeqCst)>=1,"the full outbound queue drops the slow peer");
    assert!(wait_until(1000,||live(&r)==0));
    assert!(worst<Duration::from_secs(2),"RPC stayed responsive while broadcasting: worst {worst:?} in {:?}",t0.elapsed());
    let (code,b)=rpc(r.rpc,r#"{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}"#,false);assert_eq!(code,200,"{b}");
    drop(slow);
}
#[test] fn reconnect_churn_keeps_threads_and_slots_bounded(){let _g=serial();
    let r=start("churn",small());let base=threads();
    for i in 0..200{let mut s=connect(&r);if i%2==0{let _=s.write_all(&hello(&r,"churn"));}drop(s);}
    assert!(wait_until(3000,||live(&r)==0),"live={}",live(&r));
    assert!(wait_until(3000,||threads()<=base+2),"threads {} vs {base}",threads());
    let mut s=connect(&r);s.write_all(&hello(&r,"after")).unwrap();assert!(wait_until(500,||live(&r)==1),"still accepts peers");
}
#[test] fn rpc_connection_cap_refuses_excess_unread_and_keeps_serving(){let _g=serial();
    // network.md RPC_CONN_MAX: an excess connection is closed without being read (503).
    let mut l=small();l.rpc.conn_max=4;l.rpc.read_deadline=Duration::from_millis(1500);
    let r=start("rpccap",l);let base=threads();let refused0=pocold::rpc::COUNTERS.refused.load(Ordering::SeqCst);
    let mut idle:Vec<TcpStream>=(0..12).map(|_|TcpStream::connect(("127.0.0.1",r.rpc)).unwrap()).collect();
    std::thread::sleep(Duration::from_millis(300));
    assert!(threads()<=base+4,"at most conn_max request threads: {} vs {base}",threads());
    assert!(pocold::rpc::COUNTERS.refused.load(Ordering::SeqCst)-refused0>=8,"the 8 excess connections are refused");
    // While the slots are held, a client is refused at once rather than queued.
    let t=Instant::now();let (code,_)=rpc(r.rpc,r#"{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}"#,false);
    assert!(code==503||code==0,"refused (503 or reset): {code}");assert!(t.elapsed()<Duration::from_secs(1),"refused promptly");
    // The whole-request deadline (1.5 s) closes the idle readers, even a client trickling bytes; then clients are served.
    for s in idle.iter_mut(){s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();assert!(closed(s));}
    let (code,b)=rpc(r.rpc,r#"{"jsonrpc":"2.0","id":2,"method":"eth_blockNumber","params":[]}"#,false);assert_eq!(code,200,"{b}");
    let mut trickle=TcpStream::connect(("127.0.0.1",r.rpc)).unwrap();
    for _ in 0..5{let _=trickle.write_all(b"P");std::thread::sleep(Duration::from_millis(400));}
    trickle.set_read_timeout(Some(Duration::from_secs(2))).unwrap();assert!(closed(&mut trickle),"trickling request closed");
    // Many concurrent clients each finish promptly: served (200) or refused (503 or reset), none hangs.
    let t=Instant::now();
    let hs:Vec<_>=(0..24).map(|i|{let p=r.rpc;std::thread::spawn(move||rpc(p,&format!(r#"{{"jsonrpc":"2.0","id":{i},"method":"eth_chainId","params":[]}}"#),false).0)}).collect();
    let codes:Vec<u16>=hs.into_iter().map(|h|h.join().unwrap()).collect();
    assert!(codes.iter().all(|c|[200,503,0].contains(c)),"{codes:?}");assert!(codes.iter().any(|c|*c==200));assert!(t.elapsed()<Duration::from_secs(4));
}
#[test] fn rpc_batches_answer_every_member_in_order_and_cap_their_length(){let _g=serial();
    // BATCH_RESP_MAX itself is checked by the rpc unit test (batch_members_beyond_the_byte_limit_are_not_run);
    // here the streamed batch keeps member order and ids end to end, and BATCH_MAX holds.
    let r=start("batch",small());
    let batch:Vec<String>=(0..20).map(|i|format!(r#"{{"jsonrpc":"2.0","id":{i},"method":"eth_chainId","params":[]}}"#)).collect();
    let (code,b)=rpc(r.rpc,&format!("[{}]",batch.join(",")),false);assert_eq!(code,200);
    let v:serde_json::Value=serde_json::from_str(&b).unwrap();let a=v.as_array().unwrap();
    assert_eq!(a.len(),20);for (i,x) in a.iter().enumerate(){assert_eq!(x["id"],i as u64);assert!(x["result"].is_string());}
    let (_,b)=rpc(r.rpc,&format!("[{}]",(0..21).map(|_|batch[0].clone()).collect::<Vec<_>>().join(",")),false);assert!(b.contains("-32600"),"{b}");
}
#[test] fn a10_origin_deny_applies_to_every_batch_member(){let _g=serial();
    let r=start("origin",small());
    let batch=r#"[{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]},{"jsonrpc":"2.0","id":2,"method":"pocol_getTemplate","params":[]},
        {"jsonrpc":"2.0","id":3,"method":"pocol_submitShare","params":["0x00",1]},5,{"jsonrpc":"2.0","id":4}]"#;
    let (code,b)=rpc(r.rpc,batch,true);assert_eq!(code,200);
    let v:serde_json::Value=serde_json::from_str(&b).unwrap();let a=v.as_array().unwrap();
    assert!(a[0]["result"].is_string(),"permitted member runs: {}",a[0]);
    for i in [1,2]{assert_eq!(a[i]["error"]["code"],-32601,"{}",a[i]);assert_eq!(a[i]["error"]["message"],"method not available to sites");assert!(a[i].get("result").is_none());}
    assert_eq!(a[3]["error"]["code"],-32600);assert_eq!(a[4]["error"]["code"],-32600);
    // The singleton form is equally denied; without an Origin the local miner keeps its interface.
    let (_,b)=rpc(r.rpc,r#"{"jsonrpc":"2.0","id":9,"method":"pocol_getTemplate","params":[]}"#,true);assert!(b.contains("-32601"),"{b}");
    let (_,b)=rpc(r.rpc,r#"[{"jsonrpc":"2.0","id":9,"method":"pocol_getTemplate","params":[]}]"#,false);assert!(b.contains("\"result\""),"{b}");
}

#[test] fn inbound_floods_cannot_take_the_slots_for_configured_peers(){let _g=serial();
    // Review finding (A05): dials used to share peers_max/handshaking_max with inbound connections.
    let target=TcpListener::bind("127.0.0.1:0").unwrap();let taddr=target.local_addr().unwrap();target.set_nonblocking(true).unwrap();
    let accept=|t:&TcpListener|{let s=Instant::now();loop{if let Ok((c,_))=t.accept(){return Some(c)}if s.elapsed()>Duration::from_secs(3){return None}std::thread::sleep(Duration::from_millis(20));}};
    let mut l=small();l.net.hello_deadline=Duration::from_secs(10);
    let r=start_with("outbound",l,vec![taddr]);
    let first=accept(&target).expect("the node dials its configured peer");
    // Every inbound handshake slot is taken by connections that never send a Hello.
    let idle:Vec<TcpStream>=(0..8).map(|_|connect(&r)).collect();
    assert!(wait_until(1000,||r.net.counters.handshaking.load(Ordering::SeqCst)==3),"inbound handshakes full");
    assert_eq!(r.net.counters.outbound.load(Ordering::SeqCst),1);
    // The configured peer drops; the node reconnects although inbound is full.
    drop(first);
    assert!(accept(&target).is_some(),"outbound reconnects despite a full inbound set");
    assert!(wait_until(1000,||r.net.counters.outbound.load(Ordering::SeqCst)==1));drop(idle);
}
/// RpcGuard REQ_BUF (network.md:229): request line, headers and body together. A request that
/// fills REQ_BUF exactly is served; one byte more is 413 without reaching the node.
#[test] fn rpc_request_buffer_covers_headers_and_body(){let _g=serial();
    let r=start("reqbuf",Limits::default());
    let call=r#"{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}"#;
    let head=|n:usize|format!("POST / HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: {n}\r\n\r\n");
    let send=|extra:usize|->u16{
        let n=pocold::rpc::REQ_BUF-head(1_000_000).len()+extra;assert_eq!(head(n).len(),head(1_000_000).len());
        let mut body=call.to_string();body.push_str(&" ".repeat(n-call.len()));
        let mut s=TcpStream::connect(("127.0.0.1",r.rpc)).unwrap();s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let _=s.write_all(head(n).as_bytes());let _=s.write_all(body.as_bytes());
        let mut out=String::new();let _=s.read_to_string(&mut out);out.get(9..12).and_then(|c|c.parse().ok()).unwrap_or(0)
    };
    assert_eq!(send(0),200,"headers + body == REQ_BUF is served");
    assert_eq!(send(1),413,"one byte over REQ_BUF");
}
/// A13 thread inventory under a stalled consensus thread: heavy eth_calls (30M gas) keep it
/// busy while peers fill the event queue and churn. Every reader joins its writer and delivers
/// Closed before it releases its slot, so the threads alive never exceed two per peer slot plus
/// the RPC connection in use (and this test's own threads).
#[test] fn peer_threads_stay_within_the_inventory_while_consensus_is_stalled(){let _g=serial();
    let r=start("inventory",small());let base=threads();let peers_max=6usize;
    let stop=std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let heavy={let (port,stop)=(r.rpc,stop.clone());std::thread::spawn(move||{let mut n=0;while !stop.load(Ordering::SeqCst){
        let (code,_)=rpc(port,r#"{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"data":"0x5b600056","gas":"0x1c9c380"},"latest"]}"#,false);if code==200{n+=1}}n})};
    let churn:Vec<_>=(0..3).map(|i|{let (port,stop,h)=(r.p2p,stop.clone(),hello(&r,&format!("churn{i}")));std::thread::spawn(move||{let mut k=0;while !stop.load(Ordering::SeqCst){
        if let Ok(mut s)=TcpStream::connect(("127.0.0.1",port)){let _=s.set_write_timeout(Some(Duration::from_millis(200)));let _=s.write_all(&h);
            for _ in 0..100{if s.write_all(&frame(&Msg::GetRange{start:1,count:1})).is_err(){break}}k+=1;}
    }k})}).collect();
    let own=1+3;let t=Instant::now();let mut worst=0usize;
    while t.elapsed()<Duration::from_secs(6){worst=worst.max(threads().saturating_sub(base+own));std::thread::sleep(Duration::from_millis(3));}
    stop.store(true,Ordering::SeqCst);let calls=heavy.join().unwrap();let conns:usize=churn.into_iter().map(|h|h.join().unwrap()).sum();
    assert!(calls>=2&&conns>=10,"the scenario ran: {calls} heavy calls, {conns} peer connections");
    assert!(worst<=2*peers_max+1,"threads beyond the inventory: {worst} > {}",2*peers_max+1);
    assert!(wait_until(5000,||live(&r)==0&&threads()<=base+2),"live={} threads {} vs {base}",live(&r),threads());
    println!("INVENTORY {}",serde_json::json!({"worstExtraThreads":worst,"bound":2*peers_max+1,"heavyCalls":calls,"peerConnections":conns}));
}

// ---------------- round 2: the RPC work deadline, tested on its own ----------------
const HEAVY:&str=r#"{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"data":"0x5b600056","gas":"0x1c9c380"},"latest"]}"#;
const LIGHT:&str=r#"{"jsonrpc":"2.0","id":2,"method":"eth_blockNumber","params":[]}"#;
fn timed(port:u16,body:&str)->(u16,Duration){let t=Instant::now();let (c,_)=rpc(port,body,false);(c,t.elapsed())}
fn counter(c:&std::sync::atomic::AtomicUsize)->usize{c.load(Ordering::SeqCst)}
/// While a 30M-gas eth_call holds the consensus thread, requests queued behind it get 504 at the
/// work deadline (not when the work would end), are never run once it has passed, and release
/// their connection threads; a batch stops starting members at the deadline.
/// The heavy call's duration on this host and build: the shorter of two warm runs on a node with
/// a wide deadline. Deadlines under test are fractions of it, so the tests do not depend on how
/// fast the build is.
fn heavy_duration()->Duration{
    let mut wide=small();wide.rpc.work_deadline=Duration::from_secs(60);let w=start("heavy-duration",wide);
    (0..2).map(|_|{let (code,t)=timed(w.rpc,HEAVY);assert_eq!(code,200);t}).min().unwrap()
}
fn stats(port:u16)->serde_json::Value{let (_,b)=rpc(port,r#"{"jsonrpc":"2.0","id":9,"method":"pocol_getRpcStats","params":[]}"#,false);serde_json::from_str::<serde_json::Value>(&b).unwrap()["result"].clone()}
/// Review F8: the work deadline, independently of build speed. The deadline under test is a
/// quarter of the heavy call's measured duration d, so the heavy call always outlasts it:
/// - the heavy caller is answered 504 at the deadline, while the work runs on;
/// - light requests sent meanwhile are run (200) when they are drained before the heavy event,
///   or wait behind it and expire (504); one dequeued after its deadline is skipped, never run,
///   so the skipped count is at most the 504s, and at least one is skipped;
/// - in a batch whose first member runs past the deadline, the 19 later members are not started;
/// - afterwards no connection thread, queued body or response reservation is left.
#[test] fn rpc_work_deadline_skips_expired_work_and_releases_resources(){let _g=serial();
    let c=&pocold::rpc::COUNTERS;let d=heavy_duration();let dl=(d/4).max(Duration::from_millis(2));
    let mut l=small();l.rpc.work_deadline=dl;let r=start("deadline",l);
    let base=threads();let (e0,m0)=(counter(&c.expired),counter(&c.expired_members));
    let stop=Arc::new(AtomicBool::new(false));
    let h=std::thread::spawn({let p=r.rpc;move||timed(p,HEAVY)});
    let lights:Vec<_>=(0..8).map(|_|{let (p,stop)=(r.rpc,stop.clone());std::thread::spawn(move||{let mut v=vec![];while !stop.load(Ordering::SeqCst){v.push(rpc(p,LIGHT,false).0)}v})}).collect();
    let (hc,ht)=h.join().unwrap();std::thread::sleep(d);stop.store(true,Ordering::SeqCst);
    let codes:Vec<u16>=lights.into_iter().flat_map(|t|t.join().unwrap()).collect();
    assert_eq!(hc,504);assert!(ht>=dl&&ht<d,"the heavy caller is answered at the deadline ({dl:?}), not after the work ({d:?}): {ht:?}");
    // 503: the light lane is full of requests that expired behind the heavy call and are not yet
    // skipped; they were never queued.
    assert!(codes.iter().all(|c|matches!(*c,200|503|504)),"{codes:?}");let late=codes.iter().filter(|c|**c==504).count();
    assert!(wait_until(10_000,||rpc(r.rpc,LIGHT,false).0==200),"the node serves again");
    let skipped=counter(&c.expired)-e0;
    assert!(late>=1&&skipped>=1&&skipped<=late,"light 504s {late}, skipped {skipped} (of {} light requests)",codes.len());
    // A batch: the first member runs past the deadline; the 19 after it are not started.
    let mut b=vec![HEAVY.to_string()];b.extend((0..19).map(|_|LIGHT.to_string()));let body=format!("[{}]",b.join(","));
    let (code,t)=timed(r.rpc,&body);assert_eq!(code,504);assert!(t<d,"{t:?}");
    assert!(wait_until(10_000,||counter(&c.expired_members)-m0==19),"members after the deadline are not started: {}",counter(&c.expired_members)-m0);
    // Resources: connection threads, queued bodies and reservations are all released.
    assert!(wait_until(5000,||counter(&c.active)==0&&threads()<=base+2),"active={} threads {} vs {base}",counter(&c.active),threads());
    let st=stats(r.rpc);assert_eq!(st["queued"],0);assert_eq!(st["heavyReserved"],0);assert_eq!(st["lightReserved"],pocold::rpc::LIGHT_RESP_MAX,"only the stats request itself is reserved");
    println!("DEADLINE {}",serde_json::json!({"heavyMs":d.as_millis() as u64,"workDeadlineMs":dl.as_millis() as u64,"heavyAnsweredMs":ht.as_millis() as u64,
        "lightRequests":codes.len(),"light504":late,"light503":codes.iter().filter(|c|**c==503).count(),"skipped":skipped,"batchMembersNotRun":counter(&c.expired_members)-m0}));
}
/// Review F4: the body of a heavy request whose caller already got 504 stays queued until the
/// node reaches it. At most queued_max (2·conn_max) are held at any moment, a further heavy
/// request is 503 (counted), and every held body is released when the node skips it.
#[test] fn abandoned_queued_bodies_are_capped_and_released(){let _g=serial();
    let c=&pocold::rpc::COUNTERS;let d=heavy_duration();
    let mut l=small();l.rpc.conn_max=2;l.rpc.work_deadline=(d/8).max(Duration::from_millis(1));let qmax=pocold::rpc::queued_max(&l.rpc);let r=start("queued",l);
    let (f0,q0)=(counter(&c.queue_full),counter(&c.queued));
    let stop=Arc::new(AtomicBool::new(false));let peak=Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let sampler={let (stop,peak)=(stop.clone(),peak.clone());std::thread::spawn(move||while !stop.load(Ordering::SeqCst){peak.fetch_max(counter(&pocold::rpc::COUNTERS.queued).saturating_sub(q0),Ordering::SeqCst);std::thread::yield_now();})};
    let mut rounds=0;
    while counter(&c.queue_full)==f0&&rounds<5{rounds+=1;
        // One heavy call holds the consensus thread for about d; two senders keep abandoning
        // heavy requests (each answered 504 at d/8, its body left queued).
        let h=std::thread::spawn({let p=r.rpc;move||rpc(p,HEAVY,false).0});std::thread::sleep(d/16);
        let senders:Vec<_>=(0..2).map(|_|{let p=r.rpc;std::thread::spawn(move||{let t=Instant::now();let mut v=vec![];while t.elapsed()<d{v.push(rpc(p,HEAVY,false).0)}v})}).collect();
        for s in senders{s.join().unwrap();}h.join().unwrap();
        assert!(wait_until(30_000,||counter(&c.queued)==q0),"queued bodies are released once skipped: {}",counter(&c.queued));
    }
    stop.store(true,Ordering::SeqCst);sampler.join().unwrap();
    let full=counter(&c.queue_full)-f0;let peak=peak.load(Ordering::SeqCst);
    assert!(full>=1,"queued_max was reached and a heavy request refused 503 ({rounds} rounds, peak {peak})");
    assert!(peak<=qmax,"at most queued_max ({qmax}) bodies are held: {peak}");
    assert_eq!(stats(r.rpc)["queued"],0);
    println!("QUEUED {}",serde_json::json!({"queuedMax":qmax,"peakQueued":peak,"refused503":full,"rounds":rounds}));
}
/// Response pools on a node: with the heavy pool held full, a heavy batch carrying a transaction
/// is answered -32021 busy for every member and nothing runs (the transaction is not pooled);
/// with the pool free the same batch runs. An answer's reservation is its size while the reply
/// lives and is released when the reply drops.
#[test] fn a_full_heavy_pool_answers_busy_before_anything_runs(){let _g=serial();
    use pocold::rpc::{answer,Request,HEAVY_RESP_POOL};
    let dir=std::env::temp_dir().join(format!("pocold-net-pools-{}",std::process::id()));let _=std::fs::remove_dir_all(&dir);
    let cfg=Config{dir,name:"pools".into(),miner:None,listen:None,peers:vec![],rpc:None,stop_at:None,log:false,limits:Limits::default()};
    let mut n=Node::open(cfg,spec()).unwrap();let pools=n.resp_pools();
    let tx=Tx{chain_id:777940,nonce:0,max_priority:U256::from(1u64),max_fee:U256::from(10_000_000_000u64),gas:21000,to:Some(revm::primitives::Address::ZERO),value:U256::ZERO,data:Default::default()}.sign_1559(&devnet::account_key("alice"));
    let body=format!(r#"[{{"jsonrpc":"2.0","id":1,"method":"eth_sendRawTransaction","params":["0x{}"]}},{{"jsonrpc":"2.0","id":2,"method":"eth_blockNumber","params":[]}}]"#,hex(&tx));
    let req=|b:&str|{let (t,_r)=std::sync::mpsc::channel();Request{body:b.as_bytes().to_vec(),reply:t,site:false,deadline:Instant::now()+Duration::from_secs(30),light:false,held:None}};
    let held=pools.hold_heavy(HEAVY_RESP_POOL-1024).unwrap();
    let busy=answer(&mut n,&req(&body));let v:serde_json::Value=serde_json::from_str(&busy.body).unwrap();
    assert!(v.as_array().map_or(false,|a|a.len()==2&&a.iter().all(|i|i["error"]["code"]==-32021)),"every member is busy: {v}");
    assert_eq!(n.pool.txs.len(),0,"nothing ran: the transaction was not pooled");drop(busy);drop(held);assert_eq!(pools.in_use().0,0);
    let ok=answer(&mut n,&req(&body));let v:serde_json::Value=serde_json::from_str(&ok.body).unwrap();
    assert!(v[0]["result"].is_string(),"with the pool free the batch runs: {v}");assert_eq!(n.pool.txs.len(),1);
    assert_eq!(pools.in_use().0,ok.body.capacity(),"the reservation shrank to the answer");drop(ok);assert_eq!(pools.in_use().0,0,"released with the reply");
}
fn hex(b:&[u8])->String{b.iter().map(|x|format!("{x:02x}")).collect()}
/// Light/heavy scheduling, deterministically (review F2, F9): a turn runs at most LIGHT_TURN
/// waiting light requests, then the node wakes itself for the rest, so any other event waits for
/// at most LIGHT_TURN light executions however many are queued. Light requests do overtake heavy
/// ones that arrived earlier (and run between a batch's members): HTTP requests sent concurrently
/// have no order, and a client that needs one waits for each answer.
#[test] fn a_light_turn_runs_at_most_light_turn_requests_then_wakes_the_node(){let _g=serial();
    use pocold::{node::{Event,LIGHT_TURN},rpc::Request};
    let dir=std::env::temp_dir().join(format!("pocold-net-turn-{}",std::process::id()));let _=std::fs::remove_dir_all(&dir);
    let cfg=Config{dir,name:"turn".into(),miner:None,listen:None,peers:vec![],rpc:None,stop_at:None,log:false,limits:Limits::default()};
    let mut n=Node::open(cfg,spec()).unwrap();let lane=n.light_lane();
    let (t,r)=std::sync::mpsc::channel();let queued=20;
    for _ in 0..queued{lane.tx.try_send(Event::Rpc(Request{body:LIGHT.as_bytes().to_vec(),reply:t.clone(),site:false,deadline:Instant::now()+Duration::from_secs(30),light:true,held:None})).unwrap();}
    let w0=counter(&pocold::rpc::COUNTERS.wakes);
    n.drain_light();let first=r.try_iter().count();
    assert_eq!(first,LIGHT_TURN,"one turn runs LIGHT_TURN light requests");
    assert!(lane.wake.load(Ordering::SeqCst)&&counter(&pocold::rpc::COUNTERS.wakes)==w0+1,"a full turn wakes the node for the rest");
    n.drain_light();assert_eq!(r.try_iter().count(),LIGHT_TURN);n.drain_light();assert_eq!(r.try_iter().count(),queued-2*LIGHT_TURN,"the last turn takes what is left");
}
/// Review F2: under a light flood the main queue holds at most one Wake at a time, so far fewer
/// Wakes are sent than light requests pushed, and main events still progress: a new peer's
/// handshake is answered and a heavy request completes, each within a bound that does not grow
/// with the flood (before every main event at most LIGHT_TURN light requests run).
#[test] fn a_light_flood_coalesces_wakes_and_main_events_progress(){let _g=serial();
    let c=&pocold::rpc::COUNTERS;let d=heavy_duration();let r=start("flood",small());
    let (w0,p0)=(counter(&c.wakes),counter(&c.light_pushed));
    let stop=Arc::new(AtomicBool::new(false));
    let flood:Vec<_>=(0..16).map(|_|{let (p,stop)=(r.rpc,stop.clone());std::thread::spawn(move||{let mut n=0;while !stop.load(Ordering::SeqCst){if rpc(p,LIGHT,false).0==200{n+=1}}n})}).collect();
    std::thread::sleep(Duration::from_millis(500));
    // A peer's handshake is a main event: Connected makes the node send its Hello.
    let t=Instant::now();let mut s=connect(&r);s.write_all(&hello(&r,"flood-peer")).unwrap();
    let mut len=[0u8;4];s.read_exact(&mut len).unwrap();let mut f=vec![0u8;u32::from_be_bytes(len) as usize];s.read_exact(&mut f).unwrap();
    let hello_at=t.elapsed();assert!(matches!(Msg::decode(&f),Ok(Msg::Hello{..})),"the node answers the handshake");
    let (hc,ht)=timed(r.rpc,HEAVY);
    stop.store(true,Ordering::SeqCst);let served:usize=flood.into_iter().map(|h|h.join().unwrap()).sum();
    let (wakes,pushed)=(counter(&c.wakes)-w0,counter(&c.light_pushed)-p0);
    println!("FLOOD {}",serde_json::json!({"lightServed":served,"lightPushed":pushed,"wakes":wakes,"helloMs":hello_at.as_millis() as u64,"heavyMs":ht.as_millis() as u64,"heavyAloneMs":d.as_millis() as u64}));
    assert!(served>=100,"the flood ran: {served}");
    assert!(wakes>=1&&wakes*2<pushed,"Wakes are coalesced: {wakes} for {pushed} light requests");
    assert!(hello_at<Duration::from_secs(2),"the handshake progressed under the flood: {hello_at:?}");
    assert_eq!(hc,200);assert!(ht<d*4+Duration::from_secs(1),"the heavy request progressed under the flood: {ht:?} (alone {d:?})");
}
/// Review F7: the miner is joined before it is replaced, so a mining node never has two miner
/// threads. The node mines alone (fallback templates) until height 6, and every new template
/// replaces the miner; /proc is sampled continuously for threads named "miner". The node stops
/// at that height, so it does not load the tests after this one.
#[test] fn miner_replacement_keeps_at_most_one_miner_thread(){let _g=serial();
    #[cfg(not(target_os="linux"))]{eprintln!("THREADS-NOT-MEASURED");return}
    let miners=||->Vec<String>{std::fs::read_dir("/proc/self/task").unwrap().filter_map(|e|{let e=e.ok()?;let n=std::fs::read_to_string(e.path().join("comm")).ok()?;(n.trim()=="miner").then(||e.file_name().to_string_lossy().to_string())}).collect()};
    let before=miners().len();assert_eq!(before,0,"no miner runs before the test");
    let dir=std::env::temp_dir().join(format!("pocold-net-miner-{}",std::process::id()));let _=std::fs::remove_dir_all(&dir);
    let cfg=Config{dir,name:"miner".into(),miner:Some(devnet::miner_identity("a").key),listen:None,peers:vec![],rpc:None,stop_at:Some(6),log:false,limits:small()};
    let mut node=Node::open(cfg,spec()).unwrap();node.start_network().unwrap();let run=std::thread::spawn(move||node.run());
    let (mut peak,mut seen)=(0usize,std::collections::HashSet::new());let t=Instant::now();
    while t.elapsed()<Duration::from_secs(120)&&!run.is_finished(){let m=miners();peak=peak.max(m.len());seen.extend(m);}
    assert!(run.is_finished(),"the mining node reached height 6");run.join().unwrap();
    assert!(wait_until(2000,||miners().is_empty()),"the miner is joined when the node stops");
    let handles=pocold::miner::PEAK.load(Ordering::SeqCst);
    println!("MINER {}",serde_json::json!({"minerThreadsSeen":seen.len(),"peakConcurrentSampled":peak,"peakLiveHandles":handles}));
    assert!(seen.len()>=2,"the miner was replaced at least once: {} miner threads seen",seen.len());
    // Exact: the handle count bounds the threads at every instant; sampling /proc is a cross-check.
    assert_eq!(handles,1,"a miner was started before the previous one was joined");
    assert!(peak<=1,"at most one miner thread at a time: {peak}");
}
/// Bounded adversarial load: 4 connections send 30M-gas eth_calls back to back, and 2 send
/// 20-member heavy batches. Each request holds the consensus thread for at most one heavy member
/// beyond the work deadline, and the queue is FIFO, so a legitimate request waits behind at most
/// one request per adversarial connection. Every legitimate request is answered with its result.
#[test] fn legitimate_requests_progress_under_bounded_heavy_load(){let _g=serial();
    let mut l=small();l.rpc.work_deadline=Duration::from_millis(2500);let r=start("progress",l);
    let (code,heavy)=timed(r.rpc,HEAVY);assert_eq!(code,200);
    let stop=std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let batch=format!("[{}]",vec![HEAVY;20].join(","));
    let adv:Vec<_>=(0..6).map(|i|{let (p,stop,body)=(r.rpc,stop.clone(),if i<4{HEAVY.to_string()}else{batch.clone()});
        std::thread::spawn(move||{let mut n=0;while !stop.load(Ordering::SeqCst){rpc(p,&body,false);n+=1}n})}).collect();
    std::thread::sleep(Duration::from_millis(300));
    let t0=Instant::now();let mut legit=Vec::new();
    while t0.elapsed()<Duration::from_secs(12){legit.push(timed(r.rpc,LIGHT));std::thread::sleep(Duration::from_millis(100));}
    stop.store(true,Ordering::SeqCst);let rounds:usize=adv.into_iter().map(|h|h.join().unwrap()).sum();
    let worst=legit.iter().map(|x|x.1).max().unwrap();
    // FIFO: at most one request per adversarial connection ahead, each <= deadline + one heavy member.
    let bound=Duration::from_millis(2500)+heavy*2;
    let ok=legit.iter().filter(|x|x.0==200).count();
    println!("PROGRESS {}",serde_json::json!({"heavyMs":heavy.as_millis() as u64,"legitRequests":legit.len(),"legitOk":ok,"worstMs":worst.as_millis() as u64,"adversaryRounds":rounds}));
    assert!(legit.len()>=4&&rounds>=6,"the load ran: {} legit, {rounds} adversarial",legit.len());
    assert_eq!(ok,legit.len(),"every legitimate request is answered: {legit:?}");
    assert!(worst<=bound,"worst legitimate latency {worst:?} > {bound:?}");
}
