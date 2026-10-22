//! A05 resource bounds (P2P and RPC, separately) and A10 ORIGIN_DENY per batch member,
//! on a real node over loopback sockets. Limits are shrunk so every case stays small.
use std::io::{Read,Write};
use std::net::{TcpListener,TcpStream};
use std::sync::atomic::Ordering;
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
#[test] fn rpc_work_deadline_skips_expired_work_and_releases_resources(){let _g=serial();
    let mut l=small();l.rpc.work_deadline=Duration::from_millis(400);let r=start("deadline",l);
    let c=&pocold::rpc::COUNTERS;let (e0,m0)=(counter(&c.expired),counter(&c.expired_members));
    // The heavy call alone (warm-up), without a deadline in the way: its duration on this host.
    let mut wide=small();wide.rpc.work_deadline=Duration::from_secs(60);let w=start("deadline-wide",wide);
    let (code,heavy)=timed(w.rpc,HEAVY);assert_eq!(code,200);assert!(heavy>Duration::from_millis(900),"the heavy call must outlast the deadline: {heavy:?}");
    let base=threads();
    // 250 ms: the heavy call has left the queue (behind at most one coalesced tick) and holds the
    // consensus thread; light requests that arrive now wait for it (they are drained before the
    // next event, never in the middle of one).
    let h=std::thread::spawn({let p=r.rpc;move||timed(p,HEAVY)});std::thread::sleep(Duration::from_millis(250));
    let quick:Vec<_>=(0..10).map(|_|{let p=r.rpc;std::thread::spawn(move||timed(p,LIGHT))}).collect();
    let quick:Vec<(u16,Duration)>=quick.into_iter().map(|t|t.join().unwrap()).collect();
    let (hc,ht)=h.join().unwrap();
    assert_eq!(hc,504);assert!(ht<Duration::from_millis(900),"the caller is answered at the deadline, not after the work: {ht:?}");
    for (code,t) in &quick{assert_eq!(*code,504);assert!(*t>=Duration::from_millis(350)&&*t<Duration::from_millis(900),"{t:?}");}
    // Once the consensus thread is free, the expired requests are skipped, not run (no polling
    // here: a poll that expired would be counted too).
    std::thread::sleep(heavy+Duration::from_millis(500));
    assert_eq!(counter(&c.expired)-e0,10,"each request whose deadline passed in the queue was skipped");
    assert_eq!(rpc(r.rpc,LIGHT,false).0,200,"the node serves again");
    // A heavy batch: the first member runs past the deadline; the 19 after it are not started.
    let mut b=vec![HEAVY.to_string()];b.extend((0..19).map(|_|LIGHT.to_string()));let body=format!("[{}]",b.join(","));
    let (code,t)=timed(r.rpc,&body);assert_eq!(code,504);assert!(t<Duration::from_millis(900),"{t:?}");
    std::thread::sleep(heavy+Duration::from_millis(500));
    assert_eq!(counter(&c.expired_members)-m0,19,"members after the deadline are not started");
    // Resources: no connection thread is left behind.
    assert!(wait_until(3000,||counter(&c.active)==0&&threads()<=base+2),"active={} threads {} vs {base}",counter(&c.active),threads());
    println!("DEADLINE {}",serde_json::json!({"workDeadlineMs":400,"heavyMs":heavy.as_millis() as u64,"heavyAnsweredMs":ht.as_millis() as u64,
        "queuedAnsweredMs":quick.iter().map(|q|q.1.as_millis() as u64).collect::<Vec<_>>(),"skipped":counter(&c.expired)-e0,"batchMembersNotRun":counter(&c.expired_members)-m0}));
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
