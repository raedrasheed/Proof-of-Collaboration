//! Peer transport (VA-spec v1, development/VA-SPEC.md): TCP on loopback, frames
//! [u32 BE length][RLP([type, ...fields])], length <= MAX_FRAME. Malformed frames
//! or a wrong network identity close the connection; they never touch block state.
use std::io::{Read,Write};
use std::net::{TcpListener,TcpStream,SocketAddr};
use std::sync::{Arc,Mutex,mpsc::Sender};
use std::time::Duration;
use crate::rlp;

pub const MAX_FRAME:usize=8*1024*1024;

#[derive(Clone,Debug,PartialEq,Eq)]
pub enum Msg{
    Hello{chain_id:u64,genesis:[u8;32],head:[u8;32],height:u64,node:String},
    Block{header:Vec<u8>,body:Vec<u8>},
    Template{shell:Vec<u8>,body:Vec<u8>},
    Share{tid:[u8;32],nonce:u64},
    GetBlock{hash:[u8;32]},
    GetRange{start:u64,count:u64},
    Tx{raw:Vec<u8>},
}
fn u64b(v:u64,o:&mut Vec<u8>){let b=v.to_be_bytes();let f=b.iter().position(|x|*x!=0).unwrap_or(8);rlp::encode_bytes(&b[f..],o)}
impl Msg{
    pub fn encode(&self)->Vec<u8>{
        let mut p=Vec::new();
        match self{
            Msg::Hello{chain_id,genesis,head,height,node}=>{u64b(0,&mut p);u64b(*chain_id,&mut p);rlp::encode_bytes(genesis,&mut p);rlp::encode_bytes(head,&mut p);u64b(*height,&mut p);rlp::encode_bytes(node.as_bytes(),&mut p);}
            Msg::Block{header,body}=>{u64b(1,&mut p);rlp::encode_bytes(header,&mut p);rlp::encode_bytes(body,&mut p);}
            Msg::Template{shell,body}=>{u64b(2,&mut p);rlp::encode_bytes(shell,&mut p);rlp::encode_bytes(body,&mut p);}
            Msg::Share{tid,nonce}=>{u64b(3,&mut p);rlp::encode_bytes(tid,&mut p);rlp::encode_bytes(&nonce.to_be_bytes(),&mut p);}
            Msg::GetBlock{hash}=>{u64b(4,&mut p);rlp::encode_bytes(hash,&mut p);}
            Msg::GetRange{start,count}=>{u64b(5,&mut p);u64b(*start,&mut p);u64b(*count,&mut p);}
            Msg::Tx{raw}=>{u64b(6,&mut p);rlp::encode_bytes(raw,&mut p);}
        }
        let mut o=Vec::new();rlp::encode_list_payload(&p,&mut o);o
    }
    pub fn decode(b:&[u8])->Result<Self,String>{
        let it=rlp::decode(b).map_err(|e|e.code().to_string())?;let f=it.list().ok_or("msg")?;
        let bytes=|i:usize|->Result<Vec<u8>,String>{f.get(i).and_then(|x|x.bytes()).map(|x|x.to_vec()).ok_or_else(||"field".to_string())};
        let num=|i:usize|->Result<u64,String>{let v=bytes(i)?;if v.len()>8||v.first()==Some(&0){return Err("int".into())}Ok(v.iter().fold(0u64,|a,x|(a<<8)|*x as u64))};
        let h32=|i:usize|->Result<[u8;32],String>{bytes(i)?.try_into().map_err(|_|"hash".to_string())};
        let n=|k:usize|->Result<(),String>{if f.len()==k{Ok(())}else{Err("arity".into())}};
        let m=match num(0)?{
            0=>{n(6)?;Msg::Hello{chain_id:num(1)?,genesis:h32(2)?,head:h32(3)?,height:num(4)?,node:String::from_utf8(bytes(5)?).map_err(|_|"utf8")?}}
            1=>{n(3)?;Msg::Block{header:bytes(1)?,body:bytes(2)?}}
            2=>{n(3)?;Msg::Template{shell:bytes(1)?,body:bytes(2)?}}
            3=>{n(3)?;let nb=bytes(2)?;if nb.len()!=8{return Err("nonce".into())}Msg::Share{tid:h32(1)?,nonce:u64::from_be_bytes(nb.try_into().unwrap())}}
            4=>{n(2)?;Msg::GetBlock{hash:h32(1)?}}
            5=>{n(3)?;Msg::GetRange{start:num(1)?,count:num(2)?}}
            6=>{n(2)?;Msg::Tx{raw:bytes(1)?}}
            _=>return Err("type".into())
        };
        if m.encode()!=b{return Err("noncanonical".into())}
        Ok(m)
    }
}

pub type PeerId=u64;
#[derive(Debug)]
pub enum NetEvent{Connected(PeerId,Peer),Message(PeerId,Msg),Closed(PeerId)}
#[derive(Clone,Debug)]
pub struct Peer{pub id:PeerId,stream:Arc<Mutex<TcpStream>>,pub addr:String,pub outbound:bool}
impl Peer{
    pub fn send(&self,m:&Msg)->bool{
        let b=m.encode();if b.len()>MAX_FRAME{return false}
        let mut s=match self.stream.lock(){Ok(s)=>s,Err(_)=>return false};
        s.write_all(&(b.len() as u32).to_be_bytes()).and_then(|_|s.write_all(&b)).is_ok()
    }
    pub fn close(&self){if let Ok(s)=self.stream.lock(){let _=s.shutdown(std::net::Shutdown::Both);}}
}

static NEXT:std::sync::atomic::AtomicU64=std::sync::atomic::AtomicU64::new(1);
fn spawn_peer(stream:TcpStream,outbound:bool,events:Sender<NetEvent>){
    let _=stream.set_nodelay(true);let addr=stream.peer_addr().map(|a|a.to_string()).unwrap_or_default();
    let id=NEXT.fetch_add(1,std::sync::atomic::Ordering::SeqCst);
    let reader=match stream.try_clone(){Ok(r)=>r,Err(_)=>return};
    let peer=Peer{id,stream:Arc::new(Mutex::new(stream)),addr,outbound};
    if events.send(NetEvent::Connected(id,peer.clone())).is_err(){return}
    std::thread::Builder::new().name(format!("peer-{id}")).spawn(move||{
        let mut r=reader;
        loop{
            let mut len=[0u8;4];if r.read_exact(&mut len).is_err(){break}
            let n=u32::from_be_bytes(len) as usize;if n==0||n>MAX_FRAME{break}
            let mut buf=vec![0u8;n];if r.read_exact(&mut buf).is_err(){break}
            match Msg::decode(&buf){Ok(m)=>{if events.send(NetEvent::Message(id,m)).is_err(){break}}Err(_)=>break}
        }
        peer.close();let _=events.send(NetEvent::Closed(id));
    }).expect("spawn peer");
}
/// Accepts inbound peers on `listener` (loopback only).
pub fn listen(listener:TcpListener,events:Sender<NetEvent>){
    std::thread::Builder::new().name("p2p-listen".into()).spawn(move||{
        for s in listener.incoming(){match s{Ok(s)=>{if s.peer_addr().map(|a|a.ip().is_loopback()).unwrap_or(false){spawn_peer(s,false,events.clone())}}Err(_)=>continue}}
    }).expect("spawn listener");
}
/// Keeps an outbound connection to `addr`, reconnecting after loss. The node
/// maintains `connected` from Connected/Closed events (outbound peer addresses).
pub fn dial(addr:SocketAddr,events:Sender<NetEvent>,connected:Arc<Mutex<std::collections::HashSet<String>>>){
    std::thread::Builder::new().name(format!("dial-{addr}")).spawn(move||{
        loop{
            let live=connected.lock().map(|s|s.contains(&addr.to_string())).unwrap_or(false);
            if !live{
                if let Ok(s)=TcpStream::connect_timeout(&addr,Duration::from_millis(500)){
                    if let Ok(mut set)=connected.lock(){set.insert(addr.to_string());}
                    spawn_peer(s,true,events.clone());
                }
            }
            std::thread::sleep(Duration::from_millis(300));
        }
    }).expect("spawn dialer");
}
