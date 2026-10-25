//! C-1 E4.2 (proposals/C1-STORAGE-DESIGN.md, "E4 design"): `state.redb`, the node store of the state trie.
//!
//! It keeps the nodes of every pinned state version (lp4 `node_trie`): each node under its `Id` (the
//! Keccak-256 of its serialization) with the number of stored nodes and pins that name it, the runtime
//! code by hash, and the preimages of the hashed keys. A commit stores a version's new nodes and pins its
//! root in one redb transaction; releasing a pin deletes, in one transaction, the nodes nothing names
//! any more. The store is derived data (invariant I1): it can be rebuilt from the journal, and a store
//! that does not open or is found damaged is set aside and rebuilt, as `history.redb` is.
//!
//! Reads are checked: a node whose bytes do not hash to its `Id`, or do not decode, marks the store
//! damaged and is never served. A bounded cache (`NODE_CACHE` bytes, counted in A13) sits in front of the
//! node table; redb's own page cache (`STATE_PAGE_CACHE`) is set explicitly.
use std::collections::{HashMap,VecDeque};
use std::panic::{catch_unwind,AssertUnwindSafe};
use std::path::{Path,PathBuf};
use std::sync::{Arc,Mutex,atomic::{AtomicBool,Ordering}};
use pocol_lp4_execution::node_trie::{Batch,Id,Node,NodeStore};
use redb::{Database,Durability,ReadableTable,ReadableTableMetadata,TableDefinition};
use revm::primitives::{keccak256,Address,Bytecode,Bytes,B256,U256};

/// node id -> reference count (u32 big-endian) ++ node encoding.
const NODES:TableDefinition<&[u8;32],&[u8]>=TableDefinition::new("node");
/// code hash -> runtime bytes (kept for good: storage.md keeps code to the end).
const CODE:TableDefinition<&[u8;32],&[u8]>=TableDefinition::new("code");
/// Keccak(address) -> address.
const ADDRS:TableDefinition<&[u8;32],&[u8;20]>=TableDefinition::new("addr");
/// address ++ Keccak(slot) -> slot.
const SLOTS:TableDefinition<&[u8;52],&[u8;32]>=TableDefinition::new("slotkey");
/// root id -> pins.
const PINS:TableDefinition<&[u8;32],u32>=TableDefinition::new("pins");

pub const FILE:&str="state.redb";
/// Written when the store was found damaged while running; the next open rebuilds it.
pub const DAMAGED:&str="state.redb.damaged";
/// redb's page cache for state.redb (A13).
pub const STATE_PAGE_CACHE:usize=64<<20;
/// The decoded-node cache in front of the node table (A13): bytes of node encodings held.
pub const NODE_CACHE:usize=256<<20;

#[derive(Debug)]
pub struct StateStoreError(pub String);
fn err(e:impl std::fmt::Display)->StateStoreError{StateStoreError(e.to_string())}

/// Decoded nodes by id, bounded by their encodings' bytes; the oldest go first.
#[derive(Default)]
struct Cache{map:HashMap<Id,(Arc<Node>,usize)>,order:VecDeque<Id>,bytes:usize}
impl Cache{
    fn get(&self,id:&Id)->Option<Arc<Node>>{self.map.get(id).map(|x|x.0.clone())}
    fn put(&mut self,id:Id,n:Arc<Node>,len:usize,cap:usize){
        if self.map.contains_key(&id){return}
        self.map.insert(id,(n,len));self.order.push_back(id);self.bytes+=len;
        while self.bytes>cap{let Some(old)=self.order.pop_front() else{break};if let Some((_,l))=self.map.remove(&old){self.bytes-=l;}}
    }
    fn remove(&mut self,id:&Id){if let Some((_,l))=self.map.remove(id){self.bytes-=l;}}
}

pub struct StateStore{db:Database,path:PathBuf,dir:PathBuf,pub rebuilt:bool,damaged:AtomicBool,cache:Mutex<Cache>,cache_cap:usize,
    /// Nodes read from the table (cache misses) and nodes written, since open (measurements).
    pub reads:std::sync::atomic::AtomicU64,pub writes:std::sync::atomic::AtomicU64}

fn node_value(count:u32,enc:&[u8])->Vec<u8>{let mut v=Vec::with_capacity(4+enc.len());v.extend_from_slice(&count.to_be_bytes());v.extend_from_slice(enc);v}
fn slot_key(a:&Address,k:&[u8;32])->[u8;52]{let mut x=[0u8;52];x[..20].copy_from_slice(a.as_slice());x[20..].copy_from_slice(k);x}

impl StateStore{
    /// Opens `dir/state.redb`. A file redb cannot open (an error or a panic inside redb), one that fails
    /// redb's full integrity check, or one marked damaged, is moved aside (`state.redb.aside`) and a new,
    /// empty store is created; `rebuilt` tells the caller, which refills it from the journal (I1).
    pub fn open(dir:&Path)->Result<Self,StateStoreError>{Self::open_with(dir,NODE_CACHE)}
    pub fn open_with(dir:&Path,cache_cap:usize)->Result<Self,StateStoreError>{
        let path=dir.join(FILE);let marker=dir.join(DAMAGED);
        let create=|p:&Path|->Result<Database,StateStoreError>{
            let mut db=catch_unwind(AssertUnwindSafe(||{let mut b=Database::builder();b.set_cache_size(STATE_PAGE_CACHE);b.create(p)})).map_err(|_|StateStoreError("redb panicked at open".into()))?.map_err(err)?;
            match catch_unwind(AssertUnwindSafe(||db.check_integrity())){Ok(Ok(true))=>{}_=>return Err(StateStoreError("integrity check failed".into()))}
            catch_unwind(AssertUnwindSafe(||->Result<(),StateStoreError>{let w=db.begin_write().map_err(err)?;
                {w.open_table(NODES).map_err(err)?;w.open_table(CODE).map_err(err)?;w.open_table(ADDRS).map_err(err)?;w.open_table(SLOTS).map_err(err)?;w.open_table(PINS).map_err(err)?;}
                w.commit().map_err(err)})).map_err(|_|StateStoreError("redb panicked at open".into()))??;
            Ok(db)};
        let first=if marker.exists(){Err(StateStoreError("marked damaged".into()))}else{create(&path)};
        let (db,rebuilt)=match first{
            Ok(db)=>(db,false),
            Err(_)=>{let aside=dir.join(format!("{FILE}.aside"));let _=std::fs::remove_file(&aside);let _=std::fs::rename(&path,&aside);
                let db=create(&path)?;let _=std::fs::remove_file(&marker);(db,true)}
        };
        Ok(Self{db,path,dir:dir.to_path_buf(),rebuilt,damaged:AtomicBool::new(false),cache:Mutex::new(Cache::default()),cache_cap,reads:Default::default(),writes:Default::default()})
    }
    pub fn path(&self)->&Path{&self.path}
    pub fn is_damaged(&self)->bool{self.damaged.load(Ordering::SeqCst)}
    /// Marks the store damaged: nothing more is served from it and the next open rebuilds it.
    pub fn mark_damaged(&self,why:&str)->StateStoreError{
        if !self.damaged.swap(true,Ordering::SeqCst){let _=std::fs::write(self.dir.join(DAMAGED),why.as_bytes());}
        StateStoreError(format!("state store damaged: {why}"))
    }
    fn guard<T>(&self,f:impl FnOnce()->Result<T,StateStoreError>)->Result<T,StateStoreError>{
        if self.is_damaged(){return Err(StateStoreError("state store damaged".into()))}
        catch_unwind(AssertUnwindSafe(f)).unwrap_or_else(|_|Err(self.mark_damaged("redb panicked")))
    }
    /// redb's full integrity check (every page checksum).
    pub fn verify(&mut self)->Result<bool,StateStoreError>{
        let db=&mut self.db;catch_unwind(AssertUnwindSafe(||db.check_integrity())).map_err(|_|StateStoreError("redb panicked in check_integrity".into()))?.map_err(err)
    }
    /// A node read from the table and checked: its bytes hash to its id and decode. A failure marks the
    /// store damaged.
    pub fn try_node(&self,id:&Id)->Result<Option<Arc<Node>>,StateStoreError>{
        if let Some(n)=self.cache.lock().unwrap().get(id){return Ok(Some(n))}
        let v=self.guard(||{let r=self.db.begin_read().map_err(err)?;let t=r.open_table(NODES).map_err(err)?;Ok(t.get(id).map_err(err)?.map(|v|v.value().to_vec()))})?;
        let Some(v)=v else{return Ok(None)};
        self.reads.fetch_add(1,Ordering::Relaxed);
        if v.len()<4||keccak256(&v[4..]).0!=*id{return Err(self.mark_damaged("a node's bytes do not hash to its id"))}
        let n=Node::decode(&v[4..]).ok_or_else(||self.mark_damaged("a node does not decode"))?;let n=Arc::new(n);
        self.cache.lock().unwrap().put(*id,n.clone(),v.len()-4,self.cache_cap);Ok(Some(n))
    }
    /// The reference count stored with a node (None: not stored).
    pub fn count(&self,id:&Id)->Result<Option<u32>,StateStoreError>{
        self.guard(||{let r=self.db.begin_read().map_err(err)?;let t=r.open_table(NODES).map_err(err)?;Ok(t.get(id).map_err(err)?.map(|v|u32::from_be_bytes(v.value()[..4].try_into().unwrap())))})
    }
    pub fn pins(&self)->Result<Vec<(Id,u32)>,StateStoreError>{
        self.guard(||{let r=self.db.begin_read().map_err(err)?;let t=r.open_table(PINS).map_err(err)?;let mut out=Vec::new();
            for kv in t.iter().map_err(err)?{let (k,v)=kv.map_err(err)?;out.push((*k.value(),v.value()));}Ok(out)})
    }
    /// Bytes of node encodings the cache holds (at most its bound).
    pub fn cache_bytes(&self)->usize{self.cache.lock().unwrap().bytes}
    pub fn node_count(&self)->Result<u64,StateStoreError>{self.guard(||{let r=self.db.begin_read().map_err(err)?;let t=r.open_table(NODES).map_err(err)?;t.len().map_err(err)})}
    /// Stores the nodes of `root` that the batch holds (every node reachable from it that is not stored
    /// yet, each counting one reference to each child), the batch's code and preimages, and pins the root
    /// once, in one transaction (`durable`: fsynced at commit).
    pub fn commit(&self,b:&Batch,root:Option<Id>,durable:bool)->Result<(),StateStoreError>{
        self.guard(||{
            let mut w=self.db.begin_write().map_err(err)?;if !durable{w.set_durability(Durability::None);}
            {
                let mut c=w.open_table(CODE).map_err(err)?;for (h,code) in &b.code{if c.get(&h.0).map_err(err)?.is_none(){c.insert(&h.0,code.original_bytes().as_ref()).map_err(err)?;}}
                let mut a=w.open_table(ADDRS).map_err(err)?;for (k,addr) in &b.addrs{if a.get(k).map_err(err)?.is_none(){a.insert(k,&addr.0 .0).map_err(err)?;}}
                let mut s=w.open_table(SLOTS).map_err(err)?;for ((addr,k),v) in &b.slots{let key=slot_key(addr,k);if s.get(&key).map_err(err)?.is_none(){s.insert(&key,&v.to_be_bytes::<32>()).map_err(err)?;}}
                if let Some(root)=root{
                    let mut p=w.open_table(PINS).map_err(err)?;let n=p.get(&root).map_err(err)?.map_or(0,|v|v.value());p.insert(&root,n+1).map_err(err)?;
                    let mut t=w.open_table(NODES).map_err(err)?;let mut stack=vec![root];
                    while let Some(id)=stack.pop(){
                        let cur=t.get(&id).map_err(err)?.map(|v|v.value().to_vec());
                        match cur{
                            Some(v)=>{let n=u32::from_be_bytes(v[..4].try_into().unwrap());t.insert(&id,node_value(n+1,&v[4..]).as_slice()).map_err(err)?;}
                            None=>{
                                let node=b.nodes.get(&id).ok_or_else(||StateStoreError(format!("node {} is neither stored nor in the batch",B256::from(id))))?;
                                t.insert(&id,node_value(1,&node.encode()).as_slice()).map_err(err)?;self.writes.fetch_add(1,Ordering::Relaxed);
                                stack.extend(node.children());
                            }
                        }
                    }
                }
            }
            w.commit().map_err(err)
        })
    }
    /// Releases one pin of `root` in one transaction: every node no pin or stored node names any more is
    /// deleted, with the references it held.
    pub fn unpin(&self,root:&Id,durable:bool)->Result<(),StateStoreError>{
        let mut gone=Vec::new();
        self.guard(||{
            let mut w=self.db.begin_write().map_err(err)?;if !durable{w.set_durability(Durability::None);}
            {
                let mut p=w.open_table(PINS).map_err(err)?;
                let n=p.get(root).map_err(err)?.map(|v|v.value()).ok_or_else(||StateStoreError(format!("root {} is not pinned",B256::from(*root))))?;
                if n>1{p.insert(root,n-1).map_err(err)?;}else{p.remove(root).map_err(err)?;}
                let mut t=w.open_table(NODES).map_err(err)?;let mut stack=vec![*root];
                while let Some(id)=stack.pop(){
                    let v=t.get(&id).map_err(err)?.map(|v|v.value().to_vec()).ok_or_else(||StateStoreError(format!("node {} is named but not stored",B256::from(id))))?;
                    let n=u32::from_be_bytes(v[..4].try_into().unwrap());
                    if n>1{t.insert(&id,node_value(n-1,&v[4..]).as_slice()).map_err(err)?;continue}
                    t.remove(&id).map_err(err)?;gone.push(id);
                    let node=Node::decode(&v[4..]).ok_or_else(||StateStoreError("a node does not decode".into()))?;stack.extend(node.children());
                }
            }
            w.commit().map_err(err)
        })?;
        let mut c=self.cache.lock().unwrap();for id in &gone{c.remove(id);}
        Ok(())
    }
    /// Recounts every node's references from the pins: equal to the stored counts, and no stored node that
    /// no pin reaches (a test of the counts; it reads the whole table).
    pub fn recount(&self)->Result<(),String>{
        let pins=self.pins().map_err(|e|e.0)?;let mut count:HashMap<Id,u32>=HashMap::new();let mut seen=std::collections::HashSet::new();
        for (r,c) in &pins{*count.entry(*r).or_insert(0)+=*c;}
        let mut stack:Vec<Id>=pins.iter().map(|x|x.0).collect();
        while let Some(id)=stack.pop(){
            if !seen.insert(id){continue}
            let n=self.try_node(&id).map_err(|e|e.0)?.ok_or_else(||format!("node {} is reachable but not stored",B256::from(id)))?;
            for c in n.children(){*count.entry(c).or_insert(0)+=1;stack.push(c);}
        }
        let stored=self.node_count().map_err(|e|e.0)?;
        if seen.len() as u64!=stored{return Err(format!("{stored} nodes stored, {} reachable",seen.len()))}
        for id in &seen{let c=self.count(id).map_err(|e|e.0)?;if c!=count.get(id).copied(){return Err(format!("node {}: stored count {c:?}, recounted {:?}",B256::from(*id),count.get(id)))}}
        Ok(())
    }
    fn read<T>(&self,f:impl FnOnce(&redb::ReadTransaction)->Result<T,StateStoreError>)->Option<T>{
        match self.guard(||{let r=self.db.begin_read().map_err(err)?;f(&r)}){Ok(v)=>Some(v),Err(e)=>panic!("C-1 E4: state store read failed: {}",e.0)}
    }
}
impl NodeStore for StateStore{
    /// A missing node is None; a damaged store panics (the caller's state cannot be read: never served).
    fn node(&self,id:&Id)->Option<Arc<Node>>{match self.try_node(id){Ok(n)=>n,Err(e)=>panic!("C-1 E4: {}",e.0)}}
    /// Code that does not hash to its key marks the store damaged and is never served.
    fn code(&self,h:&B256)->Option<Bytecode>{
        let b=self.read(|r|{let t=r.open_table(CODE).map_err(err)?;Ok(t.get(&h.0).map_err(err)?.map(|v|v.value().to_vec()))}).flatten()?;
        if keccak256(&b)!=*h{panic!("C-1 E4: {}",self.mark_damaged("code does not hash to its key").0)}
        Some(Bytecode::new_raw(Bytes::from(b)))
    }
    fn address(&self,k:&[u8;32])->Option<Address>{self.read(|r|{let t=r.open_table(ADDRS).map_err(err)?;Ok(t.get(k).map_err(err)?.map(|v|Address::from(*v.value())))}).flatten()}
    fn slot_key(&self,a:&Address,k:&[u8;32])->Option<U256>{self.read(|r|{let t=r.open_table(SLOTS).map_err(err)?;Ok(t.get(&slot_key(a,k)).map_err(err)?.map(|v|U256::from_be_bytes(*v.value())))}).flatten()}
}
impl pocol_lp4_execution::node_trie::TrieStore for StateStore{
    /// Durable: a block's nodes are committed before its journal record (I3).
    fn commit(&self,b:&Batch,root:Option<Id>)->Result<(),String>{StateStore::commit(self,b,root,true).map_err(|e|e.0)}
    fn unpin(&self,root:&Id)->Result<(),String>{StateStore::unpin(self,root,false).map_err(|e|e.0)}
    fn pinned(&self)->Result<u64,String>{Ok(self.pins().map_err(|e|e.0)?.iter().map(|x|u64::from(x.1)).sum())}
}
