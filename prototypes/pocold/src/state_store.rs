//! C-1 E4.2 (proposals/C1-STORAGE-DESIGN.md, "E4 design"): `state.redb`, the node store of the state trie.
//!
//! It keeps the nodes of every pinned state version (lp4 `node_trie`): each node under its `Id` (the
//! Keccak-256 of its serialization) with the number of stored nodes and pins that name it, the runtime
//! code by hash (C-1 E5: a leaf keeps its key's preimage). A commit stores a version's new nodes and pins its
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
use revm::primitives::{keccak256,Bytecode,Bytes,B256};

/// node id -> reference count (u32 big-endian) ++ node encoding.
const NODES:TableDefinition<&[u8;32],&[u8]>=TableDefinition::new("node");
/// code hash -> runtime bytes (kept for good: storage.md keeps code to the end).
const CODE:TableDefinition<&[u8;32],&[u8]>=TableDefinition::new("code");
/// The store's format ("format" -> FORMAT). C-1 E5: a leaf keeps its key's preimage (format 2); a store
/// of another format is set aside and rebuilt, as a damaged one is (derived data, I1).
const META:TableDefinition<&str,u64>=TableDefinition::new("meta");
pub const FORMAT:u64=2;
/// root id -> pins.
const PINS:TableDefinition<&[u8;32],u32>=TableDefinition::new("pins");
/// C-1 E4.4 (D-6): checkpoint sequence -> the sealed chain snapshot (`checkpoint::encode`).
const CKPT:TableDefinition<u64,&[u8]>=TableDefinition::new("checkpoint");
/// Checkpoint sequence -> the roots it pins (32 bytes each, a root once per entry that holds it), so a
/// checkpoint is released without decoding its snapshot.
const CKPT_ROOTS:TableDefinition<u64,&[u8]>=TableDefinition::new("checkpoint_roots");

pub const FILE:&str="state.redb";
/// Written when the store was found damaged while running; the next open rebuilds it.
pub const DAMAGED:&str="state.redb.damaged";
/// redb's page cache for state.redb (A13).
pub const STATE_PAGE_CACHE:usize=64<<20;
/// The decoded-node cache in front of the node table (A13): resident bytes held (`CACHE_ENTRY` per node and
/// what its decoded node holds, `Node::resident_bytes`).
pub const NODE_CACHE:usize=256<<20;
/// C-1 E4.5: the cache's own share per node: its map slot (the id, the `Arc` and its size) and its place in
/// the eviction order, each at twice its size (a table at most half full grows by doubling).
pub const CACHE_ENTRY:usize=2*std::mem::size_of::<(Id,(Arc<Node>,usize))>()+2*std::mem::size_of::<Id>()+1;

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
    /// Set when the node closes (`close`): versions are no longer released one by one.
    closing:AtomicBool,
    /// Nodes read from the table (cache misses) and nodes written, since open (measurements).
    pub reads:std::sync::atomic::AtomicU64,pub writes:std::sync::atomic::AtomicU64}

fn node_value(count:u32,enc:&[u8])->Vec<u8>{let mut v=Vec::with_capacity(4+enc.len());v.extend_from_slice(&count.to_be_bytes());v.extend_from_slice(enc);v}

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
                {let nodes=w.open_table(NODES).map_err(err)?;w.open_table(CODE).map_err(err)?;w.open_table(PINS).map_err(err)?;
                 w.open_table(CKPT).map_err(err)?;w.open_table(CKPT_ROOTS).map_err(err)?;let mut m=w.open_table(META).map_err(err)?;
                 let format=m.get("format").map_err(err)?.map(|v|v.value());
                 match format{Some(FORMAT)=>{}None if nodes.is_empty().map_err(err)?=>{m.insert("format",FORMAT).map_err(err)?;}
                     f=>return Err(StateStoreError(format!("state store format {f:?}, not {FORMAT}")))}}
                w.commit().map_err(err)})).map_err(|_|StateStoreError("redb panicked at open".into()))??;
            Ok(db)};
        let first=if marker.exists(){Err(StateStoreError("marked damaged".into()))}else{create(&path)};
        let (db,rebuilt)=match first{
            Ok(db)=>(db,false),
            Err(_)=>{let aside=dir.join(format!("{FILE}.aside"));let _=std::fs::remove_file(&aside);let _=std::fs::rename(&path,&aside);
                let db=create(&path)?;let _=std::fs::remove_file(&marker);(db,true)}
        };
        Ok(Self{db,path,dir:dir.to_path_buf(),rebuilt,damaged:AtomicBool::new(false),cache:Mutex::new(Cache::default()),cache_cap,closing:AtomicBool::new(false),reads:Default::default(),writes:Default::default()})
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
    /// store damaged. A damaged store serves nothing, not even a node its cache holds.
    pub fn try_node(&self,id:&Id)->Result<Option<Arc<Node>>,StateStoreError>{
        if self.is_damaged(){return Err(StateStoreError("state store damaged".into()))}
        if let Some(n)=self.cache.lock().unwrap().get(id){return Ok(Some(n))}
        let v=self.guard(||{let r=self.db.begin_read().map_err(err)?;let t=r.open_table(NODES).map_err(err)?;Ok(t.get(id).map_err(err)?.map(|v|v.value().to_vec()))})?;
        let Some(v)=v else{return Ok(None)};
        self.reads.fetch_add(1,Ordering::Relaxed);
        if v.len()<4||keccak256(&v[4..]).0!=*id{return Err(self.mark_damaged("a node's bytes do not hash to its id"))}
        let n=Node::decode(&v[4..]).ok_or_else(||self.mark_damaged("a node does not decode"))?;let n=Arc::new(n);
        let len=CACHE_ENTRY+n.resident_bytes();self.cache.lock().unwrap().put(*id,n.clone(),len,self.cache_cap);Ok(Some(n))
    }
    /// The reference count stored with a node (None: not stored).
    pub fn count(&self,id:&Id)->Result<Option<u32>,StateStoreError>{
        self.guard(||{let r=self.db.begin_read().map_err(err)?;let t=r.open_table(NODES).map_err(err)?;Ok(t.get(id).map_err(err)?.map(|v|u32::from_be_bytes(v.value()[..4].try_into().unwrap())))})
    }
    pub fn pins(&self)->Result<Vec<(Id,u32)>,StateStoreError>{
        self.guard(||{let r=self.db.begin_read().map_err(err)?;let t=r.open_table(PINS).map_err(err)?;let mut out=Vec::new();
            for kv in t.iter().map_err(err)?{let (k,v)=kv.map_err(err)?;out.push((*k.value(),v.value()));}Ok(out)})
    }
    /// C-1 E4.5: the bytes of every key and value stored, over all tables (file size over this is the
    /// file factor measured in evidence/c1-e4).
    pub fn stored_bytes(&self)->Result<u64,StateStoreError>{
        self.guard(||{let r=self.db.begin_read().map_err(err)?;let mut n=0u64;
            {let t=r.open_table(NODES).map_err(err)?;for kv in t.iter().map_err(err)?{let (_,v)=kv.map_err(err)?;n+=32+v.value().len() as u64;}}
            {let t=r.open_table(CODE).map_err(err)?;for kv in t.iter().map_err(err)?{let (_,v)=kv.map_err(err)?;n+=32+v.value().len() as u64;}}
            {let t=r.open_table(PINS).map_err(err)?;n+=t.len().map_err(err)?*(32+4);}
            {let t=r.open_table(CKPT).map_err(err)?;for kv in t.iter().map_err(err)?{let (_,v)=kv.map_err(err)?;n+=8+v.value().len() as u64;}}
            {let t=r.open_table(CKPT_ROOTS).map_err(err)?;for kv in t.iter().map_err(err)?{let (_,v)=kv.map_err(err)?;n+=8+v.value().len() as u64;}}
            Ok(n)})
    }
    /// C-1 E5: redb's own account of the file (measurements): (allocated pages' bytes, fragmented bytes,
    /// metadata bytes), read in a write transaction that is dropped uncommitted.
    pub fn file_stats(&self)->Result<(u64,u64,u64),StateStoreError>{
        self.guard(||{let w=self.db.begin_write().map_err(err)?;let s=w.stats().map_err(err)?;let r=(s.allocated_pages()*s.page_size() as u64,s.fragmented_bytes(),s.metadata_bytes());w.abort().map_err(err)?;Ok(r)})
    }
    /// Resident bytes the cache holds (at most its bound).
    pub fn cache_bytes(&self)->usize{self.cache.lock().unwrap().bytes}
    pub fn node_count(&self)->Result<u64,StateStoreError>{self.guard(||{let r=self.db.begin_read().map_err(err)?;let t=r.open_table(NODES).map_err(err)?;t.len().map_err(err)})}
    /// Stores the nodes of `root` that the batch holds (every node reachable from it that is not stored
    /// yet, each counting one reference to each child), the batch's code, and pins the root
    /// once, in one transaction (`durable`: fsynced at commit).
    pub fn commit(&self,b:&Batch,root:Option<Id>,durable:bool)->Result<(),StateStoreError>{
        self.guard(||{
            let mut w=self.db.begin_write().map_err(err)?;if !durable{w.set_durability(Durability::None);}
            {
                let mut c=w.open_table(CODE).map_err(err)?;for (h,code) in &b.code{if c.get(&h.0).map_err(err)?.is_none(){c.insert(&h.0,code.original_bytes().as_ref()).map_err(err)?;}}
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
            crate::crash_point("state-txn");
            w.commit().map_err(err)
        })
    }
    /// Releases one pin of `root` in one transaction: every node no pin or stored node names any more is
    /// deleted, with the references it held.
    pub fn unpin(&self,root:&Id,durable:bool)->Result<(),StateStoreError>{
        let mut gone=Vec::new();
        self.guard(||{
            let mut w=self.db.begin_write().map_err(err)?;if !durable{w.set_durability(Durability::None);}
            {let mut p=w.open_table(PINS).map_err(err)?;let mut t=w.open_table(NODES).map_err(err)?;release(&mut p,&mut t,root,&mut gone)?;}
            w.commit().map_err(err)
        })?;
        self.forget(&gone);Ok(())
    }
    /// C-1 E5: the node is closing. The versions its entries pin are left pinned rather than released one
    /// transaction each as the entries drop (non-durable transactions whose pages redb reuses only after a
    /// durable commit, so a close released every version into new pages: closing after a replay from genesis
    /// grew the file from 17 MB to 34 MB and from 68 MB to 270 MB, evidence/c1-e4/disk-close-ab-*.log). The next open releases them in one durable transaction
    /// (`reset_pins`, what it does after a crash), or starts the store empty when no checkpoint is kept.
    pub fn close(&self){self.closing.store(true,Ordering::SeqCst);}
    fn forget(&self,gone:&[Id]){let mut c=self.cache.lock().unwrap();for id in gone{c.remove(id);}}
    /// C-1 E4.4: the stored checkpoints, oldest first: (sequence, snapshot bytes, the roots it pins).
    pub fn checkpoints(&self)->Result<Vec<(u64,Vec<u8>,Vec<Id>)>,StateStoreError>{
        self.guard(||{let r=self.db.begin_read().map_err(err)?;let c=r.open_table(CKPT).map_err(err)?;let x=r.open_table(CKPT_ROOTS).map_err(err)?;let mut out=Vec::new();
            for kv in c.iter().map_err(err)?{let (k,v)=kv.map_err(err)?;let seq=k.value();
                let roots=x.get(seq).map_err(err)?.ok_or_else(||StateStoreError(format!("checkpoint {seq} has no roots record")))?.value().to_vec();
                if roots.len()%32!=0{return Err(StateStoreError(format!("checkpoint {seq}: roots record of {} bytes",roots.len())))}
                out.push((seq,v.value().to_vec(),roots.chunks(32).map(|c|c.try_into().unwrap()).collect()));}
            Ok(out)})
    }
    /// C-1 E4.4: the pins the stored checkpoints hold.
    pub fn checkpoint_pins(&self)->Result<u64,StateStoreError>{
        self.guard(||{let r=self.db.begin_read().map_err(err)?;let x=r.open_table(CKPT_ROOTS).map_err(err)?;let mut n=0u64;
            for kv in x.iter().map_err(err)?{n+=(kv.map_err(err)?.1.value().len()/32) as u64;}Ok(n)})
    }
    /// C-1 E4.4: stores a checkpoint under the next sequence and pins each of its roots once (as a block
    /// commit pins its root), then releases the oldest checkpoints beyond `keep`, in one durable
    /// transaction: a crash leaves the checkpoints before it or after it, never a part of one. Every root
    /// must already be stored (each is an entry's pinned version). Returns the new sequence.
    pub fn write_checkpoint(&self,snapshot:&[u8],roots:&[Id],keep:usize)->Result<u64,StateStoreError>{
        let mut gone=Vec::new();
        let seq=self.guard(||{
            let w=self.db.begin_write().map_err(err)?;let seq;
            {
                let mut c=w.open_table(CKPT).map_err(err)?;let mut x=w.open_table(CKPT_ROOTS).map_err(err)?;
                let mut p=w.open_table(PINS).map_err(err)?;let mut t=w.open_table(NODES).map_err(err)?;
                seq=c.last().map_err(err)?.map_or(0,|(k,_)|k.value()+1);
                let flat:Vec<u8>=roots.iter().flat_map(|r|r.iter().copied()).collect();
                c.insert(seq,snapshot).map_err(err)?;x.insert(seq,flat.as_slice()).map_err(err)?;
                for r in roots{pin_stored(&mut p,&mut t,r)?;}
                let mut seqs=Vec::new();for kv in c.iter().map_err(err)?{seqs.push(kv.map_err(err)?.0.value());}
                for old in seqs.iter().take(seqs.len().saturating_sub(keep.max(1))){drop_one(&mut c,&mut x,&mut p,&mut t,*old,&mut gone)?;}
            }
            crate::crash_point("checkpoint-txn");
            w.commit().map_err(err)?;Ok(seq)
        })?;
        self.forget(&gone);Ok(seq)
    }
    /// C-1 E4.4: releases one checkpoint (one that failed verification at open) and its pins, durably.
    pub fn drop_checkpoint(&self,seq:u64)->Result<(),StateStoreError>{
        let mut gone=Vec::new();
        self.guard(||{
            let w=self.db.begin_write().map_err(err)?;
            {let mut c=w.open_table(CKPT).map_err(err)?;let mut x=w.open_table(CKPT_ROOTS).map_err(err)?;let mut p=w.open_table(PINS).map_err(err)?;let mut t=w.open_table(NODES).map_err(err)?;
             drop_one(&mut c,&mut x,&mut p,&mut t,seq,&mut gone)?;}
            w.commit().map_err(err)
        })?;
        self.forget(&gone);Ok(())
    }
    /// C-1 E4.4: at open, before any version is pinned again: the pins become exactly the stored
    /// checkpoints' (a pin of a running node's entry, or of a block whose journal record a crash cut
    /// off, is released with every node only it held), in one durable transaction. A root pinned fewer
    /// times than the checkpoints name it means the counts are not what the commits made them: an error,
    /// and the caller rebuilds the store.
    pub fn reset_pins(&self)->Result<u64,StateStoreError>{
        let mut gone=Vec::new();let mut released=0u64;
        self.guard(||{
            let w=self.db.begin_write().map_err(err)?;
            {
                let x=w.open_table(CKPT_ROOTS).map_err(err)?;let mut want:HashMap<Id,u32>=HashMap::new();
                for kv in x.iter().map_err(err)?{let (_,v)=kv.map_err(err)?;let v=v.value();if v.len()%32!=0{return Err(StateStoreError("a checkpoint roots record is not whole roots".into()))}
                    for c in v.chunks(32){*want.entry(c.try_into().unwrap()).or_insert(0)+=1;}}
                let mut p=w.open_table(PINS).map_err(err)?;let mut t=w.open_table(NODES).map_err(err)?;
                let mut held=Vec::new();for kv in p.iter().map_err(err)?{let (k,v)=kv.map_err(err)?;held.push((*k.value(),v.value()));}
                for (r,n) in &want{let h=held.iter().find(|x|x.0==*r).map_or(0,|x|x.1);if h<*n{return Err(StateStoreError(format!("root {} pinned {h} times, checkpoints name it {n} times",B256::from(*r))))}}
                for (r,n) in held{for _ in 0..n-want.get(&r).copied().unwrap_or(0){release(&mut p,&mut t,&r,&mut gone)?;released+=1;}}
            }
            w.commit().map_err(err)
        })?;
        self.forget(&gone);Ok(released)
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
type Pins<'a>=redb::Table<'a,&'static [u8;32],u32>;type Nodes<'a>=redb::Table<'a,&'static [u8;32],&'static [u8]>;
/// One pin of `root` released within a write transaction: every node nothing names any more is deleted.
fn release(p:&mut Pins<'_>,t:&mut Nodes<'_>,root:&Id,gone:&mut Vec<Id>)->Result<(),StateStoreError>{
    let n=p.get(root).map_err(err)?.map(|v|v.value()).ok_or_else(||StateStoreError(format!("root {} is not pinned",B256::from(*root))))?;
    if n>1{p.insert(root,n-1).map_err(err)?;}else{p.remove(root).map_err(err)?;}
    let mut stack=vec![*root];
    while let Some(id)=stack.pop(){
        let v=t.get(&id).map_err(err)?.map(|v|v.value().to_vec()).ok_or_else(||StateStoreError(format!("node {} is named but not stored",B256::from(id))))?;
        let n=u32::from_be_bytes(v[..4].try_into().unwrap());
        if n>1{t.insert(&id,node_value(n-1,&v[4..]).as_slice()).map_err(err)?;continue}
        t.remove(&id).map_err(err)?;gone.push(id);
        let node=Node::decode(&v[4..]).ok_or_else(||StateStoreError("a node does not decode".into()))?;stack.extend(node.children());
    }
    Ok(())
}
/// One more pin of a stored root within a write transaction (its node counts one more reference).
fn pin_stored(p:&mut Pins<'_>,t:&mut Nodes<'_>,root:&Id)->Result<(),StateStoreError>{
    let v=t.get(root).map_err(err)?.map(|v|v.value().to_vec()).ok_or_else(||StateStoreError(format!("root {} is not stored",B256::from(*root))))?;
    let n=u32::from_be_bytes(v[..4].try_into().unwrap());t.insert(root,node_value(n+1,&v[4..]).as_slice()).map_err(err)?;
    let k=p.get(root).map_err(err)?.map_or(0,|v|v.value());p.insert(root,k+1).map_err(err)?;Ok(())
}
fn drop_one(c:&mut redb::Table<'_,u64,&'static [u8]>,x:&mut redb::Table<'_,u64,&'static [u8]>,p:&mut Pins<'_>,t:&mut Nodes<'_>,seq:u64,gone:&mut Vec<Id>)->Result<(),StateStoreError>{
    let roots=x.remove(seq).map_err(err)?.map(|v|v.value().to_vec()).unwrap_or_default();c.remove(seq).map_err(err)?;
    for r in roots.chunks(32){release(p,t,&r.try_into().unwrap(),gone)?;}Ok(())
}
impl NodeStore for StateStore{
    /// A damaged store panics (the caller's state cannot be read: never served). A missing node is None,
    /// which every reader of a version treats as fatal (`node_trie` asks only for nodes a stored node or a
    /// pinned root names): the store is marked damaged as well, so the next open rebuilds it (C-1 E4.4).
    fn node(&self,id:&Id)->Option<Arc<Node>>{match self.try_node(id){Ok(Some(n))=>Some(n),Ok(None)=>{self.mark_damaged(&format!("node {} is named but not stored",B256::from(*id)));None}Err(e)=>panic!("C-1 E4: {}",e.0)}}
    /// Code that does not hash to its key marks the store damaged and is never served.
    fn code(&self,h:&B256)->Option<Bytecode>{
        let b=self.read(|r|{let t=r.open_table(CODE).map_err(err)?;Ok(t.get(&h.0).map_err(err)?.map(|v|v.value().to_vec()))}).flatten()?;
        if keccak256(&b)!=*h{panic!("C-1 E4: {}",self.mark_damaged("code does not hash to its key").0)}
        Some(Bytecode::new_raw(Bytes::from(b)))
    }
}
impl pocol_lp4_execution::node_trie::TrieStore for StateStore{
    /// Durable: a block's nodes are committed before its journal record (I3).
    fn commit(&self,b:&Batch,root:Option<Id>)->Result<(),String>{StateStore::commit(self,b,root,true).map_err(|e|e.0)}
    fn unpin(&self,root:&Id)->Result<(),String>{if self.closing.load(Ordering::SeqCst){return Ok(())}StateStore::unpin(self,root,false).map_err(|e|e.0)}
    /// The pins entries hold: every pin but the checkpoints' (C-1 E4.4).
    fn pinned(&self)->Result<u64,String>{let all:u64=self.pins().map_err(|e|e.0)?.iter().map(|x|u64::from(x.1)).sum();Ok(all-self.checkpoint_pins().map_err(|e|e.0)?)}
}
