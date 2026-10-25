//! C-1 E4.2: state.redb, the node store of the state trie (pocold::state_store).
use pocold::state_store::StateStore;
use pocol_lp4_execution::node_trie::{Batch,Id,NodeStore,NodeTrie,TrieState};
use pocol_lp4_execution::state_trie::{StateTrie,Touched};
use pocol_lp4_execution::view::View;
use revm::{db::AccountState,primitives::{AccountInfo,Address,Bytecode,Bytes,B256,U256},InMemoryDB};

struct Rng(u64);
impl Rng{fn next(&mut self)->u64{self.0^=self.0<<13;self.0^=self.0>>7;self.0^=self.0<<17;self.0}fn below(&mut self,n:u64)->u64{self.next()%n}}
fn codes()->Vec<Bytecode>{vec![Bytecode::default(),Bytecode::new_raw(Bytes::from_static(&[0x60,1,0x60,0,0x55])),Bytecode::new_raw(Bytes::from_static(&[0x00]))]}
fn addr(r:&mut Rng,pool:u64)->Address{Address::from_word(B256::from(U256::from(r.below(pool))))}
fn info(r:&mut Rng,c:&[Bytecode])->AccountInfo{let code=c[r.below(c.len() as u64) as usize].clone();AccountInfo{balance:U256::from(r.below(1<<40)),nonce:r.below(5),code_hash:code.hash_slow(),code:Some(code)}}
fn state(r:&mut Rng,n:u64,c:&[Bytecode])->InMemoryDB{
    let mut db=InMemoryDB::default();
    for _ in 0..n{let a=addr(r,4*n);db.insert_account_info(a,info(r,c));for _ in 0..r.below(6){db.insert_account_storage(a,U256::from(r.below(50)),U256::from(r.below(4))).unwrap();}}
    db
}
fn mutate(r:&mut Rng,db:&InMemoryDB,c:&[Bytecode],pool:u64)->InMemoryDB{
    let mut d=db.clone();let addrs:Vec<Address>=d.accounts.keys().copied().collect();
    for _ in 0..1+r.below(20){
        let a=if addrs.is_empty()||r.below(4)==0{addr(r,pool)}else{addrs[r.below(addrs.len() as u64) as usize]};
        match r.below(7){
            0=>{d.accounts.remove(&a);}
            1=>{if let Some(x)=d.accounts.get_mut(&a){x.account_state=AccountState::NotExisting}}
            2=>{if let Some(x)=d.accounts.get_mut(&a){x.storage.clear();x.account_state=AccountState::StorageCleared}}
            3=>d.insert_account_info(a,info(r,c)),
            _=>{if !d.accounts.contains_key(&a){d.insert_account_info(a,info(r,c))}for _ in 0..1+r.below(4){d.insert_account_storage(a,U256::from(r.below(60)),U256::from(r.below(3))).unwrap();}}
        }
    }
    d
}
/// Every account, code and slot of `db` reads the same through the stored version.
fn same(db:&InMemoryDB,t:&TrieState<'_>,ctx:&str){
    for (a,x) in &db.accounts{
        let exists=!matches!(x.account_state,AccountState::NotExisting);let g=t.account(a);assert_eq!(g.is_some(),exists,"{ctx}: {a}");
        let Some(g)=g else{continue};
        assert_eq!((g.info.nonce,g.info.balance,g.info.code_hash),(x.info.nonce,x.info.balance,x.info.code_hash),"{ctx}: {a}");
        assert_eq!(g.info.code.map(|c|c.original_bytes()),x.info.code.clone().map(|c|c.original_bytes()),"{ctx}: code of {a}");
        let mut s1:Vec<(U256,U256)>=x.storage.iter().filter(|(_,v)|**v!=U256::ZERO).map(|(k,v)|(*k,*v)).collect();let mut s2=Vec::new();
        t.each_slot(a,&mut |k,v|s2.push((*k,*v)));s1.sort();s2.sort();assert_eq!(s1,s2,"{ctx}: slots of {a}");
        for (k,v) in &x.storage{assert_eq!(t.slot(a,k),*v,"{ctx}: {a} slot {k}");}
    }
}
fn dir(tag:&str)->std::path::PathBuf{let d=std::env::temp_dir().join(format!("pocold-e4-{tag}-{}",std::process::id()));let _=std::fs::remove_dir_all(&d);std::fs::create_dir_all(&d).unwrap();d}

#[test] fn stored_versions_have_their_roots_and_states_and_survive_reopen(){
    let c=codes();let mut r=Rng(0xe42);let d=dir("versions");
    let mut db=state(&mut r,200,&c);let pool=800;
    let mut pinned:std::collections::VecDeque<(Option<Id>,InMemoryDB)>=Default::default();
    {
        let s=StateStore::open(&d).unwrap();assert!(!s.rebuilt);
        let mut b=Batch::default();let mut t=NodeTrie::build(&db,&s,&mut b);
        assert_eq!(t.root(&s,&b),StateTrie::build(&db).root());
        s.commit(&b,t.world,true).unwrap();pinned.push_back((t.world,db.clone()));
        for step in 0..40{
            let next=mutate(&mut r,&db,&c,pool);let touched=Touched::between(&db,&next);
            let mut b=Batch::default();let u=t.update(&s,&mut b,&next,&touched);
            assert_eq!(u.root(&s,&b),StateTrie::build(&next).root(),"step {step}");
            assert_eq!(u.root(&s,&b),pocol_lp4_execution::apply::state_root(&next).unwrap(),"step {step}");
            s.commit(&b,u.world,step%3==0).unwrap();pinned.push_back((u.world,next.clone()));
            if pinned.len()>5{if let (Some(old),_)=pinned.pop_front().unwrap(){s.unpin(&old,false).unwrap()}}
            s.recount().unwrap_or_else(|e|panic!("step {step}: {e}"));
            t=u;db=next;
        }
        for (w,st) in &pinned{same(st,&TrieState{store:&s,trie:NodeTrie{world:*w},block_hashes:&st.block_hashes},"live");}
        assert!(s.writes.load(std::sync::atomic::Ordering::Relaxed)>500,"positive control: nodes were written");
        // A durable commit makes the earlier non-durable ones durable.
        let b=Batch::default();s.commit(&b,None,true).unwrap();
    }
    let s=StateStore::open(&d).unwrap();assert!(!s.rebuilt,"a clean store reopens as it is");
    s.recount().unwrap();assert_eq!(s.pins().unwrap().len(),pinned.iter().filter(|x|x.0.is_some()).count());
    for (w,st) in &pinned{same(st,&TrieState{store:&s,trie:NodeTrie{world:*w},block_hashes:&st.block_hashes},"reopened");}
    for (w,_) in &pinned{if let Some(w)=w{s.unpin(w,true).unwrap()}}
    assert_eq!(s.node_count().unwrap(),0,"releasing every pin empties the node table");
    let _=std::fs::remove_dir_all(&d);
}

#[test] fn a_damaged_node_is_never_served_and_the_store_is_rebuilt(){
    let c=codes();let mut r=Rng(5);let d=dir("damage");let db=state(&mut r,60,&c);
    let world={let s=StateStore::open(&d).unwrap();let mut b=Batch::default();let t=NodeTrie::build(&db,&s,&mut b);s.commit(&b,t.world,true).unwrap();t.world.unwrap()};
    // Overwrite the root node's bytes with another node's (a flipped record that still decodes).
    {
        let db2=redb::Database::open(d.join("state.redb")).unwrap();const NODES:redb::TableDefinition<&[u8;32],&[u8]>=redb::TableDefinition::new("node");
        let w=db2.begin_write().unwrap();{let mut t=w.open_table(NODES).unwrap();
            let other:Vec<u8>={use redb::ReadableTable;let it=t.iter().unwrap();let mut v=None;for kv in it{let (k,x)=kv.unwrap();if *k.value()!=world{v=Some(x.value().to_vec());break}}v.unwrap()};
            t.insert(&world,other.as_slice()).unwrap();}
        w.commit().unwrap();
    }
    let s=StateStore::open(&d).unwrap();assert!(!s.rebuilt,"redb's checksums hold: the damage is in a record");
    let e=s.try_node(&world).unwrap_err();assert!(e.0.contains("hash to its id"),"{}",e.0);
    assert!(s.is_damaged()&&d.join("state.redb.damaged").exists());
    assert!(s.try_node(&world).is_err(),"a damaged store serves nothing");
    assert!(s.pins().is_err()&&s.node_count().is_err(),"not even a node it holds intact");
    drop(s);let s=StateStore::open(&d).unwrap();assert!(s.rebuilt&&s.node_count().unwrap()==0,"the next open rebuilds it empty");
    drop(s);
    // A torn file is set aside and the store recreated.
    let f=d.join("state.redb");let len=std::fs::metadata(&f).unwrap().len();
    {let s=StateStore::open(&d).unwrap();let mut b=Batch::default();let t=NodeTrie::build(&db,&s,&mut b);s.commit(&b,t.world,true).unwrap();}
    let len2=std::fs::metadata(&f).unwrap().len();assert!(len2>=len);
    std::fs::OpenOptions::new().write(true).open(&f).unwrap().set_len(len2/2).unwrap();
    let s=StateStore::open(&d).unwrap();assert!(s.rebuilt,"a torn store is rebuilt");assert!(d.join("state.redb.aside").exists());
    let _=std::fs::remove_dir_all(&d);
}

#[test] fn a_small_node_cache_reads_the_same(){
    // The cache bound only changes how often the table is read: 4 KiB forces misses on nearly every node.
    let c=codes();let mut r=Rng(77);let d=dir("cache");let db=state(&mut r,300,&c);
    let s=StateStore::open_with(&d,4096).unwrap();let mut b=Batch::default();let t=NodeTrie::build(&db,&s,&mut b);s.commit(&b,t.world,true).unwrap();
    let reads0=s.reads.load(std::sync::atomic::Ordering::Relaxed);
    same(&db,&TrieState{store:&s,trie:t,block_hashes:&db.block_hashes},"small cache");
    assert!(s.reads.load(std::sync::atomic::Ordering::Relaxed)>reads0+1000,"positive control: the table was read on misses");
    assert_eq!(s.code(&c[1].hash_slow()).map(|x|x.original_bytes()),Some(c[1].original_bytes()));
    assert!(s.cache_bytes()<=4096,"the cache holds at most its bound: {}",s.cache_bytes());
    let _=std::fs::remove_dir_all(&d);
}

#[test] fn a_released_version_is_not_served_from_the_cache(){
    let c=codes();let mut r=Rng(19);let d=dir("release");let db=state(&mut r,80,&c);
    let s=StateStore::open(&d).unwrap();let mut b=Batch::default();let t=NodeTrie::build(&db,&s,&mut b);s.commit(&b,t.world,true).unwrap();
    let root=t.world.unwrap();
    same(&db,&TrieState{store:&s,trie:t,block_hashes:&db.block_hashes},"before release");assert!(s.cache_bytes()>0,"positive control: nodes are cached");
    s.unpin(&root,true).unwrap();
    assert!(s.try_node(&root).unwrap().is_none(),"a released node is gone from the table and the cache");
    assert_eq!(s.node_count().unwrap(),0);assert_eq!(s.cache_bytes(),0,"every released node left the cache");
    let _=std::fs::remove_dir_all(&d);
}

#[test] fn code_that_does_not_hash_to_its_key_is_never_served(){
    let c=codes();let mut r=Rng(23);let d=dir("code");let db=state(&mut r,40,&c);let h=c[1].hash_slow();
    {let s=StateStore::open(&d).unwrap();let mut b=Batch::default();let t=NodeTrie::build(&db,&s,&mut b);s.commit(&b,t.world,true).unwrap();assert!(s.code(&h).is_some());}
    {
        let db2=redb::Database::open(d.join("state.redb")).unwrap();const CODE:redb::TableDefinition<&[u8;32],&[u8]>=redb::TableDefinition::new("code");
        let w=db2.begin_write().unwrap();{let mut t=w.open_table(CODE).unwrap();t.insert(&h.0,&[0x60u8,9,0x00][..]).unwrap();}w.commit().unwrap();
    }
    let s=StateStore::open(&d).unwrap();
    let got=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||s.code(&h)));
    assert!(got.is_err(),"the code read refuses bytes that do not hash to the key");assert!(s.is_damaged(),"and marks the store damaged");
    drop(s);assert!(StateStore::open(&d).unwrap().rebuilt);
    let _=std::fs::remove_dir_all(&d);
}

/// C-1 E5: a store of another format (a store written before leaves kept their keys' preimages) is set
/// aside and rebuilt, never read; one of the current format reopens as it is.
#[test] fn a_store_of_another_format_is_rebuilt(){
    let d=std::env::temp_dir().join(format!("pocold-ss-format-{}",std::process::id()));let _=std::fs::remove_dir_all(&d);std::fs::create_dir_all(&d).unwrap();
    {let s=StateStore::open(&d).unwrap();assert!(!s.rebuilt);}
    {let s=StateStore::open(&d).unwrap();assert!(!s.rebuilt,"the current format reopens as it is");}
    {let db=redb::Database::open(d.join(pocold::state_store::FILE)).unwrap();let w=db.begin_write().unwrap();
     {let meta:redb::TableDefinition<&str,u64>=redb::TableDefinition::new("meta");let mut m=w.open_table(meta).unwrap();m.insert("format",1).unwrap();}w.commit().unwrap();}
    let s=StateStore::open(&d).unwrap();assert!(s.rebuilt,"format 1 is set aside and rebuilt");assert!(d.join(format!("{}.aside",pocold::state_store::FILE)).exists());
    drop(s);let _=std::fs::remove_dir_all(&d);
}

/// C-1 E4.4: a node a stored node names but the table does not hold (a record lost from the file) is not
/// served: the read answers None, which every reader of a version treats as fatal, and the store is marked
/// damaged, so nothing more is served from it and the next open rebuilds it.
#[test] fn a_missing_node_marks_the_store_damaged(){
    let c=codes();let mut r=Rng(31);let d=dir("missing");let db=state(&mut r,60,&c);
    let (world,child)={let s=StateStore::open(&d).unwrap();let mut b=Batch::default();let t=NodeTrie::build(&db,&s,&mut b);s.commit(&b,t.world,true).unwrap();
        let w=t.world.unwrap();(w,s.try_node(&w).unwrap().unwrap().children()[0])};
    {
        let db2=redb::Database::open(d.join("state.redb")).unwrap();const NODES:redb::TableDefinition<&[u8;32],&[u8]>=redb::TableDefinition::new("node");
        let w=db2.begin_write().unwrap();{let mut t=w.open_table(NODES).unwrap();assert!(t.remove(&child).unwrap().is_some());}w.commit().unwrap();
    }
    let s=StateStore::open(&d).unwrap();assert!(!s.rebuilt,"redb's checksums hold: a record is missing, not a page");
    assert!(s.try_node(&world).unwrap().is_some()&&!s.is_damaged(),"positive control: the root itself is intact");
    assert!(NodeStore::node(&s,&child).is_none(),"the missing node is not served");
    assert!(s.is_damaged()&&d.join("state.redb.damaged").exists(),"and the store is marked damaged");
    assert!(s.try_node(&world).is_err(),"a damaged store serves nothing");
    drop(s);assert!(StateStore::open(&d).unwrap().rebuilt,"the next open rebuilds it");
    let _=std::fs::remove_dir_all(&d);
}
