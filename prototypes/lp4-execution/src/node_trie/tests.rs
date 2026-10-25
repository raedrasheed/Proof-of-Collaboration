use super::*;
use revm::primitives::Bytes;

struct Rng(u64);
impl Rng{fn next(&mut self)->u64{self.0^=self.0<<13;self.0^=self.0>>7;self.0^=self.0<<17;self.0}fn below(&mut self,n:u64)->u64{self.next()%n}}
fn codes()->Vec<Bytecode>{vec![Bytecode::default(),Bytecode::new_raw(Bytes::from_static(&[0x60,1,0x60,0,0x55])),Bytecode::new_raw(Bytes::from_static(&[0x00])),Bytecode::new_raw(Bytes::from_static(&[0x60,2,0x00]))]}
fn info(r:&mut Rng,codes:&[Bytecode])->AccountInfo{
    let code=codes[r.below(codes.len() as u64) as usize].clone();
    AccountInfo{balance:U256::from(r.below(1<<40)),nonce:r.below(5),code_hash:code.hash_slow(),code:Some(code)}
}
fn addr(r:&mut Rng,pool:u64)->Address{Address::from_word(B256::from(U256::from(r.below(pool))))}
fn random_state(r:&mut Rng,n:u64,codes:&[Bytecode])->InMemoryDB{
    let mut db=InMemoryDB::default();
    for _ in 0..n{let a=addr(r,4*n+8);db.insert_account_info(a,info(r,codes));for _ in 0..r.below(6){db.insert_account_storage(a,U256::from(r.below(50)),U256::from(r.below(4))).unwrap();}}
    db
}
/// One block's worth of changes, as `state_trie`'s test makes them: new and removed accounts, balance and
/// nonce changes, slots written, zeroed and cleared, an account marked not existing.
fn mutate(r:&mut Rng,db:&InMemoryDB,codes:&[Bytecode],pool:u64)->InMemoryDB{
    let mut d=db.clone();let addrs:Vec<Address>=d.accounts.keys().copied().collect();
    for _ in 0..1+r.below(20){
        let a=if addrs.is_empty()||r.below(4)==0{addr(r,pool)}else{addrs[r.below(addrs.len() as u64) as usize]};
        match r.below(7){
            0=>{d.accounts.remove(&a);}
            1=>{if let Some(x)=d.accounts.get_mut(&a){x.account_state=AccountState::NotExisting}}
            2=>{if let Some(x)=d.accounts.get_mut(&a){x.storage.clear();x.account_state=AccountState::StorageCleared}}
            3=>d.insert_account_info(a,info(r,codes)),
            _=>{if !d.accounts.contains_key(&a){d.insert_account_info(a,info(r,codes))}
                for _ in 0..1+r.below(4){d.insert_account_storage(a,U256::from(r.below(60)),U256::from(r.below(3))).unwrap();}}
        }
    }
    d
}
/// Every read the executor makes of a state, compared between the whole state and the trie version.
fn same_reads(db:&InMemoryDB,t:&dyn View,pool:u64,ctx:&str){
    let ex=|a:&Address|db.accounts.get(a).filter(|x|!matches!(x.account_state,AccountState::NotExisting)).is_some();
    for i in 0..pool{
        let a=Address::from_word(B256::from(U256::from(i)));
        let (p,q)=(db.account(&a).filter(|x|x.exists()),t.account(&a));
        assert_eq!(p.as_ref().map(|x|(x.info.nonce,x.info.balance,x.info.code_hash)),q.as_ref().map(|x|(x.info.nonce,x.info.balance,x.info.code_hash)),"{ctx}: account {i}");
        if let Some(q)=&q{
            let code=|v:&dyn View,i:&AccountInfo|i.code.clone().or_else(||v.contract(&i.code_hash)).map(|c|c.original_bytes());
            assert_eq!(code(db,&p.as_ref().unwrap().info),code(t,&q.info),"{ctx}: code of {i}");
        }
        for k in 0..60u64{let k=U256::from(k);assert_eq!(if ex(&a){db.slot(&a,&k)}else{U256::ZERO},t.slot(&a,&k),"{ctx}: slot {i}/{k}");}
        let (mut s1,mut s2)=(Vec::new(),Vec::new());
        if ex(&a){db.each_slot(&a,&mut |k,v|{if *v!=U256::ZERO{s1.push((*k,*v))}});}
        t.each_slot(&a,&mut |k,v|s2.push((*k,*v)));s1.sort();s2.sort();assert_eq!(s1,s2,"{ctx}: slots of {i}");
    }
    let mut x1:Vec<Address>=db.accounts.iter().filter(|(_,x)|!matches!(x.account_state,AccountState::NotExisting)).map(|(a,_)|*a).collect();
    let mut x2=Vec::new();t.each_account(&mut |a,acc|{assert!(acc.exists());x2.push(*a)});x1.sort();x2.sort();assert_eq!(x1,x2,"{ctx}: accounts");
}

#[test]
fn node_encodings_round_trip(){
    let codes=codes();let mut r=Rng(3);let db=random_state(&mut r,300,&codes);
    let s=MemStore::default();let mut b=Batch::default();let _=NodeTrie::build(&db,&s,&mut b);
    assert!(b.nodes.len()>300,"positive control: {} nodes",b.nodes.len());
    for (id,n) in &b.nodes{let e=n.encode();assert_eq!(Node::decode(&e).as_ref(),Some(&**n));assert_eq!(&keccak256(&e).0,id);
        assert!(Node::decode(&e[..e.len()-1]).is_none());let mut longer=e.clone();longer.push(0);assert!(Node::decode(&longer).is_none());}
}

#[test]
fn trie_versions_in_a_store_give_world_roots_and_the_state_reads(){
    let codes=codes();let mut r=Rng(0x4e3);
    for case in 0..12u64{
        let n=[0,1,2,40,150,300][case as usize%6];let pool=4*n+8;
        let mut db=random_state(&mut r,n,&codes);
        let mut store=MemStore::default();let mut b=Batch::default();
        let mut t=NodeTrie::build(&db,&store,&mut b);
        assert_eq!(t.root(&store,&b),crate::genesis_builder::world_root(&db).unwrap(),"case {case} build");
        store.commit(&b,t.world);
        let mut pinned:std::collections::VecDeque<(Option<Id>,InMemoryDB)>=[(t.world,db.clone())].into();
        for step in 0..25{
            let next=mutate(&mut r,&db,&codes,pool);let touched=Touched::between(&db,&next);
            let mut b=Batch::default();let u=t.update(&store,&mut b,&next,&touched);
            let root=u.root(&store,&b);
            assert_eq!(root,crate::genesis_builder::world_root(&next).unwrap(),"case {case} step {step}");
            assert_eq!(root,crate::state_trie::StateTrie::build(&next).root());
            store.commit(&b,u.world);pinned.push_back((u.world,next.clone()));
            // A window of four versions stays pinned; older ones are released.
            if pinned.len()>4{let (old,_)=pinned.pop_front().unwrap();if let Some(o)=old{store.unpin(&o)}}
            store.recount().unwrap_or_else(|e|panic!("case {case} step {step}: {e}"));
            // Every pinned version still reads as its own state.
            for (w,st) in &pinned{same_reads(st,&TrieState{store:&store,trie:NodeTrie{world:*w},block_hashes:&st.block_hashes},pool,&format!("case {case} step {step}"));}
            t=u;db=next;
        }
        for (w,_) in pinned{if let Some(w)=w{store.unpin(&w)}}
        assert!(store.nodes.is_empty(),"case {case}: {} nodes left after every root is released",store.nodes.len());
    }
}

#[test]
fn an_update_from_an_overlay_view_equals_the_update_from_its_merge(){
    // The executor gives its write set and the overlay itself (C-1 E3); the update must read the child
    // through the view, not through a whole state.
    let codes=codes();let mut r=Rng(91);
    let parent=random_state(&mut r,120,&codes);
    let store=MemStore::default();let mut b0=Batch::default();let t=NodeTrie::build(&parent,&store,&mut b0);
    let mut store=store;store.commit(&b0,t.world);
    for case in 0..40{
        let mut ov=crate::view::Overlay::new(&parent);
        for _ in 0..1+r.below(6){
            let a=addr(&mut r,488);let mut acct=revm::primitives::Account{info:ov.account(&a).map(|x|x.info).unwrap_or_default(),storage:Default::default(),status:revm::primitives::AccountStatus::Touched};
            match r.below(4){0=>acct.status|=revm::primitives::AccountStatus::SelfDestructed,1=>{acct.info.balance+=U256::from(7);}
                _=>{for _ in 0..3{let k=U256::from(r.below(50));let o=ov.slot(&a,&k);acct.storage.insert(k,revm::primitives::EvmStorageSlot::new_changed(o,U256::from(r.below(3))));}}}
            crate::user_phase::commit_tx_on(&mut ov,[(a,acct)].into(),true);
        }
        let merged=ov.merge();let touched=ov.touched();
        let mut b1=Batch::default();let mut b2=Batch::default();
        let via_view=t.update(&store,&mut b1,&ov,&touched);let via_merge=t.update(&store,&mut b2,&merged,&touched);
        assert_eq!(via_view,via_merge,"case {case}");
        assert_eq!(via_view.root(&store,&b1),crate::genesis_builder::world_root(&merged).unwrap(),"case {case}");
    }
}

/// p1_trie's root of raw 32-byte keys holding nonzero integers (as `state_trie`'s raw test).
fn reference(rows:&std::collections::BTreeMap<Key,U256>)->B256{
    let entries:Vec<(Vec<u8>,Vec<u8>)>=rows.iter().map(|(k,v)|{let mut e=Vec::new();rlp_uint(v,&mut e);(k.to_vec(),e)}).collect();
    B256::from(crate::trie::root(&entries,entries.len()).unwrap())
}
/// Keys that share long prefixes, so extensions above branches split and merge at every depth (hashed
/// keys almost never do).
fn clustered_key(r:&mut Rng)->Key{
    let mut k=[0u8;32];let shared=r.below(65) as usize;
    for i in 0..64{let n=if i<shared{(i%3) as u8}else{r.below(16) as u8};if i%2==0{k[i/2]|=n<<4}else{k[i/2]|=n}}
    k
}
#[test]
fn raw_clustered_keys_build_and_update_give_p1_roots(){
    let mut r=Rng(0x9e3779b97f4a7c15);let store=MemStore::default();
    for round in 0..300{
        let mut model=std::collections::BTreeMap::new();let mut b=Batch::default();let mut t:Option<(Id,Arc<Node>)>=None;
        for _ in 0..1+r.below(12){
            let mut ch:Vec<(Key,Option<Val>)>=Vec::new();
            for _ in 0..1+r.below(if round%2==0{4}else{40}){
                let k=if !model.is_empty()&&r.below(3)==0{*model.keys().nth(r.below(model.len() as u64) as usize).unwrap()}else{clustered_key(&mut r)};
                if ch.iter().any(|(x,_)|*x==k){continue}
                let small=r.below(2)==0;let v=if r.below(3)==0{None}else{Some(U256::from(1+r.below(if small{3}else{u64::MAX})))};
                ch.push((k,v.map(Val::Slot)));
            }
            ch.sort_by(|a,b|a.0.cmp(&b.0));
            for (k,v) in &ch{match v{Some(Val::Slot(v))=>{model.insert(*k,*v);}_=>{model.remove(k);}}}
            t=update(&store,&mut b,t,0,&ch);
            assert_eq!(root_of(t.as_ref().map(|x|&*x.1)),reference(&model),"round {round}");
        }
    }
}
