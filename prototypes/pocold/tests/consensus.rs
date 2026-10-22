//! LP5 consensus tests: fresh-genesis production, replay determinism, D133 fork
//! choice (heavier / tied / signed-first), per-item H-pre/H-full rejections,
//! envelope-vs-block rejection, evidence, finality.
use std::collections::HashMap;
use pocold::{chain::{Chain,Reject,Spec},types::*,hashes,rlp};
use pocol_lp4_execution::{apply,devnet::{self,DevnetConfig},txsign::{Key,Tx}};
use revm::primitives::{Address,B256,U256};

struct Net{chain:Chain,keys:HashMap<Address,Key>}
fn cfg(miners:&[&str])->DevnetConfig{let mut c=DevnetConfig::new(777910,1_800_000_000,miners);c.target_g=devnet::to_fixed((U256::from(1)<<244)-U256::from(1));c.d_att=10;c.tau=40;c.c=8;c}
fn net_with(c:&DevnetConfig)->Net{
    let d=devnet::build(c).unwrap();let mut keys=HashMap::new();
    for m in &d.miners{keys.insert(m.id,Key::from_secret(&m.key.secret()).unwrap());}
    let spec=Spec{genesis_hash:d.genesis_hash.0,spec_bytes:d.spec_bytes,profile:d.profile,genesis:d.genesis};
    Net{chain:Chain::new(spec),keys}
}
fn net()->Net{net_with(&cfg(&["a","b","c"]))}

/// Mines a nonce for the header's template; fills shares (<= T_share) and winnerSig.
fn seal_block(n:&Net,h:lp1hdr::Header,body:Body,attempt:u32,start:u64)->Block{try_seal(n,h,body,attempt,start).expect("no solution in nonce space")}
/// None when the bounded nonce space holds no solution (probability ~e^-c).
fn try_seal(n:&Net,mut h:lp1hdr::Header,body:Body,attempt:u32,start:u64)->Option<Block>{
    let p=n.chain.get(&h.parent_hash).unwrap().clone();let ctx=n.chain.child_ctx(&p,attempt).unwrap();
    let tid=template_id(&h.ut_raw);let mut shares=vec![];let mut x=start;
    loop{if (x as u128)>=ctx.assignment.nonce_max(){return None}let ph=pow_hash(&tid,x);if le_target(&ph,&ctx.t_share){if le_target(&ph,&ctx.target){break}shares.push(x);}x+=1;}
    let owner=addr(&ctx.assignment.owner(x).unwrap());
    h.nonce=x;shares.truncate(256);h.shares=shares;reseal(&mut h);
    h.winner_sig=n.keys[&owner].sign_hash(&B256::from(hashes::win_msg(&tid,x,&share_root(&h))));reseal(&mut h);
    Some(Block{header:h,body})
}
mod lp1hdr{pub use pocold::header::Header;}
/// Fallback at attempt a; if its nonce space has no solution, the next attempt (consensus §4).
fn fallback(n:&Net,parent:[u8;32],a:u32)->Block{let p=n.chain.get(&parent).unwrap().clone();
    for a in a..a+16{let (h,_,_)=n.chain.build_fallback(&p,a).unwrap();if let Some(b)=try_seal(n,h,Body::default(),a,0){return b}}panic!("no fallback solution")}
/// Signed template by Draw(h,0); a different in-window timestamp is a new TemplateID.
fn signed(n:&Net,parent:[u8;32],body:Body,ts_offset:u64)->Block{
    let p=n.chain.get(&parent).unwrap().clone();let ctx=n.chain.child_ctx(&p,0).unwrap();
    for off in ts_offset..u64::from(n.chain.spec.cp().D_att){let (h,_,_)=n.chain.build_signed(&p,&n.keys[&ctx.proposer],ctx.window.lower()+off,body.clone(),vec![]).unwrap();
        if let Some(b)=try_seal(n,h,body.clone(),0,0){return b}}panic!("no signed solution")
}
fn import(n:&mut Net,b:&Block)->bool{let (e,_)=n.chain.validate(b,None,0).unwrap_or_else(|e|panic!("h={} {e:?}",b.header.h));n.chain.insert(e)}
fn reject(n:&Net,b:&Block)->Reject{n.chain.validate(b,None,0).err().expect("must reject")}
fn remine(n:&Net,mut h:lp1hdr::Header,body:Body)->Block{h.nonce=0;h.shares=vec![];reseal(&mut h);let a=h.a;
    // A mutated template may hold no solution; mutate the timestamp minimally only if needed is not allowed, so search the full space.
    seal_block(n,h,body,a,0)}

#[test] fn thirty_five_blocks_from_fresh_genesis_replay_identically(){
    let mut n=net();let mut blocks=vec![];
    let alice=devnet::account_key("alice");let bob=devnet::account_key("bob").address();
    let (mut nonce,mut sent)=(0u64,0u64);
    for i in 0..35u64{
        let head=n.chain.head;
        let b=if i%3==2{fallback(&n,head,0)}else{
            let txs=if i%5==1{nonce+=1;sent+=i;vec![Tx{chain_id:777910,nonce:nonce-1,max_priority:U256::from(1_000_000_000u64),max_fee:U256::from(100_000_000_000u64),gas:21000,to:Some(bob),value:U256::from(i),data:Default::default()}.sign_1559(&alice)]}else{vec![]};
            signed(&n,head,Body{txs,evidence:vec![]},0)};
        assert!(import(&mut n,&b),"new head at {i}");blocks.push(b);
    }
    assert_eq!(n.chain.head().height,35);
    assert_eq!(n.chain.head().state.accounts[&bob].info.balance,U256::from(10u128.pow(24))+U256::from(sent));assert_eq!(nonce,5);
    // Every miner earned rewards; ledger and pending invariants hold at the head.
    let s=&n.chain.head().state;for id in apply::record_list(s){assert!(s.accounts[&apply::miner_record(s,id).unwrap().reward].info.balance>U256::ZERO);}
    apply::check_escrow_invariant(s,&n.chain.spec.profile,35,false).unwrap();
    // Replay into a fresh chain: identical hashes and state roots for every block.
    let mut m=net();for b in &blocks{import(&mut m,b);}
    assert_eq!(m.chain.head,n.chain.head);
    for b in &blocks{let (x,y)=(&n.chain.blocks[&b.hash()],&m.chain.blocks[&b.hash()]);assert_eq!(apply::state_root(&x.state).unwrap(),apply::state_root(&y.state).unwrap());assert_eq!(x.result,y.result);}
}

/// Independent reference for D133: W, then key of the LCA children.
fn reference_best(n:&Net)->[u8;32]{
    let tips:Vec<[u8;32]>=n.chain.blocks.keys().copied().collect();
    let path=|h:[u8;32]|{let mut v=vec![];let mut c=Some(h);while let Some(x)=c{v.push(x);c=n.chain.blocks[&x].parent;}v.reverse();v};
    let key=|h:&[u8;32]|{let e=&n.chain.blocks[h];(if e.signed{0}else{1},e.import_seq,e.hash)};
    let mut best=tips[0];
    for t in tips{
        let (a,b)=(&n.chain.blocks[&t],&n.chain.blocks[&best]);
        let better=if a.total_work!=b.total_work{a.total_work>b.total_work}else if t==best{false}else{
            let (pa,pb)=(path(t),path(best));let i=pa.iter().zip(pb.iter()).take_while(|(x,y)|x==y).count();key(&pa[i])<key(&pb[i])};
        if better{best=t}
    }
    best
}
#[test] fn fork_choice_heavier_tied_signed_first_and_rollback(){
    let mut n=net();for _ in 0..5{let h=n.chain.head;let b=fallback(&n,h,0);import(&mut n,&b);}
    let base=n.chain.head;
    // Tie at h=6: fallback imported first, then signed sibling: signed-first wins.
    let fb=fallback(&n,base,0);let sg=signed(&n,base,Body::default(),0);
    assert_eq!(n.chain.blocks[&base].total_work+pocold::chain::work(&fb.header.target),n.chain.blocks[&base].total_work+pocold::chain::work(&sg.header.target));
    import(&mut n,&fb);assert_eq!(n.chain.head,fb.hash());
    assert!(import(&mut n,&sg),"signed sibling wins the tie");assert_eq!(n.chain.head,sg.hash());assert_eq!(n.chain.head,reference_best(&n));
    // Two fallback siblings at h=6 (different attempts): earlier import wins the tie
    let fb1=fallback(&n,base,fb.header.a+1);
    if n.chain.blocks[&base].total_work+pocold::chain::work(&fb1.header.target)==n.chain.blocks[&sg.hash()].total_work{import(&mut n,&fb1);assert_eq!(n.chain.head,sg.hash());}
    else{import(&mut n,&fb1);}
    assert_eq!(n.chain.head,reference_best(&n));
    // Heavier: extend the fallback branch by two blocks -> head moves (reorg).
    let a7=fallback(&n,fb.hash(),0);import(&mut n,&a7);let a8=fallback(&n,a7.hash(),0);import(&mut n,&a8);
    assert_eq!(n.chain.head,reference_best(&n));assert_eq!(n.chain.head,a8.hash());
    // Rollback determinism: each tip's stored state equals a fresh re-execution of its branch.
    let mut m=net();for b in [&fb,&a7,&a8]{let _=b;}
    let mut cur=n.chain.head;let mut path=vec![];while let Some(p)=n.chain.blocks[&cur].parent{path.push(cur);cur=p;}path.reverse();
    for h in &path{let e=n.chain.blocks[h].clone();let b=Block{header:e.header.clone(),body:e.body.clone()};import(&mut m,&b);}
    assert_eq!(apply::state_root(&m.chain.head().state).unwrap(),apply::state_root(&n.chain.head().state).unwrap());
    // Extend the signed branch to be heavier again -> reorg back.
    let b7=fallback(&n,sg.hash(),0);import(&mut n,&b7);let b8=fallback(&n,b7.hash(),0);import(&mut n,&b8);let b9=fallback(&n,b8.hash(),0);import(&mut n,&b9);
    assert_eq!(n.chain.head,reference_best(&n));assert_eq!(n.chain.head,b9.hash());
}

#[test] fn every_validity_item_rejects_its_mutation(){
    let mut n=net();for _ in 0..3{let h=n.chain.head;let b=fallback(&n,h,0);import(&mut n,&b);}
    let head=n.chain.head;
    let good=signed(&n,head,Body::default(),0);
    let block=|why:&str,r:Reject|match r{Reject::Block(s)=>assert!(s.contains(why),"expected {why}, got {s}"),o=>panic!("expected Block({why}), got {o:?}")};
    // 1b NetID.
    let mut h=good.header.clone();h.chain_id+=1;reseal(&mut h);block("netChain",reject(&n,&Block{header:h,body:Body::default()}));
    let mut h=good.header.clone();h.genesis_hash[0]^=1;reseal(&mut h);block("netGenesis",reject(&n,&Block{header:h,body:Body::default()}));
    // 2 height.
    let mut h=good.header.clone();h.h+=1;reseal(&mut h);block("2 height",reject(&n,&Block{header:h,body:Body::default()}));
    // 5 target (unsigned fallback copy so item 3 does not fire first).
    let fbg=fallback(&n,head,0);
    let mut h=fbg.header.clone();h.target=Fixed::from_be_slice(&(from_fixed(&h.target)>>1u32).to_be_bytes::<32>()).unwrap();reseal(&mut h);block("5 target",reject(&n,&Block{header:h,body:Body::default()}));
    // 6 nonce >= nMax, 7 PoW.
    let mut h=fbg.header.clone();h.nonce=u64::MAX;reseal(&mut h);block("6",reject(&n,&Block{header:h,body:Body::default()}));
    let ftid=template_id(&fbg.header.ut_raw);let target=fbg.header.target;
    let bad=(0..).find(|x|!le_target(&pow_hash(&ftid,*x),&target)).unwrap();
    let mut h=fbg.header.clone();h.nonce=bad;reseal(&mut h);block("7 pow",reject(&n,&Block{header:h,body:Body::default()}));
    let tid=template_id(&good.header.ut_raw);
    // 9 shares: unsorted, equal to nonce, above T_share.
    if good.header.shares.len()>=2{let mut h=good.header.clone();h.shares.swap(0,1);reseal(&mut h);block("9 shares not strictly ascending",reject(&n,&Block{header:h,body:Body::default()}));}
    let mut h=good.header.clone();h.shares=vec![h.nonce];reseal(&mut h);block("9 share range",reject(&n,&Block{header:h,body:Body::default()}));
    let p=n.chain.get(&head).unwrap().clone();let ctx=n.chain.child_ctx(&p,0).unwrap();
    let over=(0..).find(|x|*x!=good.header.nonce&&!le_target(&pow_hash(&tid,*x),&ctx.t_share)).unwrap();
    let mut h=good.header.clone();h.shares=vec![over];reseal(&mut h);block("9 share target",reject(&n,&Block{header:h,body:Body::default()}));
    // 11 gasLimit / baseFee (re-mined so PoW passes).
    let mut h=good.header.clone();h.gas_limit+=1;reseal(&mut h);let b=remine_signed(&n,h,ctx.proposer);block("11 gasLimit",reject(&n,&b));
    let mut h=good.header.clone();h.base_fee=to_fixed(from_fixed(&h.base_fee)+U256::from(1));reseal(&mut h);let b=remine_signed(&n,h,ctx.proposer);block("11 baseFee",reject(&n,&b));
    // 12 proposer not Draw(h,0): a validly signed template by another identity.
    let other=*n.keys.keys().find(|k|**k!=ctx.proposer).unwrap();
    let mut h=good.header.clone();h.proposer=other.to_vec();reseal(&mut h);let b=remine_signed(&n,h,other);block("12 proposer",reject(&n,&b));
    // 17 stateRoot.
    let mut h=good.header.clone();h.state_root[0]^=1;reseal(&mut h);let b=remine_signed(&n,h,ctx.proposer);block("17 stateRoot",reject(&n,&b));
    // Fallback: wrong timestamp (4) and non-empty body (12).
    let fb=fallback(&n,head,0);
    let mut h=fb.header.clone();h.ts+=1;reseal(&mut h);let b=remine(&n,h,Body::default());block("4 fallback timestamp",reject(&n,&b));
    let tx=Tx{chain_id:777910,nonce:0,max_priority:U256::from(1u64),max_fee:U256::from(10_000_000_000u64),gas:21000,to:Some(Address::ZERO),value:U256::ZERO,data:Default::default()}.sign_1559(&devnet::account_key("alice"));
    // A fallback header committing to the empty body plus a non-empty body is another copy (envelope);
    // a fallback header that commits to a non-empty body is invalid (12).
    let b=Block{header:fb.header.clone(),body:Body{txs:vec![tx.clone()],evidence:vec![]}};assert!(matches!(reject(&n,&b),Reject::Envelope(s) if s.contains("body does not match")));
    let body=Body{txs:vec![tx],evidence:vec![]};let mut h=fb.header.clone();h.tx_root=pocold::types::ordered_root(&body.txs).unwrap();reseal(&mut h);
    let b=remine(&n,h,body);block("12 fallback body",reject(&n,&b));
    // Envelope rejection: winnerSig from a non-owner rejects only this copy.
    let mut h=good.header.clone();h.winner_sig=n.keys[&other].sign_hash(&B256::from(hashes::win_msg(&tid,h.nonce,&share_root(&h))));reseal(&mut h);
    let copy=Block{header:h,body:Body::default()};
    if addr(&ctx.assignment.owner(good.header.nonce).unwrap())!=other{
        assert_eq!(copy.hash(),good.hash(),"winnerSig is not committed by blockHash");
        assert!(matches!(reject(&n,&copy),Reject::Envelope(_)));
    }
    assert!(import(&mut n,&good),"a valid copy of the same blockHash is still accepted");
    // Unknown parent.
    let mut h=good.header.clone();h.parent_hash=[7;32];reseal(&mut h);assert_eq!(reject(&n,&Block{header:h,body:Body::default()}),Reject::UnknownParent);
}
fn remine_signed(n:&Net,mut h:lp1hdr::Header,signer:Address)->Block{
    let tid=template_id(&h.ut_raw);h.sig=n.keys[&signer].sign_hash(&B256::from(hashes::sig_msg(&tid))).to_vec();reseal(&mut h);remine(n,h,Body::default())
}

#[test] fn evidence_type1_and_type2_punish_through_a_signed_block(){
    let mut n=net();for _ in 0..3{let h=n.chain.head;let b=fallback(&n,h,0);import(&mut n,&b);}
    // Type 1: the drawn proposer of h=4 signs two different templates.
    let head=n.chain.head;let p=n.chain.get(&head).unwrap().clone();let ctx=n.chain.child_ctx(&p,0).unwrap();let accused1=ctx.proposer;
    let (t1,_,_)=n.chain.build_signed(&p,&n.keys[&accused1],ctx.window.lower(),Body::default(),vec![]).unwrap();
    let (t2,_,_)=n.chain.build_signed(&p,&n.keys[&accused1],ctx.window.lower()+1,Body::default(),vec![]).unwrap();
    let st=|h:&lp1hdr::Header|{let mut p=h.ut_raw.clone();rlp::encode_bytes(&h.sig,&mut p);let mut o=Vec::new();rlp::encode_list_payload(&p,&mut o);o};
    let mut ev1=Vec::new();rlp::encode_bytes(&[1],&mut ev1);ev1.extend(st(&t1));ev1.extend(st(&t2));let mut e1=Vec::new();rlp::encode_list_payload(&ev1,&mut e1);
    let b4=seal_block(&n,t1.clone(),Body::default(),0,0);import(&mut n,&b4);
    // Type 2: the winner of h=4 signs a second share root for the same TemplateID+nonce.
    let winner=n.chain.head().result.clone().unwrap().winner;let tid=template_id(&b4.header.ut_raw);
    let mut alt=b4.header.clone();alt.shares=vec![];reseal(&mut alt);
    let root1=share_root(&b4.header);let root2=share_root(&alt);assert_ne!(root1,root2);
    let sig2=n.keys[&winner].sign_hash(&B256::from(hashes::win_msg(&tid,b4.header.nonce,&root2)));
    let mut ev2=Vec::new();rlp::encode_bytes(&[2],&mut ev2);rlp::encode_bytes(&tid,&mut ev2);rlp::encode_bytes(&b4.header.nonce.to_be_bytes(),&mut ev2);
    rlp::encode_bytes(&root1,&mut ev2);rlp::encode_bytes(&b4.header.winner_sig,&mut ev2);rlp::encode_bytes(&root2,&mut ev2);rlp::encode_bytes(&sig2,&mut ev2);
    let mut e2=Vec::new();rlp::encode_list_payload(&ev2,&mut e2);
    let mut evidence=vec![e1.clone()];if winner!=accused1{evidence.push(e2.clone());}
    // Include in a signed block at h=5 (the drawn proposer must not be one of the accused for this test to apply cleanly).
    let head=n.chain.head;let p=n.chain.get(&head).unwrap().clone();let ctx=n.chain.child_ctx(&p,0).unwrap();
    let effects=n.chain.evidence_effects(&p,&Body{txs:vec![],evidence:evidence.clone()},5).unwrap();
    assert_eq!(effects.len(),evidence.len());
    let (h,_,_)=n.chain.build_signed(&p,&n.keys[&ctx.proposer],ctx.window.lower(),Body{txs:vec![],evidence:evidence.clone()},effects).unwrap();
    let b5=seal_block(&n,h,Body{txs:vec![],evidence:evidence.clone()},0,0);import(&mut n,&b5);
    let s=&n.chain.head().state;
    let r=apply::miner_record(s,accused1).unwrap();assert!(r.tomb);assert_eq!(r.bond_state,2);
    if winner!=accused1{let r=apply::miner_record(s,winner).unwrap();assert!(r.tomb);assert_ne!(apply::pending(s,4).1>>168u32,U256::ZERO,"pot 4 invalidated");}
    // Re-using the same evidence later is invalid (accused already a tomb).
    let head=n.chain.head;let p=n.chain.get(&head).unwrap().clone();
    assert!(matches!(n.chain.evidence_effects(&p,&Body{txs:vec![],evidence:vec![e1]},6),Err(Reject::Block(_))));
}

#[test] fn final_block_has_no_child_and_h_end_is_enforced(){
    let mut c=cfg(&["a","b"]);c.h_close=4;c.h_end=9;let mut n=net_with(&c);
    let mut final_at=None;
    for _ in 0..9{let h=n.chain.head;let b=fallback(&n,h,0);import(&mut n,&b);if n.chain.head().is_final{final_at=Some(n.chain.head().height);break}}
    assert_eq!(final_at,Some(9));
    let s=&n.chain.head().state;for j in 1..=9{assert_eq!(apply::pending(s,j).1,U256::ZERO);}
    let head=n.chain.head;let p=n.chain.get(&head).unwrap().clone();
    assert!(n.chain.build_fallback(&p,0).is_err(),"no valid child above H_END/final");
}

#[test] fn k_hist_retention_and_trie_rebuild_for_deep_fork(){
    let mut n=net();n.chain.k_hist=4;let mut hashes=vec![n.chain.head];
    for _ in 0..12{let h=n.chain.head;let b=fallback(&n,h,0);import(&mut n,&b);n.chain.retain();hashes.push(n.chain.head);}
    let pruned:Vec<u64>=n.chain.blocks.values().filter(|e|e.pruned).map(|e|e.height).collect();
    assert!(pruned.iter().all(|h|*h>=1&&*h<=8)&&pruned.len()==8,"{pruned:?}");
    // A fork child of pruned height 3 needs TrieRebuild; the rebuilt state matches the committed root.
    let fork_parent=hashes[3];
    let mut m=net();for h in &hashes[1..=3]{let e=n.chain.blocks[h].clone();import(&mut m,&Block{header:e.header,body:e.body});}
    let child=fallback(&m,fork_parent,1);
    assert_eq!(n.chain.validate(&child,None,0).err(),Some(Reject::NeedsRebuild(fork_parent)));
    n.chain.ensure_state(&fork_parent).unwrap();assert!(n.chain.rebuilds>=3);
    let (e,_)=n.chain.validate(&child,None,0).unwrap();n.chain.insert(e);
    assert_eq!(apply::state_root(&n.chain.blocks[&fork_parent].state).unwrap().0,n.chain.blocks[&fork_parent].header.state_root);
}

#[test] fn template_form_classes_follow_d129(){
    let mut n=net();for _ in 0..2{let h=n.chain.head;let b=fallback(&n,h,0);import(&mut n,&b);}
    let head=n.chain.head;let good=signed(&n,head,Body::default(),0);
    // proposer present but sig removed: envelope (sig bytes are not committed).
    let mut h=good.header.clone();h.sig=vec![];reseal(&mut h);assert!(matches!(reject(&n,&Block{header:h,body:Body::default()}),Reject::Envelope(_)));
    // fallback-shaped header carrying a sig: envelope.
    let fb=fallback(&n,head,0);let mut h=fb.header.clone();h.sig=good.header.sig.clone();reseal(&mut h);assert!(matches!(reject(&n,&Block{header:h,body:Body::default()}),Reject::Envelope(_)));
    // proposer present with a != 0 is committed content: block reject.
    let mut h=good.header.clone();h.a=1;reseal(&mut h);assert!(matches!(reject(&n,&Block{header:h,body:Body::default()}),Reject::Block(s) if s.contains("a=0")));
}

#[test] fn node_detects_template_equivocation_and_produces_valid_evidence(){
    use pocold::{node::{Config,Event,Node},net::{Msg,NetEvent}};
    let c=cfg(&["a","b","c"]);let d=devnet::build(&c).unwrap();
    let keys:HashMap<Address,Key>=d.miners.iter().map(|m|(m.id,Key::from_secret(&m.key.secret()).unwrap())).collect();
    let spec=Spec{genesis_hash:d.genesis_hash.0,spec_bytes:d.spec_bytes.clone(),profile:d.profile.clone(),genesis:devnet::build(&c).unwrap().genesis};
    let dir=std::env::temp_dir().join(format!("pocold-ev-{}",std::process::id()));let _=std::fs::remove_dir_all(&dir);
    let mut node=Node::open(Config{dir,name:"t".into(),miner:None,listen:None,peers:vec![],rpc:None,delta_rel:600,phi:100_000_000,gamma:1,stop_at:None,log:false},spec).unwrap();
    node.handle(Event::Tick);
    let net2=Net{chain:Chain::new(Spec{genesis_hash:d.genesis_hash.0,spec_bytes:d.spec_bytes.clone(),profile:d.profile.clone(),genesis:d.genesis}),keys};
    let g=net2.chain.head;let p=net2.chain.get(&g).unwrap().clone();let ctx=net2.chain.child_ctx(&p,0).unwrap();
    let mk=|off:u64|{let (h,_,_)=net2.chain.build_signed(&p,&net2.keys[&ctx.proposer],ctx.window.lower()+off,Body::default(),vec![]).unwrap();h};
    let (t1,t2)=(mk(0),mk(1));
    // Simulate the node's production loop at h=1 (it starts producing on run(); use the handler directly).
    for t in [&t1,&t2]{node.handle(Event::Net(NetEvent::Message(1,Msg::Template{shell:t.encoded.clone(),body:Body::default().encode()})));}
    assert_eq!(node.evidence_pool.len(),1,"one type-1 evidence");
    // The evidence is valid in a block at h=2 on a branch whose h=1 drew the same proposer.
    let mut n2=net2;let b1=fallback(&n2,g,0);import(&mut n2,&b1);
    let head=n2.chain.head;let ph=n2.chain.get(&head).unwrap().clone();
    let eff=n2.chain.evidence_effects(&ph,&Body{txs:vec![],evidence:node.evidence_pool.clone()},2).unwrap();
    assert_eq!(eff,vec![apply::EvidenceEffect::Punish{accused:ctx.proposer}]);
}

#[test] fn journal_replay_rebuilds_pruned_state_for_a_journaled_fork(){
    // LP10 finding: a node that imported a fork child of a block below the K_hist window
    // (live TrieRebuild) must replay that journal; replay applies the same TrieRebuild.
    use pocold::node::{Config,Node};
    let c=cfg(&["a","b","c"]);let d=devnet::build(&c).unwrap();
    let spec=|| Spec{genesis_hash:d.genesis_hash.0,spec_bytes:d.spec_bytes.clone(),profile:d.profile.clone(),genesis:devnet::build(&c).unwrap().genesis};
    let dir=std::env::temp_dir().join(format!("pocold-replay-{}",std::process::id()));let _=std::fs::remove_dir_all(&dir);
    let conf=||Config{dir:dir.clone(),name:"r".into(),miner:None,listen:None,peers:vec![],rpc:None,delta_rel:600,phi:100_000_000,gamma:1,stop_at:None,log:false};
    let mut n=net();let mut hashes=vec![n.chain.head];
    let mut node=Node::open(conf(),spec()).unwrap();
    for _ in 0..70{let h=n.chain.head;let b=fallback(&n,h,0);import(&mut n,&b);node.import(b,None).unwrap();hashes.push(n.chain.head);}
    node.chain.retain();
    let fork_parent=hashes[3];
    let mut m=net();for h in &hashes[1..=3]{let e=n.chain.blocks[h].clone();import(&mut m,&Block{header:e.header,body:e.body});}
    let child=fallback(&m,fork_parent,1);let child_hash=child.hash();
    assert!(node.chain.blocks[&fork_parent].pruned,"fork parent below the K_hist window");
    node.import(child,None).expect("live import rebuilds the pruned parent");
    let head=node.chain.head;drop(node);
    let again=Node::open(conf(),spec()).expect("replay of a journal that contains a deep fork");
    assert_eq!(again.chain.head,head);assert!(again.chain.get(&child_hash).is_some());
    let _=std::fs::remove_dir_all(&dir);
}

#[test] fn a_valid_header_with_a_foreign_body_rejects_only_that_copy(){
    // Review finding (HIGH): a peer relaying a real header with a mismatched body must not get the
    // block marked invalid; the correct body is accepted afterwards.
    use pocold::node::{Config,Node};
    let c=cfg(&["a","b","c"]);let d=devnet::build(&c).unwrap();
    let spec=Spec{genesis_hash:d.genesis_hash.0,spec_bytes:d.spec_bytes.clone(),profile:d.profile.clone(),genesis:d.genesis};
    let dir=std::env::temp_dir().join(format!("pocold-copy-{}",std::process::id()));let _=std::fs::remove_dir_all(&dir);
    let mut node=Node::open(Config{dir:dir.clone(),name:"c".into(),miner:None,listen:None,peers:vec![],rpc:None,delta_rel:600,phi:100_000_000,gamma:1,stop_at:None,log:false},spec).unwrap();
    let n=net();let g=n.chain.head;let good=fallback(&n,g,0);
    let junk=Block{header:good.header.clone(),body:Body{txs:vec![vec![0xc0;40]],evidence:vec![]}};
    assert!(matches!(node.import(junk,None),Err(Reject::Envelope(_))),"mismatched body is an envelope rejection");
    assert!(node.import(good.clone(),None).expect("the real block is still accepted"),"becomes head");
    assert_eq!(node.chain.head,good.hash());
    let _=std::fs::remove_dir_all(&dir);
}

// ---------------- audit A01 regressions: unbound bodies never poison a valid header ----------------
fn a01_node(tag:&str)->(pocold::node::Node,std::path::PathBuf){
    use pocold::node::{Config,Node};
    let c=cfg(&["a","b","c"]);let d=devnet::build(&c).unwrap();
    let spec=Spec{genesis_hash:d.genesis_hash.0,spec_bytes:d.spec_bytes,profile:d.profile,genesis:d.genesis};
    let dir=std::env::temp_dir().join(format!("pocold-a01-{tag}-{}",std::process::id()));let _=std::fs::remove_dir_all(&dir);
    (Node::open(Config{dir:dir.clone(),name:"a01".into(),miner:None,listen:None,peers:vec![],rpc:None,delta_rel:600,phi:100_000_000,gamma:1,stop_at:None,log:false},spec).unwrap(),dir)
}
#[test] fn a01_malformed_or_unbound_bodies_reject_only_the_copy(){
    let n=net();let g=n.chain.head;let good=fallback(&n,g,0);
    let tx=Tx{chain_id:777910,nonce:0,max_priority:U256::from(1u64),max_fee:U256::from(10_000_000_000u64),gas:21000,to:Some(Address::ZERO),value:U256::ZERO,data:Default::default()}.sign_1559(&devnet::account_key("alice"));
    let copies:Vec<(&str,Body)>=vec![
        ("empty tx item",Body{txs:vec![vec![]],evidence:vec![]}),
        ("empty evidence item",Body{txs:vec![],evidence:vec![vec![]]}),
        ("empty tx among valid ones",Body{txs:vec![tx.clone(),vec![]],evidence:vec![]}),
        ("undecodable tx bytes",Body{txs:vec![vec![0xff,0x01,0x02]],evidence:vec![]}),
        ("undecodable evidence bytes",Body{txs:vec![],evidence:vec![vec![0xc1]]}),
        ("valid tx, header commits to the empty body",Body{txs:vec![tx],evidence:vec![]}),
        ("oversized tx item",Body{txs:vec![vec![0x02;200_000]],evidence:vec![]}),
    ];
    let (mut node,dir)=a01_node("copies");
    for (what,body) in &copies{
        let r=node.import(Block{header:good.header.clone(),body:body.clone()},None);
        assert!(matches!(r,Err(Reject::Envelope(_))),"{what}: must be an envelope rejection, got {r:?}");
    }
    assert!(node.import(good.clone(),None).expect("legitimate body after every malformed copy"),"becomes head");
    assert_eq!(node.chain.head,good.hash());
    let _=std::fs::remove_dir_all(&dir);
}
#[test] fn a01_committed_invalid_body_is_still_a_block_rejection_and_cached(){
    // The header commits to a body whose content is invalid: that is a verdict on the block hash.
    let mut n=net();for _ in 0..2{let h=n.chain.head;let b=fallback(&n,h,0);import(&mut n,&b);}
    let head=n.chain.head;let p=n.chain.get(&head).unwrap().clone();let ctx=n.chain.child_ctx(&p,0).unwrap();
    let good=signed(&n,head,Body::default(),0);
    let garbage=Body{txs:vec![vec![0x02,0xc0]],evidence:vec![]};
    let mut h=good.header.clone();h.tx_root=pocold::types::ordered_root(&garbage.txs).unwrap();reseal(&mut h);
    let mut b=remine_signed(&n,h,ctx.proposer);b.body=garbage;
    let r=n.chain.validate(&b,None,0);
    assert!(matches!(r,Err(Reject::Block(_))),"committed invalid content is a block rejection, got {:?}",r.err());
    // Through the node: the hash is cached as invalid and a resubmission is refused.
    let (mut node,dir)=a01_node("committed");
    let parent=n.chain.blocks[&head].parent.unwrap();
    for h in [parent,head]{let e=n.chain.blocks[&h].clone();node.import(Block{header:e.header,body:e.body},None).unwrap();}
    assert!(matches!(node.import(b.clone(),None),Err(Reject::Block(_))));
    assert!(matches!(node.import(b,None),Err(Reject::Block(s)) if s.contains("known invalid")),"cached verdict for committed content");
    let _=std::fs::remove_dir_all(&dir);
}
