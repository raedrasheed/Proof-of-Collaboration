//! LP5 consensus tests: fresh-genesis production, replay determinism, D133 fork
//! choice (heavier / tied / signed-first), per-item H-pre/H-full rejections,
//! envelope-vs-block rejection, evidence, finality.
use std::collections::HashMap;
use pocold::{chain::{Chain,Reject,Spec},types::*,hashes,rlp};
use pocol_lp4_execution::{apply,devnet::{self,DevnetConfig},txsign::{Key,Tx}};
use revm::primitives::{Address,B256,U256};

struct Net{chain:Chain,keys:HashMap<Address,Key>}
/// Gate-valid test profile (A02): about 2^12 hashes per block (target 2^244-1 at T_blk=4),
/// c=8, and D_att=73 so that R7 holds with single-host timing: 73+5 >= 2(7+8*4).
/// Genesis is in the past: honest single-host Φ=0 tolerates no future timestamps.
fn cfg(miners:&[&str])->DevnetConfig{let mut c=DevnetConfig::new(777910,1_700_000_000,miners);c.hash_rate=1024;c.d_att=73;c.tau=40;c.c=8;c}
/// The admitted spec (full ParamGate with measured timing); a Devnet alone cannot boot.
fn admitted(c:&DevnetConfig)->Spec{let d=devnet::build(c).unwrap();Spec::new(d.admit(&pocold::single_host_local()).unwrap_or_else(|e|panic!("{e}")).0)}
fn net_with(c:&DevnetConfig)->Net{
    let d=devnet::build(c).unwrap();let mut keys=HashMap::new();
    for m in &d.miners{keys.insert(m.id,Key::from_secret(&m.key.secret()).unwrap());}
    Net{chain:Chain::new(admitted(c)),keys}
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
    apply::check_escrow_invariant(s,n.chain.spec.profile(),35,false).unwrap();
    // Replay into a fresh chain: identical hashes and state roots for every block.
    let mut m=net();for b in &blocks{import(&mut m,b);}
    assert_eq!(m.chain.head,n.chain.head);
    for b in &blocks{let (x,y)=(&n.chain.blocks[&b.hash()],&m.chain.blocks[&b.hash()]);assert_eq!(apply::state_root(&x.state).unwrap(),apply::state_root(&y.state).unwrap());assert_eq!(x.result,y.result);}
}

/// Independent reference for D133: W, then key of the LCA children.
fn reference_best(n:&Net)->[u8;32]{best_of(&n.chain)}
/// D133 over every stored block of a chain, computed from whole paths (not the incremental head).
fn best_of(chain:&Chain)->[u8;32]{
    let tips:Vec<[u8;32]>=chain.blocks.keys().copied().collect();
    let path=|h:[u8;32]|{let mut v=vec![];let mut c=Some(h);while let Some(x)=c{v.push(x);c=chain.blocks[&x].parent;}v.reverse();v};
    let key=|h:&[u8;32]|{let e=&chain.blocks[h];(if e.signed{0}else{1},e.import_seq,e.hash)};
    let mut best=tips[0];
    for t in tips{
        let (a,b)=(&chain.blocks[&t],&chain.blocks[&best]);
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
    // Gate-valid short end (end/full style): R_max=0 and a two-record registry make
    // R20 need Z_close >= ceil(2/2)+P2+D+1 = 8, so H_CLOSE+Z_close <= H_END=9 (R13).
    let mut c=cfg(&["a","b"]);c.h_close=1;c.h_end=9;c.r_max=0;c.m_max=2;c.reg_records_max=2;c.ret=2;c.z_close=8;let mut n=net_with(&c);
    let mut final_at=None;
    for _ in 0..9{let h=n.chain.head;let b=fallback(&n,h,0);import(&mut n,&b);if n.chain.head().is_final{final_at=Some(n.chain.head().height);break}}
    assert_eq!(final_at,Some(9));
    let s=&n.chain.head().state;for j in 1..=9{assert_eq!(apply::pending(s,j).1,U256::ZERO);}
    let head=n.chain.head;let p=n.chain.get(&head).unwrap().clone();
    assert!(n.chain.build_fallback(&p,0).is_err(),"no valid child above H_END/final");
}

#[test] fn ordinary_blocks_then_closing_then_final_at_h_end(){
    // Review finding: the test above runs with H_CLOSE=1, so the ordinary-to-closing transition is
    // covered here with the audited H_CLOSE=4 and the gate-valid H_END = H_CLOSE + Z_close = 12 (R13).
    let mut c=cfg(&["a","b"]);c.h_close=4;c.h_end=12;c.r_max=0;c.m_max=2;c.reg_records_max=2;c.ret=2;c.z_close=8;let mut n=net_with(&c);
    let mut closing=vec![];let mut final_at=None;
    for _ in 0..12{let h=n.chain.head;let b=fallback(&n,h,0);import(&mut n,&b);let e=n.chain.head();
        closing.push((e.height,apply::chain_facts(&e.state).closing));if e.is_final{final_at=Some(e.height);break}}
    assert!(closing.iter().filter(|(h,_)|*h<4).all(|(_,c)|!c),"ordinary below H_CLOSE: {closing:?}");
    assert!(closing.iter().filter(|(h,_)|*h>=4).all(|(_,c)|*c),"closing from H_CLOSE on: {closing:?}");
    assert_eq!(final_at,Some(12));
    let head=n.chain.head;let p=n.chain.get(&head).unwrap().clone();assert!(n.chain.build_fallback(&p,0).is_err(),"no valid child above H_END/final");
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
    let spec=admitted(&c);
    let dir=std::env::temp_dir().join(format!("pocold-ev-{}",std::process::id()));let _=std::fs::remove_dir_all(&dir);
    let mut node=Node::open(Config{dir,name:"t".into(),miner:None,listen:None,peers:vec![],rpc:None,stop_at:None,log:false,limits:Default::default()},spec).unwrap();
    node.handle(Event::Tick);
    let net2=Net{chain:Chain::new(admitted(&c)),keys};
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
    let c=cfg(&["a","b","c"]);
    let spec=|| admitted(&c);
    let dir=std::env::temp_dir().join(format!("pocold-replay-{}",std::process::id()));let _=std::fs::remove_dir_all(&dir);
    let conf=||Config{dir:dir.clone(),name:"r".into(),miner:None,listen:None,peers:vec![],rpc:None,stop_at:None,log:false,limits:Default::default()};
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
    let c=cfg(&["a","b","c"]);
    let spec=admitted(&c);
    let dir=std::env::temp_dir().join(format!("pocold-copy-{}",std::process::id()));let _=std::fs::remove_dir_all(&dir);
    let mut node=Node::open(Config{dir:dir.clone(),name:"c".into(),miner:None,listen:None,peers:vec![],rpc:None,stop_at:None,log:false,limits:Default::default()},spec).unwrap();
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
    let c=cfg(&["a","b","c"]);
    let spec=admitted(&c);
    let dir=std::env::temp_dir().join(format!("pocold-a01-{tag}-{}",std::process::id()));let _=std::fs::remove_dir_all(&dir);
    (Node::open(Config{dir:dir.clone(),name:"a01".into(),miner:None,listen:None,peers:vec![],rpc:None,stop_at:None,log:false,limits:Default::default()},spec).unwrap(),dir)
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

// ---------------- audit A03 regression: an over-limit log is an exceptional halt ----------------
#[test] fn a03_over_limit_log_halts_the_transaction_and_the_block_is_valid(){
    // The audited case: CREATE whose initcode emits LOG0 with 32769 data bytes (36+32769 > 32768).
    let mut n=net();let h=n.chain.head;let b=fallback(&n,h,0);import(&mut n,&b);
    let alice=devnet::account_key("alice");let before=n.chain.head().state.accounts[&alice.address()].info.clone();
    let init=vec![0x61,0x80,0x01,0x5f,0xa0,0x00];
    let tx=Tx{chain_id:777910,nonce:0,max_priority:U256::from(1u64),max_fee:U256::from(100_000_000_000u64),gas:2_000_000,to:None,value:U256::ZERO,data:init.into()}.sign_1559(&alice);
    let head=n.chain.head;let blk=signed(&n,head,Body{txs:vec![tx],evidence:vec![]},0);
    let (e,_)=n.chain.validate(&blk,None,0).expect("the block stays valid");
    let it=rlp::decode(&e.receipts[0][1..]).unwrap();let l=it.list().unwrap();
    assert_eq!(l[0].bytes().unwrap(),&[] as &[u8],"status 0");assert_eq!(l[3].list().unwrap().len(),0,"no logs");
    assert_eq!(e.gas_used,2_000_000,"all gas charged");assert_eq!(e.cum_log_bytes,0,"a halted transaction charges no log bytes");
    let a=&e.state.accounts[&alice.address()].info;assert_eq!(a.nonce,before.nonce+1);assert!(a.balance<before.balance);
    assert!(n.chain.insert(e),"becomes head");
    // Within the limit the same pattern succeeds and the chain accumulates its log bytes.
    let init=vec![0x61,0x7f,0xdc,0x5f,0xa0,0x00];// LOG0 with 32732 bytes: 36+32732 = 32768
    let tx=Tx{chain_id:777910,nonce:1,max_priority:U256::from(1u64),max_fee:U256::from(100_000_000_000u64),gas:2_000_000,to:None,value:U256::ZERO,data:init.into()}.sign_1559(&alice);
    let head=n.chain.head;let blk=signed(&n,head,Body{txs:vec![tx],evidence:vec![]},0);
    let (e,_)=n.chain.validate(&blk,None,0).unwrap();let it=rlp::decode(&e.receipts[0][1..]).unwrap();
    assert_eq!(it.list().unwrap()[0].bytes().unwrap(),&[1u8]);assert_eq!(e.cum_log_bytes,32768);
}

// ---------------- audit A11 regressions: detached transactions return to the pool ----------------
fn a11_node(tag:&str)->(pocold::node::Node,std::path::PathBuf){
    use pocold::node::{Config,Node};
    let dir=std::env::temp_dir().join(format!("pocold-a11-{tag}-{}",std::process::id()));let _=std::fs::remove_dir_all(&dir);
    (Node::open(Config{dir:dir.clone(),name:"a11".into(),miner:None,listen:None,peers:vec![],rpc:None,stop_at:None,log:false,limits:Default::default()},admitted(&cfg(&["a","b","c"]))).unwrap(),dir)
}
fn pay(key:&Key,nonce:u64,value:u64)->Vec<u8>{Tx{chain_id:777910,nonce,max_priority:U256::from(1_000_000_000u64),max_fee:U256::from(100_000_000_000u64),gas:21000,to:Some(devnet::account_key("bob").address()),value:U256::from(value),data:Default::default()}.sign_1559(key)}
fn pool(n:&pocold::node::Node)->Vec<Vec<u8>>{n.pool.txs.iter().map(|(_,r)|r.clone()).collect()}
/// Builds `count` fallback blocks on `parent` in harness `h` (importing them there) and returns them.
fn branch(h:&mut Net,parent:[u8;32],count:usize,bodies:&[Body])->Vec<Block>{
    let mut out=vec![];let mut p=parent;
    for i in 0..count{let b=match bodies.get(i){Some(body) if !body.txs.is_empty()=>signed(h,p,body.clone(),0),_=>fallback(h,p,0)};import(h,&b);p=b.hash();out.push(b);}
    out
}
#[test] fn a11_reorg_restores_detached_transactions_without_resubmission(){
    let alice=devnet::account_key("alice");let t0=pay(&alice,0,7);
    let (mut node,dir)=a11_node("restore");let mut h=net();let g=h.chain.head;
    node.submit_tx(t0.clone(),false).unwrap();assert_eq!(pool(&node),vec![t0.clone()]);
    // submit -> mine: the block carrying t0 becomes head and t0 leaves the pool.
    let old=branch(&mut h,g,1,&[Body{txs:vec![t0.clone()],evidence:vec![]}]);
    assert!(node.import(old[0].clone(),None).unwrap());assert!(pool(&node).is_empty());
    // A heavier competing branch without t0: t0 is detached and returns, still valid.
    let mut h2=net();let new=branch(&mut h2,g,2,&[]);
    for b in &new{node.import(b.clone(),None).unwrap();}
    assert_eq!(node.chain.head,new[1].hash(),"reorganized to the heavier branch");
    assert_eq!(pool(&node),vec![t0],"the detached transaction is back in the pool");
    let _=std::fs::remove_dir_all(&dir);
}
#[test] fn a11_excludes_included_and_conflicting_transactions_and_keeps_order(){
    let alice=devnet::account_key("alice");let bob=devnet::account_key("bob");
    let (t0,t1,t2)=(pay(&alice,0,1),pay(&alice,1,2),pay(&bob,0,3));
    let conflict=pay(&alice,0,99);// same nonce as t0, different transaction
    // Old branch: two blocks [t0], [t1] plus t2 waiting in the pool.
    let (mut node,dir)=a11_node("order");let mut h=net();let g=h.chain.head;
    let old=branch(&mut h,g,2,&[Body{txs:vec![t0.clone()],evidence:vec![]},Body{txs:vec![t1.clone()],evidence:vec![]}]);
    for b in &old{node.import(b.clone(),None).unwrap();}
    node.submit_tx(t2.clone(),false).unwrap();node.submit_tx(t2.clone(),false).unwrap();assert_eq!(pool(&node),vec![t2.clone()],"duplicates are kept once");
    // Multiple detached blocks, oldest first, then the previous pool.
    let mut h2=net();let new=branch(&mut h2,g,3,&[]);
    for b in &new{node.import(b.clone(),None).unwrap();}
    assert_eq!(node.chain.head,new[2].hash());assert_eq!(pool(&node),vec![t0.clone(),t1.clone(),t2.clone()]);
    // The new canonical branch includes a different transaction with alice's nonce 0: every
    // detached transaction is revalidated on the new head.
    let (mut node,dir2)=a11_node("conflict");let mut h=net();let g=h.chain.head;
    let old=branch(&mut h,g,2,&[Body{txs:vec![t0.clone()],evidence:vec![]},Body{txs:vec![t1.clone()],evidence:vec![]}]);
    for b in &old{node.import(b.clone(),None).unwrap();}
    let mut h2=net();let new=branch(&mut h2,g,3,&[Body{txs:vec![conflict.clone()],evidence:vec![]},Body::default(),Body::default()]);
    for b in &new{node.import(b.clone(),None).unwrap();}
    assert_eq!(node.chain.head,new[2].hash());
    assert_eq!(pool(&node),vec![t1.clone()],"t0 conflicts with the included nonce 0 and is dropped; t1 (nonce 1) is valid again");
    // A branch that includes t0 itself: t0 is not restored (already canonical).
    let (mut node,dir3)=a11_node("included");let mut h=net();let g=h.chain.head;
    let old=branch(&mut h,g,1,&[Body{txs:vec![t0.clone()],evidence:vec![]}]);node.import(old[0].clone(),None).unwrap();
    let mut h2=net();let new=branch(&mut h2,g,2,&[Body::default(),Body{txs:vec![t0.clone()],evidence:vec![]}]);
    for b in &new{node.import(b.clone(),None).unwrap();}
    assert_eq!(node.chain.head,new[1].hash());assert!(pool(&node).is_empty(),"included on the new branch: not restored");
    for d in [dir,dir2,dir3]{let _=std::fs::remove_dir_all(&d);}
}

// ---------------- audit A13 regressions: enforced resource assumptions ----------------
fn admitted_with(c:&DevnetConfig,local:pocol_lp4_execution::admission::NodeLocal)->Spec{Spec::new(devnet::build(c).unwrap().admit(&local).unwrap_or_else(|e|panic!("{e}")).0)}
#[test] fn a13_side_branch_states_are_capped_and_rebuilt_on_demand(){
    let local=pocol_lp4_execution::admission::NodeLocal{side_max:2,..pocold::single_host_local()};
    let c=cfg(&["a","b","c"]);let d=devnet::build(&c).unwrap();let mut keys=HashMap::new();
    for m in &d.miners{keys.insert(m.id,Key::from_secret(&m.key.secret()).unwrap());}
    let mut n=Net{chain:Chain::new(admitted_with(&c,local)),keys};let g=n.chain.head;
    // Five competing children of genesis (attempts 0..4) and a canonical extension.
    let kids:Vec<Block>=(0..5u32).map(|a|fallback(&n,g,a)).collect();
    for b in &kids{let (e,_)=n.chain.validate(b,None,0).unwrap();n.chain.insert(e);n.chain.retain();}
    let (side,with_state)=n.chain.side_counts();assert_eq!(side,4);assert!(with_state<=2,"at most side_max side states: {with_state}");
    // A pruned side block is rebuilt when a child extends it.
    let pruned=kids.iter().map(|b|b.hash()).find(|h|!n.chain.is_canonical(h)&&n.chain.blocks[h].pruned).expect("a pruned side block");
    let child=fallback_on_pruned(&mut n,pruned);
    let (e,_)=match n.chain.validate(&child,None,0){Err(Reject::NeedsRebuild(p))=>{n.chain.ensure_state(&p).unwrap();n.chain.validate(&child,None,0).unwrap()}r=>r.unwrap()};
    assert!(n.chain.insert(e),"the rebuilt branch is now the heaviest");
}
/// Builds a fallback child of `parent` after rebuilding its state in a scratch copy.
fn fallback_on_pruned(n:&mut Net,parent:[u8;32])->Block{n.chain.ensure_state(&parent).unwrap();fallback(n,parent,0)}
#[test] fn a13_rebuild_of_a_deep_fork_keeps_only_the_target_state(){
    let mut n=net();n.chain.k_hist=4;let mut hashes=vec![n.chain.head];
    for _ in 0..14{let h=n.chain.head;let b=fallback(&n,h,0);import(&mut n,&b);n.chain.retain();hashes.push(n.chain.head);}
    let target=hashes[6];assert!(n.chain.blocks[&target].pruned);
    n.chain.ensure_state(&target).unwrap();
    assert!(!n.chain.blocks[&target].pruned,"target rebuilt");
    for h in &hashes[1..6]{assert!(n.chain.blocks[h].pruned,"intermediate states are not kept (rolling rebuild)");}
}
#[test] fn a13_boot_refuses_a_bound_above_the_memory_budget(){
    use pocold::node::{Config,Limits,Node};
    let dir=std::env::temp_dir().join(format!("pocold-a13-{}",std::process::id()));
    let conf=|limits:Limits,peers:usize|Config{dir:dir.clone(),name:"a13".into(),miner:None,listen:None,peers:(0..peers).map(|i|format!("127.0.0.1:{}",1+i).parse().unwrap()).collect(),rpc:None,stop_at:None,log:false,limits};
    let l=pocold::single_host_local();let default=admitted(&cfg(&["a","b","c"]));
    // The devnet's own configuration: default limits, two configured peers.
    let d=pocold::resources::derive(default.cp(),l.k_hist,l.side_max,&Limits::default(),2).unwrap();
    let need=pocold::resources::budget_required(d.total).unwrap();
    // 1. The approved default boots, with its 1/8 reserve inside the 6 GiB budget.
    assert!(need<=u128::from(pocold::node::MEM_BUDGET),"the default needs {need} B: {d:?}");
    let _=std::fs::remove_dir_all(&dir);
    Node::open(conf(Limits::default(),2),default).expect("the approved default devnet boots");
    // 2. A budget one byte below what that bound requires is refused.
    let _=std::fs::remove_dir_all(&dir);
    let err=Node::open(conf(Limits{mem_budget:(need-1) as u64,..Default::default()},2),admitted(&cfg(&["a","b","c"]))).err().expect("a budget below the requirement is refused");
    assert!(err.starts_with("A13 memory bound")&&err.contains("exceeds the node memory budget"),"{err}");
    // 3. The requirement itself boots (the boundary is exact).
    let _=std::fs::remove_dir_all(&dir);
    Node::open(conf(Limits{mem_budget:need as u64,..Default::default()},2),admitted(&cfg(&["a","b","c"]))).expect("exactly the required budget boots");
    // 4. Network-scale caps cannot be held by a full-snapshot node within the default budget.
    let mut big=cfg(&["a","b","c"]);big.slot_cap=4_000_000;big.acct_cap=1_000_000;
    let _=std::fs::remove_dir_all(&dir);
    let err=Node::open(conf(Limits::default(),2),admitted(&big)).err().expect("network-scale caps exceed the budget");assert!(err.contains("exceeds the node memory budget"),"{err}");
    let mib=|x:u128|format!("{:.1}",x as f64/1048576.0);
    println!("A13-BOUND {}",serde_json::json!({"totalBytes":d.total.to_string(),"totalGiB":format!("{:.3}",d.total as f64/1073741824.0),"requiredBudgetBytes":need.to_string(),"budgetGiB":pocold::node::MEM_BUDGET>>30,
        "snapshots":d.snapshots,"snapshotMiB":mib(d.snapshot_bytes),"codeMiB":mib(d.code),"historyMiB":mib(d.history),"sideBlocksMiB":mib(d.side_blocks),"queuesMiB":mib(d.queues),"rpcMiB":mib(d.rpc),"threadsMiB":mib(d.threads),"executionMiB":mib(d.execution)}));
    let _=std::fs::remove_dir_all(&dir);
}

// ---------------- review finding (A13): the pool's pending state follows the block caps ----------------
#[test] fn a13_pool_pending_state_is_capped_and_normalized(){
    use pocold::node::{Config,Node};
    let mut c=cfg(&["a","b","c"]);c.slot_cap=40;
    let dir=std::env::temp_dir().join(format!("pocold-a13-pool-{}",std::process::id()));let _=std::fs::remove_dir_all(&dir);
    let mut node=Node::open(Config{dir:dir.clone(),name:"pool".into(),miner:None,listen:None,peers:vec![],rpc:None,stop_at:None,log:false,limits:Default::default()},admitted(&c)).unwrap();
    // Each CREATE stores 16 fresh slots in its constructor and leaves an account without code.
    let mut init=Vec::new();for i in 0..16u8{init.extend([0x60,0x01,0x60,i,0x55]);}init.push(0x00);
    let alice=devnet::account_key("alice");
    let create=|nonce:u64|Tx{chain_id:777910,nonce,max_priority:U256::from(1_000_000_000u64),max_fee:U256::from(100_000_000_000u64),gas:1_000_000,to:None,value:U256::ZERO,data:init.clone().into()}.sign_1559(&alice);
    let slots=|n:&Node|n.pool_state().accounts.values().filter(|a|a.info().is_some()).map(|a|a.storage.values().filter(|v|**v!=U256::ZERO).count()).sum::<usize>();
    let base=slots(&node);
    assert!(node.submit_tx(create(0),false).is_ok()&&node.submit_tx(create(1),false).is_ok(),"32 of 40 slots");
    let e=node.submit_tx(create(2),false).unwrap_err();assert!(e.contains("SlotCap"),"{e}");
    assert_eq!(node.pool.txs.len(),2);assert_eq!(slots(&node),base+32,"the refused transaction left no effects");
    // Reads and empty calls leave no residue in the pending state (normalize).
    let mut read=Vec::new();for i in 0..200u8{read.extend([0x60,i,0x54,0x50]);}read.push(0x00);
    let entries=|n:&Node|n.pool_state().accounts.values().map(|a|a.storage.len()).sum::<usize>();let e0=entries(&node);
    let tx=Tx{chain_id:777910,nonce:2,max_priority:U256::from(1_000_000_000u64),max_fee:U256::from(100_000_000_000u64),gas:1_000_000,to:None,value:U256::ZERO,data:read.into()}.sign_1559(&alice);
    node.submit_tx(tx,false).unwrap();assert_eq!(entries(&node),e0,"200 SLOADs add no storage entries");
    // Second review: zero-value calls touch empty accounts. They are removed as in a block (EIP-161),
    // so neither the pending state nor the meter drifts.
    let profile=admitted(&c);let recount=|n:&Node|pocol_lp4_execution::user_phase::PoolMeter::of(n.pool_state(),profile.profile()).live();
    let accounts=|n:&Node|n.pool_state().accounts.len();let a0=accounts(&node);assert_eq!(node.pool_live(),recount(&node));
    for k in 0..3u64{let to=Address::from([0xee;20]);
        let tx=Tx{chain_id:777910,nonce:3+k,max_priority:U256::from(1_000_000_000u64),max_fee:U256::from(100_000_000_000u64),gas:21000,to:Some(to),value:U256::ZERO,data:Default::default()}.sign_1559(&alice);
        node.submit_tx(tx,false).unwrap();assert_eq!(node.pool_live(),recount(&node),"meter = recount after zero-value transfer {k}");}
    // A constructor making 300 zero-value CALLs to fresh addresses leaves none of them behind.
    let mut calls=Vec::new();for i in 0..300u16{calls.extend([0x60,0x00,0x60,0x00,0x60,0x00,0x60,0x00,0x60,0x00,0x61,(i>>8) as u8,i as u8,0x61,0xff,0xff,0xf1,0x50]);}calls.push(0x00);
    let tx=Tx{chain_id:777910,nonce:6,max_priority:U256::from(1_000_000_000u64),max_fee:U256::from(100_000_000_000u64),gas:8_000_000,to:None,value:U256::ZERO,data:calls.into()}.sign_1559(&alice);
    node.submit_tx(tx,false).unwrap();assert_eq!(node.pool_live(),recount(&node),"meter = recount after 300 empty calls");
    assert!(accounts(&node)<=a0+2,"touched empty accounts are not kept: {} -> {}",a0,accounts(&node));
    let _=std::fs::remove_dir_all(&dir);
}

// ---------------- review finding (A05): range sync continues after a truncated response ----------------
#[test] fn range_sync_reaches_the_peer_head_through_truncated_responses(){
    use pocold::node::{Config,Limits,Node};
    use std::io::{Read,Write};
    let port=||std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let c=cfg(&["a","b","c"]);let mut n=net();let mut blocks=vec![];
    for _ in 0..120{let h=n.chain.head;let b=fallback(&n,h,0);import(&mut n,&b);blocks.push(b);}
    // A small peer queue: every range response stops after about 16 KiB (half the queue).
    let mut l=Limits::default();l.net.queue_bytes_max=32*1024;
    let (pa,pb,rb)=(port(),port(),port());let tag=std::process::id();
    let dir=|x:&str|{let d=std::env::temp_dir().join(format!("pocold-sync-{x}-{tag}"));let _=std::fs::remove_dir_all(&d);d};
    let mut a=Node::open(Config{dir:dir("a"),name:"a".into(),miner:None,listen:Some(format!("127.0.0.1:{pa}").parse().unwrap()),peers:vec![],rpc:None,stop_at:None,log:false,limits:l.clone()},admitted(&c)).unwrap();
    for b in blocks{a.import(b,None).unwrap();}assert_eq!(a.chain.head().height,120);
    a.start_network().unwrap();std::thread::spawn(move||a.run());
    let mut b=Node::open(Config{dir:dir("b"),name:"b".into(),miner:None,listen:Some(format!("127.0.0.1:{pb}").parse().unwrap()),peers:vec![format!("127.0.0.1:{pa}").parse().unwrap()],
        rpc:Some(format!("127.0.0.1:{rb}").parse().unwrap()),stop_at:None,log:false,limits:l},admitted(&c)).unwrap();
    b.start_network().unwrap();std::thread::spawn(move||b.run());
    let height=||->u64{let Ok(mut s)=std::net::TcpStream::connect(("127.0.0.1",rb)) else{return 0};let body=r#"{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}"#;
        let _=write!(s,"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n{body}",body.len());let mut o=String::new();let _=s.read_to_string(&mut o);
        o.split("\"result\":\"0x").nth(1).and_then(|x|u64::from_str_radix(x.split('"').next()?,16).ok()).unwrap_or(0)};
    let t=std::time::Instant::now();while height()<120&&t.elapsed()<std::time::Duration::from_secs(60){std::thread::sleep(std::time::Duration::from_millis(200));}
    assert_eq!(height(),120,"B syncs all 120 blocks from A (one Hello, truncated range responses)");
}

// ---------------- review finding: BODY_MAX bounds the encoded body on every path ----------------
#[test] fn body_max_bounds_the_encoded_body_not_the_item_sum(){
    let mut n=net();for _ in 0..2{let h=n.chain.head;let b=fallback(&n,h,0);import(&mut n,&b);}
    let head=n.chain.head;let p=n.chain.get(&head).unwrap().clone();let ctx=n.chain.child_ctx(&p,0).unwrap();
    let max=n.chain.spec.cp().BODY_MAX as usize;let k=max/100;
    // k items of 100 bytes: the raw sum fits BODY_MAX, the encoding (2-byte item headers) does not.
    let body=Body{txs:vec![vec![0x02;100];k],evidence:vec![]};assert!(k*100<=max&&body.encode().len()>max);
    let good=signed(&n,head,Body::default(),0);
    let mut h=good.header.clone();h.tx_root=pocold::types::ordered_root(&body.txs).unwrap();reseal(&mut h);
    let mut b=remine_signed(&n,h,ctx.proposer);b.body=body.clone();
    assert!(matches!(n.chain.validate(&b,None,0),Err(Reject::Block(s)) if s.contains("BODY_MAX")),"the locally checked limit is the encoded one");
    assert!(Body::decode(&body.encode(),max).is_err(),"peers reject the same body at decode");
}

// ---------------- second review: eth_getLogs limits answer -32020 with resume data (network.md:298) ----------------
#[test] fn get_logs_limits_answer_32020_with_resume_data(){
    use pocold::node::{Config,Node};
    let mut n=net();let alice=devnet::account_key("alice");
    // Init code: 546 LOG0 of zero bytes (the per-block log count limit), then STOP.
    let mut init=vec![0x61,0x02,0x22,0x5b];// PUSH2 546; JUMPDEST(3)
    init.extend([0x5f,0x5f,0xa0,0x60,0x01,0x90,0x03,0x80,0x60,0x03,0x57,0x00]);// PUSH0 PUSH0 LOG0; PUSH1 1 SWAP1 SUB; DUP1 PUSH1 3 JUMPI; STOP
    let mut first=0;
    for k in 0..19u64{let head=n.chain.head;
        let tx=Tx{chain_id:777910,nonce:k,max_priority:U256::from(1u64),max_fee:U256::from(100_000_000_000u64),gas:2_000_000,to:None,value:U256::ZERO,data:init.clone().into()}.sign_1559(&alice);
        let b=signed(&n,head,Body{txs:vec![tx],evidence:vec![]},0);import(&mut n,&b);if k==0{first=n.chain.head().height;}}
    let dir=std::env::temp_dir().join(format!("pocold-logs-{}",std::process::id()));let _=std::fs::remove_dir_all(&dir);
    let mut node=Node::open(Config{dir:dir.clone(),name:"logs".into(),miner:None,listen:None,peers:vec![],rpc:None,stop_at:None,log:false,limits:Default::default()},admitted(&cfg(&["a","b","c"]))).unwrap();
    let mut hs:Vec<_>=n.chain.blocks.values().filter(|e|e.height>0).map(|e|(e.height,e.hash)).collect();hs.sort();
    for (_,h) in hs{let e=n.chain.blocks[&h].clone();node.import(Block{header:e.header,body:e.body},None).unwrap();}
    let q=format!(r#"{{"jsonrpc":"2.0","id":5,"method":"eth_getLogs","params":[{{"fromBlock":"0x{:x}","toBlock":"latest"}}]}}"#,first);
    let v:serde_json::Value=serde_json::from_str(&pocold::rpc::handle(&mut node,q.as_bytes())).unwrap();
    let e=&v["error"];assert_eq!(e["code"],-32020,"{v}");assert_eq!(e["data"]["reason"],"resultCount");assert_eq!(v["id"],5);
    // 18 complete blocks hold 9828 logs; the 19th would pass LOGS_COUNT_MAX = 10000.
    let x=first+18;assert_eq!(e["data"]["nextFromBlock"],format!("0x{x:x}"));assert_eq!(e["data"]["lastCompleteBlock"],format!("0x{:x}",x-1));assert_eq!(e["data"]["fromBlock"],format!("0x{first:x}"));
    // Resuming from nextFromBlock succeeds.
    let q=format!(r#"{{"jsonrpc":"2.0","id":6,"method":"eth_getLogs","params":[{{"fromBlock":"0x{x:x}","toBlock":"latest"}}]}}"#);
    let v:serde_json::Value=serde_json::from_str(&pocold::rpc::handle(&mut node,q.as_bytes())).unwrap();assert_eq!(v["result"].as_array().map(|a|a.len()),Some(546),"{}",&v.to_string()[..200.min(v.to_string().len())]);
    let _=std::fs::remove_dir_all(&dir);
}
/// RpcGuard SCRATCH (network.md:220, (ز)): eth_getLogs charges the working bytes it materializes
/// against the heavy SCRATCH budget; an overflow is -32020 {scratch} with the same resume data as a
/// per-block limit, and the partial result is dropped. A heavy request is run through `answer`, which
/// derives the budget from the node's running SCRATCH_HEAVY, so a small limit reaches the bound in
/// the first block (546 logs ≈ 130 KiB). With the default 16 MiB budget the same block succeeds.
#[test] fn get_logs_scratch_limit_is_32020_scratch_with_resume_data(){
    use pocold::node::{Config,Limits,Node};use pocold::rpc::{self,Request};use std::time::{Duration,Instant};
    let mut n=net();let alice=devnet::account_key("alice");
    let mut init=vec![0x61,0x02,0x22,0x5b];init.extend([0x5f,0x5f,0xa0,0x60,0x01,0x90,0x03,0x80,0x60,0x03,0x57,0x00]);// 546 LOG0 then STOP
    let mut first=0;
    for k in 0..3u64{let head=n.chain.head;
        let tx=Tx{chain_id:777910,nonce:k,max_priority:U256::from(1u64),max_fee:U256::from(100_000_000_000u64),gas:2_000_000,to:None,value:U256::ZERO,data:init.clone().into()}.sign_1559(&alice);
        let b=signed(&n,head,Body{txs:vec![tx],evidence:vec![]},0);import(&mut n,&b);if k==0{first=n.chain.head().height;}}
    let hs:Vec<_>={let mut v:Vec<_>=n.chain.blocks.values().filter(|e|e.height>0).map(|e|(e.height,e.hash)).collect();v.sort();v};
    let getlogs=|node:&mut Node|->serde_json::Value{
        let q=format!(r#"{{"jsonrpc":"2.0","id":7,"method":"eth_getLogs","params":[{{"fromBlock":"0x{first:x}","toBlock":"0x{first:x}"}}]}}"#);
        let (t,_r)=std::sync::mpsc::channel();
        let a=rpc::answer(node,&Request::local(q.into_bytes(),t,Instant::now()+Duration::from_secs(30),false));
        serde_json::from_str::<serde_json::Value>(&a.body).unwrap()
    };
    // Small SCRATCH_HEAVY: the first block's logs exceed it -> -32020 {scratch}, no result.
    let dir=std::env::temp_dir().join(format!("pocold-scratch-{}",std::process::id()));let _=std::fs::remove_dir_all(&dir);
    let tight=Limits{rpc:rpc::Limits{scratch_heavy:60_000,..Default::default()},..Default::default()};
    let mut node=Node::open(Config{dir:dir.clone(),name:"scratch".into(),miner:None,listen:None,peers:vec![],rpc:None,stop_at:None,log:false,limits:tight},admitted(&cfg(&["a","b","c"]))).unwrap();
    for (_,h) in &hs{let e=n.chain.blocks[h].clone();node.import(Block{header:e.header,body:e.body},None).unwrap();}
    let v=getlogs(&mut node);let e=&v["error"];
    assert_eq!(e["code"],-32020,"{v}");assert_eq!(e["data"]["reason"],"scratch");
    assert_eq!(e["data"]["fromBlock"],format!("0x{first:x}"));assert_eq!(e["data"]["nextFromBlock"],format!("0x{first:x}"));assert!(e["data"]["lastCompleteBlock"].is_null());assert!(v.get("result").is_none());
    // Default SCRATCH_HEAVY (16 MiB): the same block succeeds with all 546 logs.
    let dir2=std::env::temp_dir().join(format!("pocold-scratch2-{}",std::process::id()));let _=std::fs::remove_dir_all(&dir2);
    let mut node2=Node::open(Config{dir:dir2.clone(),name:"scratch2".into(),miner:None,listen:None,peers:vec![],rpc:None,stop_at:None,log:false,limits:Default::default()},admitted(&cfg(&["a","b","c"]))).unwrap();
    for (_,h) in &hs{let e=n.chain.blocks[h].clone();node2.import(Block{header:e.header,body:e.body},None).unwrap();}
    assert_eq!(getlogs(&mut node2)["result"].as_array().map(|a|a.len()),Some(546),"the default budget answers the block");
    // Review M3/V5: past its COMPUTE_DEADLINE (here already at entry) each log handler answers -32020
    // {deadline} with the resume data of no progress (network.md:300), and its scan stops at the first
    // block, before it materializes any log (the handler's charged working set stays 0).
    let fh=format!("0x{first:x}");let bh=pocold::types::hex(&hs.iter().find(|x|x.0==first).unwrap().1);
    for q in [format!(r#"{{"jsonrpc":"2.0","id":1,"method":"eth_getLogs","params":[{{"fromBlock":"{fh}","toBlock":"{fh}"}}]}}"#),
        format!(r#"{{"jsonrpc":"2.0","id":2,"method":"pocol_getLogs","params":[{{"fromBlock":"{fh}","toBlock":"{fh}"}}]}}"#),
        format!(r#"{{"jsonrpc":"2.0","id":3,"method":"pocol_getLogs","params":[{{"blockHash":"{bh}"}}]}}"#)]{
        let mut b=rpc::Budget{compute_by:Instant::now(),scratch_max:usize::MAX,scratch_used:0,walled:false};
        let v:serde_json::Value=serde_json::from_str(&rpc::handle_until_budgeted(&mut node2,q.as_bytes(),false,None,None,&mut b)).unwrap();let e=&v["error"];
        assert_eq!(e["code"],-32020,"{v}");assert_eq!(e["data"]["reason"],"deadline");assert_eq!(e["data"]["fromBlock"],fh);assert_eq!(e["data"]["nextFromBlock"],fh);assert!(e["data"]["lastCompleteBlock"].is_null());
        assert_eq!(b.scratch_used,0,"the scan stopped at its first block: {q}");
    }
    let _=std::fs::remove_dir_all(&dir);let _=std::fs::remove_dir_all(&dir2);
}

// ---------------- proposal vectors (development/audit-2026-10-22/proposals): D-BODY-MAX ----------------
/// The independent model's encoded lengths equal pocold's Body encoding, and the decode path
/// (BODY_MAX on the encoded body, the recommended alternative) accepts exactly the bodies the
/// model marks valid. Agreement is not an approval of the proposal.
#[test] fn d_body_max_vectors(){
    let v:serde_json::Value=serde_json::from_str(include_str!("../../../development/audit-2026-10-22/proposals/vectors/d-body-max.json")).unwrap();
    let rec=v["recommended"].as_str().unwrap();let max=v["constants"]["BODY_MAX"].as_u64().unwrap() as usize;
    for s in v["scenarios"].as_array().unwrap(){
        let items=|k:&str|s[k].as_array().unwrap().iter().map(|n|vec![0xabu8;n.as_u64().unwrap() as usize]).collect::<Vec<_>>();
        let body=pocold::types::Body{txs:items("txSizes"),evidence:items("evidenceSizes")};let enc=body.encode();
        assert_eq!(enc.len() as u64,s["encodedLen"].as_u64().unwrap(),"{}",s["id"]);
        assert_eq!(pocold::types::Body::decode(&enc,max).is_ok(),s["expected"][rec]["valid"]==true,"{}",s["id"]);
    }
}

// ---------------- A13: the itemized model bound of the default devnet ----------------
#[test] fn a13_bound_breakdown(){
    use pocold::node::Limits;
    // The values pocold boots with: its node-local parameters, default limits, two configured peers.
    let l=pocold::single_host_local();
    let d=pocold::resources::derive(admitted(&cfg(&["a","b","c"])).cp(),l.k_hist,l.side_max,&Limits::default(),2).unwrap();
    assert_eq!(d.items.iter().map(|x|x.1).sum::<u128>(),d.total);
    println!("A13-BREAKDOWN {}",serde_json::json!({"total":d.total.to_string(),"items":d.items.iter().map(|(k,v)|serde_json::json!([k,v.to_string()])).collect::<Vec<_>>()}));
}

// ---------------- second round-2 review: side-branch retention, eviction and replay ----------------
fn retention_node(tag:&str)->(pocold::node::Node,std::path::PathBuf,impl Fn()->pocold::node::Config){
    use pocold::node::{Config,Node};
    let dir=std::env::temp_dir().join(format!("pocold-retain-{tag}-{}",std::process::id()));let _=std::fs::remove_dir_all(&dir);
    let d=dir.clone();let conf=move||Config{dir:d.clone(),name:"retain".into(),miner:None,listen:None,peers:vec![],rpc:None,stop_at:None,log:false,limits:Default::default()};
    (Node::open(conf(),admitted(&cfg(&["a","b","c"]))).unwrap(),dir,conf)
}
/// `n` blocks from `parent`: the first by `first`, then fallbacks at attempt 0.
fn grow(h:&mut Net,parent:[u8;32],n:usize,first:&dyn Fn(&Net,[u8;32])->Block)->Vec<Block>{
    let mut out=vec![];let mut p=parent;for i in 0..n{let b=if i==0{first(h,p)}else{fallback(h,p,0)};import(h,&b);h.chain.retain();p=b.hash();out.push(b);}out
}
/// A heavier competing branch whose fork is 150 blocks deep (more than the 64 a review showed
/// unadoptable) is adopted with the default limits: the node switches to its tip.
#[test] fn a_competing_branch_within_side_blocks_max_is_adopted(){
    let depth=150usize;let mut a=net();let g=a.chain.head;
    let ours=grow(&mut a,g,depth,&|n,p|signed(n,p,Body::default(),0));
    let mut b=net();let target=a.chain.head().total_work;let mut theirs=vec![];let mut p=g;
    while b.chain.head().total_work<=target{let x=fallback(&b,p,0);import(&mut b,&x);b.chain.retain();p=x.hash();theirs.push(x);}
    for _ in 0..2{let x=fallback(&b,p,0);import(&mut b,&x);p=x.hash();theirs.push(x);}
    let (mut n,dir,_)=retention_node("adopt");
    for x in &ours{n.import(x.clone(),None).unwrap();}
    for x in &theirs{n.import(x.clone(),None).unwrap_or_else(|e|panic!("h={}: {e:?}",x.header.h));assert!(n.chain.side_counts().0<=pocold::chain::SIDE_BLOCKS_MAX);}
    assert_eq!(n.chain.head,theirs.last().unwrap().hash(),"the heavier branch ({} blocks against {depth}) is adopted",theirs.len());
    let _=std::fs::remove_dir_all(&dir);
}
/// Second review: a valid, included transaction of TX_MAX bytes is fetched by hash in the light lane,
/// and its answer stays within network.md's 2·TX_MAX + 2 KiB (no `raw` beside `input`).
#[test] fn a_max_size_transaction_is_answered_in_the_light_lane(){
    let mut h=net();let g=h.chain.head;let txmax=h.chain.spec.cp().TX_MAX as usize;let alice=devnet::account_key("alice");
    let mk=|len:usize|Tx{chain_id:777910,nonce:0,max_priority:U256::from(1_000_000_000u64),max_fee:U256::from(100_000_000_000u64),gas:2_000_000,to:Some(devnet::account_key("bob").address()),value:U256::ZERO,data:vec![0u8;len].into()}.sign_1559(&alice);
    let mut len=txmax-200;while mk(len+1).len()<=txmax{len+=1;}
    let raw=mk(len);assert!(raw.len()<=txmax&&raw.len()+64>txmax);let hash=revm::primitives::keccak256(&raw);
    let b=signed(&h,g,Body{txs:vec![raw.clone()],evidence:vec![]},0);import(&mut h,&b);
    let (mut n,dir,_)=retention_node("txmax");n.import(b,None).unwrap();assert_eq!(n.chain.head().body.txs.len(),1);
    let body=format!(r#"{{"jsonrpc":"2.0","id":3,"method":"eth_getTransactionByHash","params":["{hash}"]}}"#);assert!(pocold::rpc::is_light(body.as_bytes()));
    let (t,_r)=std::sync::mpsc::channel();
    let a=pocold::rpc::answer(&mut n,&pocold::rpc::Request::local(body.into_bytes(),t,std::time::Instant::now()+std::time::Duration::from_secs(30),true));
    let v:serde_json::Value=serde_json::from_str(&a.body).unwrap();
    assert_eq!(v["result"]["hash"],format!("{hash}"),"answered, not -32008: {}",&a.body[..a.body.len().min(200)]);
    assert!(v["result"].get("raw").is_none());assert!(a.body.len()<=2*txmax+2048,"{} B",a.body.len());
    let _=std::fs::remove_dir_all(&dir);
}


// ---------------- D-REORG-REDB acceptance (owner-approved storage repair; D133 and validity unchanged) ----------------
// Retention (R_keep, the side cap) is local (consensus.md:29), so most tests lower it to reach the
// boundaries quickly; the spec-depth tests run the defaults in release (`--ignored`).
use serde_json::json;
fn rnode(tag:&str,r_keep:u64,side_cap:usize)->(pocold::node::Node,std::path::PathBuf,impl Fn()->pocold::node::Config){
    use pocold::node::{Config,Limits,Node};
    let dir=std::env::temp_dir().join(format!("pocold-redb-{tag}-{}",std::process::id()));let _=std::fs::remove_dir_all(&dir);
    let (d,name)=(dir.clone(),tag.to_string());
    let conf=move||Config{dir:d.clone(),name:name.clone(),miner:None,listen:None,peers:vec![],rpc:None,stop_at:None,log:false,limits:Limits{r_keep,side_cap,..Default::default()}};
    (Node::open(conf(),admitted(&cfg(&["a","b","c"]))).unwrap(),dir,conf)
}
fn reopen(conf:&dyn Fn()->pocold::node::Config)->pocold::node::Node{pocold::node::Node::open(conf(),admitted(&cfg(&["a","b","c"]))).expect("reopen")}
/// A fallback branch from `parent` whose cumulative work strictly exceeds `than`, then `extra` more blocks.
fn heavier(h:&mut Net,parent:[u8;32],than:U256,extra:usize)->Vec<Block>{
    let mut out=vec![];let mut p=parent;
    while h.chain.get(&p).unwrap().total_work<=than{let x=fallback(h,p,0);import(h,&x);h.chain.retain();p=x.hash();out.push(x);}
    for _ in 0..extra{let x=fallback(h,p,0);import(h,&x);h.chain.retain();p=x.hash();out.push(x);}
    out
}
/// Non-canonical blocks the side cap applies to (not protected by a session).
fn unprotected(n:&pocold::node::Node)->usize{n.chain.blocks.keys().filter(|h|n.chain.blocks[*h].height>0&&!n.chain.is_canonical(h)&&!n.chain.protect.contains(*h)).count()}
fn rpc_local(n:&mut pocold::node::Node,method:&str,params:serde_json::Value)->serde_json::Value{
    let body=json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}).to_string();let (t,_r)=std::sync::mpsc::channel();
    let a=pocold::rpc::answer(n,&pocold::rpc::Request::local(body.into_bytes(),t,std::time::Instant::now()+std::time::Duration::from_secs(120),false));
    serde_json::from_str::<serde_json::Value>(&a.body).unwrap()["result"].clone()
}
/// Every canonical block (with full transactions) and every receipt, as the node answers them over RPC.
fn chain_view(n:&mut pocold::node::Node)->Vec<serde_json::Value>{
    let top=n.chain.head().height;let mut out=vec![];
    for h in 0..=top{let b=rpc_local(n,"eth_getBlockByNumber",json!([format!("{h:#x}"),true]));
        for t in b["transactions"].as_array().cloned().unwrap_or_default(){out.push(rpc_local(n,"eth_getTransactionReceipt",json!([t["hash"]])));}
        out.push(b);}
    out
}

/// network.md:144 (adoption at depth <= R_keep) and governance.md:200 (deeper: manual checkpoint).
/// Depth R_keep: the heavier branch is adopted, its offloaded blocks are restored, and RPC answers the
/// same chain after restart. Depth R_keep+1: NOT adopted and NOT invalid (no blockReject, no invalid
/// mark: retention is never a validity rule); the node stays on the valid lighter chain.
fn r_keep_boundary(rk:u64,side_cap:usize,tag:&str){
    let mut a=net();let g=a.chain.head;
    // Ours starts at attempt 1 (a later timestamp, so less work per block): theirs, delivered without a
    // session, overtakes within fewer blocks than the depth and fits the side cap unprotected.
    let ours=grow(&mut a,g,rk as usize+1,&|n,p|fallback(n,p,1));
    let mut b=net();let theirs=heavier(&mut b,g,a.chain.head().total_work,1);
    let (mut n,dir,conf)=rnode(&format!("{tag}-at"),rk,side_cap);
    for x in &ours[..rk as usize]{n.import(x.clone(),None).unwrap();}
    assert_eq!(n.chain.head().height,rk,"the fork point (genesis) is at depth R_keep");
    for x in &theirs{n.import(x.clone(),None).unwrap_or_else(|e|panic!("h={}: {e:?}",x.header.h));}
    let tip=theirs.last().unwrap().hash();
    assert_eq!(n.chain.head,tip,"a heavier branch forked at depth R_keep ({rk}) is adopted");
    assert!(n.stats.restored>0&&n.chain.canonical_resident(),"positive control: its blocks were offloaded as side blocks and restored on adoption");
    let view=chain_view(&mut n);drop(n);
    let mut r=reopen(&conf);assert_eq!(r.chain.head,tip,"restart replays to the adopted head");assert!(r.chain.canonical_resident());assert_eq!(r.stats.replay_skipped,0);
    assert_eq!(chain_view(&mut r),view,"RPC answers the same chain after restart");drop(r);
    let (mut n,dir2,conf2)=rnode(&format!("{tag}-beyond"),rk,side_cap);
    for x in &ours{n.import(x.clone(),None).unwrap();}
    let ours_tip=ours.last().unwrap().hash();let rec0=n.journal_records();
    for x in &theirs{if let Err(Reject::Block(w))=n.import(x.clone(),None){panic!("retention never yields a validity verdict: {w}")}}
    assert_eq!(n.chain.head,ours_tip,"depth R_keep+1 is not adopted (governance.md:200: manual checkpoint)");
    assert!(theirs.iter().all(|x|!n.chain.invalid.contains_key(&x.hash())),"and no block of it is marked invalid");
    assert!(matches!(n.import(theirs[0].clone(),None),Err(Reject::Evicted)),"a block at or below head-R_keep is refused by local retention");
    assert_eq!(n.journal_records(),rec0,"before validation or journaling (retention would remove it at once)");
    drop(n);let r=reopen(&conf2);assert_eq!(r.chain.head,ours_tip);assert_eq!(r.stats.replay_skipped,0);
    println!("R_KEEP-BOUNDARY {}",json!({"rKeep":rk,"ourBlocks":ours.len(),"theirBlocks":theirs.len(),"adoptedAtRKeep":true,"adoptedBeyond":false}));
    for d in [dir,dir2]{let _=std::fs::remove_dir_all(&d);}
}
#[test] fn r_keep_boundary_adopts_at_depth_r_keep_and_keeps_the_valid_chain_beyond(){r_keep_boundary(24,24,"rk")}
/// The spec depth with the default limits (R_keep = 2048, governance.md:15; side cap 2048). Release
/// only: about 4,000 blocks are mined and validated twice. Run with
/// `cargo test --release --test consensus -- --ignored adoption_at_the_spec_depth`.
#[test] #[ignore="spec-depth test: run in release with --ignored"]
fn adoption_at_the_spec_depth_2048_and_not_at_2049(){r_keep_boundary(pocold::chain::R_KEEP,pocold::chain::SIDE_BLOCKS_MAX,"spec")}

/// Lowest-work unprotected leaves leave first and the cap holds after a deep reorg. An evicted block
/// received unsolicited is refused before validation or journaling (churn guard); a sync session
/// (solicited) takes it again (consensus.md §10: a branch that becomes heavier is fetched by sync).
/// Replay reproduces the live head.
#[test] fn side_cap_holds_after_a_reorg_and_only_a_session_takes_an_evicted_block_again(){
    let (rk,cap)=(64u64,16usize);let depth=40usize;let mut a=net();let g=a.chain.head;
    // Ours starts at attempt 1 (a later timestamp, less work per block); theirs is heavier sooner.
    let ours=grow(&mut a,g,depth,&|n,p|fallback(n,p,1));
    let mut b=net();let theirs=heavier(&mut b,g,a.chain.head().total_work,0);
    let (mut n,dir,conf)=rnode("cap",rk,cap);
    for x in &ours{n.import(x.clone(),None).unwrap();}
    for x in &theirs{let _=n.import(x.clone(),None);assert!(unprotected(&n)<=cap,"{} unprotected side blocks after h={}",unprotected(&n),x.header.h);}
    let head=theirs.last().unwrap().hash();assert_eq!(n.chain.head,head);
    assert!(n.chain.evicted_total>=(depth-cap) as u64,"evicted {}",n.chain.evicted_total);
    let tip=ours.last().unwrap();assert!(!n.chain.blocks.contains_key(&tip.hash()),"the lowest-work leaf went first");
    let records=n.journal_records();
    assert!(matches!(n.import(tip.clone(),None),Err(Reject::Evicted)),"an evicted block received unsolicited is refused");
    assert_eq!(n.journal_records(),records,"and not journaled again");
    for x in &ours{let _=n.import_with(x.clone(),None,true);}
    assert!(n.stats.refetched>0&&n.chain.blocks.contains_key(&tip.hash()),"a session takes evicted blocks again (refetched {})",n.stats.refetched);
    assert_eq!(n.chain.head,head,"the lighter branch stays a side branch");assert_eq!(n.chain.head,best_of(&n.chain));
    n.chain.protect.clear();n.chain.retain();assert!(unprotected(&n)<=cap);
    drop(n);let r=reopen(&conf);assert_eq!(r.chain.head,head,"replay reproduces the live head");assert_eq!(r.stats.replay_skipped,0);assert!(r.chain.canonical_resident());
    let _=std::fs::remove_dir_all(&dir);
}

/// The multi-branch case a metadata cap alone does not cover: while a sync session delivers a heavier
/// branch forked deep, competing side branches flood past the cap. Only unprotected leaves are evicted,
/// so the session branch D133 prefers is adopted; on restart replay protects every block a later record
/// builds on, so it reproduces the same head with no record skipped.
#[test] fn a_session_branch_is_adopted_through_a_flood_of_competing_side_branches(){
    // R_keep 16: protect_max 32. The flood is siblings of the head (equal work to the head, losing its
    // tie by importSeq), so each is heavier than any not-yet-adopted session block and the session tip
    // is always the lowest-work leaf. Flood plus session branch exceed cap + protect_max = 36, the
    // bound replay applies, so replay must evict, and only its child-record protection spares the tip.
    let (rk,cap)=(16u64,4usize);let mut a=net();let g=a.chain.head;
    let ours=grow(&mut a,g,12,&|n,p|fallback(n,p,1));let parent=ours[ours.len()-2].hash();
    let mut noise:Vec<Block>=vec![];for att in 1..44u32{let y=fallback(&a,parent,att);if !noise.iter().any(|z|z.hash()==y.hash()){noise.push(y);}}
    let mut b=net();let theirs=heavier(&mut b,g,a.chain.head().total_work,1);
    let (mut n,dir,conf)=rnode("flood",rk,cap);
    for x in &ours{n.import(x.clone(),None).unwrap();}
    let (mut noise_in,per)=(0,noise.len().div_ceil(theirs.len()-1));
    for (k,x) in theirs.iter().enumerate(){
        n.import_with(x.clone(),None,true).unwrap_or_else(|e|panic!("session block h={}: {e:?}",x.header.h));
        for y in noise.iter().skip(per*k).take(per){if n.import(y.clone(),None).is_ok(){noise_in+=1;}}
        assert!(unprotected(&n)<=cap);assert!(n.chain.protect.len()<=n.chain.protect_max());
    }
    assert!(noise_in+theirs.len()>cap+n.chain.protect_max()&&n.chain.evicted_total>0,"positive control: the flood ({noise_in} side blocks) exceeded cap + protect_max");
    let tip=theirs.last().unwrap().hash();assert_eq!(n.chain.head,tip,"the heavier session branch is adopted");assert_eq!(n.chain.head,best_of(&n.chain));
    assert!(n.chain.canonical_resident());
    n.chain.protect.clear();n.chain.retain();let view=chain_view(&mut n);drop(n);
    let mut r=reopen(&conf);assert_eq!(r.stats.replay_skipped,0,"every journal record's parent was retained on replay");
    assert_eq!(r.chain.head,tip);assert_eq!(chain_view(&mut r),view);
    let _=std::fs::remove_dir_all(&dir);
}

/// consensus.md:205: a block removed by retention and imported again takes a NEW importSeq. A second
/// journal record of a stored block is such a re-import, so replay gives it a new importSeq, and the
/// equal-work tie at the fork point follows the re-import order (mutation control: replay that keeps
/// the old importSeq picks the other branch).
#[test] fn replay_gives_a_reimported_block_a_new_import_seq(){
    let alice=devnet::account_key("alice");let mut h=net();let g=h.chain.head;
    let y=signed(&h,g,Body::default(),0);let x=signed(&h,g,Body{txs:vec![pay(&alice,0,7)],evidence:vec![]},0);
    assert_eq!(x.header.ts,y.header.ts,"same timestamp, so their children have the same target");
    import(&mut h,&y);import(&mut h,&x);
    let (x2,y2)=(fallback(&h,x.hash(),0),fallback(&h,y.hash(),0));
    assert_eq!(h.chain.blocks[&x.hash()].total_work+pocold::chain::work(&x2.header.target),h.chain.blocks[&y.hash()].total_work+pocold::chain::work(&y2.header.target),"equal work");
    let (mut n,dir,conf)=rnode("seq",64,16);n.import(y.clone(),None).unwrap();n.import(x.clone(),None).unwrap();
    assert_eq!(n.chain.head,y.hash(),"the first imported wins the signed tie");
    let binding=n.chain.spec.genesis_hash();drop(n);
    {let mut rec=pocold::store::open(&dir,&binding).unwrap();let again=rec.payloads[0].clone();rec.journal.append(&again).unwrap();}
    let mut n=reopen(&conf);assert_eq!(n.chain.head,x.hash(),"y re-imported after x: x now has the smaller importSeq");
    n.import(x2.clone(),None).unwrap();n.import(y2.clone(),None).unwrap();assert_eq!(n.chain.head,x2.hash());assert_eq!(n.chain.head,best_of(&n.chain));
    drop(n);let r=reopen(&conf);assert_eq!(r.chain.head,x2.hash(),"replay keeps the re-import order");
    let _=std::fs::remove_dir_all(&dir);
}

/// Off-heap fidelity (frozen test 6): an offloaded side block is served byte-equal from the journal,
/// viewed over RPC with its transactions, and re-executed from its journaled body to its committed
/// state root; a wrong offset is an error, never an empty body.
#[test] fn an_offloaded_block_is_served_viewed_and_re_executed_from_the_journal(){
    let alice=devnet::account_key("alice");let mut h=net();let g=h.chain.head;
    let main=grow(&mut h,g,3,&|n,p|fallback(n,p,0));
    let side=signed(&h,g,Body{txs:vec![pay(&alice,0,9)],evidence:vec![]},0);
    let (mut n,dir,_)=rnode("offload",64,16);
    for x in &main{n.import(x.clone(),None).unwrap();}n.import(side.clone(),None).unwrap();
    let sh=side.hash();assert!(!n.chain.is_canonical(&sh),"the one-block branch is lighter");
    let e=&n.chain.blocks[&sh];assert!(e.offloaded&&e.body.txs.is_empty()&&e.header.encoded.is_empty()&&e.tx_hashes.is_empty(),"positive control: the side block is offloaded");
    match n.block_msg(&sh){Some(pocold::net::Msg::Block{header,body})=>{assert_eq!(header,side.header.encoded);assert_eq!(body,side.body.encode());}m=>panic!("{m:?}")}
    let v=rpc_local(&mut n,"eth_getBlockByHash",json!([hex(&sh),true]));
    assert_eq!(v["transactions"][0]["hash"],format!("{}",revm::primitives::keccak256(&side.body.txs[0])));assert_eq!(v["size"],format!("{:#x}",side.header.encoded.len()));
    {let x=n.chain.blocks.get_mut(&sh).unwrap();x.state=Default::default();x.pruned=true;}
    n.rebuild_state(&sh).expect("re-executed from the journaled body to its committed state root");
    assert_eq!(apply::state_root(&n.chain.blocks[&sh].state).unwrap().0,side.header.state_root);
    n.chain.blocks.get_mut(&sh).unwrap().body_off=Some(41);
    assert!(n.body_of(&sh).is_err(),"a wrong offset is an error, never an empty body");
    let _=std::fs::remove_dir_all(&dir);
}

/// Crash consistency (frozen test 5). The adopting block's record is fsynced before the commit file
/// counts it and before the in-memory adoption, so a crash leaves the old chain or the whole adopted
/// chain, never a mix: (a) record fsynced, commit not updated: reopens on the adopted chain; (b) record
/// torn mid-write: reopens on the old chain, and the block re-delivered is adopted. In each, head,
/// canonical chain, state, RPC (blocks, receipts, transaction index) and journal agree.
#[test] fn a_crash_around_an_adoption_reopens_on_one_whole_chain(){
    let alice=devnet::account_key("alice");let mut a=net();let g=a.chain.head;
    let ours=grow(&mut a,g,8,&|n,p|signed(n,p,Body::default(),0));
    let mut b=net();let first=signed(&b,g,Body{txs:vec![pay(&alice,0,5)],evidence:vec![]},0);import(&mut b,&first);
    let mut theirs=vec![first.clone()];theirs.extend(heavier(&mut b,first.hash(),a.chain.head().total_work,0));
    let (mut n,dir,conf)=rnode("crash",64,16);
    for x in &ours{n.import(x.clone(),None).unwrap();}
    let (last,prefix)=theirs.split_last().unwrap();
    for x in prefix{n.import(x.clone(),None).unwrap();}assert_eq!(n.chain.head,ours.last().unwrap().hash(),"the prefix is lighter");
    let old_view=chain_view(&mut n);
    let (jp,cp)=(dir.join("blocks.journal"),dir.join("blocks.commit"));let (j0,c0)=(std::fs::metadata(&jp).unwrap().len() as usize,std::fs::read(&cp).unwrap());
    n.import(last.clone(),None).unwrap();assert_eq!(n.chain.head,last.hash(),"adopted");let new_view=chain_view(&mut n);drop(n);
    let j1=std::fs::read(&jp).unwrap();assert!(j1.len()>j0);
    let tx=format!("{}",revm::primitives::keccak256(&first.body.txs[0]));
    // (a) the record is complete and fsynced; the crash came before the commit-file update.
    std::fs::write(&cp,&c0).unwrap();
    let mut r=reopen(&conf);assert_eq!(r.chain.head,last.hash());assert!(r.chain.canonical_resident());assert_eq!(r.stats.replay_skipped,0);
    assert_eq!(chain_view(&mut r),new_view,"the whole adopted chain");assert_eq!(rpc_local(&mut r,"eth_getTransactionReceipt",json!([tx]))["blockHash"],json!(hex(&first.hash())));
    drop(r);
    // (b) the record was torn mid-write (never committed).
    std::fs::write(&cp,&c0).unwrap();std::fs::write(&jp,&j1[..j0+(j1.len()-j0)/2]).unwrap();
    let mut r=reopen(&conf);assert_eq!(r.chain.head,ours.last().unwrap().hash(),"the old chain, whole");assert!(r.chain.canonical_resident());
    assert_eq!(chain_view(&mut r),old_view);assert!(rpc_local(&mut r,"eth_getTransactionReceipt",json!([tx])).is_null(),"no transaction index entry from the lighter branch");
    assert!(prefix.iter().all(|x|r.chain.blocks.get(&x.hash()).map_or(false,|e|e.offloaded)),"the lighter prefix is retained as offloaded side blocks");
    r.import(last.clone(),None).unwrap();assert_eq!(r.chain.head,last.hash());assert_eq!(chain_view(&mut r),new_view,"re-delivery adopts the same chain");
    drop(r);let mut r=reopen(&conf);assert_eq!(chain_view(&mut r),new_view);
    let _=std::fs::remove_dir_all(&dir);
}

/// Equal-work branches: at every height all of them use the same attempt, so their timestamps and
/// targets stay equal (a template without a solution moves all branches to the next attempt).
fn lockstep(nets:&mut [Net],firsts:&[Block],len:usize)->Vec<Vec<Block>>{
    let mut out:Vec<Vec<Block>>=firsts.iter().map(|b|vec![b.clone()]).collect();
    for (n,b) in nets.iter_mut().zip(firsts){import(n,b);}
    for _ in 1..len{
        let mut a=0u32;
        let next=loop{
            let got:Vec<Option<Block>>=nets.iter().zip(out.iter()).map(|(n,br)|{let p=n.chain.get(&br.last().unwrap().hash()).unwrap().clone();
                let (h,_,_)=n.chain.build_fallback(&p,a).unwrap();try_seal(n,h,Body::default(),a,0)}).collect();
            if got.iter().all(|x|x.is_some()){break got.into_iter().map(|x|x.unwrap()).collect::<Vec<_>>()}a+=1;
        };
        for ((n,br),b) in nets.iter_mut().zip(out.iter_mut()).zip(next){import(n,&b);n.chain.retain();br.push(b);}
    }
    out
}
/// D133 at depth (frozen test 3), through eviction and re-fetch (frozen test 4). Three equal-work
/// branches from genesis: X (fallback first), Y and Z (signed first, same timestamp). X is imported
/// first; Y, delivered by a session, wins the tie at its tip because a signed block precedes a fallback
/// at the fork point (D15/D133), a reorg `depth` deep; X is evicted down to the cap. Z ties Y with both
/// signed: Y keeps the head (smaller importSeq). X, extended by one block and re-fetched by a session,
/// becomes heavier and is adopted. The head equals the whole-path D133 reference after every step and
/// after restart.
fn d133_at_depth(depth:usize,rk:u64,cap:usize,tag:&str){
    let alice=devnet::account_key("alice");
    let mut nets=vec![net(),net(),net()];let g=nets[0].chain.head;
    let x0=fallback(&nets[0],g,0);
    let lower=nets[1].chain.child_ctx(&nets[1].chain.get(&g).unwrap().clone(),0).unwrap().window.lower();
    let off=x0.header.ts-lower;
    let y0=signed(&nets[1],g,Body::default(),off);let z0=signed(&nets[2],g,Body{txs:vec![pay(&alice,0,3)],evidence:vec![]},off);
    assert!(x0.header.ts==y0.header.ts&&y0.header.ts==z0.header.ts,"one timestamp at the fork point");
    let br=lockstep(&mut nets,&[x0,y0,z0],depth);let (x,y,z)=(&br[0],&br[1],&br[2]);
    let w=|n:&Net,b:&Block|n.chain.blocks[&b.hash()].total_work;
    assert!(w(&nets[0],x.last().unwrap())==w(&nets[1],y.last().unwrap())&&w(&nets[1],y.last().unwrap())==w(&nets[2],z.last().unwrap()),"equal work at the tips");
    let xe=fallback(&nets[0],x.last().unwrap().hash(),0);
    let (mut n,dir,conf)=rnode(tag,rk,cap);
    for b in x{n.import(b.clone(),None).unwrap();}assert_eq!(n.chain.head,x.last().unwrap().hash());
    for b in y{n.import_with(b.clone(),None,true).unwrap();}
    assert_eq!(n.chain.head,y.last().unwrap().hash(),"signed before fallback at the fork point: a reorg {depth} deep");assert_eq!(n.chain.head,best_of(&n.chain));
    n.chain.protect.clear();n.chain.retain();assert!(n.chain.evicted_total>=(depth-cap) as u64,"positive control: X was evicted ({})",n.chain.evicted_total);
    for b in z{n.import_with(b.clone(),None,true).unwrap();}
    assert_eq!(n.chain.head,y.last().unwrap().hash(),"both signed: the smaller importSeq (Y) keeps the head");assert_eq!(n.chain.head,best_of(&n.chain));
    n.chain.protect.clear();n.chain.retain();
    let before=n.stats.refetched;
    for b in x.iter().chain(std::iter::once(&xe)){n.import_with(b.clone(),None,true).unwrap_or_else(|e|panic!("re-fetch h={}: {e:?}",b.header.h));}
    assert!(n.stats.refetched>before,"positive control: evicted X blocks were re-fetched");
    assert_eq!(n.chain.head,xe.hash(),"X, now heavier, is adopted after re-fetch");assert_eq!(n.chain.head,best_of(&n.chain));assert!(n.chain.canonical_resident());
    n.chain.protect.clear();n.chain.retain();let view=chain_view(&mut n);drop(n);
    let mut r=reopen(&conf);assert_eq!(r.chain.head,xe.hash());assert_eq!(r.stats.replay_skipped,0);assert_eq!(r.chain.head,best_of(&r.chain));assert_eq!(chain_view(&mut r),view);
    println!("D133-DEPTH {}",json!({"depth":depth,"rKeep":rk,"cap":cap,"evicted":r.chain.evicted_total}));
    let _=std::fs::remove_dir_all(&dir);
}
#[test] fn d133_tie_break_at_depth_holds_through_eviction_and_refetch(){d133_at_depth(40,128,8,"d133")}
/// Deeper than the former 320-block cap, within R_keep (default). Release only; run with
/// `cargo test --release --test consensus -- --ignored d133_tie_break_at_depth_400`.
#[test] #[ignore="spec-depth test: run in release with --ignored"]
fn d133_tie_break_at_depth_400_holds_through_eviction_and_refetch(){d133_at_depth(400,pocold::chain::R_KEEP,16,"d133-400")}

fn rpc_tcp(port:u16,method:&str,params:serde_json::Value)->serde_json::Value{
    use std::io::{Read,Write};
    let Ok(mut s)=std::net::TcpStream::connect(("127.0.0.1",port)) else{return serde_json::Value::Null};
    let body=json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}).to_string();
    let _=write!(s,"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n{body}",body.len());let mut o=String::new();let _=s.read_to_string(&mut o);
    o.split("\r\n\r\n").nth(1).and_then(|b|serde_json::from_str::<serde_json::Value>(b).ok()).map(|v|v["result"].clone()).unwrap_or(serde_json::Value::Null)
}
fn wait_for(secs:u64,f:&dyn Fn()->bool)->bool{let t=std::time::Instant::now();while t.elapsed()<std::time::Duration::from_secs(secs){if f(){return true}std::thread::sleep(std::time::Duration::from_millis(200));}f()}
/// consensus.md §10 / D118 re-fetch over the network (frozen tests 4 and 8). Node A held a lighter
/// branch and evicted it (side cap). Peer P serves that branch, now heavier, as its canonical chain.
/// A's sync session (Status work, locator) re-fetches the evicted blocks (solicited), adopts P's head
/// and restores the adopted blocks, so every canonical block and receipt A answers over RPC equals
/// P's. A third node C syncs the same chain from A alone, so A serves its restored history.
#[test] fn a_sync_session_refetches_an_evicted_branch_and_serves_it(){
    use pocold::node::{Config,Limits,Node};
    let port=||std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let alice=devnet::account_key("alice");let c=cfg(&["a","b","c"]);
    let mut a=net();let g=a.chain.head;let ours=grow(&mut a,g,20,&|n,p|signed(n,p,Body::default(),0));
    let noise:Vec<Block>=ours.iter().skip(6).take(10).map(|x|fallback(&a,x.hash(),1)).collect();
    let mut b=net();let first=signed(&b,g,Body{txs:vec![pay(&alice,0,5)],evidence:vec![]},0);import(&mut b,&first);
    let mut theirs=vec![first.clone()];theirs.extend(heavier(&mut b,first.hash(),a.chain.head().total_work,3));
    let lim=Limits{r_keep:64,side_cap:6,..Default::default()};
    let (pa,pp,pc,ra,rp,rc)=(port(),port(),port(),port(),port(),port());let tag=std::process::id();
    let dir=|x:&str|{let d=std::env::temp_dir().join(format!("pocold-refetch-{x}-{tag}"));let _=std::fs::remove_dir_all(&d);d};
    let addr=|p:u16|->std::net::SocketAddr{format!("127.0.0.1:{p}").parse().unwrap()};
    let conf=|name:&str,listen:u16,peers:Vec<std::net::SocketAddr>,rpc:u16|Config{dir:dir(name),name:name.into(),miner:None,listen:Some(addr(listen)),peers,rpc:Some(addr(rpc)),stop_at:None,log:false,limits:lim.clone()};
    let mut na=Node::open(conf("a",pa,vec![addr(pp)],ra),admitted(&c)).unwrap();
    for x in &ours{na.import(x.clone(),None).unwrap();}
    for x in &theirs[..8]{let _=na.import(x.clone(),None);}
    for x in &noise{let _=na.import(x.clone(),None);}
    assert!(theirs[..8].iter().any(|x|!na.chain.blocks.contains_key(&x.hash())),"positive control: A evicted part of the lighter branch (cap {})",lim.side_cap);
    assert_eq!(na.chain.head,ours.last().unwrap().hash());
    let mut np=Node::open(conf("p",pp,vec![],rp),admitted(&c)).unwrap();
    for x in &theirs{np.import(x.clone(),None).unwrap();}let target=json!(hex(&np.chain.head));
    np.start_network().unwrap();std::thread::spawn(move||np.run());
    na.start_network().unwrap();std::thread::spawn(move||na.run());
    let head=|p:u16|rpc_tcp(p,"eth_getBlockByNumber",json!(["latest",false]))["hash"].clone();
    assert!(wait_for(300,&||head(ra)==target),"A adopts P's head: {} vs {target}",head(ra));
    let st=rpc_tcp(ra,"pocol_status",json!([]));
    assert!(st["stats"]["refetched"].as_u64().unwrap_or(0)>0&&st["stats"]["restored"].as_u64().unwrap_or(0)>0&&st["stats"]["syncSessions"].as_u64().unwrap_or(0)>0,
        "positive control: a session re-fetched evicted blocks and the adopted ones were restored: {}",st["stats"]);
    let top=theirs.last().unwrap().header.h;
    let view=|p:u16|{let mut v=vec![];for h in 0..=top{let b=rpc_tcp(p,"eth_getBlockByNumber",json!([format!("{h:#x}"),true]));
        for t in b["transactions"].as_array().cloned().unwrap_or_default(){v.push(rpc_tcp(p,"eth_getTransactionReceipt",json!([t["hash"]])));}v.push(b);}v};
    let pv=view(rp);assert!(pv.iter().all(|x|!x.is_null()));
    assert_eq!(view(ra),pv,"A answers P's chain: blocks, transactions, receipts");
    let mut nc=Node::open(conf("c",pc,vec![addr(pa)],rc),admitted(&c)).unwrap();nc.start_network().unwrap();std::thread::spawn(move||nc.run());
    assert!(wait_for(300,&||head(rc)==target),"C syncs from A");assert_eq!(view(rc),pv,"C, served by A, answers the same chain");
    println!("REFETCH-NET {}",json!({"ourBlocks":ours.len(),"theirBlocks":theirs.len(),"sideCap":lim.side_cap,"stats":st["stats"],"retention":st["retention"]}));
}
/// eth_call / eth_estimateGas on a block whose state is pruned (outside the K_hist window, or a block
/// adopted after its state was pruned as a side block) answer -32017 like the state reads (consensus.md
/// §10), never a simulation on an empty state.
#[test] fn a_call_on_a_pruned_state_is_32017_not_an_empty_state_simulation(){
    let mut h=net();let g=h.chain.head;let blocks=grow(&mut h,g,40,&|n,p|fallback(n,p,0));
    let (mut n,dir,_)=rnode("call",64,16);for x in &blocks{n.import(x.clone(),None).unwrap();}
    assert!(n.chain.canonical_at(1).unwrap().pruned,"block 1 is outside the K_hist window");
    let body=json!({"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":format!("{:#x}",devnet::account_key("bob").address())},"0x1"]}).to_string();let (t,_r)=std::sync::mpsc::channel();
    let a=pocold::rpc::answer(&mut n,&pocold::rpc::Request::local(body.into_bytes(),t,std::time::Instant::now()+std::time::Duration::from_secs(60),false));
    let v:serde_json::Value=serde_json::from_str(&a.body).unwrap();assert_eq!(v["error"]["code"],-32017,"{v}");
    assert!(!rpc_local(&mut n,"eth_call",json!([{"to":format!("{:#x}",devnet::account_key("bob").address())},"latest"])).is_null(),"the head state answers");
    let _=std::fs::remove_dir_all(&dir);
}
/// A session's protection covers only its non-canonical blocks: a linear catch-up far longer than
/// protect_max (2·R_keep, here 16) completes through continuation rounds, since each block it
/// delivers extends the canonical chain and needs no protection.
#[test] fn a_long_catch_up_is_not_bounded_by_the_protected_branch_size(){
    use pocold::node::{Config,Limits,Node};
    let port=||std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let c=cfg(&["a","b","c"]);let mut h=net();let g=h.chain.head;let blocks=grow(&mut h,g,60,&|n,p|fallback(n,p,0));
    let mut lim=Limits{r_keep:8,side_cap:8,..Default::default()};lim.net.queue_bytes_max=32*1024;
    let (pa,pb,ra)=(port(),port(),port());let tag=std::process::id();
    let dir=|x:&str|{let d=std::env::temp_dir().join(format!("pocold-catchup-{x}-{tag}"));let _=std::fs::remove_dir_all(&d);d};
    let addr=|p:u16|->std::net::SocketAddr{format!("127.0.0.1:{p}").parse().unwrap()};
    let mut np=Node::open(Config{dir:dir("p"),name:"p".into(),miner:None,listen:Some(addr(pb)),peers:vec![],rpc:None,stop_at:None,log:false,limits:lim.clone()},admitted(&c)).unwrap();
    for x in &blocks{np.import(x.clone(),None).unwrap();}let target=json!(hex(&np.chain.head));
    np.start_network().unwrap();std::thread::spawn(move||np.run());
    let mut na=Node::open(Config{dir:dir("a"),name:"a".into(),miner:None,listen:Some(addr(pa)),peers:vec![addr(pb)],rpc:Some(addr(ra)),stop_at:None,log:false,limits:lim},admitted(&c)).unwrap();
    na.start_network().unwrap();std::thread::spawn(move||na.run());
    let head=||rpc_tcp(ra,"eth_getBlockByNumber",json!(["latest",false]))["hash"].clone();
    assert!(wait_for(300,&||head()==target),"A catches up 60 blocks with protect_max 16: at {}",head());
    let st=rpc_tcp(ra,"pocol_status",json!([]));assert!(st["stats"]["syncRounds"].as_u64().unwrap_or(0)>1,"positive control: truncated rounds were continued: {}",st["stats"]);
}
/// R21's K_hist window prunes canonical states only; non-canonical states are bounded by side_max.
/// A competing branch below the window therefore imports with its tip's state kept, so a deep
/// adoption needs no rebuild per block (pruning side states too re-executed each block's ancestry
/// from genesis: quadratic work at depth R_keep).
#[test] fn a_side_branch_below_the_k_hist_window_imports_without_rebuilding_each_parent(){
    let mut a=net();let g=a.chain.head;let ours=grow(&mut a,g,24,&|n,p|signed(n,p,Body::default(),0));
    let mut b=net();let theirs=grow(&mut b,g,16,&|n,p|fallback(n,p,1));
    let (mut n,dir,_)=rnode("kwin",64,64);n.chain.k_hist=4;
    for x in &ours{n.import(x.clone(),None).unwrap();}
    let before=n.chain.rebuilds;
    for x in &theirs{n.import(x.clone(),None).unwrap();}
    assert!(theirs.iter().all(|x|!n.chain.is_canonical(&x.hash())),"the branch stays lighter (side)");
    assert!(n.chain.rebuilds-before<=1,"linear import: {} re-executions for {} side blocks",n.chain.rebuilds-before,theirs.len());
    let (_,with_state)=n.chain.side_counts();assert!(with_state<=n.chain.spec.local().side_max as usize);
    let _=std::fs::remove_dir_all(&dir);
}

/// A peer cannot hold the sync slot with a false Status: one announcing enormous work that answers with
/// copies of our own blocks (and re-announces new heads) makes no progress after its first pass, so its
/// session ends after SESSION_STALL_MS and the round-robin reaches the honest heavier peer, whose branch
/// is adopted. Local test peers only.
#[test] fn a_peer_with_a_false_status_cannot_hold_the_sync_session(){
    use pocold::{node::{Config,Limits,Node},net::Msg};use std::io::{Read,Write};
    let port=||std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let c=cfg(&["a","b","c"]);let mut a=net();let g=a.chain.head;let ours=grow(&mut a,g,20,&|n,p|signed(n,p,Body::default(),0));
    let mut b=net();let theirs=heavier(&mut b,g,a.chain.head().total_work,2);
    let lim=Limits{r_keep:64,side_cap:16,..Default::default()};
    let (pa,pp,ra)=(port(),port(),port());let tag=std::process::id();
    let dir=|x:&str|{let d=std::env::temp_dir().join(format!("pocold-liar-{x}-{tag}"));let _=std::fs::remove_dir_all(&d);d};
    let addr=|p:u16|->std::net::SocketAddr{format!("127.0.0.1:{p}").parse().unwrap()};
    let mut na=Node::open(Config{dir:dir("a"),name:"a".into(),miner:None,listen:Some(addr(pa)),peers:vec![],rpc:Some(addr(ra)),stop_at:None,log:false,limits:lim.clone()},admitted(&c)).unwrap();
    for x in &ours{na.import(x.clone(),None).unwrap();}
    let (chain_id,genesis)=(na.chain.spec.chain_id(),na.chain.spec.genesis_hash());
    na.start_network().unwrap();std::thread::spawn(move||na.run());
    // The false peer: Hello with maximal work and an unknown head, then copies of A's own blocks forever.
    let frame=|m:&Msg|{let e=m.encode();let mut o=(e.len() as u32).to_be_bytes().to_vec();o.extend(e);o};
    let mut x=std::net::TcpStream::connect(addr(pa)).unwrap();let mut xr=x.try_clone().unwrap();
    std::thread::spawn(move||{let mut buf=[0u8;65536];while xr.read(&mut buf).map_or(false,|n|n>0){}});
    let copies:Vec<Vec<u8>>=ours.iter().map(|y|frame(&Msg::Block{header:y.header.encoded.clone(),body:y.body.encode()})).collect();
    std::thread::spawn(move||{let mut k=0u64;loop{
        if k%20==0{let head=[(k/20) as u8;32];if x.write_all(&frame(&Msg::Hello{chain_id,genesis,head,height:1_000_000,work:[0xff;32],node:"x".into()})).is_err(){break}}
        if x.write_all(&copies[(k as usize)%copies.len()]).is_err(){break}k+=1;std::thread::sleep(std::time::Duration::from_millis(50));}});
    let head=|p:u16|rpc_tcp(p,"eth_getBlockByNumber",json!(["latest",false]))["hash"].clone();
    assert!(wait_for(20,&||rpc_tcp(ra,"pocol_status",json!([]))["stats"]["syncSessions"].as_u64().unwrap_or(0)>=1),"the false peer's first Hello starts a session");
    let mut np=Node::open(Config{dir:dir("p"),name:"p".into(),miner:None,listen:Some(addr(pp)),peers:vec![addr(pa)],rpc:None,stop_at:None,log:false,limits:lim},admitted(&c)).unwrap();
    for y in &theirs{np.import(y.clone(),None).unwrap();}let target=json!(hex(&np.chain.head));
    np.start_network().unwrap();std::thread::spawn(move||np.run());
    assert!(wait_for(120,&||head(ra)==target),"A adopts the honest heavier peer's head despite the false peer: {} vs {target}",head(ra));
    let st=rpc_tcp(ra,"pocol_status",json!([]));assert!(st["stats"]["syncSessions"].as_u64().unwrap_or(0)>=2,"{}",st["stats"]);
}
/// Replay never runs with a smaller R_keep than live used: the largest value is kept beside the
/// journal (retention.rkeep). Reopening with a smaller configured R_keep still replays a branch adopted
/// at a depth the smaller window would have cut, to the same head with no record skipped.
#[test] fn replay_uses_the_largest_r_keep_the_data_directory_has_used(){
    use pocold::node::{Config,Limits,Node};
    let mut a=net();let g=a.chain.head;let ours=grow(&mut a,g,40,&|n,p|fallback(n,p,1));
    let mut b=net();let theirs=heavier(&mut b,g,a.chain.head().total_work,1);
    let dir=std::env::temp_dir().join(format!("pocold-redb-rkmax-{}",std::process::id()));let _=std::fs::remove_dir_all(&dir);
    let conf=|rk:u64|Config{dir:dir.clone(),name:"rk".into(),miner:None,listen:None,peers:vec![],rpc:None,stop_at:None,log:false,limits:Limits{r_keep:rk,side_cap:64,..Default::default()}};
    let mut n=Node::open(conf(64),admitted(&cfg(&["a","b","c"]))).unwrap();
    for x in ours.iter().chain(theirs.iter()){n.import(x.clone(),None).unwrap();}
    let tip=theirs.last().unwrap().hash();assert_eq!(n.chain.head,tip,"adopted at depth 40 with R_keep 64");drop(n);
    let r=Node::open(conf(24),admitted(&cfg(&["a","b","c"]))).unwrap();
    assert_eq!(r.stats.replay_skipped,0,"replay used R_keep 64, not the configured 24");assert_eq!(r.chain.head,tip);assert_eq!(r.chain.r_keep,24,"the configured value applies after replay");
    assert_eq!(std::fs::read_to_string(dir.join("retention.rkeep")).unwrap().trim(),"64");
    let _=std::fs::remove_dir_all(&dir);
}
/// A session block that arrives before its parent waits as an orphan and, when the parent arrives, is
/// imported with the parent's solicited status: protected from the side cap (here 0) like the rest of
/// the session's branch.
#[test] fn a_session_block_arriving_before_its_parent_stays_protected(){
    let mut a=net();let g=a.chain.head;let ours=grow(&mut a,g,6,&|n,p|signed(n,p,Body::default(),0));
    let mut b=net();let theirs=grow(&mut b,g,3,&|n,p|fallback(n,p,1));
    let (mut n,dir,_)=rnode("orphan",64,0);for x in &ours{n.import(x.clone(),None).unwrap();}
    assert!(matches!(n.import_with(theirs[1].clone(),None,true),Err(Reject::UnknownParent)),"the child arrives first");
    n.import_with(theirs[0].clone(),None,true).unwrap();
    for x in &theirs[..2]{assert!(n.chain.blocks.contains_key(&x.hash())&&n.chain.protect.contains(&x.hash()),"h={} is stored and protected",x.header.h);}
    assert_eq!(unprotected(&n),0);
    let _=std::fs::remove_dir_all(&dir);
}
/// The R_keep boundary in retain(): a side block imported inside the window stays while it is less
/// than R_keep below the head and is removed (with its descendants) once it is exactly R_keep below.
/// Independent of the import-time refusal of new blocks below the window.
#[test] fn the_r_keep_boundary_removes_a_side_block_exactly_r_keep_below_the_head(){
    let rk=8u64;let mut a=net();let g=a.chain.head;let ours=grow(&mut a,g,rk as usize+1,&|n,p|signed(n,p,Body::default(),0));
    let side=fallback(&a,g,1);
    let (mut n,dir,_)=rnode("boundary",rk,64);n.import(ours[0].clone(),None).unwrap();n.import(side.clone(),None).unwrap();
    assert!(!n.chain.is_canonical(&side.hash()),"a side block at height 1");
    for x in &ours[1..rk as usize]{n.import(x.clone(),None).unwrap();}
    assert_eq!(n.chain.head().height,rk);assert!(n.chain.blocks.contains_key(&side.hash()),"R_keep-1 below the head: kept");
    n.import(ours[rk as usize].clone(),None).unwrap();
    assert!(!n.chain.blocks.contains_key(&side.hash()),"exactly R_keep below the head: removed by retention");
    assert!(!n.chain.invalid.contains_key(&side.hash()),"removed locally, never invalid");
    let _=std::fs::remove_dir_all(&dir);
}
