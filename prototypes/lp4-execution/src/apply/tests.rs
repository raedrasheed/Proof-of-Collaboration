use super::*;
use crate::devnet::{self,DevnetConfig};
use revm::primitives::B256;

fn devnet3()->devnet::Devnet{devnet::build(&DevnetConfig::new(777900,1_800_000_000,&["a","b","c"])).expect("devnet")}

fn run_chain(net:&devnet::Devnet,blocks:u64,txs_at:&dyn Fn(u64)->Vec<Vec<u8>>)->Vec<(BlockOutput,ParentResult)>{
    let mut state=net.genesis.state().clone();let mut out=Vec::new();let mut prev:Option<ParentResult>=None;
    let ids:Vec<Address>=net.miners.iter().map(|m|m.id).collect();
    let mut base_fee=U256::from(1_000_000_000u64);let mut parent_gas=0u64;
    for h in 1..=blocks{
        if h>1{base_fee=crate::fees::next_base_fee(base_fee,parent_gas,8_000_000).unwrap();}
        let txs=txs_at(h);
        let input=BlockInput{height:h,timestamp:1_800_000_000+2*h,base_fee,gas_limit:8_000_000,prevrandao:B256::ZERO,
            proposer:if h%2==0{Proposer::Signed(ids[(h as usize)%3])}else{Proposer::Fallback},
            parent_result:prev.clone(),evidence:vec![],evidence_raw:&[],transactions:&txs,ancestors:vec![(0,net.genesis_hash)]};
        let o=apply_block(&state,&net.genesis,&net.profile,&input).unwrap_or_else(|e|panic!("h={h}: {e:?}"));
        state=o.state.clone();parent_gas=o.gas_used;
        // Winner rotates; shares: one for each other miner, two for the next one.
        let w=ids[(h as usize)%3];let s=vec![(10,ids[(h as usize+1)%3]),(20,ids[(h as usize+1)%3]),(30,ids[(h as usize+2)%3])];
        let pr=ParentResult{block_hash:B256::from(U256::from(h)),winner:w,shares:s};
        prev=Some(pr.clone());out.push((o,pr));
    }
    out
}

#[test] fn genesis_builds_with_v1_programs_and_ledger_empty(){
    let net=devnet3();let g=net.genesis.state();
    assert_eq!(active_list(g).len(),3);assert_eq!(record_list(g).len(),3);
    let f=chain_facts(g);assert_eq!(f.held_total,U256::from(3u64)*U256::from(10u128.pow(20)));assert!(!f.closing);
    assert!(g.accounts[&ledger()].storage.values().all(|v|*v==U256::ZERO));
    assert_eq!(state_root(g).unwrap(),net.genesis.root());
}

#[test] fn twenty_blocks_settle_and_keep_invariants(){
    let net=devnet3();let chain=run_chain(&net,20,&|_|vec![]);
    let d=u64::from(net.profile.cp().D);let k=d.max(u64::from(net.profile.cp().W_w));
    let last=&chain.last().unwrap().0.state;
    // Ledger keeps exactly heights [h-K, h-1] after pruning (h=20,K=8 -> 12..19).
    for j in 1..=19{ let present=share_total(last,j)!=0; assert_eq!(present,j>=20-k,"ledger height {j}"); }
    for j in 12..=19{assert_eq!(share_total(last,j),4);}
    // Every settled pot paid winner/proposer/share owners: reward balances positive.
    for m in &net.miners{assert!(last.accounts[&m.reward].info.balance>U256::ZERO,"{}",m.label);}
    // lastShare updated to the latest recorded height for every miner (all appear each height).
    for m in &net.miners{assert_eq!(miner_record(last,m.id).unwrap().last_share,19);}
    // pending window [h-D+1,h].
    for j in 1..=20{let present=pending(last,j).1!=U256::ZERO;assert_eq!(present,j>20-d);}
}

#[test] fn settlement_matches_independent_formula(){
    // Block 1 is fallback; settle(1) runs at h=1+D. Reproduce SV-style arithmetic.
    let net=devnet3();let d=u64::from(net.profile.cp().D);
    let chain=run_chain(&net,d+1,&|_|vec![]);
    let before=&chain[(d-1) as usize].0.state;let after=&chain[d as usize].0.state;
    let pr=&chain[0].1; // ParentResult of block 1
    let (amount,_,_)=pending(before,1);assert_eq!(amount,U256::from(2_000_000_000_000_000_000u128));
    let wp=amount*U256::from(1000)/U256::from(10000);let pp=amount*U256::from(500)/U256::from(10000);
    let r=amount-wp-pp;let c=U256::from(4);let q=U256::from(64);
    let mut expect=std::collections::HashMap::new();
    let mut add=|a:Address,v:U256|{*expect.entry(a).or_insert(U256::ZERO)+=v;};
    add(pr.winner,wp);add(pr.winner,pp); // fallback: propPart to winner
    let mut counts=std::collections::HashMap::new();for a in pr.owner_sequence(){*counts.entry(a).or_insert(0u64)+=1;}
    let mut sum=U256::ZERO;for (a,n) in &counts{let p=r*U256::from(*n)/q;sum+=p;add(*a,p);}
    let a_total=r*c/q;let burn=(r-a_total)+(a_total-sum);
    // Delta of each reward balance at h=D+1 equals settle(1) payout plus nothing else.
    for m in &net.miners{
        let delta=after.accounts[&m.reward].info.balance-before.accounts[&m.reward].info.balance;
        assert_eq!(delta,*expect.get(&m.id).unwrap_or(&U256::ZERO),"{}",m.label);
    }
    let burned=chain_facts(after).burned_total-chain_facts(before).burned_total;assert_eq!(burned,burn);
}

#[test] fn user_transfer_tips_flow_into_pot(){
    use crate::txsign::Tx;
    let net=devnet3();let alice=devnet::account_key("alice");let bob=devnet::account_key("bob").address();
    let tx=Tx{chain_id:777900,nonce:0,max_priority:U256::from(2_000_000_000u64),max_fee:U256::from(10_000_000_000u64),gas:21000,to:Some(bob),value:U256::from(12345),data:Default::default()}.sign_1559(&alice);
    let chain=run_chain(&net,2,&|h|if h==2{vec![tx.clone()]}else{vec![]});
    let o=&chain[1].0;assert_eq!(o.gas_used,21000);assert_eq!(o.tips,U256::from(21000u64*2_000_000_000));
    let (amount,meta,_)=pending(&o.state,2);assert_eq!(amount,U256::from(2_000_000_000_000_000_000u128)+o.tips);
    assert_eq!(meta>>8u32,U256::from_be_slice(net.miners[2].id.as_slice()),"signed proposer recorded");
    assert_eq!(o.state.accounts[&bob].info.balance,U256::from(10u128.pow(24))+U256::from(12345));
}

#[test] fn wrong_parent_result_presence_and_reverted_system_call_reject(){
    let net=devnet3();let g=net.genesis.state();
    let bad=BlockInput{height:1,timestamp:1_800_000_002,base_fee:U256::from(1_000_000_000u64),gas_limit:8_000_000,prevrandao:B256::ZERO,proposer:Proposer::Fallback,
        parent_result:Some(ParentResult{block_hash:B256::ZERO,winner:net.miners[0].id,shares:vec![]}),evidence:vec![],evidence_raw:&[],transactions:&[],ancestors:vec![]};
    assert!(matches!(apply_block(g,&net.genesis,&net.profile,&bad),Err(ApplyError::Context(_))));
    let chain=run_chain(&net,1,&|_|vec![]);
    // h=2 with a winner of address zero: recordResult reverts -> whole block rejected.
    let input=BlockInput{height:2,timestamp:1_800_000_004,base_fee:U256::from(875_000_000u64),gas_limit:8_000_000,prevrandao:B256::ZERO,proposer:Proposer::Fallback,
        parent_result:Some(ParentResult{block_hash:B256::ZERO,winner:Address::ZERO,shares:vec![]}),evidence:vec![],evidence_raw:&[],transactions:&[],ancestors:vec![]};
    assert!(matches!(apply_block(&chain[0].0.state,&net.genesis,&net.profile,&input),Err(ApplyError::System{..})));
}

#[test] fn evidence_burns_bond_and_tombs_identity(){
    let net=devnet3();let chain=run_chain(&net,3,&|_|vec![]);let s=&chain[2].0.state;let accused=net.miners[1].id;
    let input=BlockInput{height:4,timestamp:1_800_000_008,base_fee:U256::from(1_000_000_000u64)/U256::from(2),gas_limit:8_000_000,prevrandao:B256::ZERO,proposer:Proposer::Fallback,
        parent_result:Some(chain[2].1.clone()),evidence:vec![EvidenceEffect::PunishAndInvalidate{accused,j:3}],evidence_raw:&[vec![0xc0]],transactions:&[],ancestors:vec![]};
    let base=crate::fees::next_base_fee(chain[2].0.state.accounts.get(&escrow()).map(|_|U256::from(1u64)).unwrap()*U256::ZERO+chain_base(&chain),0,8_000_000).unwrap();
    let input=BlockInput{base_fee:base,..input};
    let o=apply_block(s,&net.genesis,&net.profile,&input).unwrap();
    let r=miner_record(&o.state,accused).unwrap();assert!(r.tomb);assert_eq!(r.bond_state,2);assert_eq!(r.status,2);
    assert_eq!(active_list(&o.state).len(),2);
    assert_eq!(o.facts.held_total,U256::from(2u64)*U256::from(10u128.pow(20)));
    assert_eq!(pending(&o.state,3).1>>168u32,U256::from(1),"pot 3 invalidated");
    // Punishing a tomb again rejects the block.
    let again=BlockInput{height:5,timestamp:1_800_000_010,base_fee:crate::fees::next_base_fee(base,0,8_000_000).unwrap(),parent_result:Some(chain[2].1.clone()),evidence:vec![EvidenceEffect::Punish{accused}],..input};
    assert!(apply_block(&o.state,&net.genesis,&net.profile,&again).is_err());
}
fn chain_base(chain:&[(BlockOutput,ParentResult)])->U256{let mut b=U256::from(1_000_000_000u64);for (o,_) in chain.iter().take(chain.len()-1){b=crate::fees::next_base_fee(b,o.gas_used,8_000_000).unwrap();}b}

#[test] fn closing_cursor_pays_bonds_and_final_block_settles_everything(){
    let mut cfg=DevnetConfig::new(777901,1_800_000_000,&["a","b","c"]);cfg.h_close=10;cfg.h_end=16;cfg.ret=2;
    let net=devnet::build(&cfg).unwrap();
    let ids:Vec<Address>=net.miners.iter().map(|m|m.id).collect();
    let mut state=net.genesis.state().clone();let mut prev:Option<ParentResult>=None;let mut base=U256::from(1_000_000_000u64);
    let bond=U256::from(10u128.pow(20));
    let mut finals=vec![];
    for h in 1..=16u64{
        let input=BlockInput{height:h,timestamp:1_800_000_000+2*h,base_fee:base,gas_limit:8_000_000,prevrandao:B256::ZERO,proposer:Proposer::Fallback,
            parent_result:prev.clone(),evidence:vec![],evidence_raw:&[],transactions:&[],ancestors:vec![]};
        let o=apply_block(&state,&net.genesis,&net.profile,&input).unwrap_or_else(|e|panic!("h={h} {e:?}"));
        base=crate::fees::next_base_fee(base,o.gas_used,8_000_000).unwrap();
        if h>=10{assert!(o.facts.closing,"closing from H_CLOSE");assert_eq!(o.facts.close_h,10);}
        if h==10{assert!(!o.facts.cursor_done,"RET=2 of 3 records");assert_eq!(o.facts.held_total,bond);}
        if h==11{assert!(o.facts.cursor_done);assert_eq!(o.facts.held_total,U256::ZERO);}
        finals.push(o.is_final);
        state=o.state.clone();prev=Some(ParentResult{block_hash:B256::ZERO,winner:ids[(h%3) as usize],shares:vec![]});
    }
    assert_eq!(finals.iter().filter(|f|**f).count(),1);assert!(finals[15],"h=16 is final");
    // F: no pending at all, every pot settled, no subsidy issued at F.
    for j in 1..=16{assert_eq!(pending(&state,j),(U256::ZERO,U256::ZERO,Address::ZERO),"pending[{j}]");}
    for m in &net.miners{let r=miner_record(&state,m.id).unwrap();assert_eq!(r.bond_state,3,"PAID");}
    // Supply identity: escrow balance == burnedTotal exactly (all held/pending gone).
    let f=chain_facts(&state);assert_eq!(state.accounts[&escrow()].info.balance,f.burned_total);
    // Total value: issued subsidy over 15 blocks + bonds = reward balances + burned.
    let rewards:U256=net.miners.iter().map(|m|state.accounts[&m.reward].info.balance).fold(U256::ZERO,|a,b|a+b);
    assert_eq!(rewards+f.burned_total,U256::from(15u64)*U256::from(2_000_000_000_000_000_000u128)+U256::from(3u64)*bond);
    // No child of F.
    let child=BlockInput{height:17,timestamp:1_800_000_034,base_fee:base,gas_limit:8_000_000,prevrandao:B256::ZERO,proposer:Proposer::Fallback,
        parent_result:prev.clone(),evidence:vec![],evidence_raw:&[],transactions:&[],ancestors:vec![]};
    assert!(apply_block(&state,&net.genesis,&net.profile,&child).is_err());
}

// ---- ExecFixture SV1–SV7s (incentives.md), executed through the compiled Escrow ----
struct Sv{net:devnet::Devnet,state:InMemoryDB}
fn put(db:&mut InMemoryDB,a:Address,k:U256,v:U256){db.insert_account_storage(a,k,v).unwrap();}
fn kslot(a:U256,b:U256)->U256{U256::from_be_bytes(keccak256([a.to_be_bytes::<32>(),b.to_be_bytes::<32>()].concat()).0)}
impl Sv{
    fn new(alpha:u16,gamma:u16)->Self{let mut c=DevnetConfig::new(777902,1_800_000_000,&["w"]);c.alpha_bp=alpha;c.gamma_bp=gamma;
        let net=devnet::build(&c).unwrap();let state=net.genesis.state().clone();Self{net,state}}
    fn identity(&mut self,label:&str,tomb:bool,record:bool)->Address{
        let id=crate::txsign::Key::devnet(&format!("sv-id:{label}")).address();let reward=crate::txsign::Key::devnet(&format!("sv-rw:{label}")).address();
        self.state.insert_account_info(reward,revm::primitives::AccountInfo{nonce:1,..Default::default()});
        if record{let r=record_slot(id);let w0=U256::from(1)|(U256::from(if tomb{2}else{1})<<16)|(U256::from(tomb as u8)<<8);
            put(&mut self.state,registry(),r,w0);put(&mut self.state,registry(),r+U256::from(1),U256::from_be_slice(reward.as_slice()));}
        id
    }
    fn reward(&self,id:Address)->Address{let r=record_slot(id);Address::from_word(B256::from(word(&self.state,registry(),r+U256::from(1))))}
    fn ledger(&mut self,j:u64,counts:&[(Address,u64)]){
        let total:u64=counts.iter().map(|c|c.1).sum();put(&mut self.state,ledger(),kslot(U256::from(j),U256::ZERO),U256::from(total));
        let n=kslot(U256::from(j),U256::from(1));let l=kslot(U256::from(j),U256::from(2));put(&mut self.state,ledger(),l,U256::from(counts.len()));
        let e=U256::from_be_bytes(keccak256(l.to_be_bytes::<32>()).0);
        for (i,(a,c)) in counts.iter().enumerate(){put(&mut self.state,ledger(),U256::from_be_bytes(keccak256([a.into_word().as_slice(),n.to_be_bytes::<32>().as_slice()].concat()).0),U256::from(*c));put(&mut self.state,ledger(),e+U256::from(i),U256::from_be_slice(a.as_slice()));}
    }
    fn pot(&mut self,j:u64,amount:u64,meta:U256,winner:Address){
        let b=kslot(U256::from(j),U256::from(3));put(&mut self.state,escrow(),b,U256::from(amount));put(&mut self.state,escrow(),b+U256::from(1),meta);put(&mut self.state,escrow(),b+U256::from(2),U256::from_be_slice(winner.as_slice()));
        self.state.accounts.get_mut(&escrow()).unwrap().info.balance+=U256::from(amount);
    }
    fn settle(&mut self,j:u64)->U256{
        let d=u64::from(self.net.profile.cp().D);let before=chain_facts(&self.state).burned_total;
        let block=NativeBlockContext{height:U256::from(j+d),timestamp:U256::from(1_800_000_100u64),gas_limit:U256::from(8_000_000u64),base_fee:U256::ZERO,prevrandao:B256::ZERO};
        let cp=self.net.profile.cp();let mut ex=Exec{state:self.state.clone(),profile:&self.net.profile,block,origin:Address::ZERO,used:0,limits:CodeLimits{runtime:cp.B_code_max,logical:cp.CODE_CAP},meter:Meter::default()};
        let mut data=selector("settle(uint256)");enc_u256(&mut data,U256::from(j));ex.call("settle",escrow(),data).unwrap();
        let after=chain_facts(&ex.state).burned_total;self.state=ex.state;after-before
    }
    fn bal(&self,id:Address)->U256{self.state.accounts.get(&self.reward(id)).map(|a|a.info.balance).unwrap_or_default()}
}
#[test] fn sv1_to_sv7s_exec_fixture_values(){
    // SV1: R=64000 {w:1} -> A=1000, baseBurn=63000.
    let mut s=Sv::new(0,0);let w=s.identity("w",false,true);s.ledger(1,&[(w,1)]);s.pot(1,64000,U256::from(1),w);
    assert_eq!(s.settle(1),U256::from(63000));assert_eq!(s.bal(w),U256::from(1000));
    // SV2: R=101 {w:1, 64 ids x1} -> A=101, sum p=65, roundBurn=36.
    let mut s=Sv::new(0,0);let w=s.identity("w",false,true);let mut c=vec![(w,1)];for i in 0..64{c.push((s.identity(&format!("i{i}"),false,true),1));}
    s.ledger(1,&c);s.pot(1,101,U256::from(1),w);assert_eq!(s.settle(1),U256::from(36));
    // SV3: R=1000 {w:3,x:2} -> 46/31, roundBurn=1, baseBurn=922.
    let mut s=Sv::new(0,0);let w=s.identity("w",false,true);let x=s.identity("x",false,true);s.ledger(1,&[(w,3),(x,2)]);s.pot(1,1000,U256::from(1),w);
    assert_eq!(s.settle(1),U256::from(923));assert_eq!((s.bal(w),s.bal(x)),(U256::from(46),U256::from(31)));
    // SV4: R=6400 {w:1, t:1 tomb} -> paid 100, penaltyBurn 100, baseBurn 6200.
    let mut s=Sv::new(0,0);let w=s.identity("w",false,true);let t=s.identity("t",true,true);s.ledger(1,&[(w,1),(t,1)]);s.pot(1,6400,U256::from(1),w);
    assert_eq!(s.settle(1),U256::from(6300));assert_eq!(s.bal(w),U256::from(100));assert_eq!(s.bal(t),U256::ZERO);
    // SV5: as SV4 but t has no record -> payBurn 100.
    let mut s=Sv::new(0,0);let w=s.identity("w",false,true);let t=s.identity("t",false,false);s.ledger(1,&[(w,1),(t,1)]);s.pot(1,6400,U256::from(1),w);
    assert_eq!(s.settle(1),U256::from(6300));assert_eq!(s.bal(w),U256::from(100));
    // SV6: invalid pot -> invalidBurn 5000.
    let mut s=Sv::new(1000,500);let w=s.identity("w",false,true);s.ledger(1,&[(w,1)]);s.pot(1,5000,U256::from(1)|(U256::from(1)<<168),w);
    assert_eq!(s.settle(1),U256::from(5000));assert_eq!(s.bal(w),U256::ZERO);
    // SV7: fallback pot 80000, C=1 -> 8000+4000 to winner, A=1062, baseBurn=66938, paid 13062.
    let mut s=Sv::new(1000,500);let w=s.identity("w",false,true);s.ledger(1,&[(w,1)]);s.pot(1,80000,U256::from(1),w);
    assert_eq!(s.settle(1),U256::from(66938));assert_eq!(s.bal(w),U256::from(13062));
    // SV7s: signed pot 164000 (proposer = w), C=1 -> paid 26778, baseBurn 137222.
    let mut s=Sv::new(1000,500);let w=s.identity("w",false,true);s.ledger(1,&[(w,1)]);s.pot(1,164000,U256::from_be_slice(w.as_slice())<<8u32,w);
    assert_eq!(s.settle(1),U256::from(137222));assert_eq!(s.bal(w),U256::from(26778));
}
