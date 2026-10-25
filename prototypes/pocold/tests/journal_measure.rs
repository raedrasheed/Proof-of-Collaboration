//! TRACK journal (audit-2026-10-22): measurement of the on-disk journal growth and the cost of
//! re-execution from genesis (open replay, deep-fork rebuild, restore), the re-execution cost per gas
//! and per block by block kind and state size, and the open memory. This test only MEASURES the
//! existing code (store::encode_record/encode_frame, Node::open replay, Chain::validate,
//! Chain::ensure_state, Chain::restore_canonical); it does not change behaviour and does not attack.
//! The harness profile is DevnetConfig::new with hash_rate 1024, d_att 73, tau 40, c 8 (cfg()): the
//! devnet caps, GAS_LIMIT, BODY_MAX and H_END, with an easier PoW and a wider attempt window.
//! It prints machine-readable `JM-*` lines consumed by development/audit-2026-10-22/JOURNAL-GROWTH-
//! AND-REPLAY.md. The heavy variants are `#[ignore]` and run in release:
//!   flock <cpu.lock> cargo test --release --test journal_measure -- --ignored --nocapture
//! See each test for scope. Facts used: a journal record is RLP([headerBytes, bodyBytes,
//! parentResultBytes]) (store::encode_record) framed with OVERHEAD = 41 B (store::OVERHEAD);
//! receipts/logs are NOT stored, they are re-derived on replay (store.rs doc, chain::validate).
use pocold::{chain::{Chain,Spec},store,types::*};
use pocold::header::Header;
use pocold::node::{Config,Limits,Node};
use pocol_lp4_execution::{devnet::{self,DevnetConfig},txsign::{Key,Tx}};
use revm::primitives::{Address,B256,U256};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Instant;

// ---- harness (self-contained; test files are separate crates, nothing imports consensus.rs) ----
fn cfg()->DevnetConfig{let mut c=DevnetConfig::new(777910,1_700_000_000,&["a","b","c"]);c.hash_rate=1024;c.d_att=73;c.tau=40;c.c=8;c}
fn admitted()->Spec{let c=cfg();let d=devnet::build(&c).unwrap();Spec::new(d.admit(&pocold::single_host_local()).unwrap_or_else(|e|panic!("{e}")).0)}
struct Net{chain:Chain,keys:HashMap<Address,Key>}
fn net()->Net{let c=cfg();let d=devnet::build(&c).unwrap();let mut keys=HashMap::new();
    for m in &d.miners{keys.insert(m.id,Key::from_secret(&m.key.secret()).unwrap());}
    Net{chain:Chain::new(admitted()),keys}}
fn try_seal(n:&Net,mut h:Header,body:Body,attempt:u32,start:u64)->Option<Block>{
    let p=n.chain.full_entry(&h.parent_hash).unwrap();let ctx=n.chain.child_ctx(&p,attempt).unwrap();
    let tid=template_id(&h.ut_raw);let mut shares=vec![];let mut x=start;
    loop{if (x as u128)>=ctx.assignment.nonce_max(){return None}let ph=pow_hash(&tid,x);if le_target(&ph,&ctx.t_share){if le_target(&ph,&ctx.target){break}shares.push(x);}x+=1;}
    let owner=addr(&ctx.assignment.owner(x).unwrap());
    h.nonce=x;shares.truncate(256);h.shares=shares;reseal(&mut h);
    h.winner_sig=n.keys[&owner].sign_hash(&B256::from(pocold::hashes::win_msg(&tid,x,&share_root(&h))));reseal(&mut h);
    Some(Block{header:h,body})}
fn fallback(n:&Net,parent:[u8;32],a:u32)->Block{let p=n.chain.full_entry(&parent).unwrap();
    for a in a..a+16{let (h,_,_)=n.chain.build_fallback(&p,a).unwrap();if let Some(b)=try_seal(n,h,Body::default(),a,0){return b}}panic!("no fallback solution")}
/// A signed a=0 block at ts = parent ts + T_blk (the window starts at parent ts + 1): on the ASERT schedule,
/// like a fallback a=0 block (lower + dFbWait), so a long run of signed blocks does not harden the target
/// (at parent ts + 1 each one ran 3 s ahead and the PoW work doubled every ~13 blocks).
fn signed(n:&Net,parent:[u8;32],body:Body)->Block{
    let p=n.chain.full_entry(&parent).unwrap();let ctx=n.chain.child_ctx(&p,0).unwrap();
    for off in u64::from(n.chain.spec.cp().T_blk).saturating_sub(1)..u64::from(n.chain.spec.cp().D_att){let (h,_,_)=n.chain.build_signed(&p,&n.keys[&ctx.proposer],ctx.window.lower()+off,body.clone(),vec![]).unwrap_or_else(|e|panic!("build_signed: {e:?}"));
        if let Some(b)=try_seal(n,h,body.clone(),0,0){return b}}panic!("no signed solution")}
fn import(n:&mut Net,b:&Block){let (e,_)=n.chain.validate(b,None,0).unwrap_or_else(|e|panic!("h={} {e:?}",b.header.h));n.chain.insert(e);n.chain.retain();}

// max_fee is set very high (1e15 wei) so a chain of full blocks, whose EIP-1559 base fee rises ~12.5%
// per full block, never outruns it within the measured runs.
fn pay(key:&Key,nonce:u64)->Vec<u8>{Tx{chain_id:777910,nonce,max_priority:U256::from(1_000_000_000u64),max_fee:U256::from(1_000_000_000_000_000u64),gas:21000,to:Some(devnet::account_key("bob").address()),value:U256::from(1u64),data:Default::default()}.sign_1559(key)}
/// A call with `len` zero calldata bytes to an EOA (no code runs): fills body bytes cheaply (zero
/// calldata gas) up to TX_MAX. Two of them reach BODY_MAX; each reserves GAS_LIMIT/2-50k so the pair
/// stays under GAS_LIMIT (calldata of this length costs far less than that reservation).
fn big_call(key:&Key,nonce:u64,len:usize)->Vec<u8>{Tx{chain_id:777910,nonce,max_priority:U256::from(1u64),max_fee:U256::from(1_000_000_000_000_000u64),gas:3_950_000,to:Some(devnet::account_key("bob").address()),value:U256::ZERO,data:vec![0u8;len].into()}.sign_1559(key)}
/// The most 21000-gas transfers build_signed accepts on `head` (a full-gas transfer block), found by
/// re-execution only (no PoW), then returned so the caller seals once.
fn pack_transfers(n:&Net,head:[u8;32],alice:&Key)->Vec<Vec<u8>>{
    let p=n.chain.full_entry(&head).unwrap();
    let (mut lo,mut hi)=(1usize,400usize);
    let ok=|k:usize|{let txs:Vec<Vec<u8>>=(0..k as u64).map(|i|pay(alice,i)).collect();
        n.chain.build_signed(&p,&n.keys[&n.chain.child_ctx(&p,0).unwrap().proposer],n.chain.child_ctx(&p,0).unwrap().window.lower(),Body{txs,evidence:vec![]},vec![]).is_ok()};
    assert!(ok(lo),"a single 21000-gas transfer must build");
    while lo<hi{let mid=(lo+hi+1)/2;if ok(mid){lo=mid}else{hi=mid-1}}
    (0..lo as u64).map(|i|pay(alice,i)).collect()
}
/// Init code: a loop of LOG0(0 bytes) `n` times then STOP (same shape as the eth_getLogs test). At
/// n=546 it hits LOG_COUNT_MAX; a log-heavy block's receipts are large but its JOURNAL record is not.
/// `gas` is the tx gas limit (so a log-heavy tx can be packed beside a compute filler in one block).
fn log_deploy_gas(key:&Key,nonce:u64,n:u16,gas:u64)->Vec<u8>{
    let mut init=vec![0x61,(n>>8) as u8,(n&0xff) as u8,0x5b];// PUSH2 n; JUMPDEST(3)
    init.extend([0x5f,0x5f,0xa0,0x60,0x01,0x90,0x03,0x80,0x60,0x03,0x57,0x00]);// PUSH0 PUSH0 LOG0; PUSH1 1 SWAP1 SUB; DUP1 PUSH1 3 JUMPI; STOP
    Tx{chain_id:777910,nonce,max_priority:U256::from(1u64),max_fee:U256::from(1_000_000_000_000_000u64),gas,to:None,value:U256::ZERO,data:init.into()}.sign_1559(key)}
fn log_deploy(key:&Key,nonce:u64,n:u16)->Vec<u8>{log_deploy_gas(key,nonce,n,8_000_000)}
/// A single compute-heavy tx that burns its whole gas limit: init code `JUMPDEST PUSH1 0 JUMP` is a
/// tight infinite loop, so creation runs out of gas (status 0, gas_used = gas limit, no logs). One per
/// block gives a FULL-GAS block that is bounded by neither TX_CAP (1 tx) nor TXBYTES_CAP (tiny body),
/// so H_END of them is reachable: the per-block replay worst case (J-V6). `gas` <= GAS_LIMIT headroom.
fn compute_oog(key:&Key,nonce:u64,gas:u64)->Vec<u8>{
    Tx{chain_id:777910,nonce,max_priority:U256::from(1u64),max_fee:U256::from(1_000_000_000_000_000u64),gas,to:None,value:U256::ZERO,data:vec![0x5b,0x60,0x00,0x56].into()}.sign_1559(key)}

// ---- full-gas compute kinds (J2-B1): one creation tx whose init code loops one operation until it runs
// out of its 7.95M gas. Like compute_oog, each is one tx with a body of at most 4.4 KB, so TX_CAP (1 tx)
// and TXBYTES_CAP bound how many a chain holds only weakly; the kinds differ in re-execution time per gas. ----
/// The tx gas of every compute kind (as compute_oog in JM-KIND/JM-BYTES; GAS_LIMIT is 8,000,000).
const FULL_GAS:u64=7_950_000;
fn deploy(key:&Key,nonce:u64,gas:u64,value:u64,init:Vec<u8>)->Vec<u8>{Tx{chain_id:777910,nonce,max_priority:U256::from(1u64),max_fee:U256::from(1_000_000_000_000_000u64),gas,to:None,value:U256::from(value),data:init.into()}.sign_1559(key)}
/// CODECOPY `input` to memory 0, then STATICCALL(GAS, addr, 0, args, ret_off, ret) until OOG. `args` >=
/// input.len() (the rest is zero memory). A precompile is warm (100 gas per call) and runs to its end.
fn precompile_loop(addr:u8,input:&[u8],args:u16,ret:u16)->Vec<u8>{
    let (len,ro)=(input.len() as u16,args.div_ceil(32)*32);assert!(args>=len);
    let c0=[0x61,(len>>8) as u8,len as u8,0x61,0x00,30,0x60,0x00,0x39,0x5b,0x61,(ret>>8) as u8,ret as u8,0x61,(ro>>8) as u8,ro as u8,
        0x61,(args>>8) as u8,args as u8,0x60,0x00,0x60,addr,0x5a,0xfa,0x50,0x61,0x00,0x09,0x56];
    let mut c=c0.to_vec();c.extend_from_slice(input);c
}
/// KECCAK256(0, n) in a loop (the memory expansion is paid once).
fn keccak_loop(n:u16)->Vec<u8>{vec![0x5b,0x61,(n>>8) as u8,n as u8,0x60,0x00,0x20,0x50,0x60,0x00,0x56]}
/// MSTORE at a rising offset: memory grows one word per iteration until the quadratic cost exhausts gas.
fn mem_grow_loop()->Vec<u8>{vec![0x60,0x00,0x5b,0x80,0x80,0x52,0x60,0x20,0x01,0x60,0x02,0x56]}
/// MCOPY(n, 0, n) in a loop.
fn mcopy_loop(n:u16)->Vec<u8>{vec![0x5b,0x61,(n>>8) as u8,n as u8,0x60,0x00,0x61,(n>>8) as u8,n as u8,0x5e,0x60,0x00,0x56]}
/// STATICCALL(GAS, helper, 0, 32, 0, 0) in a loop with calldata `x`: each call is a fresh frame whose
/// memory expands to x+32 bytes (MEM_HELPER).
fn mem_frame_loop(helper:Address,x:u32)->Vec<u8>{
    let mut c=vec![0x62,(x>>16) as u8,(x>>8) as u8,x as u8,0x60,0x00,0x52,0x5b,0x60,0x00,0x60,0x00,0x60,0x20,0x60,0x00,0x73];
    c.extend_from_slice(helper.as_slice());c.extend([0x5a,0xfa,0x50,0x60,0x07,0x56]);c
}
/// Init code deploying the runtime PUSH1 0 CALLDATALOAD MLOAD STOP.
const MEM_HELPER:[u8;17]=[0x60,0x05,0x60,0x0c,0x60,0x00,0x39,0x60,0x05,0x60,0x00,0xf3,0x60,0x00,0x35,0x51,0x00];

// ---- state-interacting full-gas compute kinds (J-REV3-1): the families the third review named (SSTORE
// cold/warm, cold CALL to fresh accounts, EXTCODECOPY, LOG-heavy, CREATE2). Each is one init-code loop that
// STOPs on a gas guard (so the create succeeds and any state it made persists), except log0_loop (which
// halts at LOG_COUNT_MAX) and cold_call/extcodecopy (which touch cold accounts but create nothing). The
// CREATE2 kind is the O(creates x live-accounts) regime: code_caps::register's create_return calls
// current_total (an O(db.accounts) scan) on every successful create. ----
/// SSTORE(i,1) at a rising slot i while gas >= 30000, then STOP: CREATES ~359 fresh storage slots in the
/// newly deployed contract (identical to the "slots" fill of jm_state_size_term).
fn sstore_fresh_loop()->Vec<u8>{vec![0x60,0x00,0x5b,0x61,0x75,0x30,0x5a,0x10,0x60,0x15,0x57,0x60,0x01,0x81,0x55,0x60,0x01,0x01,0x60,0x02,0x56,0x5b,0x00]}
/// SSTORE(0,v) with a rising v while gas >= 5000, then STOP: rewrites ONE slot (warm after the first), so
/// the state does not grow; measures the warm SSTORE-reset cost per gas.
fn sstore_warm_loop()->Vec<u8>{vec![0x60,0x01,0x5b,0x80,0x60,0x00,0x55,0x61,0x13,0x88,0x5a,0x10,0x60,0x15,0x57,0x60,0x01,0x01,0x60,0x02,0x56,0x5b,0x00]}
/// CALL(gas=0,addr=base+i,value=0,0,0,0,0) at a rising cold address while gas >= 3000, then STOP: touches a
/// fresh cold account each iteration (2600 gas) but, value being 0, creates nothing (no current_total scan).
fn cold_call_loop(base:u64)->Vec<u8>{let mut c=vec![0x67];c.extend(base.to_be_bytes());
    c.extend([0x5b,0x61,0x0b,0xb8,0x5a,0x10,0x60,0x27,0x57,0x60,0x00,0x60,0x00,0x60,0x00,0x60,0x00,0x60,0x00,0x85,0x60,0x00,0xf1,0x50,0x60,0x01,0x01,0x60,0x09,0x56,0x5b,0x00]);c}
/// EXTCODECOPY(addr=base+i,0,0,0) at a rising cold address while gas >= 3000, then STOP: cold account access
/// (2600 gas) with no copy, no state change.
fn extcodecopy_loop(base:u64)->Vec<u8>{let mut c=vec![0x67];c.extend(base.to_be_bytes());
    c.extend([0x5b,0x61,0x0b,0xb8,0x5a,0x10,0x60,0x20,0x57,0x60,0x00,0x60,0x00,0x60,0x00,0x83,0x3c,0x60,0x01,0x01,0x60,0x09,0x56,0x5b,0x00]);c}
/// LOG0(0,0) in a tight loop with no gas guard: the block meter halts the tx at LOG_COUNT_MAX (546) logs
/// (exceptional halt, all gas charged, status 0, logs discarded), so LOG is NOT a per-gas worst case.
fn log0_loop()->Vec<u8>{vec![0x5b,0x60,0x00,0x60,0x00,0xa0,0x60,0x00,0x56]}
/// CREATE2 of the empty-returning child (PUSH1 0 DUP1 RETURN) with a rising salt while gas >= 40000, then
/// STOP: CREATES ~248 fresh (empty-code, nonce 1) accounts, each paying a full current_total scan.
fn create2_loop()->Vec<u8>{vec![0x63,0x60,0x00,0x80,0xf3,0x60,0x00,0x52,0x60,0x00,0x5b,0x61,0x9c,0x40,0x5a,0x10,0x60,0x22,0x57,0x80,0x60,0x04,0x60,0x1c,0x60,0x00,0xf5,0x50,0x60,0x01,0x01,0x60,0x0a,0x56,0x5b,0x00]}
/// CALL(0,base+i,1 wei,0,0,0,0) at a rising fresh address while gas >= 40000, then STOP: CREATES ~230
/// accounts (the account fill of jm_state_size_term; a value-bearing cold CALL creates the callee).
fn fill_accts_init(base:u64)->Vec<u8>{let mut c=vec![0x67];c.extend(base.to_be_bytes());c.extend([0x5b,0x62,0x00,0x9c,0x40,0x5a,0x10,0x60,0x28,0x57,0x60,0x00,0x60,0x00,0x60,0x00,0x60,0x00,
    0x60,0x01,0x85,0x60,0x00,0xf1,0x50,0x60,0x01,0x01,0x60,0x09,0x56,0x5b,0x00]);c}
/// The empty-returning child init code used by create2_loop and the many-small-create blocks.
const EMPTY_CHILD:[u8;4]=[0x60,0x00,0x80,0xf3];
fn h32(s:&str)->[u8;32]{let mut o=[0u8;32];for (i,b) in o.iter_mut().enumerate(){*b=u8::from_str_radix(&s[2*i..2*i+2],16).unwrap();}o}
fn hexv(s:&str)->Vec<u8>{(0..s.len()/2).map(|i|u8::from_str_radix(&s[2*i..2*i+2],16).unwrap()).collect()}
/// A valid ecrecover input (bob's signature of a fixed hash).
fn ecrecover_input()->Vec<u8>{
    let k=devnet::account_key("bob");let sig=k.sign_hash(&B256::from([7u8;32]));
    let mut v=[7u8;32].to_vec();let mut w=[0u8;32];w[31]=27+sig[64];v.extend(w);v.extend(&sig[..64]);v
}
/// `pairs` copies of (G1 generator, G2 generator): a valid input (the check returns 0).
fn pairing_input(pairs:usize)->Vec<u8>{
    let mut g1=[0u8;64];g1[31]=1;g1[63]=2;
    let g2=["198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2","1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed",
        "090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b","12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa"];
    let mut v=vec![];for _ in 0..pairs{v.extend(g1);for x in g2{v.extend(h32(x));}}v
}
fn g1_add_input()->Vec<u8>{let mut v=vec![0u8;128];v[31]=1;v[63]=2;v[95]=1;v[127]=2;v}
fn g1_mul_input()->Vec<u8>{let mut v=vec![0u8;96];v[31]=1;v[63]=2;for b in &mut v[64..]{*b=0xff;}v}
fn blake2f_input(rounds:u32)->Vec<u8>{let mut v=vec![0u8;213];v[..4].copy_from_slice(&rounds.to_be_bytes());v[212]=1;v}
/// The c-kzg-4844 verify_kzg_proof_case_correct_proof_31ebd010e6098750 vector (revm-precompile's own test).
fn kzg_input()->Vec<u8>{
    use sha2::Digest;let commitment=hexv("8f59a8d2a1a625a17f3fea0fe5eb8c896db3764f3185481bc22f91b4aaffcca25f26936857bc3a7c2539ea8ec3a952b7");
    let mut vh=sha2::Sha256::digest(&commitment).to_vec();vh[0]=1;
    [vh,hexv("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000"),hexv("1522a4a7f34e1ea350ae07c29c96c7e79655aa926122e95fe69fcbd932ca49e9"),commitment,
     hexv("a62ad71d14c5719385c0686f1871430475bf3a00f0aa3f7b8dd99a9abc2160744faf0070725e00b60ad9a026a15b1a8c")].concat()
}
/// MODEXP(base, exp, mod) with `b`, `e`, `m` byte lengths: exponent all ones (the maximum iteration count
/// for its length), base and modulus pseudo-random with the top bit set (the base even when b <= 8); the
/// modulus odd, even (odd part times 2: CRT, two exponentiations) or a power of two ("pow2").
fn modexp_input(b:usize,e:usize,m:usize,md_kind:&str)->Vec<u8>{
    let mut v=vec![];for l in [b,e,m]{let mut w=[0u8;32];w[24..].copy_from_slice(&(l as u64).to_be_bytes());v.extend(w);}
    let fill=|n:usize,s:u8|->Vec<u8>{(0..n).map(|i|(i as u8).wrapping_mul(37).wrapping_add(s)).collect()};
    let mut base=fill(b,11);if let Some(x)=base.first_mut(){*x|=0x80;}if b<=8{if let Some(x)=base.last_mut(){*x&=!1}}
    let mut md=fill(m,101);if let Some(x)=md.first_mut(){*x|=0x80;}
    match md_kind{"odd"=>{if let Some(x)=md.last_mut(){*x|=1}},"even"=>{if let Some(x)=md.last_mut(){*x=(*x|3)&!1}},_=>{md=vec![0u8;m];md[0]=0x80;}}
    v.extend(base);v.extend(vec![0xffu8;e]);v.extend(md);v
}
const MODEXP_SHAPES:[(usize,usize,usize,&str);23]=[(1,32,1,"odd"),(8,32,8,"odd"),(8,32,8,"even"),(32,32,32,"odd"),(8,256,8,"even"),
    (1,1024,1,"odd"),(1,1024,1,"even"),(2,1024,2,"even"),(4,1024,4,"even"),(8,1024,8,"odd"),(8,1024,8,"even"),(8,1024,8,"pow2"),(8,4096,8,"even"),
    (16,1024,16,"odd"),(16,1024,16,"even"),(24,1024,24,"even"),(32,1024,32,"odd"),(32,1024,32,"even"),(64,1024,64,"odd"),(64,64,64,"odd"),
    (128,128,128,"odd"),(256,256,256,"odd"),(512,512,512,"odd")];
/// Every self-contained full-gas compute kind: (name, precompile address or 0, the whole call input, init code).
fn compute_kinds()->Vec<(String,u8,Vec<u8>,Vec<u8>)>{
    let pre=|name:&str,addr:u8,input:Vec<u8>,args:u16,ret:u16|{let mut full=input.clone();full.resize(args as usize,0);(name.to_string(),addr,full,precompile_loop(addr,&input,args,ret))};
    let op=|name:&str,init:Vec<u8>|(name.to_string(),0u8,vec![],init);
    let mut v=vec![op("jump_loop",vec![0x5b,0x60,0x00,0x56]),
        pre("ecrecover",1,ecrecover_input(),128,32),pre("ecrecover_invalid_v",1,vec![0u8;128],128,32),
        pre("sha256_32KiB",2,vec![],32768,32),pre("ripemd160_32KiB",3,vec![],32768,32),pre("identity_32KiB",4,vec![],32768,32768),pre("identity_0B",4,vec![],0,0),
        pre("bn_add",6,g1_add_input(),128,64),pre("bn_mul",7,g1_mul_input(),96,64),
        pre("bn_pair_1",8,pairing_input(1),192,32),pre("bn_pair_2",8,pairing_input(2),384,32),pre("bn_pair_10",8,pairing_input(10),1920,32),
        pre("blake2f_100k",9,blake2f_input(100_000),213,64),pre("blake2f_12",9,blake2f_input(12),213,64),
        pre("kzg_point_eval",0x0a,kzg_input(),192,64),
        op("keccak_32B",keccak_loop(32)),op("keccak_1KiB",keccak_loop(1024)),op("keccak_32KiB",keccak_loop(32768)),
        op("mem_grow_mstore",mem_grow_loop()),op("mcopy_32KiB",mcopy_loop(32768)),
        // State-interacting families (J-REV3-1); measured on the small genesis state here, their state
        // dependence is in jm_create_state_term / jm_state_size_term.
        op("sstore_fresh",sstore_fresh_loop()),op("sstore_warm",sstore_warm_loop()),
        op("cold_call",cold_call_loop(1u64<<50)),op("extcodecopy_cold",extcodecopy_loop(1u64<<50)),
        op("log0_loop",log0_loop()),op("create2_loop",create2_loop())];
    for (b,e,m,mk) in MODEXP_SHAPES{let input=modexp_input(b,e,m,mk);let n=input.len() as u16;
        v.push(pre(&format!("modexp_b{b}_e{e}_m{m}_{mk}"),5,input,n,m as u16));}
    v
}
fn compute_init(kind:&str)->Option<Vec<u8>>{if kind=="full_gas_compute"{return Some(vec![0x5b,0x60,0x00,0x56])}compute_kinds().into_iter().find(|k|k.0==kind).map(|k|k.3)}
/// One block body of `kind` at alice's `nonce` (advanced): the JM-KIND kinds or any compute kind.
fn kind_body(kind:&str,alice:&Key,nonce:&mut u64,transfers_k:u64,bodymax_len:usize)->Body{
    let txs=match kind{
        "empty"=>vec![],
        "full_gas_transfers"=>(0..transfers_k).map(|i|pay(alice,*nonce+i)).collect(),
        "log_heavy_546"=>vec![log_deploy(alice,*nonce,546)],
        "full_body_max"=>vec![big_call(alice,*nonce,bodymax_len),big_call(alice,*nonce+1,bodymax_len)],
        k=>vec![deploy(alice,*nonce,FULL_GAS,0,compute_init(k).unwrap_or_else(||panic!("unknown kind {k}")))],
    };*nonce+=txs.len() as u64;Body{txs,evidence:vec![]}
}
/// A block of `kind` on `parent` (a fallback block for "empty").
fn kind_block(n:&Net,parent:[u8;32],kind:&str,alice:&Key,nonce:&mut u64,transfers_k:u64,bodymax_len:usize)->Block{
    if kind=="empty"{return fallback(n,parent,0)}let body=kind_body(kind,alice,nonce,transfers_k,bodymax_len);signed(n,parent,body)}
/// The two big_call lengths that fill a body to just under BODY_MAX.
fn bodymax_len(n:&Net,alice:&Key)->usize{let max=n.chain.spec.cp().BODY_MAX as usize;let mut len=max/2-200;
    loop{let e=(Body{txs:vec![big_call(alice,0,len),big_call(alice,1,len)],evidence:vec![]}).encode().len();
        if e>max{len-=64;}else if (Body{txs:vec![big_call(alice,0,len+64),big_call(alice,1,len+64)],evidence:vec![]}).encode().len()<=max{len+=64;}else{break}}len}
fn median(mut v:Vec<f64>)->f64{v.sort_by(|a,b|a.partial_cmp(b).unwrap());v[v.len()/2]}
/// Validate time of `b` on its (resident) parent, `reps` runs: (min ms, median ms, gasUsed).
fn validate_ms(chain:&Chain,b:&Block,reps:usize)->(f64,f64,u64){
    let mut ts=vec![];let mut gas=0;
    for _ in 0..reps{let t=Instant::now();let (e,_)=chain.validate(b,None,0).unwrap_or_else(|e|panic!("validate: {e:?}"));ts.push(t.elapsed().as_secs_f64()*1e3);gas=e.gas_used;}
    (ts.iter().cloned().fold(f64::MAX,f64::min),median(ts),gas)
}

#[cfg(target_os="linux")]
fn rss_bytes()->i64{let s=std::fs::read_to_string("/proc/self/statm").unwrap();s.split_whitespace().nth(1).unwrap().parse::<i64>().unwrap()*4096}
#[cfg(not(target_os="linux"))]
fn rss_bytes()->i64{-1}
#[cfg(target_os="linux")]
fn vmhwm_bytes()->i64{std::fs::read_to_string("/proc/self/status").unwrap().lines().find(|l|l.starts_with("VmHWM:")).map(|l|l.split_whitespace().nth(1).unwrap().parse::<i64>().unwrap()*1024).unwrap_or(-1)}
#[cfg(not(target_os="linux"))]
fn vmhwm_bytes()->i64{-1}

fn tmp(name:&str)->PathBuf{let d=std::env::temp_dir().join(format!("pocold-jm-{name}-{}",std::process::id()));let _=std::fs::remove_dir_all(&d);d}
fn disk_bytes(dir:&std::path::Path)->u64{std::fs::read(dir.join("blocks.journal")).map(|b|b.len() as u64).unwrap_or(0)}

/// The exact on-disk record size of a built block: encode_record (RLP of header/body/result),
/// framed with OVERHEAD. `result` is the parentResult the node stores; we take it from validate().
fn record_bytes(chain:&Chain,b:&Block)->usize{
    let (e,_)=chain.validate(b,None,0).unwrap();
    let rb=result_bytes(&e);
    store::encode_frame(&store::encode_record(&b.header.encoded,&b.body.encode(),&rb)).len()
}
/// Re-derive the stored parentResult bytes (node.rs result_bytes), via the public Entry.result.
fn result_bytes(e:&pocold::chain::Entry)->Vec<u8>{
    use pocold::rlp;let mut p=Vec::new();
    if let Some(r)=&e.result{rlp::encode_bytes(r.winner.as_slice(),&mut p);let mut l=Vec::new();
        for (n,o) in &r.shares{let mut q=Vec::new();rlp::encode_bytes(&n.to_be_bytes(),&mut q);rlp::encode_bytes(o.as_slice(),&mut q);rlp::encode_list_payload(&q,&mut l);}
        rlp::encode_list_payload(&l,&mut p);}
    let mut o=Vec::new();rlp::encode_list_payload(&p,&mut o);o
}

fn mnode(tag:&str)->(Node,PathBuf,impl Fn()->Config){
    let dir=tmp(tag);let d=dir.clone();
    let conf=move||Config{dir:d.clone(),name:"jm".into(),miner:None,listen:None,peers:vec![],rpc:None,stop_at:None,log:false,limits:Limits::default()};
    (Node::open(conf(),admitted()).unwrap(),dir,conf)
}

// ============================ (a1) journal bytes per record ============================
/// Bytes a single journal record occupies for each block kind. Fast; runs in all builds.
#[test]
fn jm_journal_bytes_per_record(){
    let mut n=net();let g=n.chain.head;let alice=devnet::account_key("alice");
    // one real parent so signed templates have a drawn proposer and base fee
    let p0=fallback(&n,g,0);import(&mut n,&p0);let head=n.chain.head;
    let empty=fallback(&n,head,1);
    let transfers=pack_transfers(&n,head,&alice); // the most 21000-gas transfers a block holds (~full gas)
    let full_gas=signed(&n,head,Body{txs:transfers,evidence:vec![]});
    let logheavy=signed(&n,head,Body{txs:vec![log_deploy(&alice,0,546)],evidence:vec![]});
    // Pack body to just under BODY_MAX with two big zero-calldata calls.
    let max=n.chain.spec.cp().BODY_MAX as usize;let mut len=max/2-200;
    loop{let body=Body{txs:vec![big_call(&alice,0,len),big_call(&alice,1,len)],evidence:vec![]};
        if body.encode().len()>max{len-=64;}else if (Body{txs:vec![big_call(&alice,0,len+64),big_call(&alice,1,len+64)],evidence:vec![]}).encode().len()<=max{len+=64;}else{break}}
    let body_max=signed(&n,head,Body{txs:vec![big_call(&alice,0,len),big_call(&alice,1,len)],evidence:vec![]});
    // Full-gas compute block (1 tx, ~8M gas OOG loop): the open-time worst case, bounded by no cap.
    let fg_compute=signed(&n,head,Body{txs:vec![compute_oog(&alice,0,7_950_000)],evidence:vec![]});
    // Full-gas LOG-heavy block (546 logs then a compute filler to ~8M gas): the task's "8M gas of a
    // log-heavy contract". Shows the journal record stays small while receipts/logs are large.
    let fg_logs=signed(&n,head,Body{txs:vec![log_deploy_gas(&alice,0,546,300_000),compute_oog(&alice,1,7_650_000)],evidence:vec![]});
    let kinds=[("empty",&empty),("full_gas_transfers",&full_gas),("log_heavy_546",&logheavy),("full_body_max",&body_max),("full_gas_compute",&fg_compute),("full_gas_logs",&fg_logs)];
    let mut out=serde_json::Map::new();
    for (k,b) in kinds{
        let rec=record_bytes(&n.chain,b);
        let body=b.body.encode().len();let hdr=b.header.encoded.len();let txs=b.body.txs.len();
        let (e,_)=n.chain.validate(b,None,0).unwrap();let receipts:usize=e.receipts.iter().map(|r|r.len()).sum();
        let result=result_bytes(&e).len();let shares=b.header.shares.len();
        out.insert(k.into(),serde_json::json!({"recordBytes":rec,"headerBytes":hdr,"bodyBytes":body,"resultBytes":result,"powShares":shares,"txs":txs,"receiptBytesNotStored":receipts,"gasUsed":e.gas_used,"cumLogBytes":e.cum_log_bytes}));
    }
    println!("JM-BYTES {}",serde_json::Value::Object(out));
    println!("JM-CONST {}",serde_json::json!({"OVERHEAD":store::OVERHEAD,"MAX_RECORD":store::MAX_RECORD,"BODY_MAX":n.chain.spec.cp().BODY_MAX,"TX_MAX":n.chain.spec.cp().TX_MAX,"GAS_LIMIT":n.chain.spec.cp().GAS_LIMIT}));
}

// ============================ (a2) replay-at-open + RSS, empty blocks ============================
/// Builds up to `JM_HEIGHT` empty (fallback) blocks into an on-disk journal, snapshots the data dir
/// at the checkpoints, then reopens each snapshot and times the replay-at-open (every record re-executed
/// from genesis). Replay time is NOT linear in the record count: per-record retain and rebuild_canonical
/// grow with the height (jm_replay_component_split), so open(H) ~ a*H + b*H^2/2; the checkpoints are the
/// points of that fit. VmHWM/RSS here are in-process (the build phase dominates them; jm_open_memory
/// measures the open alone). Release only. `JM_HEIGHT` overrides the max height (default 20000 = devnet
/// H_END); `JM_CHECKPOINTS` (comma list, default 1000,5000,20000) the snapshot heights.
#[test]
#[ignore="measurement: run in release with --ignored --nocapture"]
fn jm_replay_empty_blocks(){
    let h_max:u64=std::env::var("JM_HEIGHT").ok().and_then(|s|s.parse().ok()).unwrap_or(20_000);
    let cps:Vec<u64>=std::env::var("JM_CHECKPOINTS").ok().map(|s|s.split(',').filter_map(|x|x.trim().parse().ok()).collect()).unwrap_or_else(||vec![1000,5000,20000]);
    let checkpoints:Vec<u64>=cps.into_iter().filter(|c|*c<=h_max).collect();
    let (mut n,dir,_)=mnode("replay");
    let mut harness=net();let mut parent=harness.chain.head;
    let t_build=Instant::now();let mut snaps:Vec<(u64,PathBuf)>=vec![];
    for h in 1..=h_max{
        let b=fallback(&harness,parent,0);import(&mut harness,&b);parent=b.hash();
        n.import(b,None).unwrap();
        if checkpoints.contains(&h){
            let snap=tmp(&format!("snap{h}"));std::fs::create_dir_all(&snap).unwrap();
            for f in ["blocks.journal","blocks.commit","retention.rkeep"]{let s=dir.join(f);if s.exists(){std::fs::copy(&s,snap.join(f)).unwrap();}}
            snaps.push((h,snap));
        }
        if h%2000==0{eprintln!("  built {h}/{h_max} ({:.0}s)",t_build.elapsed().as_secs_f64());}
    }
    let build_s=t_build.elapsed().as_secs_f64();
    let final_disk=disk_bytes(&dir);let final_records=n.journal_records();
    drop(n);drop(harness);
    for (h,snap) in &snaps{
        let before=vmhwm_bytes();let rss0=rss_bytes();
        let t=Instant::now();
        let conf=Config{dir:snap.clone(),name:"jm".into(),miner:None,listen:None,peers:vec![],rpc:None,stop_at:None,log:false,limits:Limits::default()};
        let r=Node::open(conf,admitted()).unwrap();
        let open_s=t.elapsed().as_secs_f64();
        let after=vmhwm_bytes();let rss1=rss_bytes();
        let records=r.journal_records();assert_eq!(records,*h,"replayed {} records at checkpoint {h}",records);
        let dbytes=disk_bytes(snap);
        println!("JM-REPLAY {}",serde_json::json!({"height":h,"records":records,"journalDiskBytes":dbytes,"openSeconds":open_s,"perRecordMicros":open_s*1e6/(*h as f64),"vmHwmBeforeBytes":before,"vmHwmAfterBytes":after,"rssBeforeBytes":rss0,"rssAfterBytes":rss1}));
        drop(r);let _=std::fs::remove_dir_all(snap);
    }
    println!("JM-BUILD {}",serde_json::json!({"hMax":h_max,"buildSeconds":build_s,"finalJournalDiskBytes":final_disk,"finalRecords":final_records,"bytesPerRecordAvg":final_disk as f64/final_records.max(1) as f64}));
    let _=std::fs::remove_dir_all(&dir);
}

// ============================ (a3) per-block replay cost by block kind ============================
/// Per-record replay cost for each block kind, from a modest run (building 20k full blocks is
/// infeasible). Each record is re-executed on its parent, so the open time at height H is H * perRecord
/// plus the super-linear retain/index term of jm_replay_empty_blocks plus the fixed open cost; that fixed
/// cost (spec admission, store open; `admitted()` is inside the timer) is measured first as JM-OPEN0, the
/// open of an empty journal, so steady per-record = (openSeconds - JM-OPEN0) / records. JM_KINDS (comma
/// list) picks the kinds: the defaults, or any compute kind of compute_kinds(). Release only.
#[test]
#[ignore="measurement: run in release with --ignored --nocapture"]
fn jm_replay_by_kind(){
    let count:u64=std::env::var("JM_KIND_COUNT").ok().and_then(|s|s.parse().ok()).unwrap_or(40);
    let kinds:Vec<String>=std::env::var("JM_KINDS").map(|s|s.split(',').map(str::to_string).collect())
        .unwrap_or_else(|_|["empty","full_gas_transfers","log_heavy_546","full_body_max","full_gas_compute"].map(str::to_string).to_vec());
    {let (n,dir,conf)=mnode("kind-open0");drop(n);let mut ts=vec![];
        for _ in 0..5{let t=Instant::now();let r=Node::open(conf(),admitted()).unwrap();ts.push(t.elapsed().as_secs_f64());drop(r);}
        println!("JM-OPEN0 {}",serde_json::json!({"records":0,"openSecondsMedian":median(ts.clone()),"openSecondsMin":ts.iter().cloned().fold(f64::MAX,f64::min),"runs":5}));
        let _=std::fs::remove_dir_all(&dir);}
    for kind in kinds{let kind=kind.as_str();
        let (mut n,dir,_)=mnode(&format!("kind-{kind}"));
        let mut harness=net();let mut parent=harness.chain.head;
        let alice=devnet::account_key("alice");let mut nonce=0u64;let bl=bodymax_len(&harness,&alice);
        // The per-block transfer count is fixed (constant gas limit); compute once from the first parent.
        let transfers_k=if kind=="full_gas_transfers"{pack_transfers(&harness,parent,&alice).len() as u64}else{0};
        let t_build=Instant::now();
        for _ in 0..count{
            let b=kind_block(&harness,parent,kind,&alice,&mut nonce,transfers_k,bl);
            import(&mut harness,&b);parent=b.hash();n.import(b,None).unwrap();
        }
        let build_s=t_build.elapsed().as_secs_f64();
        let disk=disk_bytes(&dir);let records=n.journal_records();
        drop(n);drop(harness);
        let t=Instant::now();
        let conf=Config{dir:dir.clone(),name:"jm".into(),miner:None,listen:None,peers:vec![],rpc:None,stop_at:None,log:false,limits:Limits::default()};
        let r=Node::open(conf,admitted()).unwrap();
        let open_s=t.elapsed().as_secs_f64();
        assert_eq!(r.journal_records(),records);
        println!("JM-KIND {}",serde_json::json!({"kind":kind,"blocks":count,"records":records,"journalDiskBytes":disk,"bytesPerRecord":disk as f64/records.max(1) as f64,"buildSeconds":build_s,"openSeconds":open_s,"perRecordMillis":open_s*1e3/records.max(1) as f64}));
        drop(r);let _=std::fs::remove_dir_all(&dir);
    }
}

// ============================ (a4) deep-fork rebuild vs fork-point height ============================
/// A fork point below the K_hist window has a pruned state; a rebuild (ensure_state) re-executes from
/// the nearest retained ancestor, which below the window is genesis — there are no reverse diffs
/// (storage.md:70 expects them for 2048 blocks). This times ensure_state for several fork-point
/// heights, showing the rebuild cost scales with the fork-point height (linear in height, not depth).
/// Release only.
#[test]
#[ignore="measurement: run in release with --ignored --nocapture"]
fn jm_deep_fork_rebuild_vs_height(){
    let h_max:u64=std::env::var("JM_REBUILD_HEIGHT").ok().and_then(|s|s.parse().ok()).unwrap_or(5000);
    let mut harness=net();let mut parent=harness.chain.head;let blocks:Vec<Block>={
        let mut v=vec![];for _ in 0..h_max{let b=fallback(&harness,parent,0);import(&mut harness,&b);parent=b.hash();v.push(b);}v};
    // A chain that keeps ALL canonical states resident (k_hist huge) so we can prune on demand and
    // measure the rebuild of one target from genesis.
    let mut chain=Chain::new(admitted());chain.k_hist=u64::MAX;chain.side_cap=h_max as usize+8;
    for b in &blocks{let (e,_)=chain.validate(b,None,0).unwrap();chain.insert(e);}
    let mut fps:Vec<u64>=[100u64,500,1000,2048,3000,h_max].into_iter().filter(|f|*f<=h_max).collect();fps.sort_unstable();fps.dedup();
    for f in fps{
        let hash=chain.canonical_at(f).unwrap().hash;
        // Prune every canonical state except genesis, forcing a full rebuild from genesis to f.
        let hs:Vec<[u8;32]>=chain.canonical.iter().skip(1).copied().collect();
        for h in hs{let e=chain.blocks.get_mut(&h).unwrap();e.state=Default::default();e.pruned=true;}
        let before=chain.rebuilds;let t=Instant::now();
        chain.ensure_state(&hash).unwrap();
        let s=t.elapsed().as_secs_f64();
        println!("JM-REBUILD {}",serde_json::json!({"forkPointHeight":f,"reExecutions":chain.rebuilds-before,"seconds":s,"perBlockMillis":s*1e3/f as f64}));
    }
}

// ============================ (a5) deep-reorg latency: rebuild + restore ============================
/// A legal deep reorg whose fork point is below the K_hist window pays the genesis rebuild TWICE on the
/// single consensus thread (J-V1): once when the first competing block is validated (its parent, the
/// canonical fork point, has a pruned state -> NeedsRebuild -> ensure_state_with from genesis), and
/// again inside restore_canonical when the branch is adopted (restore re-executes the adopted suffix
/// from the fork point's state). The cause of the second rebuild (J2-M2): Chain::retain prunes EVERY
/// canonical state below head-K_hist (canonical.iter().skip(1).take(cut)), the fork point included, at
/// the end of the very import that rebuilt it, although a resident side branch still builds on it; the
/// side_max states are kept only for non-canonical blocks. So the fork point is pruned again long before
/// adoption, and the order of retain and restore_canonical inside the adopting import is irrelevant
/// (moving restore before retain still gives 300 + 300). JM-REORG-MECH shows it on a bare chain: the fork
/// point holds a state after the rebuild and the side insert, and none after the next retain(). Plus d
/// re-executions to validate the suffix and d to restore it: latency ~= 2*rebuild(f) + 2*d*a. The
/// resulting journal is then reopened to show open replay re-pays both rebuilds. Release only.
/// JM_REORG_HEIGHT sets the canonical height (fork point = half of it); JM_REORG_KIND (default empty)
/// builds the canonical chain C from blocks of that kind (kind_block), so the rebuilds re-execute loaded
/// blocks.
#[test]
#[ignore="measurement: run in release with --ignored --nocapture"]
fn jm_deep_reorg_latency(){
    let n_c:u64=std::env::var("JM_REORG_HEIGHT").ok().and_then(|s|s.parse().ok()).unwrap_or(600);let f=n_c/2;
    let kind=std::env::var("JM_REORG_KIND").unwrap_or_else(|_|"empty".into());
    // Builder keeps every state resident (k_hist=MAX, side_cap huge) so both branches build cleanly.
    let mut h=net();h.chain.k_hist=u64::MAX;h.chain.side_cap=n_c as usize*4+64;
    let alice=devnet::account_key("alice");let mut nonce=0u64;let bl=bodymax_len(&h,&alice);
    let tk=if kind=="full_gas_transfers"{pack_transfers(&h,h.chain.head,&alice).len() as u64}else{0};
    let mut c=vec![];let mut p=h.chain.head;for _ in 0..n_c{let b=kind_block(&h,p,&kind,&alice,&mut nonce,tk,bl);import(&mut h,&b);p=b.hash();c.push(b);}
    let fp=c[f as usize-1].hash(); // canonical block at height f
    // Competing branch T from the fork point: a signed first block (distinct from C's fallback
    // continuation, so no duplicate) whose PATH is still lighter than C until T grows past it, then
    // fallback(a=0) until strictly heavier (T is adopted only then; its path work, not per-height work,
    // decides D133). Grown in the all-states-resident builder.
    let cw=h.chain.get(&c.last().unwrap().hash()).unwrap().total_work;
    let t0=signed(&h,fp,Body::default());import(&mut h,&t0);let mut p=t0.hash();let mut t=vec![t0];
    while h.chain.get(&p).unwrap().total_work<=cw{let b=fallback(&h,p,0);import(&mut h,&b);p=b.hash();t.push(b);}
    let b=fallback(&h,p,0);import(&mut h,&b);t.push(b); // one past the crossover: a clean strict margin
    assert!(h.chain.get(&t.last().unwrap().hash()).unwrap().total_work>cw,"T must be heavier");
    drop(h);
    // J2-M2 on a bare chain (default k_hist): the fork point's state after the rebuild, after the side
    // insert of T's first block, and after the retain() that follows it (no adoption involved).
    let mech={let mut b=Chain::new(admitted());for x in &c{let (e,_)=b.validate(x,None,0).unwrap();b.insert(e);b.retain();}
        let pruned0=b.get(&fp).unwrap().pruned;b.ensure_state(&fp).unwrap();let rebuilt=!b.get(&fp).unwrap().pruned;
        let (e,_)=b.validate(&t[0],None,0).unwrap();b.insert(e);let inserted=!b.get(&fp).unwrap().pruned;let side=!b.is_canonical(&t[0].hash());
        b.retain();
        serde_json::json!({"kHist":b.k_hist,"headHeight":b.head().height,"forkPointHeight":f,"forkPointPrunedBefore":pruned0,"stateAfterRebuild":rebuilt,"stateAfterSideInsert":inserted,
            "t0NonCanonical":side,"stateAfterNextRetain":!b.get(&fp).unwrap().pruned,"t0KeepsItsState":!b.get(&t[0].hash()).unwrap().pruned})};
    println!("JM-REORG-MECH {mech}");
    // Node under test: default single-host limits (k_hist=32, side_max=8, side_cap=2048).
    let (mut n,dir,_)=mnode("reorg");
    for b in &c{n.import(b.clone(),None).unwrap();}
    assert!(f+n.chain.k_hist<n.chain.head().height,"fork point must be below the K_hist window");
    let r0=n.chain.rebuilds;
    let (mut first,mut adopt)=(None,None);let t_all=Instant::now();
    for (i,b) in t.iter().enumerate(){
        let (rb,rs)=(n.chain.rebuilds,n.stats.restored);let ti=Instant::now();let nh=n.import(b.clone(),None).unwrap();
        let (dt,dr)=(ti.elapsed().as_secs_f64(),n.chain.rebuilds-rb);
        if i==0{first=Some((dt,dr,n.chain.get(&fp).map(|e|e.pruned)));}
        if nh&&adopt.is_none()&&n.chain.head==b.hash(){adopt=Some((i,dt,dr,n.stats.restored-rs));}
    }
    let (total_s,total_rebuilds)=(t_all.elapsed().as_secs_f64(),n.chain.rebuilds-r0);
    assert_eq!(n.chain.head,t.last().unwrap().hash(),"T adopted");
    let (fi,fr,fpp)=first.unwrap();let (ai,at,ar,arest)=adopt.unwrap();
    println!("JM-REORG {}",serde_json::json!({"kind":kind,"canonicalHeight":n_c,"forkPointHeight":f,"kHist":n.chain.k_hist,"reorgDepth":n_c-f,"theirBlocks":t.len(),
        "firstSideImport":{"seconds":fi,"rebuilds":fr,"forkPointPrunedAfter":fpp},"adoptingImport":{"index":ai,"seconds":at,"rebuilds":ar,"restoredBlocks":arest},
        "allImports":{"seconds":total_s,"rebuilds":total_rebuilds},"stageAModelRebuilds":f,"actualRebuilds":total_rebuilds}));
    drop(n);
    // Reopen: replay re-imports T as a side branch then adopts, re-paying both rebuilds.
    let conf=Config{dir:dir.clone(),name:"jm".into(),miner:None,listen:None,peers:vec![],rpc:None,stop_at:None,log:false,limits:Limits::default()};
    let t=Instant::now();let r=Node::open(conf,admitted()).unwrap();let open_s=t.elapsed().as_secs_f64();
    println!("JM-REORG-OPEN {}",serde_json::json!({"records":r.journal_records(),"openSeconds":open_s,"rebuildsDuringOpen":r.chain.rebuilds}));
    drop(r);let _=std::fs::remove_dir_all(&dir);
}

// ============================ (a6) open-time memory: peak, steady, transient (fresh process) ============================
/// Returns freed heap to the OS (glibc malloc_trim), so RSS shows what is live; a no-op elsewhere.
#[cfg(all(target_os="linux",target_env="gnu"))]
fn trim_heap(){unsafe{libc::malloc_trim(0);}}
#[cfg(not(all(target_os="linux",target_env="gnu")))]
fn trim_heap(){}
/// Node::open memory in a fresh process (J-V4, J-V5, J2-M3). store::open reads the whole journal
/// (read_to_end) and parse_v2 copies each payload, and Node::open holds every payload for the whole
/// replay; after open the node keeps its resident chain. JM_MEM_OPEN=<dir> makes this process only open
/// that dir: the journal size comes from metadata (nothing is read before the baseline), freed heap is
/// trimmed, then baseline = RSS before open; peak = VmHWM after open; steady = RSS after open with the
/// node alive and freed heap trimmed (the post-open resident chain, which the A13 history terms already
/// count); transient = peak - steady (the open-only working set the A13 bound excludes). Both ratios
/// depend on the block kind (an empty-block journal is mostly headers and parentResult, a body-max one
/// mostly bodies). Absent, it builds a journal of JM_MEM_KIND (default full_body_max, up to the devnet
/// TXBYTES_CAP; other kinds JM_MEM_N blocks, default 3000 empty / 40 otherwise) into JM_MEM_DIR (kept
/// for a fresh-process open) or a temp dir, and reopens it in-process with VmHWM reset (which
/// UNDER-counts: the allocator reuses the build's freed memory). Linux only (procfs). Release only.
#[test]
#[ignore="measurement: run in release with --ignored --nocapture"]
fn jm_open_memory(){
    fn vmrss()->i64{std::fs::read_to_string("/proc/self/status").ok().and_then(|s|s.lines().find(|l|l.starts_with("VmRSS:")).and_then(|l|l.split_whitespace().nth(1).and_then(|x|x.parse().ok()))).map(|k:i64|k*1024).unwrap_or(-1)}
    let conf=|dir:&PathBuf|Config{dir:dir.clone(),name:"jm".into(),miner:None,listen:None,peers:vec![],rpc:None,stop_at:None,log:false,limits:Limits::default()};
    if let Ok(d)=std::env::var("JM_MEM_OPEN"){
        let dir=PathBuf::from(d);let jbytes=std::fs::metadata(dir.join("blocks.journal")).map(|m|m.len()).unwrap_or(0) as i64;
        let spec=admitted();trim_heap();
        let (rss0,hwm0)=(vmrss(),vmhwm_bytes());let t=Instant::now();
        let r=Node::open(conf(&dir),spec).unwrap();
        let open_s=t.elapsed().as_secs_f64();let (rss1,hwm1)=(vmrss(),vmhwm_bytes());trim_heap();let rss2=vmrss();
        let j=jbytes.max(1) as f64;
        println!("JM-OPENMEM-FRESH {}",serde_json::json!({"kind":std::env::var("JM_MEM_KIND").unwrap_or_default(),"records":r.journal_records(),"journalBytes":jbytes,"openSeconds":open_s,
            "baseline":"RSS after admitted() and malloc_trim, before Node::open; journal size from metadata",
            "rssBeforeBytes":rss0,"vmHwmBeforeBytes":hwm0,"vmHwmAfterBytes":hwm1,"rssAfterBytes":rss1,"rssAfterTrimmedBytes":rss2,
            "peakAboveBaselineBytes":(hwm1-rss0),"steadyAboveBaselineBytes":(rss2-rss0),"transientBytes":(hwm1-rss2),
            "peakOverJournal":(hwm1-rss0) as f64/j,"steadyOverJournal":(rss2-rss0) as f64/j,"transientOverJournal":(hwm1-rss2) as f64/j}));
        return
    }
    let kind=std::env::var("JM_MEM_KIND").unwrap_or_else(|_|"full_body_max".into());
    let persist=std::env::var("JM_MEM_DIR").ok();
    let dir=persist.clone().map(PathBuf::from).unwrap_or_else(||tmp("openmem"));let _=std::fs::remove_dir_all(&dir);
    let mut n=Node::open(conf(&dir),admitted()).unwrap();
    let mut harness=net();let mut parent=harness.chain.head;let alice=devnet::account_key("alice");
    let len=bodymax_len(&harness,&alice);
    let (mut nonce,mut blocks)=(0u64,0u64);
    if kind=="full_body_max"{
        loop{let body=Body{txs:vec![big_call(&alice,nonce,len),big_call(&alice,nonce+1,len)],evidence:vec![]};
            let pe=harness.chain.full_entry(&parent).unwrap();
            if pe.cum_tx_bytes+body.txs.iter().map(|t|t.len() as u64).sum::<u64>()>harness.chain.spec.cp().TXBYTES_CAP{break}
            let b=signed(&harness,parent,body);import(&mut harness,&b);parent=b.hash();n.import(b,None).unwrap();nonce+=2;blocks+=1;}
    }else{
        let count:u64=std::env::var("JM_MEM_N").ok().and_then(|s|s.parse().ok()).unwrap_or(if kind=="empty"{3000}else{40});
        let tk=if kind=="full_gas_transfers"{pack_transfers(&harness,parent,&alice).len() as u64}else{0};
        for _ in 0..count{let b=kind_block(&harness,parent,&kind,&alice,&mut nonce,tk,len);import(&mut harness,&b);parent=b.hash();n.import(b,None).unwrap();blocks+=1;}
    }
    let jbytes=disk_bytes(&dir);drop(n);drop(harness);
    std::fs::write("/proc/self/clear_refs","5").unwrap();
    let (rss0,hwm0)=(vmrss(),vmhwm_bytes());let t=Instant::now();
    let r=Node::open(conf(&dir),admitted()).unwrap();
    let open_s=t.elapsed().as_secs_f64();let (rss1,hwm1)=(vmrss(),vmhwm_bytes());
    println!("JM-OPENMEM {}",serde_json::json!({"kind":kind,"blocks":blocks,"records":r.journal_records(),"journalBytes":jbytes,"openSeconds":open_s,"inProcessUndercounts":true,
        "rssBeforeBytes":rss0,"vmHwmAfterResetBytes":hwm0,"vmHwmAfterOpenBytes":hwm1,"rssAfterBytes":rss1,
        "peakAboveBaselineBytes":(hwm1-rss0),"peakOverJournal":(hwm1-rss0) as f64/jbytes.max(1) as f64}));
    drop(r);if persist.is_none(){let _=std::fs::remove_dir_all(&dir);}
}

// ============================ (a8) worst-case re-execution cost per gas (J2-B1) ============================
/// Re-execution (Chain::validate, the work replay, rebuild and restore repeat per block) of one full-gas
/// block of every compute kind, all on the same parent, plus the empty and the 380-transfer block: min and
/// median of JM_EXEC_REPS (default 5) runs. nsPerGasNet = (median - empty median) / gasUsed is the cost per
/// unit of gas above the fixed per-block work. The r2 compute kind (jump_loop, 9.6 ms/record) is the
/// cheapest per gas of these, not the worst. The set is what was measured, not a proof of the maximum: an
/// unmeasured operation may cost more per gas. JM_EXEC_KINDS (comma list; `x*` is a prefix) restricts the
/// kinds (the empty block is always measured: it is the net baseline). Also times
/// each precompile natively on the same input (JM-PRECOMPILE: validates the input, no EVM). Release only.
#[test]
#[ignore="measurement: run in release with --ignored --nocapture"]
fn jm_exec_cost_per_gas(){
    use revm::precompile as pc;
    let reps:usize=std::env::var("JM_EXEC_REPS").ok().and_then(|s|s.parse().ok()).unwrap_or(5);
    let only:Option<Vec<String>>=std::env::var("JM_EXEC_KINDS").ok().map(|s|s.split(',').map(str::to_string).collect());
    let want=|k:&str|only.as_ref().map_or(true,|o|o.iter().any(|x|x==k||x.strip_suffix('*').is_some_and(|p|k.starts_with(p))));
    let env=revm::primitives::Env::default();
    for (k,addr,input,_) in compute_kinds(){
        if addr==0||!want(&k){continue}let inp=revm::primitives::Bytes::from(input.clone());
        let run=||->Result<u64,String>{let r=match addr{1=>pc::secp256k1::ec_recover_run(&inp,u64::MAX),2=>pc::hash::sha256_run(&inp,u64::MAX),
            3=>pc::hash::ripemd160_run(&inp,u64::MAX),4=>pc::identity::identity_run(&inp,u64::MAX),5=>pc::modexp::berlin_run(&inp,u64::MAX),
            6=>pc::bn128::run_add(&inp,150,u64::MAX),7=>pc::bn128::run_mul(&inp,6000,u64::MAX),8=>pc::bn128::run_pair(&inp,34_000,45_000,u64::MAX),
            9=>pc::blake2::run(&inp,u64::MAX),0x0a=>pc::kzg_point_evaluation::run(&inp,u64::MAX,&env),_=>unreachable!()};r.map(|o|o.gas_used).map_err(|e|format!("{e:?}"))};
        let res=run();if k!="ecrecover_invalid_v"{assert!(res.is_ok(),"{k}: precompile input must be valid: {res:?}");}
        let gas=res.clone().unwrap_or(3000);
        let t=Instant::now();let mut calls=0u64;while t.elapsed().as_secs_f64()<0.05||calls<3{let _=run();calls+=1;}
        let ns=t.elapsed().as_secs_f64()*1e9/calls as f64;
        println!("JM-PRECOMPILE {}",serde_json::json!({"kind":k,"address":addr,"inputBytes":input.len(),"ok":res.is_ok(),"gasPerCall":gas,"nsPerCall":ns,"nsPerGas":ns/gas as f64}));
    }
    let mut n=net();let g=n.chain.head;let alice=devnet::account_key("alice");
    let p0=fallback(&n,g,0);import(&mut n,&p0);
    // A parent holding the frame-memory helper, so every measured block runs on one parent.
    let helper=alice.address().create(0);let p1=signed(&n,p0.hash(),Body{txs:vec![deploy(&alice,0,200_000,0,MEM_HELPER.to_vec())],evidence:vec![]});import(&mut n,&p1);
    let head=n.chain.head;
    let mut blocks:Vec<(String,Block)>=vec![("empty_fallback".into(),fallback(&n,head,1))];
    if want("full_gas_transfers"){let mut nonce=1u64;let tr={let p=n.chain.full_entry(&head).unwrap();let ctx=n.chain.child_ctx(&p,0).unwrap();
        let (mut lo,mut hi)=(1usize,400usize);let ok=|k:usize|n.chain.build_signed(&p,&n.keys[&ctx.proposer],ctx.window.lower(),Body{txs:(0..k as u64).map(|i|pay(&alice,1+i)).collect(),evidence:vec![]},vec![]).is_ok();
        while lo<hi{let mid=(lo+hi+1)/2;if ok(mid){lo=mid}else{hi=mid-1}}lo as u64};
        blocks.push(("full_gas_transfers".into(),signed(&n,head,kind_body("full_gas_transfers",&alice,&mut nonce,tr,0))));}
    let mut kinds:Vec<(String,Vec<u8>)>=compute_kinds().into_iter().map(|k|(k.0,k.3)).collect();
    kinds.push(("mem_frame_32KiB".into(),mem_frame_loop(helper,32768)));kinds.push(("mem_frame_256KiB".into(),mem_frame_loop(helper,262144)));
    for (k,init) in kinds{if want(&k){blocks.push((k,signed(&n,head,Body{txs:vec![deploy(&alice,1,FULL_GAS,0,init)],evidence:vec![]})));}}
    let mut empty_med=0.0;
    for (k,b) in &blocks{
        let (min,med,gas)=validate_ms(&n.chain,b,reps);if k=="empty_fallback"{empty_med=med;}
        let net_ns=if gas>0{(med-empty_med)*1e6/gas as f64}else{0.0};
        println!("JM-EXEC {}",serde_json::json!({"kind":k,"txs":b.body.txs.len(),"bodyBytes":b.body.encode().len(),"gasUsed":gas,"validateMsMin":min,"validateMsMedian":med,"reps":reps,
            "nsPerGasGross":if gas>0{med*1e6/gas as f64}else{0.0},"nsPerGasNet":net_ns,"projectedMsAt8M":empty_med+net_ns*8e6/1e6}));
    }
}

// ============================ (a9) per-block cost vs state size (J2-B1) ============================
/// apply_block clones the parent state, scans it several times (genesis check_caps and sum_balances
/// twice, code_caps::validate_snapshot after every SYSTEM call, the USER phase live counts) and recomputes
/// the whole world-state root from every account and slot (lp4-execution apply.rs `parent.clone()`,
/// `state_root`), so the re-execution of ANY block grows with the live state, which SLOT_CAP/ACCT_CAP bound
/// (devnet 50,000 / 20,000). This grows the user state with full-gas blocks of fresh SSTOREs and/or of
/// 1-wei CALLs to fresh addresses, each followed by an empty block so the base fee does not outrun max_fee:
/// series "slots" to JM_STATE_SLOTS (48,000), "accounts" to JM_STATE_ACCTS (19,000), "both" the first then
/// the second on one chain. At each checkpoint it times the validate of an empty child, a full-gas bn_pair_2
/// child and a full-gas JM_STATE_CHILD child (default modexp_b8_e1024_m8_even) of the head (median of 5 /
/// 3 / 3), and state_root and clone of the head state alone. JM_STATE_SERIES picks the series.
#[test]
#[ignore="measurement: run in release with --ignored --nocapture"]
fn jm_state_size_term(){
    let env_n=|k:&str,d:u64|std::env::var(k).ok().and_then(|s|s.parse().ok()).unwrap_or(d);
    let series:Vec<String>=std::env::var("JM_STATE_SERIES").map(|s|s.split(',').map(str::to_string).collect()).unwrap_or_else(|_|["slots","accounts","both"].map(str::to_string).to_vec());
    let (slots_t,accts_t,points)=(env_n("JM_STATE_SLOTS",48_000),env_n("JM_STATE_ACCTS",19_000),env_n("JM_STATE_POINTS",6));
    let child_kind=std::env::var("JM_STATE_CHILD").unwrap_or_else(|_|"modexp_b8_e1024_m8_even".into());let child_init=compute_init(&child_kind).expect("JM_STATE_CHILD kind");
    let sys:Vec<Address>=(0..5).map(pocol_lp4_execution::apply::program_address).collect();
    // SSTORE(i,1) for i = 0.. while gas >= 30,000, then STOP.
    let fill_slots=vec![0x60,0x00,0x5b,0x61,0x75,0x30,0x5a,0x10,0x60,0x15,0x57,0x60,0x01,0x81,0x55,0x60,0x01,0x01,0x60,0x02,0x56,0x5b,0x00];
    // CALL(0, base+i, 1 wei, 0,0,0,0) for i = 0.. while gas >= 40,000, then STOP.
    let fill_accts=fill_accts_init;
    let pair=precompile_loop(8,&pairing_input(2),384,32);
    for s in series{
        let (ts,ta)=match s.as_str(){"slots"=>(slots_t,0),"accounts"=>(0,accts_t),_=>(slots_t,accts_t)};
        let mut n=net();let alice=devnet::account_key("alice");let mut nonce=0u64;
        let p0=fallback(&n,n.chain.head,0);import(&mut n,&p0);
        let live=|n:&Net|{let st=&n.chain.head().state;let (mut sl,mut ac)=(0u64,0u64);
            for (a,x) in &st.accounts{if sys.contains(a)||x.info().is_none(){continue}ac+=1;sl+=x.storage.values().filter(|v|!v.is_zero()).count() as u64;}(sl,ac)};
        let (mut next,mut blocks,t0)=(0u64,0u64,Instant::now());
        loop{
            let (sl,ac)=live(&n);let fill_s=sl+400<=ts;let fill_a=!fill_s&&ac+400<=ta;let done=!fill_s&&!fill_a;
            if sl+ac>=next||done{
                let head=n.chain.head;let (_,em,_)=validate_ms(&n.chain,&fallback(&n,head,1),5);
                let child=|init:&Vec<u8>|signed(&n,head,Body{txs:vec![deploy(&alice,nonce,FULL_GAS,0,init.clone())],evidence:vec![]});
                let (_,pm,_)=validate_ms(&n.chain,&child(&pair),3);let (_,cm,_)=validate_ms(&n.chain,&child(&child_init),3);
                let st=n.chain.head().state.clone();let mut rt=vec![];let mut ct=vec![];
                for _ in 0..3{let t=Instant::now();let _=pocol_lp4_execution::apply::state_root(&st).unwrap();rt.push(t.elapsed().as_secs_f64()*1e3);
                    let t=Instant::now();let c=st.clone();ct.push(t.elapsed().as_secs_f64()*1e3);drop(c);}
                println!("JM-STATE {}",serde_json::json!({"series":s,"height":n.chain.head().height,"liveUserSlots":sl,"liveUserAccounts":ac,"stateAccountsAll":st.accounts.len(),
                    "emptyChildValidateMs":em,"pairChildValidateMs":pm,"childKind":child_kind,"childValidateMs":cm,"stateRootMs":median(rt),"stateCloneMs":median(ct),"buildSeconds":t0.elapsed().as_secs_f64()}));
                next+=(ts+ta)/points;if done{break}
            }
            let init=if fill_s{fill_slots.clone()}else{fill_accts((blocks+1)<<40)};
            let b=signed(&n,n.chain.head,Body{txs:vec![deploy(&alice,nonce,FULL_GAS,1_000_000,init)],evidence:vec![]});nonce+=1;import(&mut n,&b);
            let f=fallback(&n,n.chain.head,0);import(&mut n,&f);blocks+=1;
        }
    }
}
/// The dominant state term of (a9) at network-scale caps without a chain: state_root and clone of a
/// synthetic state of JM_SYN_ACCTS user accounts (default 1,000,000 = network ACCT_CAP) holding
/// JM_SYN_SLOTS live slots (default 4,000,000 = network SLOT_CAP) in contracts of 359 slots (the "slots"
/// fill of (a9)), on the devnet genesis state, at 1/16, 1/4 and 1/1 of both. pocold cannot admit these
/// caps (the network profile is refused by resources::check); this measures only the two functions.
#[test]
#[ignore="measurement: run in release with --ignored --nocapture"]
fn jm_state_root_synthetic(){
    use revm::primitives::AccountInfo;
    let env_n=|k:&str,d:u64|std::env::var(k).ok().and_then(|s|s.parse().ok()).unwrap_or(d);
    let (slots,accts)=(env_n("JM_SYN_SLOTS",4_000_000),env_n("JM_SYN_ACCTS",1_000_000));const PER:u64=359;
    let base=revm::InMemoryDB::clone(&net().chain.head().state);
    for div in [16u64,4,1]{
        let (sl,ac)=(slots/div,accts/div);let contracts=sl.div_ceil(PER);assert!(contracts<=ac,"slots need {contracts} contracts > {ac} accounts");
        let mut db=base.clone();let t=Instant::now();
        for i in 0..ac{let a=Address::from_word(U256::from((1u64<<40)+i).into());
            db.insert_account_info(a,AccountInfo{balance:U256::from(1u64),nonce:u64::from(i<contracts),..Default::default()});
            if i<contracts{for k in 0..PER.min(sl-i*PER){db.insert_account_storage(a,U256::from(k),U256::from(1u64)).unwrap();}}}
        let build_s=t.elapsed().as_secs_f64();let mut rt=vec![];let mut ct=vec![];
        for _ in 0..3{let t=Instant::now();let _=pocol_lp4_execution::apply::state_root(&db).unwrap();rt.push(t.elapsed().as_secs_f64()*1e3);
            let t=Instant::now();let c=db.clone();ct.push(t.elapsed().as_secs_f64()*1e3);drop(c);}
        println!("JM-STATE-SYN {}",serde_json::json!({"userSlots":sl,"userAccounts":ac,"contracts":contracts,"stateAccountsAll":db.accounts.len(),"buildSeconds":build_s,
            "stateRootMs":median(rt.clone()),"stateRootMsMin":rt.iter().cloned().fold(f64::MAX,f64::min),"stateCloneMs":median(ct)}));
    }
}

// ============================ (a10) genesis rebuild over loaded blocks (J2-M1) ============================
/// TrieRebuild from genesis (ensure_state: the deep-fork, re-fetch and restore path, §5) over a chain of
/// JM_REBUILD_COUNT (default 20) blocks of each kind in JM_REBUILD_KINDS on one empty parent: the per-block
/// rebuild cost under load (on the small devnet genesis state: the (a9) state term comes on top).
/// jm_deep_fork_rebuild_vs_height measures it for empty blocks only. Release only.
#[test]
#[ignore="measurement: run in release with --ignored --nocapture"]
fn jm_rebuild_by_kind(){
    let count:u64=std::env::var("JM_REBUILD_COUNT").ok().and_then(|s|s.parse().ok()).unwrap_or(20);
    let kinds:Vec<String>=std::env::var("JM_REBUILD_KINDS").map(|s|s.split(',').map(str::to_string).collect())
        .unwrap_or_else(|_|["empty","full_gas_transfers","full_gas_compute","bn_pair_2"].map(str::to_string).to_vec());
    for kind in kinds{
        let mut h=net();h.chain.k_hist=u64::MAX;h.chain.side_cap=1024;let alice=devnet::account_key("alice");let mut nonce=0u64;
        let p0=fallback(&h,h.chain.head,0);import(&mut h,&p0);
        let tk=if kind=="full_gas_transfers"{pack_transfers(&h,h.chain.head,&alice).len() as u64}else{0};let bl=bodymax_len(&h,&alice);
        for _ in 0..count{let b=kind_block(&h,h.chain.head,&kind,&alice,&mut nonce,tk,bl);import(&mut h,&b);}
        // Prune every state above the empty parent p0, so the rebuild re-executes exactly the `count` loaded blocks.
        let tip=h.chain.head;let hs:Vec<[u8;32]>=h.chain.canonical.iter().skip(2).copied().collect();
        for x in hs{let e=h.chain.blocks.get_mut(&x).unwrap();e.state=Default::default();e.pruned=true;}
        let before=h.chain.rebuilds;let t=Instant::now();h.chain.ensure_state(&tip).unwrap();let s=t.elapsed().as_secs_f64();let n=h.chain.rebuilds-before;
        println!("JM-REBUILD-KIND {}",serde_json::json!({"kind":kind,"blocks":count,"reExecutions":n,"seconds":s,"perBlockMillis":s*1e3/n as f64}));
    }
}

// ============================ (a7) open replay cost by component ============================
/// Splits replay cost per record into validate / insert / retain, bucketed by height, to attribute the
/// super-linear open (J-V10): both Chain::retain (scans all resident blocks per record) and
/// Chain::insert -> rebuild_canonical (walks head->genesis on every head change) grow O(H) per record,
/// so the per-record cost is validate (flat) + insert (O(H)) + retain (O(H)). Mirrors Node::open's loop
/// on a bare Chain (replaying=true); it omits Node::open's own per-record work (record decode, the
/// events/protect bookkeeping, parentResult check), so it need not explain all of the open slope.
/// Release only. JM_SPLIT_N sets the chain length (the builder keeps the default K_hist window: it only
/// extends its head, so a 20,000-block run does not hold 20,000 states).
#[test]
#[ignore="measurement: run in release with --ignored --nocapture"]
fn jm_replay_component_split(){
    let n_c:u64=std::env::var("JM_SPLIT_N").ok().and_then(|s|s.parse().ok()).unwrap_or(6000);
    let mut harness=net();
    let mut cb=vec![];let mut p=harness.chain.head;for _ in 0..n_c{let b=fallback(&harness,p,0);import(&mut harness,&b);p=b.hash();cb.push(b);}
    drop(harness);
    let mut c=Chain::new(admitted());c.replaying=true;
    let bucket=1000usize;let mut acc=vec![(0f64,0f64,0f64);cb.len().div_ceil(bucket)];
    for (i,b) in cb.iter().enumerate(){
        let t0=Instant::now();let (e,_)=c.validate(b,None,0).unwrap();let t1=Instant::now();c.insert(e);let t2=Instant::now();c.retain();let t3=Instant::now();
        let a=&mut acc[i/bucket];a.0+=(t1-t0).as_secs_f64();a.1+=(t2-t1).as_secs_f64();a.2+=(t3-t2).as_secs_f64();
    }
    for (k,(v,ins,ret)) in acc.iter().enumerate(){let m=bucket as f64;
        println!("JM-SPLIT {}",serde_json::json!({"heights":format!("{}..{}",k*bucket+1,(k+1)*bucket),"validateMs":v*1e3/m,"insertMs":ins*1e3/m,"retainMs":ret*1e3/m}));}
}

// ============================ (a11) state-interacting block re-execution vs live state (J-REV3-1) ============================
/// The additive state term of (a9) — per-block clone + a root recomputation linear in the state — does
/// not capture the CREATE path. `code_caps::register`'s `create_return` handler calls
/// `code_caps::current_total`, which iterates ALL `db.accounts` to re-total logical code, on EVERY
/// successful CREATE/CREATE2. A create-heavy block of C creates on a state of A accounts therefore
/// re-executes in O(C·A) on top of the (a9) term. This grows the live user-account state with the (a9)
/// account fill (1-wei CALLs to fresh addresses) and at each checkpoint times the validate of: an empty
/// child (the additive (a9) term), a CREATE2-heavy child (one tx, ~248 creates), a cold-CALL child (one
/// tx, ~3000 value-0 cold CALLs — cold access but NO create, so no `current_total` scan), and a
/// many-small-create block (many one-create txs — the same regime spread over txs, not one looping tx).
/// `create2ChildMs - emptyChildMs` is the create-specific term; its growth with `liveUserAccounts` is the
/// O(creates·state) regime. The cold-CALL child is the control: cold access of the same order of
/// accounts, no `current_total`, so it must NOT grow with the state beyond the (a9) term. Release only.
/// `JM_CREATE_ACCTS` (default 16,000, below ACCT_CAP with headroom for ~248 creates) is the target live
/// account count; `JM_CREATE_POINTS` (default 6) the checkpoints.
#[test]
#[ignore="measurement: run in release with --ignored --nocapture"]
fn jm_create_state_term(){
    let env_n=|k:&str,d:u64|std::env::var(k).ok().and_then(|s|s.parse().ok()).unwrap_or(d);
    let (accts_t,points)=(env_n("JM_CREATE_ACCTS",16_000),env_n("JM_CREATE_POINTS",6));
    let sys:Vec<Address>=(0..5).map(pocol_lp4_execution::apply::program_address).collect();
    let mut n=net();let alice=devnet::account_key("alice");let mut nonce=0u64;
    let p0=fallback(&n,n.chain.head,0);import(&mut n,&p0);
    let live=|n:&Net|{let st=&n.chain.head().state;let (mut sl,mut ac)=(0u64,0u64);
        for (a,x) in &st.accounts{if sys.contains(a)||x.info().is_none(){continue}ac+=1;sl+=x.storage.values().filter(|v|!v.is_zero()).count() as u64;}(sl,ac)};
    // The most one-create (to=None empty child) txs build_signed accepts on `head`, found by re-execution.
    let pack_creates=|n:&Net,head:[u8;32],a:&Key,start:u64|->Vec<Vec<u8>>{
        let p=n.chain.full_entry(&head).unwrap();let ctx=n.chain.child_ctx(&p,0).unwrap();
        let ok=|k:usize|n.chain.build_signed(&p,&n.keys[&ctx.proposer],ctx.window.lower(),
            Body{txs:(0..k as u64).map(|i|deploy(a,start+i,120_000,0,EMPTY_CHILD.to_vec())).collect(),evidence:vec![]},vec![]).is_ok();
        let (mut lo,mut hi)=(1usize,200usize);assert!(ok(lo));while lo<hi{let mid=(lo+hi+1)/2;if ok(mid){lo=mid}else{hi=mid-1}}
        (0..lo as u64).map(|i|deploy(a,start+i,120_000,0,EMPTY_CHILD.to_vec())).collect()
    };
    let (mut next,mut blocks,t0)=(0u64,0u64,Instant::now());
    loop{
        let (sl,ac)=live(&n);let done=ac+400>accts_t;
        if ac>=next||done{
            let head=n.chain.head;let before=n.chain.head().state.accounts.len() as i64;
            let (_,em,_)=validate_ms(&n.chain,&fallback(&n,head,1),5);
            let c2=signed(&n,head,Body{txs:vec![deploy(&alice,nonce,FULL_GAS,0,create2_loop())],evidence:vec![]});
            let (_,c2m,c2g)=validate_ms(&n.chain,&c2,3);
            let (e2,_)=n.chain.validate(&c2,None,0).unwrap();let creates=e2.state.accounts.len() as i64-before;
            let cc=signed(&n,head,Body{txs:vec![deploy(&alice,nonce,FULL_GAS,0,cold_call_loop(1u64<<50))],evidence:vec![]});
            let (_,ccm,_)=validate_ms(&n.chain,&cc,3);
            let msc=pack_creates(&n,head,&alice,nonce);let msc_k=msc.len();
            let mscb=signed(&n,head,Body{txs:msc,evidence:vec![]});let (_,mscm,_)=validate_ms(&n.chain,&mscb,3);
            println!("JM-CREATE {}",serde_json::json!({"liveUserSlots":sl,"liveUserAccounts":ac,"stateAccountsAll":before,
                "emptyChildMs":em,"create2ChildMs":c2m,"create2GasUsed":c2g,"create2Creates":creates,"create2PerCreateMicros":(c2m-em)*1e3/creates.max(1) as f64,
                "coldCallChildMs":ccm,"manySmallCreateTxs":msc_k,"manySmallCreateMs":mscm,"manySmallPerCreateMicros":(mscm-em)*1e3/msc_k.max(1) as f64,
                "buildSeconds":t0.elapsed().as_secs_f64()}));
            next+=accts_t/points;if done{break}
        }
        let b=signed(&n,n.chain.head,Body{txs:vec![deploy(&alice,nonce,FULL_GAS,1_000_000,fill_accts_init((blocks+1)<<40))],evidence:vec![]});nonce+=1;import(&mut n,&b);
        let f=fallback(&n,n.chain.head,0);import(&mut n,&f);blocks+=1;
    }
}
/// The most txs `mk(start..)` build_signed accepts on `head` (re-execution only, no PoW), for the caller to seal once.
fn pack_txs<F:Fn(u64)->Vec<u8>>(n:&Net,head:[u8;32],start:u64,max:usize,mk:F)->Vec<Vec<u8>>{
    let p=n.chain.full_entry(&head).unwrap();let ctx=n.chain.child_ctx(&p,0).unwrap();
    let ok=|k:usize|n.chain.build_signed(&p,&n.keys[&ctx.proposer],ctx.window.lower(),Body{txs:(0..k as u64).map(|i|mk(start+i)).collect(),evidence:vec![]},vec![]).is_ok();
    let (mut lo,mut hi)=(1usize,max);assert!(ok(lo));while lo<hi{let mid=(lo+hi+1)/2;if ok(mid){lo=mid}else{hi=mid-1}}
    (0..lo as u64).map(|i|mk(start+i)).collect()}
/// Init code returning `len` zero bytes (PUSH2 len, PUSH1 0, RETURN): a `len`-byte runtime, the code fill.
fn zero_code_init(len:u16)->Vec<u8>{vec![0x61,(len>>8) as u8,len as u8,0x60,0x00,0xf3]}
/// JV3B-1/2 (round 3c): the per-TRANSACTION and per-create state terms by state dimension. Each USER tx runs
/// native::execute_for_profile, i.e. code_caps::validate_snapshot (a code_len pass then inventory: two
/// keccaks of every account's runtime) and build_engine (two InMemoryDB clones: with_db and
/// NativeContext::from_snapshot); each successful create runs code_caps::current_total (one code_len pass).
/// So each scan is O(accounts + logical code bytes) (code_len) or O(accounts + slots) (clone). Series:
/// "accts" (1-wei CALL fill to JM_TX_ACCTS, default 15,600), "code" (JM_TX_CODE_N, default 62, deploys of a
/// 32,768-B runtime = B_code_max: ~97.6% of the devnet CODE_CAP on ~67 accounts), "slots" (SSTORE fill to
/// JM_TX_SLOTS, default 47,000), "all" (code, then slots, then accounts to JM_TX_ALL_ACCTS, default 19,000:
/// all three dimensions near the devnet caps on one state). At JM_TX_POINTS+1 checkpoints (default 4) it
/// times validate_snapshot, inventory (~ one current_total) and one state clone alone, then the validate of an
/// empty child, a block of the most 21k transfers, a CREATE2-heavy child and a block of the most one-create
/// txs (median of 5 / 3 / 3 / 3). predictedPerTxUs = validate_snapshot + 2 clones (the per-tx scans only).
/// Release only; it measures, it asserts nothing about time.
#[test]
#[ignore="measurement: run in release with --ignored --nocapture"]
fn jm_tx_state_term(){
    use pocol_lp4_execution::code_caps;
    let env_n=|k:&str,d:u64|std::env::var(k).ok().and_then(|s|s.parse().ok()).unwrap_or(d);
    let series:Vec<String>=std::env::var("JM_TX_SERIES").map(|s|s.split(',').map(str::to_string).collect()).unwrap_or_else(|_|["accts","code","slots","all"].map(str::to_string).to_vec());
    let (accts_t,slots_t,code_n,all_a,points)=(env_n("JM_TX_ACCTS",15_600),env_n("JM_TX_SLOTS",47_000),env_n("JM_TX_CODE_N",62),env_n("JM_TX_ALL_ACCTS",19_000),env_n("JM_TX_POINTS",4));
    let sys:Vec<Address>=(0..5).map(pocol_lp4_execution::apply::program_address).collect();
    for s in series{
        let mut n=net();let alice=devnet::account_key("alice");let mut nonce=0u64;
        let p0=fallback(&n,n.chain.head,0);import(&mut n,&p0);
        let lim=code_caps::CodeLimits{runtime:n.chain.spec.cp().B_code_max,logical:n.chain.spec.cp().CODE_CAP};
        let live=|n:&Net|{let st=&n.chain.head().state;let (mut sl,mut ac)=(0u64,0u64);
            for (a,x) in &st.accounts{if sys.contains(a)||x.info().is_none(){continue}ac+=1;sl+=x.storage.values().filter(|v|!v.is_zero()).count() as u64;}(sl,ac)};
        let t0=Instant::now();let mut blocks=0u64;
        let measure=|n:&Net,nonce:u64,phase:&str,blocks:u64|{
            let head=n.chain.head;let st=n.chain.head().state.clone();let (sl,ac)=live(n);let inv=code_caps::inventory(&st).unwrap();
            let (mut vs,mut iv,mut cl)=(vec![],vec![],vec![]);
            for _ in 0..5{let t=Instant::now();code_caps::validate_snapshot(&st,lim).unwrap();vs.push(t.elapsed().as_secs_f64()*1e3);
                let t=Instant::now();let _=code_caps::inventory(&st).unwrap();iv.push(t.elapsed().as_secs_f64()*1e3);
                let t=Instant::now();let c=st.clone();cl.push(t.elapsed().as_secs_f64()*1e3);drop(c);}
            let (vs,iv,cl)=(median(vs),median(iv),median(cl));
            let (_,em,_)=validate_ms(&n.chain,&fallback(n,head,1),5);
            let tr=pack_txs(n,head,nonce,400,|i|pay(&alice,i));let tk=tr.len();
            let (_,tm,_)=validate_ms(&n.chain,&signed(n,head,Body{txs:tr,evidence:vec![]}),3);
            let c2=signed(n,head,Body{txs:vec![deploy(&alice,nonce,FULL_GAS,0,create2_loop())],evidence:vec![]});let (_,c2m,_)=validate_ms(&n.chain,&c2,3);
            let (e2,_)=n.chain.validate(&c2,None,0).unwrap();let creates=(e2.state.accounts.len() as i64-st.accounts.len() as i64).max(1);
            // C-1 S3a: the diff each validate now computes (part of the times above), alone.
            let mut df=vec![];let mut dsz=(0,0);for _ in 0..3{let t=Instant::now();let d=pocold::statediff::StateDiff::between(&st,&e2.state);df.push(t.elapsed().as_secs_f64()*1e3);dsz=d.size();}
            let diff_ms=median(df);
            // C-1 E1: the whole-state root (the reference), a trie built from the whole state, the touched set
            // of the CREATE2 child and the incremental update from the parent's trie, and the trie's size.
            use pocol_lp4_execution::state_trie::{StateTrie,Touched};
            let (mut rf,mut tb,mut tt,mut tu)=(vec![],vec![],vec![],vec![]);let mut trie=StateTrie::default();
            for _ in 0..3{let t=Instant::now();let _=pocol_lp4_execution::apply::state_root(&st).unwrap();rf.push(t.elapsed().as_secs_f64()*1e3);
                let t=Instant::now();trie=StateTrie::build(&st);tb.push(t.elapsed().as_secs_f64()*1e3);
                let t=Instant::now();let touched=Touched::between(&st,&e2.state);tt.push(t.elapsed().as_secs_f64()*1e3);
                let t=Instant::now();let u=trie.update(&e2.state,&touched);tu.push(t.elapsed().as_secs_f64()*1e3);assert_eq!(u.root().0,e2.header.state_root);}
            let ts=trie.stats();let e1=serde_json::json!({"rootFullMs":median(rf),"trieBuildMs":median(tb),"touchedMs":median(tt),"trieUpdateMs":median(tu),
                "trieLeaves":ts.leaves,"trieBranches":ts.branches,"trieKidSlots":ts.kid_slots,"trieHeapBytes":ts.heap_bytes});
            let ms=pack_txs(n,head,nonce,200,|i|deploy(&alice,i,120_000,0,EMPTY_CHILD.to_vec()));let mk=ms.len();
            let (_,mm,_)=validate_ms(&n.chain,&signed(n,head,Body{txs:ms,evidence:vec![]}),3);
            println!("JM-TXSTATE {}",serde_json::json!({"series":s,"phase":phase,"fillBlocks":blocks,"height":n.chain.head().height,"liveUserSlots":sl,"liveUserAccounts":ac,"stateAccountsAll":st.accounts.len(),"logicalCode":inv,
                "validateSnapshotMs":vs,"inventoryMs":iv,"stateCloneMs":cl,"s3aDiffCreate2Ms":diff_ms,"s3aDiffCreate2Size":[dsz.0,dsz.1],"predictedPerTxUs":(vs+2.0*cl)*1e3,"emptyChildMs":em,
                "transferTxs":tk,"transferMs":tm,"transferPerTxUs":(tm-em)*1e3/tk as f64,
                "create2Ms":c2m,"create2Creates":creates,"create2PerCreateUs":(c2m-em)*1e3/creates as f64,
                "manySmallTxs":mk,"manySmallMs":mm,"manySmallPerTxUs":(mm-em)*1e3/mk as f64,"e1":e1,"buildSeconds":t0.elapsed().as_secs_f64()}));
        };
        measure(&n,nonce,"start",0);
        // One fill block (+ a fallback, as the other fills) of each kind.
        let fill=|n:&mut Net,nonce:&mut u64,blocks:&mut u64,kind:&str|{
            let tx=match kind{"code"=>deploy(&alice,*nonce,7_900_000,0,zero_code_init(32768)),"slots"=>deploy(&alice,*nonce,FULL_GAS,0,sstore_fresh_loop()),
                _=>deploy(&alice,*nonce,FULL_GAS,1_000_000,fill_accts_init((*blocks+1)<<40))};
            let b=signed(n,n.chain.head,Body{txs:vec![tx],evidence:vec![]});*nonce+=1;import(n,&b);let f=fallback(n,n.chain.head,0);import(n,&f);*blocks+=1;};
        let legs:Vec<&str>=if s=="all"{vec!["code","slots","accts"]}else{vec![s.as_str()]};
        for leg in legs{
            let target=match leg{"code"=>code_n,"slots"=>slots_t,_=>if s=="all"{all_a}else{accts_t}};
            let progress=|n:&Net,k:u64|match leg{"code"=>k,"slots"=>live(n).0,_=>live(n).1};
            let room=|n:&Net,k:u64|match leg{"code"=>k<target,_=>progress(n,k)+400<=target};
            let (mut k,mut next)=(0u64,target/points);
            while room(&n,k){fill(&mut n,&mut nonce,&mut blocks,leg);k+=1;
                if s!="all"&&progress(&n,k)>=next&&room(&n,k){measure(&n,nonce,leg,blocks);next+=target/points;}}
            measure(&n,nonce,&format!("{leg}-end"),blocks);
        }
    }
}

/// Decision package C-1 S2: a state copy shares its code buffers with the state it was copied from.
/// Every state the chain holds along one canonical lineage (each block's state is its parent's copy
/// plus that block's changes) points at the same code bytes for a code hash, so that lineage holds each
/// runtime once. Not a measurement: it runs by default. The A13 code term (resources.rs) relies on it.
#[test] fn retained_states_of_one_lineage_share_their_code_buffers(){
    let mut n=net();let alice=devnet::account_key("alice");
    for k in 0..3u64{let b=signed(&n,n.chain.head,Body{txs:vec![deploy(&alice,k,7_900_000,0,zero_code_init(32768-k as u16))],evidence:vec![]});import(&mut n,&b);}
    for _ in 0..3{let b=signed(&n,n.chain.head,Body::default());import(&mut n,&b);}
    let ptrs=|st:&revm::db::InMemoryDB|->HashMap<B256,usize>{st.accounts.values().filter_map(|a|a.info.code.as_ref().filter(|c|c.original_bytes().len()>=32000).map(|c|(a.info.code_hash,c.original_bytes().as_ptr() as usize))).collect()};
    let head=ptrs(&n.chain.head().state);assert_eq!(head.len(),3,"positive control: three 32 KiB runtimes at the head");
    let mut states=0;let mut shared=0;
    for e in n.chain.blocks.values().filter(|e|!e.pruned&&n.chain.is_canonical(&e.hash)){
        // C-1 S3a: a retained state that is not held full is materialized from the head through the diffs,
        // so it shares the head's buffers in the same way.
        let st=n.chain.state_of(&e.hash).unwrap();let p=ptrs(&st);if p.is_empty(){continue}states+=1;
        for (h,ptr) in &p{assert_eq!(head.get(h),Some(ptr),"h={}: code {h} shares the head's buffer",e.height);shared+=1;}
        for (h,c) in &st.contracts{if c.original_bytes().len()>=32000{assert_eq!(head.get(h),Some(&(c.original_bytes().as_ptr() as usize)),"h={}: contracts map entry {h} shares it too",e.height);}}
    }
    assert!(states>=6&&shared>=12,"{states} states with code, {shared} shared runtimes");
    // Control: an independent execution of the same deploy (another chain object) makes its own buffer.
    let mut m=net();for k in 0..1u64{let b=signed(&m,m.chain.head,Body{txs:vec![deploy(&alice,k,7_900_000,0,zero_code_init(32768))],evidence:vec![]});import(&mut m,&b);}
    let other=ptrs(&m.chain.head().state);let (h,ptr)=other.iter().next().unwrap();
    assert!(head.get(h).is_some_and(|p|p!=ptr),"the same runtime executed elsewhere is a separate buffer (what a rebuilt or side state holds)");
}

/// C-1 S1: the cost of redb's full integrity check of history.redb (every page checksum), against the
/// store size, to decide whether open can afford it, and the file size against the stored payload.
/// Synthetic blocks of 4 receipts of HIST_REC bytes (default 2048) and 4 transaction index entries;
/// HIST_MB of receipts (default 256); HIST_DURABLE set: one durable commit per block as live import.
#[test]
#[ignore="measurement: run in release with --ignored --nocapture"]
fn history_integrity_check_cost(){
    use pocold::history::History;
    let dir=std::env::temp_dir().join(format!("pocold-hist-measure-{}",std::process::id()));let _=std::fs::remove_dir_all(&dir);std::fs::create_dir_all(&dir).unwrap();
    let mb:u64=std::env::var("HIST_MB").ok().and_then(|x|x.parse().ok()).unwrap_or(256);
    let rec_b:u64=std::env::var("HIST_REC").ok().and_then(|x|x.parse().ok()).unwrap_or(2048);
    let blocks=(mb<<20)/(4*rec_b);let durable=std::env::var("HIST_DURABLE").is_ok();
    {let h=History::open(&dir).unwrap();let t=Instant::now();
        for i in 0..blocks{let mut b=[0u8;32];b[..8].copy_from_slice(&i.to_be_bytes());b[8..16].copy_from_slice(&i.wrapping_mul(0x9e3779b97f4a7c15).to_be_bytes());
            let rec:Vec<Vec<u8>>=(0..4).map(|k|vec![(i as u8)^(k as u8);rec_b as usize]).collect();
            let txs:Vec<B256>=(0..4u64).map(|k|revm::primitives::keccak256((i*4+k).to_be_bytes())).collect();
            h.put_with(&b,&rec,&txs,&[],durable).unwrap();if !durable&&i%256==255{h.sync().unwrap();}}
        h.sync().unwrap();println!("JM-HIST-FILL {}",serde_json::json!({"blocks":blocks,"durableEach":durable,"ms":t.elapsed().as_millis()}));}
    let size=std::fs::metadata(dir.join(pocold::history::FILE)).unwrap().len();
    // Drop the page cache's effect as far as a user process can: a fresh open, timed separately.
    let t=Instant::now();let mut h=History::open(&dir).unwrap();let open_ms=t.elapsed().as_millis();
    let t=Instant::now();let ok=h.verify().unwrap();let check_ms=t.elapsed().as_millis();
    println!("JM-HIST-CHECK {}",serde_json::json!({"fileBytes":size,"payloadBytes":blocks*4*rec_b,"receiptBytes":rec_b,"blocks":blocks,"openMs":open_ms,"checkMs":check_ms,"clean":ok,"msPerGiB":(check_ms as f64)*((1u64<<30) as f64)/(size as f64)}));
    drop(h);let _=std::fs::remove_dir_all(&dir);
}

// ============================ C-1 E4.5: store mode against whole-state mode ============================
/// Block execution (each import), the sync of a whole chain, a reorg and open, on a whole-state node and a
/// store-mode node (`Limits::state_store`), with the state's size, the files' sizes and the process RSS.
/// JM_ST_FILL (12) blocks that create accounts, JM_ST_FULL (40) full-gas transfer blocks, then a heavier
/// fallback branch from JM_ST_FORK (8) blocks below the tip. JM_ST_MODES picks "whole-state", "store" or
/// both (default); one mode per process gives each mode's RSS alone. Release only.
#[test]
#[ignore="measurement: run in release with --ignored --nocapture"]
fn jm_store_mode_disk_impact(){
    let env_n=|k:&str,d:u64|std::env::var(k).ok().and_then(|s|s.parse().ok()).unwrap_or(d);
    let (fill,full,fork)=(env_n("JM_ST_FILL",12),env_n("JM_ST_FULL",40),env_n("JM_ST_FORK",8) as usize);
    let modes:Vec<String>=std::env::var("JM_ST_MODES").map(|s|s.split(',').map(str::to_string).collect()).unwrap_or_else(|_|vec!["whole-state".into(),"store".into()]);
    let alice=devnet::account_key("alice");let mut h=net();let mut nonce=0u64;let mut blocks=vec![];let t=Instant::now();
    for i in 0..fill{let b=signed(&h,h.chain.head,Body{txs:vec![deploy(&alice,nonce,FULL_GAS,1_000_000,fill_accts_init((i+1)<<40))],evidence:vec![]});nonce+=1;import(&mut h,&b);blocks.push(b);}
    for _ in 0..full{let txs=pack_txs(&h,h.chain.head,nonce,400,|i|pay(&alice,i));nonce+=txs.len() as u64;let b=signed(&h,h.chain.head,Body{txs,evidence:vec![]});import(&mut h,&b);blocks.push(b);}
    let tip=h.chain.head;let base=blocks.len()-fork;let mut h2=net();for b in &blocks[..base]{import(&mut h2,b);}
    let (mut side,mut p)=(vec![],blocks[base-1].hash());
    while h2.chain.get(&p).unwrap().total_work<=h.chain.get(&tip).unwrap().total_work{let b=fallback(&h2,p,0);import(&mut h2,&b);p=b.hash();side.push(b);}
    let build_s=t.elapsed().as_secs_f64();drop(h2);
    let size=|d:&std::path::Path,f:&str|std::fs::metadata(d.join(f)).map(|m|m.len()).unwrap_or(0);
    for mode in modes{
        let store=mode=="store";let dir=tmp(&format!("st-{mode}"));let d=dir.clone();
        let conf=move|every:u64|Config{dir:d.clone(),name:"jm".into(),miner:None,listen:None,peers:vec![],rpc:None,stop_at:None,log:false,limits:Limits{state_store:store,checkpoint_every:every,..Default::default()}};
        let (rss0,hwm0)=(rss_bytes(),vmhwm_bytes());
        let mut n=Node::open(conf(16),admitted()).unwrap();let (mut fill_ms,mut full_ms)=(vec![],vec![]);let t=Instant::now();
        for (i,b) in blocks.iter().enumerate(){let t=Instant::now();n.import(b.clone(),None).unwrap();let ms=t.elapsed().as_secs_f64()*1e3;if (i as u64)<fill{fill_ms.push(ms)}else{full_ms.push(ms)}}
        let sync_s=t.elapsed().as_secs_f64();
        let t=Instant::now();for b in &side{n.import(b.clone(),None).unwrap();}let reorg_s=t.elapsed().as_secs_f64();assert_eq!(n.chain.head,side.last().unwrap().hash(),"the heavier branch is adopted");
        let (rss1,hwm1)=(rss_bytes(),vmhwm_bytes());
        let st=pocold::chain::StateHandle::of(n.chain.head()).whole();
        let (accounts,slots)=(st.accounts.len(),st.accounts.values().map(|a|a.storage.values().filter(|v|!v.is_zero()).count()).sum::<usize>());
        let txs:u64=n.chain.head().cum_txs;let stored=n.chain.blocks.values().filter(|e|e.stored.is_some()).count();
        let nodes=n.state_store().map(|s|s.node_count().unwrap()).unwrap_or(0);let stored_bytes=n.state_store().map(|s|s.stored_bytes().unwrap()).unwrap_or(0);let cache=n.state_store().map(|s|s.cache_bytes()).unwrap_or(0);
        let files=serde_json::json!({"journal":size(&dir,"blocks.journal"),"history":size(&dir,"history.redb"),"state":size(&dir,"state.redb")});
        // The file against what it stores, after each phase: live import, an open that resumes from a
        // checkpoint, and an open that replays from genesis into an empty store (C-1 E5).
        let phase=|n:&Node,what:&str|{let s=n.state_store();let (alloc,frag,meta)=s.map(|s|s.file_stats().unwrap()).unwrap_or((0,0,0));
            let stored=s.map(|s|s.stored_bytes().unwrap()).unwrap_or(0);let file=size(&dir,"state.redb");
            serde_json::json!({"phase":what,"fileBytes":file,"storedBytes":stored,"allocatedBytes":alloc,"fragmentedBytes":frag,"metadataBytes":meta,
                "fileOverStored":if stored>0{file as f64/stored as f64}else{0.0},"allocatedOverStored":if stored>0{alloc as f64/stored as f64}else{0.0},"vmHwmBytes":vmhwm_bytes()})};
        let closed=|what:&str|serde_json::json!({"phase":what,"fileBytes":size(&dir,"state.redb")});
        let mut phases=vec![phase(&n,"live import")];
        let written=n.stats.checkpoints_written;drop(n);phases.push(closed("closed after live import"));
        let t=Instant::now();let n=Node::open(conf(16),admitted()).unwrap();let open_s=t.elapsed().as_secs_f64();let resumed=n.stats.resumed_from;phases.push(phase(&n,"open resumed from a checkpoint"));drop(n);phases.push(closed("closed after the resumed open"));
        let t=Instant::now();let n=Node::open(conf(0),admitted()).unwrap();let open_genesis_s=t.elapsed().as_secs_f64();assert_eq!(n.stats.resumed_from,None);phases.push(phase(&n,"open replayed from genesis"));drop(n);phases.push(closed("closed after the replay from genesis"));
        let stats=|v:&[f64]|serde_json::json!({"n":v.len(),"medianMs":median(v.to_vec()),"maxMs":v.iter().cloned().fold(0.0,f64::max),"meanMs":v.iter().sum::<f64>()/v.len().max(1) as f64});
        println!("JM-STORE {}",serde_json::json!({"mode":mode,"blocks":blocks.len(),"fillBlocks":fill,"fullBlocks":full,"forkDepth":fork,"sideBlocks":side.len(),"transactions":txs,
            "stateAccounts":accounts,"stateNonzeroSlots":slots,"storedVersions":stored,"storeNodes":nodes,"storeStoredBytes":stored_bytes,"stateFilePhases":phases,"nodeCacheBytes":cache,"checkpointsWritten":written,
            "importFillBlocks":stats(&fill_ms),"importFullBlocks":stats(&full_ms),"syncSeconds":sync_s,"reorgSeconds":reorg_s,
            "openSeconds":open_s,"openResumedFrom":resumed,"openFromGenesisSeconds":open_genesis_s,"filesBytes":files,
            "rssBeforeBytes":rss0,"rssAfterBytes":rss1,"vmHwmBeforeBytes":hwm0,"vmHwmAfterBytes":hwm1,"buildSeconds":build_s}));
        let _=std::fs::remove_dir_all(&dir);
    }
}
