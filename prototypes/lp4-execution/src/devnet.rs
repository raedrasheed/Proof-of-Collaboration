//! Local development network profiles (profileKind=simnet, NodeKind::Simnet).
//! Bootable ONLY for local devnets (OWNER-STANDING-AUTHORIZATION.md §2): disposable
//! keys, no funds. The network profile (chainId 777001) is never built here.
use revm::{InMemoryDB,primitives::{AccountInfo,Address,B256,U256}};
use crate::{apply::{Genesis,SystemPrograms},fixed,genesis_spec::{self as gs,GenesisSpec,Member},profile::{ProfileIdentity,ProfileKind,NodeKind},txsign::Key};

/// CP values in schema order. Defaults follow governance.md (network) except the
/// timing/membership/end parameters, which are scaled for a local devnet.
#[derive(Clone,Debug)]
pub struct DevnetConfig{
    pub chain_id:u64,
    pub g_ts:u64,
    /// work(target_g) ~ expected hashes per block at genesis.
    pub target_g:fixed::U256,
    pub t_blk:u32,pub tau:u32,pub d_att:u32,pub d_fb_wait:u32,
    pub d:u16,pub w_w:u16,pub m:u16,pub kappa:u8,pub s_max:u16,
    pub w_act:u32,pub theta_inact:u32,pub e_win:u32,pub u:u32,
    pub h_end:u64,pub h_close:u64,pub t_end_offset:u64,pub t_close_offset:u64,pub ret:u32,pub p2:u32,
    pub m_max:u16,
    pub alpha_bp:u16,pub gamma_bp:u16,
    pub miners:Vec<String>,
    /// Extra funded devnet accounts (label, wei).
    pub accounts:Vec<(String,U256)>,
}
impl DevnetConfig{
    pub fn new(chain_id:u64,g_ts:u64,miners:&[&str])->Self{
        Self{chain_id,g_ts,target_g:to_fixed((U256::from(1)<<(256-18))-U256::from(1)),
            t_blk:2,tau:40,d_att:10,d_fb_wait:1,d:4,w_w:8,m:32,kappa:2,s_max:256,
            w_act:32,theta_inact:64,e_win:16,u:40,h_end:100_000,h_close:99_000,t_end_offset:10_000_000,t_close_offset:9_990_000,ret:128,p2:2,m_max:64,alpha_bp:1000,gamma_bp:500,
            miners:miners.iter().map(|s|s.to_string()).collect(),
            accounts:vec![("alice".into(),U256::from(10u128.pow(24))),("bob".into(),U256::from(10u128.pow(24)))]}
    }
    pub fn cp(&self)->[fixed::U256;52]{
        let n=|v:u64|fixed::U256::from_u64(v);
        let big=|v:u128|fixed::U256::from_be_slice(&v.to_be_bytes()).unwrap();
        [n(self.g_ts),self.target_g,n(self.t_blk.into()),n(self.tau.into()),n(0),n(2),n(self.d_att.into()),n(self.d_fb_wait.into()),
         n(self.m.into()),n(self.kappa.into()),n(self.s_max.into()),n(self.d.into()),n(self.w_w.into()),n(self.alpha_bp.into()),n(self.gamma_bp.into()),
         big(2_000_000_000_000_000_000),big(100_000_000_000_000_000_000),n(2),n(self.m_max.into()),n(1),n(8192),n(16),n(64),n(16),
         n(self.w_act.into()),n(self.theta_inact.into()),n(self.e_win.into()),n(self.u.into()),n(4),n(8192),
         n(8_000_000),n(1_000_000_000),n(131072),n(196608),n(32768),n(1<<30),n(1<<33),n(10_000_000),n(4_000_000),n(1_000_000),
         n(131072),n(2048),n(256),n(512),n(96_000_000),
         n(self.h_end),n(self.g_ts+self.t_end_offset),n(self.h_close),n(self.g_ts+self.t_close_offset),n(160),n(self.ret.into()),n(self.p2.into())]
    }
}
pub fn to_fixed(v:U256)->fixed::U256{fixed::U256::from_be_slice(&v.to_be_bytes::<32>()).unwrap()}
pub fn from_fixed(v:&fixed::U256)->U256{U256::from_be_bytes(v.to_be_bytes())}

pub struct MinerIdentity{pub label:String,pub key:Key,pub id:Address,pub reward:Address}
pub struct Devnet{
    pub spec_bytes:Vec<u8>,
    pub genesis_hash:B256,
    pub profile:ProfileIdentity,
    pub alloc:InMemoryDB,
    pub genesis:Genesis,
    pub programs:SystemPrograms,
    pub miners:Vec<MinerIdentity>,
    pub forks:Vec<(u16,u64)>,
}
pub fn miner_identity(label:&str)->MinerIdentity{
    let key=Key::devnet(&format!("miner:{label}"));let reward=Key::devnet(&format!("reward:{label}")).address();
    MinerIdentity{label:label.to_string(),id:key.address(),key,reward}
}
pub fn account_key(label:&str)->Key{Key::devnet(&format!("account:{label}"))}

/// Builds alloc → derives allocRoot/sysCodeHash → encodes GenesisSpec → validates
/// the profile (simnet) → builds and root-checks the genesis state.
pub fn build(cfg:&DevnetConfig)->Result<Devnet,String>{
    if cfg.chain_id==777001{return Err("network chainId is not a devnet".into())}
    let programs=SystemPrograms::v1();
    let mut miners:Vec<MinerIdentity>=cfg.miners.iter().map(|l|miner_identity(l)).collect();
    miners.sort_by_key(|m|m.id);
    let mut alloc=InMemoryDB::default();
    for m in &miners{ // reward accounts must be durable (nonce>0), PAY-02.
        alloc.insert_account_info(m.reward,AccountInfo{nonce:1,balance:U256::ZERO,..Default::default()});
    }
    for (label,wei) in &cfg.accounts{alloc.insert_account_info(account_key(label).address(),AccountInfo{nonce:0,balance:*wei,..Default::default()});}
    let m0_list:Vec<Member>=miners.iter().map(|m|Member{id:m.id.0.0,reward_addr:m.reward.0.0}).collect();
    let mut spec=GenesisSpec{chain_id:cfg.chain_id,cp:cfg.cp(),alloc_root:[0;32],m0_list,sys_code_hash:programs.sys_code_hash().0};
    let forks=vec![(1u16,0u64)];
    // Provisional identity to derive allocRoot (the root does not depend on allocRoot itself).
    let provisional=identity(&spec,&forks)?;
    let root=Genesis::derive_root(&alloc,&provisional,&programs).map_err(|e|format!("{e:?}"))?;
    spec.alloc_root=root.0;
    let profile=identity(&spec,&forks)?;
    let genesis=Genesis::build(&alloc,&profile,&programs).map_err(|e|format!("{e:?}"))?;
    let spec_bytes=gs::encode(&spec);
    Ok(Devnet{genesis_hash:B256::from(profile.genesis_hash()),spec_bytes,profile,alloc,genesis,programs,miners,forks})
}
fn identity(spec:&GenesisSpec,forks:&[(u16,u64)])->Result<ProfileIdentity,String>{
    let bytes=gs::encode(spec);let hash=gs::genesis_hash(&bytes);
    ProfileIdentity::validate(&bytes,&hash,spec.chain_id,ProfileKind::Simnet,NodeKind::Simnet,forks).map_err(|e|format!("{e:?}"))
}
/// Rebuilds a devnet from its published files: GenesisSpec bytes + alloc JSON.
pub fn load(spec_bytes:&[u8],alloc:&InMemoryDB,forks:&[(u16,u64)])->Result<(ProfileIdentity,Genesis),String>{
    let hash=gs::genesis_hash(spec_bytes);let spec=gs::decode(spec_bytes).map_err(|e|format!("{e:?}"))?;
    let profile=ProfileIdentity::validate(spec_bytes,&hash,spec.chain_id,ProfileKind::Simnet,NodeKind::Simnet,forks).map_err(|e|format!("{e:?}"))?;
    let genesis=Genesis::build(alloc,&profile,&SystemPrograms::v1()).map_err(|e|format!("{e:?}"))?;
    Ok((profile,genesis))
}
/// alloc JSON: {"0x..":{"nonce":n,"balance":"decimal"}}
pub fn alloc_to_json(db:&InMemoryDB)->serde_json::Value{
    let mut m=serde_json::Map::new();
    let mut keys:Vec<_>=db.accounts.keys().collect();keys.sort();
    for a in keys{let i=&db.accounts[a].info;m.insert(format!("{a:#x}"),serde_json::json!({"nonce":i.nonce,"balance":i.balance.to_string()}));}
    serde_json::Value::Object(m)
}
pub fn alloc_from_json(v:&serde_json::Value)->Result<InMemoryDB,String>{
    let mut db=InMemoryDB::default();
    for (k,x) in v.as_object().ok_or("alloc object")?{
        let a:Address=k.parse().map_err(|_|"address")?;
        let nonce=x["nonce"].as_u64().ok_or("nonce")?;let balance:U256=x["balance"].as_str().ok_or("balance")?.parse().map_err(|_|"balance value")?;
        db.insert_account_info(a,AccountInfo{nonce,balance,..Default::default()});
    }
    Ok(db)
}
