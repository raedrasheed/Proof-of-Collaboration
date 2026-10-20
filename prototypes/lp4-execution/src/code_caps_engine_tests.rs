//! P2 native execution views, NOT Rust signed-wire authentication or genesis.
use crate::{native::{self,NativeBlockContext},code_caps::{self,CodeLimits},profile::{ProfileIdentity,ProfileKind,NodeKind},genesis_spec as gs};
use revm::{InMemoryDB,DatabaseCommit,db::AccountState,primitives::{Address,AccountInfo,Bytecode,Bytes,U256,B256,TxEnv,TxKind}};
fn raw(s:&str)->Vec<u8>{s.as_bytes().chunks(2).map(|p|u8::from_str_radix(std::str::from_utf8(p).unwrap(),16).unwrap()).collect()}
fn num(v:&str)->U256{U256::from_str_radix(v,10).unwrap()}
fn load()->serde_json::Value{
 fn expand(v:&mut serde_json::Value){match v{
  serde_json::Value::Array(a)=>for x in a{expand(x)},
  serde_json::Value::Object(m) if m.len()==1&&m.contains_key("hexRuns")=>{let s=m["hexRuns"].as_array().unwrap().iter().map(|x|if let Some(n)=x.as_u64(){"00".repeat(n as usize)}else{x.as_str().unwrap().to_string()}).collect::<String>();*v=serde_json::Value::String(s);},
  serde_json::Value::Object(m)=>for x in m.values_mut(){expand(x)},_=>{}
 }}let mut v=serde_json::from_str(include_str!("../tests/data/code-caps-native-views.json")).unwrap();expand(&mut v);v
}
fn info(code:&[u8])->AccountInfo{let b=Bytecode::new_raw(Bytes::copy_from_slice(code));AccountInfo::new(U256::ZERO,1,b.hash_slow(),b)}
fn identity(bytes:&[u8])->ProfileIdentity{ProfileIdentity::validate(bytes,&gs::genesis_hash(bytes),777902,ProfileKind::Synthetic,NodeKind::Simnet,&[(1,0)]).unwrap()}
fn root(db:&InMemoryDB)->B256{
 let number=|n:U256|crate::fixed::U256::from_be_slice(&n.to_be_bytes::<32>()).unwrap();let mut accounts=Vec::new();
 for (address,a) in &db.accounts{if a.account_state==AccountState::NotExisting{continue}assert!(a.storage.values().all(|v|*v==U256::ZERO));accounts.push(crate::trie::Account{address:address.0.0,nonce:a.info.nonce,balance:number(a.info.balance),storage_root:crate::trie::storage_root(&[],0).unwrap(),code_hash:a.info.code_hash.0});}
 B256::from(crate::trie::state_root(&accounts,32).unwrap())
}
fn tx(view:&serde_json::Value)->TxEnv{let to=raw(view["to"].as_str().unwrap());TxEnv{caller:Address::from_slice(&raw(view["caller"].as_str().unwrap())),transact_to:if to.is_empty(){TxKind::Create}else{TxKind::Call(Address::from_slice(&to))},nonce:Some(view["nonce"].as_u64().unwrap()),chain_id:Some(view["chain"].as_u64().unwrap()),gas_limit:view["gas"].as_u64().unwrap(),gas_price:num(view["gasPrice"].as_str().unwrap()),gas_priority_fee:view["priority"].as_str().map(num),data:Bytes::from(raw(view["input"].as_str().unwrap())),value:num(view["value"].as_str().unwrap()),..Default::default()}}
fn commit(db:&mut InMemoryDB,state:revm::primitives::EvmState){let removed:Vec<_>=state.iter().filter(|(_,a)|a.is_selfdestructed()||(a.is_touched()&&a.is_empty())).map(|(a,_)|*a).collect();db.commit(state);for address in removed{let a=db.accounts.entry(address).or_default();a.account_state=AccountState::NotExisting;a.storage.clear();a.info=Default::default();}}
#[test]fn independent_engine_limits_against_complete_state_roots(){
 let data=load();let rows=data["cases"].as_array().unwrap();assert_eq!(rows.len(),76);
 for row in rows{
  let name=row["name"].as_str().unwrap();let mut db=InMemoryDB::default();for (address,p) in row["pre"].as_object().unwrap(){let mut a=info(&raw(p["code"].as_str().unwrap()));a.balance=num(p["balance"].as_str().unwrap());a.nonce=p["nonce"].as_u64().unwrap();db.insert_account_info(Address::from_slice(&raw(address)),a);}
  assert_eq!(root(&db).as_slice(),raw(row["preRoot"].as_str().unwrap()));let before=format!("{db:?}");let spec=raw(row["genesisSpec"].as_str().unwrap());assert_eq!(gs::genesis_hash(&spec).as_slice(),raw(row["genesisHash"].as_str().unwrap()));let profile=identity(&spec);assert_eq!(profile.cp().B_code_max as u64,row["runtime"].as_u64().unwrap());assert_eq!(profile.cp().CODE_CAP,row["logical"].as_u64().unwrap());assert!(!profile.bootable());let block=NativeBlockContext{height:U256::from(300),timestamp:U256::from(12345),gas_limit:U256::from(profile.cp().GAS_LIMIT),base_fee:U256::from(100),prevrandao:B256::from([0x77;32])};
  let result=native::execute_for_profile(&db,tx(&row["nativeView"]),&block,&profile);
  if row.get("admissionError").is_some(){assert_eq!(result.is_err(),true,"{name} initcode limit");assert!(format!("{:?}",result.unwrap_err()).contains("CreateInitCodeSizeLimit"));}
  else{let r=result.unwrap();assert_eq!(r.result.is_success(),row["success"].as_bool().unwrap(),"{name} status");assert_eq!(r.result.gas_used(),row["gasUsed"].as_u64().unwrap(),"{name} gas");assert_eq!(crate::output(&r.result),raw(row["output"].as_str().unwrap()),"{name} output");let mut candidate=db.clone();commit(&mut candidate,r.state);assert_eq!(root(&candidate).as_slice(),raw(row["stateRoot"].as_str().unwrap()),"{name} complete root");assert_eq!(code_caps::inventory(&candidate).unwrap(),row["logicalAfter"].as_u64().unwrap());
   if let Some(next)=row.get("followUp"){let r=native::execute_for_profile(&candidate,tx(&next["nativeView"]),&block,&profile).unwrap();assert_eq!(r.result.gas_used()+row["gasUsed"].as_u64().unwrap(),next["gasUsed"].as_u64().unwrap());commit(&mut candidate,r.state);assert_eq!(root(&candidate).as_slice(),raw(next["stateRoot"].as_str().unwrap()));assert_eq!(code_caps::inventory(&candidate).unwrap(),next["logicalAfter"].as_u64().unwrap());}
  }assert_eq!(format!("{db:?}"),before);
 }
}
#[test]fn shared_code_charged_per_address(){let mut db=InMemoryDB::default();for n in 1..=5{db.insert_account_info(Address::from_word(U256::from(0xc0c000u64+n).into()),info(&[0;10]));}assert_eq!(code_caps::inventory(&db).unwrap(),50);assert_eq!(db.contracts.values().filter(|b|!b.is_empty()).count(),1);assert!(code_caps::validate_snapshot(&db,CodeLimits{runtime:24577,logical:50}).is_ok());assert!(code_caps::validate_snapshot(&db,CodeLimits{runtime:24577,logical:49}).is_err());}
#[test]fn missing_hash_or_r9_reject(){let mut db=InMemoryDB::default();let address=Address::from([0x22;20]);db.insert_account_info(address,info(&[0;10]));let hash=db.accounts[&address].info.code_hash;db.accounts.get_mut(&address).unwrap().info.code=None;db.contracts.remove(&hash);assert!(code_caps::inventory(&db).is_err());db.contracts.insert(hash,Bytecode::new_raw(Bytes::from(vec![0])));let r=code_caps::inventory(&db);assert_eq!(r.is_err(),true);let mut good=InMemoryDB::default();good.insert_account_info(address,info(&[]));assert!(code_caps::validate_snapshot(&good,CodeLimits{runtime:24576,logical:1<<30}).is_err());}
