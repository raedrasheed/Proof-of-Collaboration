//! Durable block journal (LP4 P9). A block is committed iff its complete record
//! (length, SHA-256, payload, commit marker) is on disk and fsynced. Restart
//! replays and re-executes every committed block in import order, so state,
//! receipts and fork choice (importSeq) are rebuilt exactly. A torn tail is never
//! reported as committed; recovery writes a NEW journal from the verified prefix
//! and keeps the original bytes. A complete record with a bad checksum is
//! corruption and stops the node (never silently skipped).
use std::fs::{self,File,OpenOptions};
use std::io::{Read,Write};
use std::path::{Path,PathBuf};
use sha2::{Digest,Sha256};

const MAGIC:&[u8;8]=b"POCOLJ1\n";
pub const MAX_RECORD:usize=4*1024*1024;

#[derive(Debug,PartialEq,Eq)]
pub enum StoreError{Io(String),Locked,Binding,Corrupt(u64),TooLarge}
impl From<std::io::Error> for StoreError{fn from(e:std::io::Error)->Self{Self::Io(e.to_string())}}

pub struct Journal{file:File,path:PathBuf,_lock:File,pub records:u64}
pub struct Recovered{pub journal:Journal,pub payloads:Vec<Vec<u8>>,pub torn_tail:bool}

fn sha(b:&[u8])->[u8;32]{Sha256::digest(b).into()}

/// Opens (or creates) the journal in `dir`, holding an exclusive OS lock on
/// `dir/LOCK` for the process lifetime (second writer => Locked).
pub fn open(dir:&Path,binding:&[u8;32])->Result<Recovered,StoreError>{
    fs::create_dir_all(dir)?;
    let lock=OpenOptions::new().create(true).truncate(false).write(true).open(dir.join("LOCK"))?;
    match lock.try_lock(){Ok(())=>{},Err(std::fs::TryLockError::WouldBlock)=>return Err(StoreError::Locked),Err(std::fs::TryLockError::Error(e))=>return Err(e.into())}
    let path=dir.join("blocks.journal");
    if !path.exists(){
        let tmp=dir.join("blocks.journal.tmp");
        {let mut f=File::create(&tmp)?;f.write_all(MAGIC)?;f.write_all(binding)?;f.sync_all()?;}
        fs::rename(&tmp,&path)?;sync_dir(dir);
    }
    let mut bytes=Vec::new();File::open(&path)?.read_to_end(&mut bytes)?;
    if bytes.len()<40||&bytes[..8]!=MAGIC||&bytes[8..40]!=binding{return Err(StoreError::Binding)}
    let mut pos=40usize;let mut payloads=Vec::new();let mut torn=false;
    while pos<bytes.len(){
        if bytes.len()-pos<4+32+1{torn=true;break}
        let len=u32::from_be_bytes(bytes[pos..pos+4].try_into().unwrap()) as usize;
        if len>MAX_RECORD{ if bytes.len()-pos<4+32+len.min(MAX_RECORD)+1{torn=true;break} return Err(StoreError::Corrupt(payloads.len() as u64)) }
        let end=pos+4+32+len+1;
        if end>bytes.len(){torn=true;break}
        let digest=&bytes[pos+4..pos+36];let payload=&bytes[pos+36..pos+36+len];let marker=bytes[end-1];
        if marker!=1||sha(payload)[..]!=digest[..]{return Err(StoreError::Corrupt(payloads.len() as u64))}
        payloads.push(payload.to_vec());pos=end;
    }
    let path=if torn{
        // Recovery: write the verified prefix to a new journal; keep the torn original.
        let n=(0..).find(|i|!dir.join(format!("blocks.journal.torn-{i}")).exists()).unwrap();
        let tmp=dir.join("blocks.journal.tmp");
        {let mut f=File::create(&tmp)?;f.write_all(&bytes[..pos])?;f.sync_all()?;}
        fs::rename(&path,dir.join(format!("blocks.journal.torn-{n}")))?;fs::rename(&tmp,&path)?;sync_dir(dir);path
    }else{path};
    let file=OpenOptions::new().append(true).open(&path)?;
    Ok(Recovered{journal:Journal{file,path,_lock:lock,records:payloads.len() as u64},payloads,torn_tail:torn})
}
fn sync_dir(dir:&Path){if let Ok(d)=File::open(dir){let _=d.sync_all();}}

impl Journal{
    /// Appends one committed record and fsyncs before returning.
    pub fn append(&mut self,payload:&[u8])->Result<(),StoreError>{
        if payload.len()>MAX_RECORD{return Err(StoreError::TooLarge)}
        let mut rec=Vec::with_capacity(payload.len()+37);
        rec.extend((payload.len() as u32).to_be_bytes());rec.extend(sha(payload));rec.extend(payload);rec.push(1);
        self.file.write_all(&rec)?;self.file.sync_data()?;self.records+=1;Ok(())
    }
    pub fn path(&self)->&Path{&self.path}
}

/// payload = RLP([headerBytes, bodyBytes, parentResultBytes]); parentResult is
/// re-derived on replay and must match (parentResultMismatch halts import).
pub fn encode_record(header:&[u8],body:&[u8],result:&[u8])->Vec<u8>{
    let mut p=Vec::new();for x in [header,body,result]{crate::rlp::encode_bytes(x,&mut p)}
    let mut o=Vec::new();crate::rlp::encode_list_payload(&p,&mut o);o
}
pub fn decode_record(b:&[u8])->Result<(Vec<u8>,Vec<u8>,Vec<u8>),String>{
    let it=crate::rlp::decode(b).map_err(|e|e.code().to_string())?;let l=it.list().ok_or("record")?;if l.len()!=3{return Err("record fields".into())}
    let f=|i:usize|l[i].bytes().map(|x|x.to_vec()).ok_or_else(||"record field".to_string());Ok((f(0)?,f(1)?,f(2)?))
}
