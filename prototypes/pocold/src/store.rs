//! Durable block journal (LP4 P9; audit A04). A block is committed iff its complete record is on
//! disk and fsynced AND the commit file counts it. Restart replays and re-executes every committed
//! block in import order, so state, receipts and fork choice (importSeq) are rebuilt exactly.
//!
//! Format v2 (`POCOLJ2`, experimental local storage, not a protocol format):
//!   journal = MAGIC(8) ‖ binding(32) ‖ record*
//!   record  = len u32 ‖ lenCheck(4) = sha256("POCOL-REC-LEN" ‖ len)[..4] ‖ sha256(payload) ‖ payload ‖ 0x01
//!   commit  = two 64-byte slots {seq u64, count u64, end u64, sha256(tag ‖ binding ‖ seq ‖ count ‖ end)}
//!             at offsets 0 and 4096 (separate sectors, so one torn sector write cannot damage both);
//!             the valid slot with the larger seq gives the committed record count and end offset.
//!             A 128-byte commit file (both slots adjacent, the first v2 layout) is read and rewritten.
//! Classification of what follows the last verified record (LP2 P3/P4):
//!   * nothing → clean;
//!   * a strict prefix of a record (header incomplete, or header check valid and record incomplete), or an
//!     all-zero suffix no longer than one maximal record → an interrupted append (torn tail): recovered
//!     into a new journal holding the verified prefix, the original bytes kept as `blocks.journal.torn-n`;
//!   * anything else (bad header check, bad digest or marker in a complete record, length over the
//!     maximum) → `Corrupt`, nothing is modified, unless it lies entirely after the committed end:
//!     with every committed record verified and at most one maximal record of bytes after them, those
//!     bytes were never committed (appends commit before the next starts), so they are an interrupted
//!     append whatever they contain (review finding: a crash can persist a later page of an append
//!     before its header page). This needs both commit slots valid or never written: with a damaged
//!     slot the surviving one may predate the last commit;
//!   * any tail after a complete record beyond the commit count → `Corrupt` (two appends in flight);
//! Fewer verified records than the commit count (damaged or truncated committed data) → `Corrupt`.
//! A v1 journal (`POCOLJ1`) is migrated only when it parses completely with no tail; otherwise the
//! store refuses to open (`LegacyNeedsReview`) and nothing is modified.
use std::fs::{self,File,OpenOptions};
use std::io::{Read,Seek,SeekFrom,Write};
use std::path::{Path,PathBuf};
use sha2::{Digest,Sha256};

const MAGIC:&[u8;8]=b"POCOLJ2\n";
const MAGIC_V1:&[u8;8]=b"POCOLJ1\n";
pub const MAX_RECORD:usize=4*1024*1024;
const HDR:usize=8;            // len + lenCheck
const OVERHEAD:usize=HDR+32+1; // header + digest + marker
const SLOT:usize=64;
/// Offset of the second commit slot (its own 4 KiB sector).
const SLOT_STRIDE:usize=4096;

#[derive(Debug,PartialEq,Eq)]
pub enum StoreError{Io(String),Locked,Binding,Corrupt(u64),TooLarge,MissingJournal,MissingCommit,CommitCorrupt,LegacyNeedsReview}
impl From<std::io::Error> for StoreError{fn from(e:std::io::Error)->Self{Self::Io(e.to_string())}}

pub struct Journal{file:File,commit:File,path:PathBuf,_lock:File,binding:[u8;32],seq:u64,end:u64,pub records:u64}
pub struct Recovered{pub journal:Journal,pub payloads:Vec<Vec<u8>>,pub torn_tail:bool,pub migrated_v1:bool}

fn sha(b:&[u8])->[u8;32]{Sha256::digest(b).into()}
fn len_check(len:u32)->[u8;4]{let mut h=Sha256::new();h.update(b"POCOL-REC-LEN");h.update(len.to_be_bytes());let d:[u8;32]=h.finalize().into();[d[0],d[1],d[2],d[3]]}
fn slot_check(binding:&[u8;32],seq:u64,count:u64,end:u64)->[u8;32]{
    let mut h=Sha256::new();h.update(b"POCOL-COMMIT");h.update(binding);h.update(seq.to_be_bytes());h.update(count.to_be_bytes());h.update(end.to_be_bytes());h.finalize().into()
}
fn slot_bytes(binding:&[u8;32],seq:u64,count:u64,end:u64)->[u8;SLOT]{
    let mut s=[0u8;SLOT];s[..8].copy_from_slice(&seq.to_be_bytes());s[8..16].copy_from_slice(&count.to_be_bytes());s[16..24].copy_from_slice(&end.to_be_bytes());
    s[24..56].copy_from_slice(&slot_check(binding,seq,count,end));s
}
/// The valid commit slot with the larger seq: (seq, count, end), and whether a slot is damaged
/// (neither valid nor never written, i.e. all zero).
fn read_commit(bytes:&[u8],binding:&[u8;32])->Option<((u64,u64,u64),bool)>{
    let second=match bytes.len(){n if n==SLOT_STRIDE+SLOT=>SLOT_STRIDE,n if n==2*SLOT=>SLOT,_=>return None};
    let parse=|s:&[u8]|{let u=|i:usize|u64::from_be_bytes(s[i..i+8].try_into().unwrap());let (seq,count,end)=(u(0),u(8),u(16));
        (s[24..56]==slot_check(binding,seq,count,end)[..]&&s[56..].iter().all(|b|*b==0)).then_some((seq,count,end))};
    let (s0,s1)=(&bytes[..SLOT],&bytes[second..second+SLOT]);
    let damaged=[s0,s1].iter().any(|s|parse(s).is_none()&&s.iter().any(|b|*b!=0));
    let best=match (parse(s0),parse(s1)){(Some(a),Some(b))=>Some(if a.0>=b.0{a}else{b}),(Some(a),None)|(None,Some(a))=>Some(a),_=>None};
    best.map(|b|(b,damaged))
}
pub fn encode_frame(payload:&[u8])->Vec<u8>{
    let mut rec=Vec::with_capacity(payload.len()+OVERHEAD);let len=payload.len() as u32;
    rec.extend(len.to_be_bytes());rec.extend(len_check(len));rec.extend(sha(payload));rec.extend(payload);rec.push(1);rec
}
enum Tail{Clean,Torn,Corrupt}
/// Parses v2 records from `pos`; returns (payloads, end of verified prefix, tail classification).
fn parse_v2(bytes:&[u8],mut pos:usize)->(Vec<Vec<u8>>,usize,Tail){
    let mut out=Vec::new();
    loop{
        let rest=&bytes[pos..];
        if rest.is_empty(){return (out,pos,Tail::Clean)}
        let zero_fill=rest.iter().all(|b|*b==0)&&rest.len()<=MAX_RECORD+OVERHEAD;
        if rest.len()<HDR{return (out,pos,Tail::Torn)}
        let len=u32::from_be_bytes(rest[..4].try_into().unwrap());
        if rest[4..8]!=len_check(len)[..]{return (out,pos,if zero_fill{Tail::Torn}else{Tail::Corrupt})}
        let len=len as usize;if len>MAX_RECORD{return (out,pos,Tail::Corrupt)}
        if rest.len()<len+OVERHEAD{return (out,pos,Tail::Torn)}
        let digest=&rest[HDR..HDR+32];let payload=&rest[HDR+32..HDR+32+len];let marker=rest[HDR+32+len];
        if marker!=1||sha(payload)[..]!=digest[..]{return (out,pos,Tail::Corrupt)}
        out.push(payload.to_vec());pos+=len+OVERHEAD;
    }
}
/// Strict v1 parse (len ‖ digest ‖ payload ‖ marker): Some only when every byte belongs to a valid record.
fn parse_v1_strict(bytes:&[u8])->Option<Vec<Vec<u8>>>{
    let mut pos=40;let mut out=Vec::new();
    while pos<bytes.len(){
        if bytes.len()-pos<37{return None}
        let len=u32::from_be_bytes(bytes[pos..pos+4].try_into().unwrap()) as usize;if len>MAX_RECORD||pos+37+len>bytes.len(){return None}
        let digest=&bytes[pos+4..pos+36];let payload=&bytes[pos+36..pos+36+len];if bytes[pos+36+len]!=1||sha(payload)[..]!=digest[..]{return None}
        out.push(payload.to_vec());pos+=37+len;
    }
    Some(out)
}
/// A commit file holding one valid slot (`seq`, `count`, `end`) in the current layout.
fn commit_file(binding:&[u8;32],seq:u64,count:u64,end:u64)->Vec<u8>{
    let mut c=vec![0u8;SLOT_STRIDE+SLOT];let off=(seq%2) as usize*SLOT_STRIDE;c[off..off+SLOT].copy_from_slice(&slot_bytes(binding,seq,count,end));c
}
fn write_new(path:&Path,dir:&Path,bytes:&[u8])->Result<(),StoreError>{
    let tmp=path.with_extension("tmp");{let mut f=File::create(&tmp)?;f.write_all(bytes)?;f.sync_all()?;}
    fs::rename(&tmp,path)?;sync_dir(dir);Ok(())
}
fn backup(dir:&Path,stem:&str,bytes:&[u8])->Result<(),StoreError>{
    let n=(0..).find(|i|!dir.join(format!("{stem}-{i}")).exists()).unwrap();
    let mut f=File::create(dir.join(format!("{stem}-{n}")))?;f.write_all(bytes)?;f.sync_all()?;Ok(())
}

/// Opens (or creates) the journal in `dir`, holding an exclusive OS lock on `dir/LOCK` for the
/// process lifetime (second writer => Locked).
pub fn open(dir:&Path,binding:&[u8;32])->Result<Recovered,StoreError>{
    fs::create_dir_all(dir)?;
    let lock=OpenOptions::new().create(true).truncate(false).write(true).open(dir.join("LOCK"))?;
    match lock.try_lock(){Ok(())=>{},Err(std::fs::TryLockError::WouldBlock)=>return Err(StoreError::Locked),Err(std::fs::TryLockError::Error(e))=>return Err(e.into())}
    let path=dir.join("blocks.journal");let cpath=dir.join("blocks.commit");
    let _=fs::remove_file(dir.join("blocks.tmp"));let _=fs::remove_file(dir.join("blocks.journal.tmp"));
    if !path.exists(){
        // Never silently restart from genesis when recovery artifacts or a commit file exist.
        let artifacts=fs::read_dir(dir)?.filter_map(|e|e.ok()).any(|e|{let n=e.file_name().to_string_lossy().to_string();n.starts_with("blocks.journal.torn-")||n.starts_with("blocks.journal.v1-")});
        if artifacts||cpath.exists(){return Err(StoreError::MissingJournal)}
        let mut head=Vec::with_capacity(40);head.extend(MAGIC);head.extend(binding);
        write_new(&cpath,dir,&commit_file(binding,0,0,40))?;
        write_new(&path,dir,&head)?;
    }
    let mut bytes=Vec::new();File::open(&path)?.read_to_end(&mut bytes)?;
    if bytes.len()<40||&bytes[8..40]!=binding{return Err(StoreError::Binding)}
    let mut migrated=false;
    if &bytes[..8]==MAGIC_V1{
        // Legacy journal: unauthenticated lengths, so only a complete, fully verified parse is trusted.
        let payloads=parse_v1_strict(&bytes).ok_or(StoreError::LegacyNeedsReview)?;
        backup(dir,"blocks.journal.v1",&bytes)?;
        let mut v2=Vec::new();v2.extend(MAGIC);v2.extend(binding);for p in &payloads{v2.extend(encode_frame(p));}
        write_new(&cpath,dir,&commit_file(binding,1,payloads.len() as u64,v2.len() as u64))?;
        write_new(&path,dir,&v2)?;bytes=v2;migrated=true;
    }
    if &bytes[..8]!=MAGIC{return Err(StoreError::Binding)}
    let mut cbytes=Vec::new();match File::open(&cpath){Ok(mut f)=>{f.read_to_end(&mut cbytes)?;},Err(_)=>return Err(StoreError::MissingCommit)}
    let ((seq,count,cend),slot_damaged)=read_commit(&cbytes,binding).ok_or(StoreError::CommitCorrupt)?;
    let (payloads,pos,tail)=parse_v2(&bytes,40);
    // Bytes that cannot be a record but lie after every committed record were never committed. Not
    // when a commit slot is damaged: the surviving older slot may predate the last commit (second
    // review: a double fault would otherwise drop a committed record).
    let uncommitted=!slot_damaged&&payloads.len() as u64==count&&pos as u64==cend&&bytes.len()-pos<=MAX_RECORD+OVERHEAD;
    let tail=if matches!(tail,Tail::Corrupt)&&uncommitted{Tail::Torn}else{tail};
    if matches!(tail,Tail::Corrupt){return Err(StoreError::Corrupt(payloads.len() as u64))}
    // Committed data must all be present and verified; extra complete records were fsynced before a crash
    // that preceded their commit-file update and are kept (they are complete and verified).
    // A crash between the journal fsync and the commit update leaves at most one such record.
    if (payloads.len() as u64)<count||(pos as u64)<cend||(payloads.len() as u64)>count+1{return Err(StoreError::Corrupt(payloads.len() as u64))}
    let torn=matches!(tail,Tail::Torn);
    // A tail after a complete uncommitted record would be a second append in flight; appends commit
    // before the next begins, so that is damage, not a crash.
    if torn&&payloads.len() as u64==count+1{return Err(StoreError::Corrupt(payloads.len() as u64))}
    if torn{
        // Recovery: preserve the original bytes (fsynced copy), write the verified prefix to a new
        // file (fsynced), atomically replace the journal, fsync the directory.
        backup(dir,"blocks.journal.torn",&bytes)?;
        write_new(&path,dir,&bytes[..pos])?;
    }
    // The first v2 layout kept both slots in one sector: rewrite it in the current layout.
    if cbytes.len()==2*SLOT{write_new(&cpath,dir,&commit_file(binding,seq,count,cend))?;}
    let commit=OpenOptions::new().read(true).write(true).open(&cpath)?;
    let file=OpenOptions::new().append(true).open(&path)?;
    let mut j=Journal{file,commit,path,_lock:lock,binding:*binding,seq,end:pos as u64,records:payloads.len() as u64};
    if j.records>count{j.write_commit()?;}
    Ok(Recovered{journal:j,payloads,torn_tail:torn,migrated_v1:migrated})
}
fn sync_dir(dir:&Path){if let Ok(d)=File::open(dir){let _=d.sync_all();}}

impl Journal{
    fn write_commit(&mut self)->Result<(),StoreError>{
        self.seq+=1;let off=(self.seq%2) as u64*SLOT_STRIDE as u64;
        self.commit.seek(SeekFrom::Start(off))?;self.commit.write_all(&slot_bytes(&self.binding,self.seq,self.records,self.end))?;self.commit.sync_data()?;Ok(())
    }
    /// Appends one record, fsyncs it, then records it in the commit file (fsynced) before returning.
    pub fn append(&mut self,payload:&[u8])->Result<(),StoreError>{
        if payload.len()>MAX_RECORD{return Err(StoreError::TooLarge)}
        let rec=encode_frame(payload);
        self.file.write_all(&rec)?;self.file.sync_data()?;self.records+=1;self.end+=rec.len() as u64;
        self.write_commit()
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
