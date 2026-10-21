//! LP4 P9 persistence: torn tail at EVERY byte offset of the last record,
//! complete-record corruption, binding mismatch, single writer.
use pocold::store::{self,StoreError};
use std::fs;

fn tmp(name:&str)->std::path::PathBuf{let d=std::env::temp_dir().join(format!("pocold-store-{name}-{}",std::process::id()));let _=fs::remove_dir_all(&d);d}
const B:[u8;32]=[9;32];

#[test] fn append_reopen_and_torn_tail_at_every_offset(){
    let dir=tmp("torn");
    let payloads:Vec<Vec<u8>>=(0..4u8).map(|i|vec![i;100+i as usize]).collect();
    {let mut r=store::open(&dir,&B).unwrap();assert!(r.payloads.is_empty());for p in &payloads{r.journal.append(p).unwrap();}}
    let full=fs::read(dir.join("blocks.journal")).unwrap();
    {let r=store::open(&dir,&B).unwrap();assert_eq!(r.payloads,payloads);assert!(!r.torn_tail);}
    let last=4+32+payloads[3].len()+1;let prefix=full.len()-last;
    for cut in prefix+1..full.len(){
        let d=tmp(&format!("cut{cut}"));fs::create_dir_all(&d).unwrap();fs::write(d.join("blocks.journal"),&full[..cut]).unwrap();
        let r=store::open(&d,&B).unwrap_or_else(|e|panic!("cut {cut}: {e:?}"));
        assert!(r.torn_tail,"cut {cut}");assert_eq!(r.payloads,payloads[..3].to_vec(),"cut {cut}: only complete records are committed");
        // Original torn bytes are preserved; the new journal holds exactly the verified prefix.
        assert_eq!(fs::read(d.join("blocks.journal.torn-0")).unwrap(),full[..cut].to_vec());
        assert_eq!(fs::read(d.join("blocks.journal")).unwrap(),full[..prefix].to_vec());
        drop(r);let again=store::open(&d,&B).unwrap();assert!(!again.torn_tail);assert_eq!(again.payloads.len(),3);
        let _=fs::remove_dir_all(&d);
    }
    // Cut exactly at a record boundary is a clean shorter journal (not torn).
    let d=tmp("boundary");fs::create_dir_all(&d).unwrap();fs::write(d.join("blocks.journal"),&full[..prefix]).unwrap();
    let r=store::open(&d,&B).unwrap();assert!(!r.torn_tail);assert_eq!(r.payloads.len(),3);
}

#[test] fn complete_record_corruption_is_never_skipped(){
    let dir=tmp("corrupt");
    {let mut r=store::open(&dir,&B).unwrap();for i in 0..3u8{r.journal.append(&[i;64]).unwrap();}}
    let full=fs::read(dir.join("blocks.journal")).unwrap();
    // Flip one byte inside each region of record 1 (length, digest, payload, marker).
    let rec=4+32+64+1;let start=40+rec;
    for off in [start,start+5,start+40,start+rec-1]{
        let mut bad=full.clone();bad[off]^=0x5a;let d=tmp(&format!("flip{off}"));fs::create_dir_all(&d).unwrap();fs::write(d.join("blocks.journal"),&bad).unwrap();
        match store::open(&d,&B){Err(StoreError::Corrupt(_))=>{},Ok(r)=>assert!(r.payloads.len()<3&&!r.payloads.iter().any(|p|p!=&vec![0u8;64]&&p!=&vec![1u8;64]&&p!=&vec![2u8;64]),"off {off}: corrupted record must not be accepted"),Err(e)=>panic!("{e:?}")}
        let _=fs::remove_dir_all(&d);
    }
}

#[test] fn binding_mismatch_and_second_writer_rejected(){
    let dir=tmp("bind");
    let first=store::open(&dir,&B).unwrap();
    assert!(matches!(store::open(&dir,&B),Err(StoreError::Locked)),"second writer while first is open");
    drop(first);
    assert!(matches!(store::open(&dir,&[1;32]),Err(StoreError::Binding)),"journal bound to another genesisHash");
}
