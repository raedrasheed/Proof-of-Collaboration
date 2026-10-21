//! LP8 T16 rejection vectors for the manifest and chunk verification.
use pocold::{site::{self,FileEntry,Manifest},rlp};
use revm::primitives::{keccak256,Address,B256};

fn good()->Manifest{
    let f=|p:&str,mime:u8,data:&[u8]|FileEntry{path:p.into(),mime,size:data.len() as u32,content_hash:keccak256(data),chunks:vec![(site::chunk_address(data),data.len() as u32)]};
    Manifest{entry:1,files:vec![f("/app.js",3,b"x"),f("/index.html",1,b"<p>"),f("/style.css",2,b"b{}")]}
}
fn rejects(m:&Manifest,why:&str){let e=Manifest::decode(&m.encode()).unwrap_err();assert!(e.contains(why),"{why}: got {e}");}

#[test] fn canonical_manifest_round_trips(){let m=good();assert_eq!(Manifest::decode(&m.encode()).unwrap(),m);}
#[test] fn t16_rejection_vectors(){
    let mut m=good();m.files.swap(0,1);rejects(&m,"sorted");                              // unsorted
    let mut m=good();m.files[1]=m.files[0].clone();rejects(&m,"sorted");                    // duplicate
    let mut m=good();m.files[0].path="/./a.js".into();rejects(&m,"bad path");             // '.'
    let mut m=good();m.files[0].path="/a\u{e9}.js".into();rejects(&m,"bad path");          // non-ASCII
    let mut m=good();m.files[0].path="/a b.js".into();rejects(&m,"bad path");             // space
    let mut m=good();m.files[0].mime=11;rejects(&m,"unknown mime");                         // unknown mime
    let mut m=good();m.entry=0;rejects(&m,"entry is not html");                             // entry not html
    let mut m=good();m.files[0].size=2;rejects(&m,"size mismatch");                         // size != sum len
    let mut m=good();m.files[0].chunks[0].1=0;rejects(&m,"chunk len");                      // len 0
    let mut b=good().encode();b.push(0);assert!(Manifest::decode(&b).is_err(),"trailing byte");
    let mut b=good().encode();b[0]=0xf9;assert!(Manifest::decode(&b).is_err(),"noncanonical RLP");
    // version byte other than 1
    let m=good();let mut b=m.encode();let i=b.iter().position(|x|*x==0x01).unwrap();b[i]=0x02;assert!(Manifest::decode(&b).is_err());
}
#[test] fn chunk_code_checks(){
    let data=b"hello chunk";let a=site::chunk_address(data);
    let mut code=vec![0u8];code.extend(data);assert_eq!(site::chunk_payload(a,&code,data.len() as u32).unwrap(),data.to_vec());
    let mut bad=code.clone();bad[0]=0x60;assert!(site::chunk_payload(a,&bad,data.len() as u32).unwrap_err().contains("code[0]"));
    assert!(site::chunk_payload(a,&code,3).unwrap_err().contains("length"));
    assert!(site::chunk_payload(Address::repeat_byte(7),&code,data.len() as u32).unwrap_err().contains("ChunkFactory"),"other factory");
    let _=B256::ZERO;let _=rlp::encode_bytes;
}
#[test] fn path_normalization_d96(){
    assert_eq!(site::normalize(""),Some(None));assert_eq!(site::normalize("/"),Some(None));assert_eq!(site::normalize("/?q=1#x"),Some(None));
    assert_eq!(site::normalize("/docs/"),Some(Some("/docs/index.html".into())));assert_eq!(site::normalize("/a.css?v=2"),Some(Some("/a.css".into())));
    for bad in ["/%2e/x","//x","/./x","/../x","/a/../b"]{assert_eq!(site::normalize(bad),None,"{bad}");}
}
