//! Fresh S8 corpus for the additive M3 entry point, distinct from preserved RP checks.
mod common;
use lp1_node::{envelope, fixtures};
#[test]
fn seeded_strict_envelope_no_panic_and_canonical_acceptance() {
    let raw = fixtures::load_chain_bytes(&common::json("chain.json")).unwrap();
    let mut r = common::Rng(0x5338_c0de_2026_1017);
    let mut accepted = 0;
    for _ in 0..12000 {
        let mut b = raw[r.below(raw.len() as u64) as usize].clone();
        let j = r.below(b.len() as u64 + 1) as usize;
        match r.below(4) {
            0 => {
                if j < b.len() {
                    b[j] ^= 1 << r.below(8);
                }
            }
            1 => b.truncate(j),
            2 => b.insert(j, r.next() as u8),
            _ => {
                if j < b.len() {
                    b[j] = r.next() as u8;
                }
            }
        }
        if let Ok(h) = envelope::decode(&b) {
            accepted += 1;
            assert_eq!(h.encode(), b);
            assert!(h.shares.windows(2).all(|a| a[0] < a[1]));
            assert!(!h.shares.contains(&h.nonce));
        }
    }
    assert!(accepted > 0);
    println!("{{\"corpus\":\"S8 envelope\",\"seed\":\"0x5338c0de20261017\",\"cases\":12000,\"accepted\":{}}}", accepted);
}
