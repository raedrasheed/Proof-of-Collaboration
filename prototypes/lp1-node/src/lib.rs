//! LP1: local experimental PoCol M3-foundation slice over accepted M1 formats.
//!
//! Scope: fixed-width integers, bounded ASERT, strict RLP and V1 header codec, SHA-256 / Keccak
//! domain hashes with secp256k1 recovery (verification only), RP window items netid / future /
//! 2-9, an immutable validated fixture chain and a read-only loopback JSON-RPC node. Not full M3,
//! not consensus, no EVM, no P2P, no transactions, no keys. The V1NET profile is synthetic and
//! non-bootable.

pub mod asert;
pub mod chain;
pub mod fixed;
pub mod fixtures;
pub mod genesis;
pub mod hashes;
pub mod header;
pub mod hex;
pub mod http;
pub mod json;
pub mod rlp;
pub mod rpc;
pub mod verify;
pub mod window;
