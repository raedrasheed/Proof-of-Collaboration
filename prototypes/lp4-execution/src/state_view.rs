//! The state an engine reads, borrowed instead of cloned (decision package C-2, item 3).
//! Complete local state backend only (InMemoryDB over EmptyDB), as collision and code_caps require.
use std::convert::Infallible;
use revm::{Database, DatabaseRef, InMemoryDB};
use revm::primitives::{AccountInfo, Address, Bytecode, B256, U256};

/// A pre-transaction (or pre-call) state, read through `DatabaseRef`. revm's `transact()` and the
/// SYSTEM frames write only to their journaled state, so the engine never needs its own copy: a
/// `CacheDB` answers `basic_ref`/`storage_ref`/`code_by_hash_ref` exactly as its mutable `Database`
/// methods do (an absent account is `None`, a NotExisting or StorageCleared account reads zero
/// slots), without the NotExisting cache entries those methods insert.
///
/// `code_total` is the state's logical code total (`code_caps::inventory`) when the caller already
/// knows it, so the CODE_CAP check of a create does not rescan the whole state.
pub struct StateRef<'a> { pub(crate) db: &'a InMemoryDB, pub(crate) code_total: Option<u64> }
impl<'a> StateRef<'a> {
    pub(crate) fn new(db: &'a InMemoryDB, code_total: Option<u64>) -> Self { Self { db, code_total } }
}
impl Database for StateRef<'_> {
    type Error = Infallible;
    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Infallible> { self.db.basic_ref(address) }
    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Infallible> { self.db.code_by_hash_ref(code_hash) }
    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Infallible> { self.db.storage_ref(address, index) }
    fn block_hash(&mut self, number: u64) -> Result<B256, Infallible> { self.db.block_hash_ref(number) }
}

/// An engine database whose complete base state can be inspected (collision, code_caps, PAY).
pub trait LocalState {
    fn local(&self) -> &InMemoryDB;
    /// The base state's logical code total, if known.
    fn code_total(&self) -> Option<u64> { None }
}
impl LocalState for InMemoryDB { fn local(&self) -> &InMemoryDB { self } }
impl LocalState for StateRef<'_> {
    fn local(&self) -> &InMemoryDB { self.db }
    fn code_total(&self) -> Option<u64> { self.code_total }
}
