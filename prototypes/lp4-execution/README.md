# LP4 experimental execution controls

Isolated Rust 1.99.1 / revm =19.7.0 / Cancun crate. Cargo.lock pins resolved
sources; default crypto precompiles remain enabled. Legacy LP1 dependencies are
untouched. No PoCol apply, native PAY semantics, accepted GST, caps or boot path.

`Sandbox::execute` clones its input database and returns revm's actual execution
result/state diff; it never commits. Synthetic unfunded-network fixtures use no
keys or signatures. CALL-family access to PAY is rejected by an experimental outer
guard pending the owner decision; this is not a consensus rule.

With the pinned toolchain on PATH and an isolated CARGO_HOME:

```sh
cargo test --locked --manifest-path prototypes/lp4-execution/Cargo.toml
cargo run --locked --manifest-path prototypes/lp4-execution/Cargo.toml --example control_vectors > work/control-vectors.json
python3 prototypes/lp4-execution/tests/control_oracle.py work/control-vectors.json
python3 prototypes/lp4-execution/tests/mutations.py work/mutations
```

Use `--offline` after fetching the exact lockfile. The Python oracle implements
only PUSH1, CHAINID, MSTORE, cold zero-to-nonzero SSTORE, RETURN and REVERT for
three fixed initial conditions; it is not an independent full EVM. Mutants are
compiled separately and must fail a selected assertion; compile errors do not count.
GeneralStateTests, PoCol deviations, independent full-EVM/state-root differential,
legacy regression and licenses/provenance audit remain acceptance obligations.

Native boundary work now lives in `pay`/`native`, separately from the original
`Sandbox` guard. Its authority is [LP4-PAY-01](../../development/LP4-PAY-APPROVAL.md)
and the linked full approved contract. `PayBoundaryHarness.sol` is explicitly test
code, not the completed Registry/Escrow implementation. Compiled-harness comparison
with independently extended py-evm checks 26 boundary executions; full reward,
closing, system-phase, caps and GenesisBuilder acceptance remains outstanding.

`cancun_control` runs upstream Ethereum control fixtures (chain ID 1, upstream
fields and transaction types), not PoCol apply. `gst_control.py` checks resulting
full-state and log hashes using Python's independent trie/RLP/Keccak against frozen
geth-generated fixture roots. It does not validate signed wire transaction bytes.
The owner has approved the additive creation rule in
[LP4-CREATE-01](../../development/LP4-COLLISION-APPROVAL.md). The same collision
handler now runs in `native::execute` and the upstream control runner; the old
optional probe has been removed. Complete InMemoryDB base storage is overlaid by
current journal values, including unloaded keys and cleared/restored slots. This
backend has no external storage and therefore no hidden slots; this does not claim
persisted-state integration, a resource bound or P2/T2 acceptance. Historical probe
receipts remain unchanged.
