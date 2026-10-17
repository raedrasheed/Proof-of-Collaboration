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
