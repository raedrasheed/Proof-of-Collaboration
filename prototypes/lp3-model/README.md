# LP3 TypeScript reference model (S6)

Pure reference arithmetic, timing, membership, nonce assignment and proposer Draw;
bounded iterative GenesisSpec decoding, canonical encoding and Keccak identity.
No parent-state authentication, signing, private keys, EVM, production node or boot.
All inputs use bigint where integers can exceed JavaScript's exact-number range.
The line adapter quotes integer tokens before JSON parsing to preserve u64 values.

Local execution uses Node 24.19 native type stripping, **not type checking**:

    node --experimental-strip-types tests.ts

Required proper type checking and Node 22 execution are a separate PR workflow with
exact TypeScript 5.9.3, @types/node 22.18.6 and undici-types 6.21.0 dependencies.
From this directory after installing those exact packages:

    npm run typecheck
    npm test

No successful CI/type-check result is claimed before its recorded completion.
The first local `node --test tests.ts` invocation reported only a file-level result
under this environment; the corrected direct invocation verifies all seven named tests.
The authored model remains subject to separate independent comparison and review.
