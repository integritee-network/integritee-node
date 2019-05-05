# substraTEE-node

This repository belongs to the [substraTEE project](https://github.com/scs/substraTEE).

A SRML-based Substrate node that implements a module to forward an encrypted payload to the substraTEE-worker.

The node uses ed25519 signatures.

# Building

Install Rust:

```bash
curl https://sh.rustup.rs -sSf | sh
```

Install required tools:

```bash
./scripts/init.sh
```

Build the WebAssembly binary:

```bash
./scripts/build.sh
```

Build all native code:

```bash
cargo build
```

# Run

You can start a development chain with:

```bash
cargo run -- --dev
```

Additional CLI usage options are available and may be shown by running `cargo run -- --help`.
