# substraTEE-node

This repository belongs to the [substraTEE project](https://github.com/scs/substraTEE).

A substrate-based node that maintains a registry of remote attested substraTEE-worker enclaves. The node also acts as a proxy for encrypted requests which are forwarded to the substraTEE-worker.

# Building

Install Rust:

```bash
curl https://sh.rustup.rs -sSf | sh
```

Install required tools:

```bash
./scripts/init.sh
```

Build the node:

```bash
cargo build
```

# Run

You can start a development chain with:

```bash
cargo run -- --dev
```

or 

```bash
./target/release/substratee-node --dev
```

Additional CLI usage options are available and may be shown by running `cargo run -- --help`.
