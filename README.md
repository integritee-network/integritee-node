# integritee-node

This repository belongs to the [Integritee project](https://book.integritee.network).

A substrate-based node that maintains a registry of remote attested integritee-service enclaves. The node also acts as a proxy for encrypted requests which are forwarded to the integritee-service.

## Build and Run
Please see our [Integritee Book](https://book.integritee.network/howto_node.html) to learn how to build and run this.

## benchmarking of weights

```
cargo build --release --features=runtime-benchmarks
./scripts/benchmark_all_pallets.sh
```