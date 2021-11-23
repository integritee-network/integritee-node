# integritee-node

This repository belongs to the [Integritee project](https://book.integritee.network).

A substrate-based node that maintains a registry of remote attested integritee-service enclaves. The node also acts as a proxy for encrypted requests which are forwarded to the integritee-service.

## Build and Run
Please see our [Integritee Book](https://book.integritee.network/howto_node.html) to learn how to build and run this.

## Benchmark the runtimes
In `./scripts` we have a script for benchmarking the runtimes.

### Current benchmark
The current weights have been benchmarked with the following reference hardware:

    GenuineIntel CPU MHz: 2494.144
    8GB of RAM
    NVMe SSD

### Running benchmark
1. Compile the node with: `cargo build --release --features runtime-benchmarks`
2. run: `./scripts/benchmark_all_pallets.sh`.
3. If changed, update the reference hardware above.

### Adding new pallets to be benchmarked
Every pallet with a `type WeightInfo` parameter in its config must be benchmarked.

1. [Cargo.toml] add `<new_pallet>/runtime-benchmarks` in the `runtime-benchmarks` feature section.
2. [runtime] add the new pallet to the `list_benchmark!` and `add_benchmark!` list.
3. add the new pallet in the script `./scripts/benchmark_all_pallets.sh` and run it.
4. [runtime/src/weights] add the new file to the modules
5. [runtime] replace the placeholder `type WeightInfo = ()` with `type WeightInfo = weights::<new_pallet>::WeightInfo<Runtime>`

## upgrade hard-coded genesis

For easy use of the binary without distributing a json chain spec, we generate a spec and build it into the binary
```
./target/release/integritee-node build-spec --chain integritee-solo-fresh --raw > integritee-solo.json
```
Then overwrite `./node/res/integritee-solo.json` but keep bootnode definitions and check other meta too.

Build the collator again and push.