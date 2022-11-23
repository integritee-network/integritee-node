# integritee-node

This repository belongs to the [Integritee project](https://book.integritee.network).

A substrate-based node that maintains a registry of remote attested integritee-service enclaves. The node also acts as a proxy for encrypted requests which are forwarded to the integritee-service.

## Build and Run
Please see our [Integritee Book](https://book.integritee.network/howto_node.html) to learn how to build and run this.

### Note
For there are some features that are highly relevant for developers:

* `skip-ias-check`: allow registering enclaves without attestation report.
* `skip-extrinsic-filtering`: We have a defensive filter for transfer extrinsics as we have an old solo-node running for archive purposes, which mustn't allow transfers. The filter can be deactivate with this feature.

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
./target/release/integritee-node build-spec --chain cranny-fresh --raw > cranny.json
```
Then overwrite spec files in `./node/res/*.json` but keep bootnode definitions and check other meta too.

Build the collator again and push.

## prepare and test runtime upgrade for Live chain

1. bump spec version. check if other runtime versions need to be bumped too. bump crate versions accordingly
2. tag version. this will trigger CI to produce a draft release with all artifacts
3. download release artifacts `integritee-node` (and postfix with version `-1.0.6`) and `integritee_node_runtime-v6.compact.compressed.wasm`
4. start a local chain with the previous, latest deployed version (`1.0.5`)
    ```
    ./integritee-node-1.0.5 purge-chain --base-path /tmp/alice --chain local
    ./integritee-node-1.0.5 purge-chain --base-path /tmp/bob --chain local
    ./integritee-node-1.0.5 --base-path /tmp/alice --chain local --alice --port 30333 --ws-port 9945 --rpc-port 9933 --node-key 0000000000000000000000000000000000000000000000000000000000000001 --telemetry-url "wss://telemetry.polkadot.io/submit/ 0" --validator
    ```

5. in another terminal
    ```
    integritee-node-1.0.5 --base-path /tmp/bob --chain local --bob --port 30334 --ws-port 9946 --rpc-port 9934 --telemetry-url "wss://telemetry.polkadot.io/submit/ 0" --validator --bootnodes /ip4/127.0.0.1/tcp/30333/p2p/12D3KooWEyoppNCUx8Yx66oV9fJnriXwCcXwDDUA2kj6vnc6iDEp
    ```
    you should see blocks produced. 
6. perform a transfer extrinsic in js/apps to test 
7. upgrade runtime to `integritee_node_runtime-v6.compact.compressed.wasm`
8. verify spec version has been upgraded in js/apps
9. stop one validator and restart it with newer binary version
10. test by pointing js/apps to the updated validator ws:// and sending a transfer
11. stop second validator and restart with new binary
12. test by pointing js/apps to the updated validator ws:// and sending a transfer
13. check that the node version has increased in js/apps
14. finally, submit runtime upgrade to live chain
