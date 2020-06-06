# encointer-node
Encointer-node is the implementation of the [encointer.org](https://encointer.org) blockchain.
Use this together with the mobile phone app [encointer-app](https://github.com/encointer/encointer-app) 

# PoC2 (v0.2.0)
Goal: show the entire flow from bootstrapping to regular ceremonies at live demos

Simplifications for PoC2 (with respect to whitepaper)

* fake time (Demonstration Speaker can warp time to next phase when people are ready)
* no anonymity, only pseudonymity
* tx fees instead of POET
* permissioned consensus instead of dPOET
* assignments on-chain instead of IPFS

The cli client is based on [substrate-api-client](https://github.com/scs/substrate-api-client)
The next PoC will be based on [substraTEE project](https://github.com/scs/substraTEE). 

## Building

Install Rust:

```bash
curl https://sh.rustup.rs -sSf | sh
```
In order to compile *ring* into wasm, you'll need LLVM-9 or above or you'll get linker errors. Here the instructions for Ubuntu 18.04

```bash
wget https://apt.llvm.org/llvm.sh
chmod +x llvm.sh
sudo ./llvm.sh 10
export CC=/usr/bin/clang-10
export AR=/usr/bin/llvm-ar-10
# if you already built, make sure to run cargo clean
```

Install required tools:

```bash
./scripts/init.sh
```

Build the node:

```bash
cargo +nightly build --release
```

## Run Dev Node

You can start a development chain with:

```bash
./target/release/encointer-node --dev --ws-port 9979 --execution native -lruntime=debug 2>&1 | grep --color=always -e "^" -e 'DEBUG runtime'
```

Additional CLI usage options are available and may be shown by running `./target/release/encointer-node --help`.

## Run Testnet Gesell Node
Join our testnet as a full node with 

```bash
./target/release/encointer-node --chain gesellSpecRaw.json --name giveyournodeaname
```

## Build CLI client
We currently have limited support for the [polkadot-js apps](https://polkadot.js.org/apps) UI. Encointer comes with a cli application instead that supports all interactions with the chain:

```bash
cargo +nightly build encointer-client --release
```

## Run Client

```
encointer-node/client> cargo build --release
encointer-node/client> ../target/release/encointer-client 127.0.0.1:9944 transfer //Alice 5GziKpBELV7fuYNy7quQfWGgVARn8onchS86azuPQkFj9nEZ 1000000
encointer-node/client> ../target/release/encointer-client 127.0.0.1:9944 list_participant_registry
encointer-node/client> ../target/release/encointer-client 127.0.0.1:9944 list_meetup_registry
encointer-node/client> ../target/release/encointer-client 127.0.0.1:9944 list_witnesses_registry
encointer-node/client> ../target/release/encointer-client --help
``` 
The master of ceremony can play fast-forward for demo purposes (ceremonies only happen ~monthly. not good for demos)
```
encointer-node/client> ./encointer-client 127.0.0.1:9944 next_phase
```

To run a full demo (you may need to fix ports in the scripts if you change them):
```
encointer-node/client> ./bootstrap_demo_currency.sh
encointer-node/client> ./demo_poc1.sh
```

## Web UI

There is no fully featured UI yet, but you can use [polkadot-js apps](https://github.com/polkadot-js/apps). 
This allows you to explore chain state but it doesn't support all types of extrinsic parameters needed. Use our CLI client instead.

## Mobile App

The PoC1 Android App doesn't work with this release anymore, but you can watch progress at [encointer-app](https://github.com/encointer/encointer-app)
