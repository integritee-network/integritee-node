# encointer-node
Encointer-node is the implementation of the [encointer.org](https://encointer.org) blockchain.
Use this together with the mobile phone app [encointer-app](https://github.com/encointer/encointer-app) 

# PoC2
Goal: show the entire flow from bootstrapping to regular ceremonies at live demos

Simplifications for PoC2 (with respect to whitepaper)

* ignore geoposition
* ignore exact time (Demonstration Speaker can warp time to next phase when people are ready)
* no anonymity, only pseudonymity
* use srml_balances for token
* tx fees instead of POET
* permissioned consensus instead of dPOET
* no chat functionality in app
* assignments on-chain instead of IPFS

The cli client is based on [substrate-api-client](https://github.com/scs/substrate-api-client)
The next PoC will be based on [substraTEE project](https://github.com/scs/substraTEE). 

## Building

Install Rust:

```bash
curl https://sh.rustup.rs -sSf | sh
```

Install required tools:

```bash
./scripts/init.sh
```

Build all native code:

```bash
cargo build --release
```

## Run Node

You can start a development chain with:

```bash
./target/release/encointer-node --dev --ws-port 9979 --execution native -lruntime=debug 2>&1 | grep --color=always -e "^" -e 'DEBUG runtime'
```

Additional CLI usage options are available and may be shown by running `./target/release/encointer-node --help`.

## Run Client
encointer comes with a cli application that allows interaction with the chain

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
