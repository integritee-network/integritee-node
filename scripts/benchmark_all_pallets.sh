#!/bin/bash

# Create `WeightInfo` implementations for all the pallets and store it in the weight module of the `runtime`.

RUNTIME_WEIGHT_DIR=runtime/src/weights
NODE=./target/release/integritee-node

mkdir -p $RUNTIME_WEIGHT_DIR

pallets=(
  "frame_system" \
  "pallet_balances" \
  "pallet_multisig" \
  "pallet_proxy" \
  "pallet_scheduler" \
  "pallet_timestamp" \
  "pallet_teerex" \
  "pallet_treasury" \
  "pallet_vesting" \
)

for pallet in ${pallets[*]}; do
  echo benchmarking "$pallet"...

  $NODE \
  benchmark \
  --chain=integritee-solo-fresh \
  --steps=50 \
  --repeat=20 \
  --pallet="$pallet" \
  --extrinsic="*" \
  --execution=wasm \
  --wasm-execution=compiled \
  --heap-pages=4096 \
  --output=./$RUNTIME_WEIGHT_DIR/"$pallet".rs \

done
