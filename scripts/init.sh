#!/usr/bin/env bash

set -e

echo "*** Initializing WASM build environment"

TOOLCHAIN=$(cat ./rust-toolchain)

if [ -z $CI_PROJECT_NAME ] ; then
   rustup update nightly
   rustup update stable
fi

rustup target add wasm32-unknown-unknown --toolchain $TOOLCHAIN
