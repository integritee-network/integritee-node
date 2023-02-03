################################################################################

# podman build -f interstellar.Dockerfile -t ghcr.io/interstellar-network/integritee_node:dev --volume ~/.cargo:/root/.cargo:rw --volume $(pwd)/target/release:/usr/src/app/target/release:rw .
# NOTE: it CAN work with Docker but it less than ideal b/c it can not reuse the host's cache
# CHECK: podman run --rm -it ghcr.io/interstellar-network/integritee_node:dev
#
# to publish:
# podman tag ghcr.io/interstellar-network/integritee_node:dev ghcr.io/interstellar-network/integritee_node:vXXX
# podman push ghcr.io/interstellar-network/integritee_node:vXXX

FROM ghcr.io/interstellar-network/ci-images/base-rust:v3 as builder

WORKDIR /usr/src/app

# "error: 'rustfmt' is not installed for the toolchain '1.59.0-x86_64-unknown-linux-gnu'"
# RUN rustup component add rustfmt

# error: failed to run custom build command for `librocksdb-sys v0.6.1+6.28.2`
#   Caused by:
#       process didn't exit successfully: `/usr/src/app/target/release/build/librocksdb-sys-e7d2d3b20efc388f/build-script-build` (exit status: 101)
#       --- stderr
#       thread 'main' panicked at 'Unable to find libclang: "couldn't find any valid shared libraries matching: ['libclang.so', 'libclang-*.so', 'libclang.so.*', 'libclang-*.so.*'], set the `LIBCLANG_PATH` environment variable to a path where one of these files can be found (invalid: [])"', /usr/local/cargo/registry/src/github.com-1ecc6299db9ec823/bindgen-0.59.2/src/lib.rs:2144:31
#
# RUN apt-get update && apt-get install -y \
#     libclang-dev \
#     && rm -rf /var/lib/apt/lists/*
# prereq of rocksys: LLVM & clang
# the script will by default install "PKG="clang-$LLVM_VERSION lldb-$LLVM_VERSION lld-$LLVM_VERSION clangd-$LLVM_VERSION""
#
# TODO customize, only install clang+llvm?
RUN apt-get update && apt-get install -y \
    lsb-release software-properties-common \
    && rm -rf /var/lib/apt/lists/*
# thread 'main' panicked at 'One of the compatible llvm toolchain must exist: llvm-{11,10,9}'
RUN wget https://apt.llvm.org/llvm.sh && \
    chmod +x llvm.sh && \
    sudo ./llvm.sh 11 && \
    rm ./llvm.sh && \
    rm -rf /var/lib/apt/lists/*

# install protoc
RUN export MY_PROTOC_URL=https://github.com/protocolbuffers/protobuf/releases/download/v21.12/protoc-21.12-linux-x86_64.zip && \
    mkdir -p /home/runner/protoc && \
    cd /home/runner/protoc && \
    wget $MY_PROTOC_URL -O prebuilt.zip && \
    unzip prebuilt.zip && \
    rm prebuilt.zip
ENV PROTOC /home/runner/protoc/bin/protoc

COPY . .
# MUST use "--locked" else Cargo.lock is ignored
RUN cargo install --locked --path node --features skip-ias-check,skip-extrinsic-filtering

# MUST also get all the shared libs; using the CMake generated list of libs
# cf https://github.com/Interstellar-Network/cmake/blob/main/export_libs.cmake
# It SHOULD be empty for "lib_garble" but we might as well handle it just in case.
# NOTE: if it fails with cp: will not overwrite just-created '/usr/local/lib/liblibyosys.so' with '/usr/src/app/target/release/build/lib-circuits-wrapper-a097322ac7999802/out/build/_deps/yosys_fetch-build/liblibyosys.so'
# It probably means you are caching the container target/ by using a volume and there are multiple build dir
# CHECK: find target/release/build/ -type d -name "*lib-garble-wrapper*"
# If yes: DELETE the dup
RUN cat $(find target/release/ -type f -name cmake_generated_libs) | tr " " "\n" |  grep "/usr/src/app/target/release/.*.so" > list_local_shared_libs && \
    xargs --arg-file=list_local_shared_libs cp --target-directory=/usr/local/lib/ && \
    rm list_local_shared_libs \
    || echo "no shared libs to copy" && touch /usr/local/lib/no_shared_lib_to_copy

################################################################################

FROM ubuntu:20.04

EXPOSE 9990 30390 8990

ENV APP_NAME integritee-node

ENV LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib

# TODO?
# - ca-certificates(+exec update-ca-certificates):
#   Thread 'tokio-runtime-worker' panicked at 'no CA certificates found', /usr/local/cargo/registry/src/github.com-1ecc6299db9ec823/hyper-rustls-0.22.1/src/connector.rs:45
#   cf https://github.com/paritytech/substrate/issues/9984
# TODO? instead cf https://rustrepo.com/repo/awslabs-aws-sdk-rust [17.]
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/cargo/bin/$APP_NAME /usr/local/bin/$APP_NAME

# CHECK
RUN ldd /usr/local/bin/$APP_NAME && \
	/usr/local/bin/$APP_NAME --version

# MUST use full path eg /usr/local/bin/integritee-service, else "Error: executable file `$APP_NAME` not found in $PATH"
# DO NOT use eg "sh -c $APP_NAME" b/c with it CMD is NOT passed to ENTRYPOINT!
ENTRYPOINT ["/usr/local/bin/integritee-node"]
# cf README: "IMPORTANT: you **MUST** use `--enable-offchain-indexing=1`"
# --ws-external, needed else can not connect from host, cf https://github.com/substrate-developer-hub/substrate-node-template/blob/main/docker-compose.yml
CMD ["--ws-external", "--dev", "--tmp", "--ws-port", "9990", "--port", "30390", "--rpc-port", "8990", "--enable-offchain-indexing=true"]