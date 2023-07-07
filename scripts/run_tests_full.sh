#!/usr/bin/env bash

# We want the code to panic if there is an integer overflow
export RUSTFLAGS="-C overflow-checks=on"

cargo test --release --no-default-features --features bls12_381 -- -Zunstable-options --report-time
cargo test --release --no-default-features --features bn254 -- -Zunstable-options --report-time
cargo test --release --no-default-features --features bls12_377 -- -Zunstable-options --report-time
