#!/usr/bin/env bash

# We want the code to panic if there is an integer overflow
export RUSTFLAGS="-C overflow-checks=on"

cargo test --release --no-default-features --features bn254 -- -Zunstable-options --report-time
