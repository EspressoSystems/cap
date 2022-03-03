#!/usr/bin/env bash
set -o xtrace
IGNORED_FILES="--ignore src/errors.rs\
               --ignore src/bin/*\
               --ignore src/parameters.rs\
               --ignore src/bench_utils/*\
              "
cargo +nightly install grcov
export CARGO_INCREMENTAL=0
export RUSTFLAGS="-Zprofile -Ccodegen-units=1 -Copt-level=3 -Clink-dead-code -Coverflow-checks=off -Zpanic_abort_tests -Cpanic=abort"
export RUSTDOCFLAGS="-Cpanic=abort"
rm -rf ./target/**/*.gcda
cargo +nightly build
cargo +nightly test --lib
grcov . -s . --binary-path ./target/debug/ -t html --branch --ignore-not-existing  $IGNORED_FILES -o ./target/debug/coverage/
echo "Coverage report available at target/debug/coverage/index.html."
