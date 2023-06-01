# Configurable Asset Privacy (CAP) protocol -- a library in the Jellyfish ecosystem

## Development environment setup

We recommend the following tools:

- [`nix`](https://nixos.org/download.html)
- [`direnv`](https://direnv.net/docs/installation.html)

Run `direnv allow` at the repo root. You should see dependencies (including Rust) being installed.
Alternatively, enter the nix-shell manually via `nix develop`.

You can check you are in the correct development environment by running `which cargo`, which should print
something like `/nix/store/2gb31jhahrm59n3lhpv1lw0wfax9cf9v-rust-minimal-1.69.0/bin/cargo`;
and running `echo $CARGO_HOME` should print `~/.cargo-nix`.

### Compiling the project for the first time

```bash
> nix develop
> cargo build
```

### WASM target

`jf-cap` can be compiled to `wasm32-unknown-unknown` target, simply run:

```
./scripts/build_wasm.sh
```

### Tests

```
> cargo test --release
```

Note that by default the _release_ mode does not check integers overflow.
In order to enforce this check run:

```
> ./scripts/run_tests.sh
```

#### Test coverage

We use [grcov](https://github.com/mozilla/grcov) for test coverage

```
> ./scripts/test_coverage.sh
```

### Generate and read the documentation

#### Standard

```
> cargo doc --open
```

### Code formatting

To format your code run

```
> cargo fmt
```

### Updating non-cargo dependencies

Run `nix flake update`.
If you would like to pin other versions, edit `flake.nix` beforehand. Commit the lock file when happy.

To update only a single input specify it as the argument, for example

```
nix flake update github:oxalica/rust-overlay
```

### Benchmarks

#### Transactions generation/verification

Running the benchmarks produces a csv file containing the information about the note being benched
(type, number of inputs/outputs, number of constraints, size in KB etc...) as well as the running time.

Benchmarks can be run

- with or without [asm optimization](https://github.com/arkworks-rs/algebra#assembly-backend-for-field-arithmetic)
- using all cores or a single core

```
>./scripts/run_benchmarks.sh --help
CAP benchmarks
Usage: ./scripts/run_benchmarks.sh [--(no-)asm] [--(no-)multi_threads] [-h|--help]
	-h, --help: Prints help

# By default no asm and no multicore
> ./scripts/run_benchmarks.sh
Multi-threads: OFF
Asm feature: OFF
...

# Activate asm and multicore
> ./scripts/run_benchmarks.sh --asm --multi_threads
Multi-threads: ON
Asm feature: ON
```

The csv files can be found at `/tmp/{note_description}_cap_benchmark.csv`,
e.g. `/tmp/transfer_note_cap_benchmark.csv`.

The criterion report can be found at `target/criterion/report/index.html`.
