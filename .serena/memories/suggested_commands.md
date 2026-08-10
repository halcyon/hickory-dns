# Suggested Commands

## Initial Setup
```sh
just init
# or manually:
cargo install just cargo-workspaces
```

## Daily Development
```sh
just default                      # check, build, test all crates (default features)
cargo test -p hickory-proto       # focused crate test while iterating
cargo test -p hickory-proto <name> # single test
```

## Full Validation
```sh
just all-features                 # complete feature matrix
just no-default-features          # minimal builds
just clippy                       # lint all crates (-D warnings)
just fmt                          # verify formatting
just cleanliness                  # clippy + fmt + audit
```

## Server Build & Run
```sh
cargo build --release -p hickory-dns
just run-example                  # local server on port 2053 with fixtures
```

## Coverage
```sh
just coverage                     # generate coverage report
just coverage-html                # open HTML report
just coverage-lcov                # export lcov format
```

## Conformance
```sh
just conformance-framework        # test harness only
just conformance-hickory          # vs local hickory-dns (requires Docker)
```

## FreeBSD Notes
- Commands are standard POSIX; no FreeBSD-specific adjustments required.
- `just` requires GNU make or native `just` binary (preferred).
