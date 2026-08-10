# Task Completion Checklist

Run these commands after completing any coding task:

## Required
```sh
cargo fmt -- --check              # verify formatting
cargo clippy -- -D warnings       # lint changed crate(s)
cargo test -p <crate>             # tests for affected crate(s)
```

## For Cross-Crate Changes
```sh
just default                      # check/build/test entire workspace
```

## For PR-Ready Changes
```sh
just clippy                       # full workspace lint
just fmt
just all-features                 # if features were touched
```
