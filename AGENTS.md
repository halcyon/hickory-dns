# Repository Guidelines

## Serena is mandatory for source-code work

Before reading, searching, or editing source code, use Serena's MCP tools
when a suitable tool exists. Built-in file/search/edit tools are fallbacks.

At the beginning of a coding session, call Serena's `initial_instructions`
tool if its instructions were not automatically supplied.

If you fall back to a built-in tool on source code, explain why Serena
could not perform that operation.

## Project Structure & Module Organization

Hickory DNS is a Rust workspace. Core libraries live under `crates/`: `proto` implements DNS protocol behavior, `net` provides transports, `resolver` performs resolution, and `server` hosts zones. The `bin/` crate builds the server; `util/` contains CLI tools. Fixtures and helpers are in `tests/test-data`, `tests/test-support`, and `tests/integration-tests`. Interoperability suites live under `conformance/`; fuzz targets are in the excluded `fuzz/` workspace. Read `ARCHITECTURE.md` before changing crate boundaries.

## Tool Usage Guidelines

- **rg (ripgrep)**: Use `rg` for fast regex or literal text search across the codebase (respects `.gitignore`). Prefer over `grep` for all content searches.

- **fd**: Use `fd` for fast file and directory discovery by name or path pattern. Prefer over `find`.

- **jaq**: Use `jaq` for querying, filtering, and transforming JSON data (e.g., `Cargo.lock`, CI configs, test output).

Do not fall back to generic text search or manual file scanning when these tools are applicable.

## Build, Test, and Development Commands

Install the workflow tools with `cargo install just cargo-workspaces`, or run `just init` for the repository-managed setup.

- `just default` checks, builds, and tests every workspace crate with default features.
- `just all-features` exercises the complete feature matrix; `just no-default-features` checks minimal builds.
- `cargo test -p hickory-proto <test_name>` runs a focused crate or test while iterating.
- `just clippy` treats Clippy warnings as errors; `just fmt` verifies formatting.
- `cargo build --release -p hickory-dns` builds the production server.
- `just run-example` starts a local server on port 2053 using repository fixtures.
- `just conformance-framework` tests the harness; broader conformance recipes may require Docker.

Use `--locked` when reproducing CI commands. The workspace MSRV is declared in `Cargo.toml`.

## Coding Style & Naming Conventions

Format Rust with `cargo fmt`; `.rustfmt.toml` selects the 2024 style. Use four-space indentation, `snake_case` for modules/functions/tests, `CamelCase` for types and traits, and `SCREAMING_SNAKE_CASE` for constants. Follow workspace lints, document public APIs, and test relevant feature combinations.

## Testing Guidelines

Place unit tests beside implementation code in `tests` modules; put cross-crate behavior in crate `tests/` directories or `tests/integration-tests`. Use descriptive names, commonly with a `_tests.rs` suffix. Every PR must pass all tests. Coverage above 85% is encouraged, not required; `just coverage` uses `cargo-llvm-cov`. Add regression tests for bug fixes.

## Commit & Pull Request Guidelines

Recent commits use short, imperative subjects, often scoped (`resolver: parse ...`, `tests: add ...`, `build(deps): bump ...`). Keep commits reviewable and separate refactoring from behavior changes. Keep each PR focused on one issue, explain user-visible or API effects, link the motivating issue when applicable, and list the commands run. Discuss medium-to-large, behavioral, or API changes in an issue first.

## Security

Never open a public issue or PR for a vulnerability. Follow `SECURITY.md` and use GitHub's private vulnerability-reporting flow.
