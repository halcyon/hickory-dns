# Conventions

## Formatting
- `cargo fmt` with `.rustfmt.toml` using `style_edition = "2024"`.
- Four-space indentation.

## Naming
- `snake_case` for modules, functions, variables, tests.
- `CamelCase` for types and traits.
- `SCREAMING_SNAKE_CASE` for constants.

## Lints
- Workspace lints in root `Cargo.toml` (`[workspace.lints.rust]`, `[workspace.lints.clippy]`).
- Clippy runs with `-D warnings` in CI.
- Notable allows: `bool_to_int_with_if`, `single_component_path_imports`, `upper_case_acronyms`.

## Documentation
- Document public APIs.
- `RUSTDOCFLAGS="-Dwarnings" cargo doc` enforces doc linting.

## Testing
- Unit tests inline in `#[cfg(test)]` modules.
- Integration tests in crate-level `tests/` or `tests/integration-tests`.
- Test files commonly use `_tests.rs` suffix.
- Add regression tests for bug fixes.

## Commits
- Short imperative subject, often scoped: `resolver: parse ...`, `tests: add ...`.
- Separate refactoring from behavior changes.
