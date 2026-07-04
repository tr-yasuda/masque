# Contributing

Contributions are welcome. This project is a learning and verification space
for MASQUE protocols, so thoughtful incremental changes are preferred over
large refactors.

## Getting started

1. Install a recent stable Rust toolchain (Rust 1.85 or later for the 2024
   edition).
2. Clone the repository.
3. Run the development checks:

   ```bash
   cargo xtask ci
   ```

## Coding conventions

- Format code with `rustfmt` using `cargo fmt --all`.
- Keep `cargo clippy --workspace --all-targets -- -D warnings` clean.
- Add or update tests for new behavior.
- Write clear commit messages and keep changes focused.
- Match the style of the surrounding code.

## Proposing changes

1. Open an issue to discuss significant features or design changes before
   investing heavily in implementation.
2. Make focused, well-explained pull requests.
3. Ensure CI passes before requesting review.

## License

By contributing, you agree that your contributions will be licensed under the
MIT license.
