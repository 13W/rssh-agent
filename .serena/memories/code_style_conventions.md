# Code Style and Conventions

## Rust Edition and Version
- Rust 2024 edition
- MSRV (Minimum Supported Rust Version): 1.89
- Toolchain specified in `rust-toolchain.toml`

## Code Organization
- **Modular crate structure**: Separate crates for core, protocol, daemon, CLI, and TUI
- **Clear separation of concerns**: Each crate has a specific responsibility
- **Error handling**: Centralized error types in rssh-core using thiserror
- **Result type**: Use `anyhow::Result` for application-level errors

## Naming Conventions
- **Module names**: lowercase with underscores (e.g., `socket_server`)
- **Type names**: PascalCase (e.g., `DaemonConfig`, `ShellStyle`)
- **Function names**: snake_case (e.g., `run_daemon`, `check_socket_alive`)
- **Constants**: SCREAMING_SNAKE_CASE (e.g., `RUNNING`)
- **Enum variants**: PascalCase (e.g., `Bash`, `Fish`, `Zsh`)

## Security Practices
- **Zeroize sensitive data**: Use `zeroize` crate for clearing secrets from memory
- **Strict permissions**: Files 0600, directories 0700, owner-only access
- **No hardcoded secrets**: Never commit passwords, keys, or tokens
- **Input validation**: Validate all external input, especially from network
- **Atomic operations**: Use atomic writes for critical files

## Async/Await
- **Runtime**: tokio with full features
- **Error handling**: Propagate errors with `?` operator
- **Cancellation**: Use tokio::select! for graceful shutdown
- **Signal handling**: Proper signal handlers for SIGTERM, SIGINT, SIGHUP

## Testing
- **Unit tests**: In `#[cfg(test)]` modules within source files
- **Integration tests**: In `tests/` directory
- **Test utilities**: Use `tempfile` for temporary directories
- **Assertions**: Use `assert_cmd` and `predicates` for CLI testing

## Documentation
- **Module docs**: Document purpose and usage at module level
- **Function docs**: Use `///` doc comments for public functions
- **Examples**: Include usage examples in doc comments where helpful
- **Safety**: Document unsafe blocks with safety invariants

## Linting and Formatting
- **rustfmt**: Enforce consistent formatting (run `cargo fmt`)
- **clippy**: Enforce with `-D warnings` (no warnings allowed)
- **CI enforcement**: All PRs must pass fmt and clippy checks

## Dependencies
- **Minimal dependencies**: Only add what's necessary
- **Security updates**: Regular audits with `cargo audit`
- **Version pinning**: Use exact versions for critical security crates
- **Feature flags**: Enable only required features