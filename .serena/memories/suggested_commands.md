# Suggested Commands for rssh-agent Development

## Build Commands
```bash
# Build all workspace crates
cargo build

# Build in release mode with optimizations
cargo build --release

# Build specific crate
cargo build -p rssh-daemon
```

## Testing Commands
```bash
# Run all tests
cargo test

# Run tests for specific crate
cargo test -p rssh-core

# Run tests with output
cargo test -- --nocapture

# Run integration tests only
cargo test --test '*'
```

## Code Quality Commands
```bash
# Format all code
cargo fmt

# Check formatting without applying changes
cargo fmt -- --check

# Run clippy linter
cargo clippy -- -D warnings

# Run clippy on all targets including tests
cargo clippy --all-targets -- -D warnings
```

## Running the Agent
```bash
# Build and run the CLI
cargo run --bin rssh-agent -- --help

# Run daemon in foreground mode
cargo run --bin rssh-agent -- daemon --foreground

# Initialize agent configuration
cargo run --bin rssh-agent -- init --dir ~/.rssh-agent
```

## Documentation
```bash
# Generate and open documentation
cargo doc --open

# Generate docs for all dependencies
cargo doc --all
```

## Dependency Management
```bash
# Check for outdated dependencies
cargo outdated

# Update dependencies
cargo update

# Audit for security vulnerabilities
cargo audit
```

## System Commands (Linux)
```bash
# List files
ls -la

# Find files
find . -name "*.rs"

# Search in files
grep -r "pattern" .

# Git status
git status

# Git diff
git diff

# Check running processes
ps aux | grep rssh

# Check open sockets
ss -lnp | grep rssh
```