# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

rssh-agent is a secure SSH agent daemon for Linux that provides drop-in compatibility with OpenSSH agent protocol while adding enhanced security features. It's written in Rust and targets Linux systems (Ubuntu ≥ 22.04, Debian 12+).

## Build and Development Commands

### Building
```bash
# Build all workspace crates
cargo build

# Build in release mode with optimizations
cargo build --release

# Build specific crate
cargo build -p rssh-daemon
```

### Testing
```bash
# Run all tests
cargo test

# Run tests for specific crate
cargo test -p rssh-core

# Run tests with output
cargo test -- --nocapture

# Run the full test suite script
./test-full.sh
```

### Code Quality
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

### Running the Agent
```bash
# Build and run the CLI
cargo run --bin rssh-agent -- --help

# Initialize agent configuration (required before first use)
cargo run --bin rssh-agent -- init --dir ~/.rssh-agent

# Run daemon in foreground mode
cargo run --bin rssh-agent -- daemon --foreground

# Run daemon in background mode
eval $(cargo run --bin rssh-agent -- daemon --dir ~/.rssh-agent)

# Launch management TUI
cargo run --bin rssh-agent -- manage

# Note: By default, memory locking failures are non-fatal (just warnings).
# Use --require-mlock flag to enforce strict memory locking:
cargo run --bin rssh-agent -- daemon --require-mlock
```

## Architecture

### Workspace Structure
The project uses a Rust workspace with 5 crates:

- **rssh-core**: Core types, errors, and crypto primitives
  - Defines common error types, key types, and cryptographic operations
  - Provides the foundation for other crates

- **rssh-proto**: SSH wire protocol implementation
  - Handles SSH agent protocol messages (OpenSSH compatible)
  - Implements message serialization/deserialization
  - Supports messages: 11, 13, 17-19, 22-23, 25

- **rssh-daemon**: Agent daemon and socket server
  - Implements the Unix domain socket server
  - Manages key storage in encrypted form
  - Handles agent protocol requests
  - Implements security hardening (mlockall, RLIMIT_CORE=0, etc.)

- **rssh-cli**: CLI entry point (binary: rssh-agent)
  - Main commands: init, daemon, lock, unlock, stop, manage
  - Handles command-line parsing with clap
  - Manages daemon lifecycle

- **rssh-tui**: Terminal UI for key management
  - Built with ratatui and crossterm
  - Provides administrative interface for key management
  - Always requires master password for access

### Security Architecture

1. **Master Password System**
   - Set once during `init`, stored as Argon2id hash
   - Required for all key operations
   - Derives separate keys for disk storage and RAM encryption

2. **Key Storage**
   - Keys stored encrypted on disk with XChaCha20-Poly1305
   - Keys in RAM are also encrypted (ephemeral-at-rest)
   - Private keys decrypted only during signing operations

3. **Process Hardening**
   - Memory locking (mlockall) prevents swapping
   - Core dumps disabled (RLIMIT_CORE=0)
   - Sensitive memory marked with MADV_DONTDUMP
   - All secrets implement zeroize for secure cleanup

### Key Flows

1. **Initialization**: `rssh-agent init` → sets master password → creates config
2. **Daemon Start**: Loads config, sets up socket, waits for connections
3. **Key Addition**: SSH client → agent protocol → decrypt with master → store encrypted
4. **Signing**: Decrypt key temporarily → sign → zeroize decrypted key
5. **Lock/Unlock**: Zeroize/re-derive memory encryption keys

## Important Implementation Details

- **Protocol Compatibility**: Implements core OpenSSH agent protocol, compatible with ssh-add and ssh
- **Supported Key Types**: Ed25519 and RSA (2048-8192 bits)
- **Constraints**: Supports confirm and lifetime constraints only
- **Platform**: Linux-only, requires Unix domain sockets
- **Dependencies**: Uses tokio for async, ssh-key for key handling, argon2 for KDF
- **Error Handling**: Comprehensive error types in rssh-core, propagated through Result types
- **Logging**: Structured logging with tracing, configurable via RUST_LOG

## Testing Approach

The codebase includes:
- Unit tests in each crate (run with `cargo test`)
- Integration test script (`test-full.sh`) that tests daemon lifecycle
- Test utilities in test directories for specific scenarios

When modifying code:
1. Run `cargo fmt` to ensure consistent formatting
2. Run `cargo clippy -- -D warnings` to catch common issues
3. Run `cargo test` to verify unit tests pass
4. Run `./test-full.sh` for integration testing if modifying daemon behavior