# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

rssh-agent is a secure SSH agent daemon for Linux that provides drop-in compatibility with OpenSSH while adding enhanced security features including encrypted key storage, a management TUI, and hardened memory management.

**Key Technologies:**
- Rust 2024 (MSRV 1.89) with Cargo workspace (5 crates)
- Tokio async runtime for daemon and socket handling
- Cryptography: Argon2id KDF + XChaCha20-Poly1305 AEAD
- SSH protocol via ssh-key crate, custom CBOR extensions
- ratatui + crossterm for terminal UI

## Development Commands

### Building & Testing
```bash
# Build everything (including TUI by default)
cargo build

# Build release version
cargo build --release

# Build without TUI feature
cargo build --no-default-features

# Run all tests
cargo test

# Run integration test script
./test-full.sh

# Format and lint (required before commits)
cargo fmt
cargo clippy -- -D warnings
```

### Running the Agent
```bash
# Initialize agent (creates config with master password)
cargo run -- init --dir ~/.ssh/rssh-agent

# Start daemon in foreground (for debugging)
cargo run -- daemon --foreground

# Start daemon normally (backgrounds, prints SSH_AUTH_SOCK)
eval "$(cargo run -- daemon)"

# Open management TUI
cargo run -- manage
```

## Architecture Overview

### Crate Structure
```
crates/
├── rssh-core/     # Crypto, storage, RAM key manager, constraints
├── rssh-proto/    # SSH wire protocol + CBOR extensions
├── rssh-daemon/   # Socket server, IPC, signal handling
├── rssh-cli/      # CLI binary with subcommands
└── rssh-tui/      # Management terminal interface
```

**Key Dependencies:**
- `tokio`: Async runtime, socket handling
- `ssh-key`: OpenSSH key format parsing/serialization
- `argon2`: Master password KDF
- `chacha20poly1305`: AEAD for encrypted storage
- `ratatui`/`crossterm`: Terminal UI
- `clap`: CLI parsing
- `ciborium`: CBOR for custom protocol extensions

### Security Model

**Master Password:** Required for all operations. Set via `rssh-agent init`. Uses Argon2id KDF with 256 MiB memory, stored as encrypted sentinel in config.json.

**Key Storage:**
- **Disk:** Keys encrypted under master password in `sha256-<hex>.json` files
- **RAM:** Keys stay AEAD-encrypted under ephemeral MemKey (derived from master + random salt)
- **Runtime:** Private keys only decrypted temporarily during signing, then zeroized

**Daemon Security:**
- `mlockall()` prevents swapping
- Socket ACL: owner-only via `SO_PEERCRED`
- Signal handling for graceful shutdown with secret zeroization

### Protocol Support

**OpenSSH Messages:** Standard agent protocol (REQUEST_IDENTITIES, SIGN_REQUEST, ADD_IDENTITY, etc.)

**Custom Extensions:** CBOR-encoded `rssh-agent@local` namespace for management operations:
- `manage.list` - List all keys with metadata
- `manage.load/unload` - RAM ↔ disk operations
- `manage.import` - Save external keys to disk
- `manage.create` - Generate new keys
- `control.shutdown` - Graceful daemon stop

**Key Types:** Ed25519 (preferred), RSA 2048-8192 bits. No ECDSA/FIDO in v0.1.0.

## Implementation Guidelines

### Error Handling
- Use custom error types in rssh-core with structured error codes
- Extension protocol always returns protocol SUCCESS with CBOR payload containing `{"ok": bool, "error": {...}}`
- Standard SSH agent messages return proper SSH_AGENT_FAILURE codes

### Memory Management
- All secrets implement `zeroize` trait
- Use secure random generation for salts/nonces
- MemKey zeroization on lock/shutdown critical for security

### File Operations
- Atomic writes: tmp → fsync → rename → fsync(dir)
- Strict permissions: directories 0700, files 0600
- No symlinks/hardlinks allowed

### Threading & Async
- Daemon uses Tokio with Unix domain socket listener
- Per-key signing serialization (max 1 concurrent sign per key)
- Extension operations through async channels to daemon core

## Testing Strategy

**Unit Tests:** Each crate has comprehensive tests for core functionality
**Integration Tests:** `test-full.sh` script tests daemon lifecycle with real ssh-add/ssh clients
**Security Tests:** Verify file permissions, socket ACLs, memory zeroization

When modifying code:
1. `cargo fmt` - required formatting
2. `cargo clippy -- -D warnings` - catch issues
3. `cargo test` - unit tests must pass
4. `./test-full.sh` - integration tests for daemon changes

## Key Files

- `Cargo.toml` - Workspace configuration, feature flags (tui enabled by default)
- `test-full.sh` - Integration test script
- `crates/rssh-*/src/lib.rs` - Crate entry points with public APIs
- `crates/rssh-daemon/src/agent.rs` - Core daemon agent implementation
- `crates/rssh-core/src/keyfile.rs` - Encrypted key storage format
- `crates/rssh-proto/src/wire.rs` - SSH protocol message handling

## Development Notes

- **Never log secrets:** Log fingerprints, error codes, paths only
- **UTF-8 validation:** All user input (descriptions, passwords) must be validated
- **Constraint handling:** confirm/lifetime stored in RAM only, survive lock/unlock
- **Certificate support:** Auto-import attached certs, validate against public key
- **Shell integration:** Daemon outputs only SSH_AUTH_SOCK (no SSH_AGENT_PID)

This codebase prioritizes security and OpenSSH compatibility. When making changes, always consider the security implications and test with real SSH clients.

## AI Team Configuration (autogenerated by team-configurator, 2025-09-13)

**Important: YOU MUST USE subagents when available for the task.**

### Detected Tech Stack
- **Language**: Rust 2024 (MSRV 1.89), Cargo workspace with 5 crates
- **Async Runtime**: Tokio 1.40+ with Unix domain sockets and signal handling
- **Cryptography**: Argon2id KDF, XChaCha20-Poly1305 AEAD, ssh-key crate, zeroize
- **TUI Framework**: ratatui 0.28+ with crossterm 0.28+ for terminal UI
- **CLI Framework**: Clap 4.5+ with derive and env features
- **Serialization**: CBOR via ciborium, JSON via serde_json
- **System Integration**: nix crate for Unix system calls, libc bindings
- **Security Focus**: Memory-safe daemon with encrypted key storage, hardened against attacks

### Team Assignment

| Task | Agent | Notes |
|------|-------|-------|
| **Rust Backend Development** | `rust-backend-expert` | Primary agent for async daemon, socket handling, crypto operations |
| **Terminal UI Development** | `rust-tui-developer` | Specialized for ratatui-based management interface improvements |
| **Code Review & Security** | `code-reviewer` | MANDATORY before merges. Focus on crypto implementations and memory safety |
| **Performance Optimization** | `performance-optimizer` | Critical for daemon efficiency, crypto speed, and memory usage |
| **Documentation & Specs** | `documentation-specialist` | Technical specs, user guides, and API documentation |
| **Codebase Analysis** | `code-archaeologist` | Deep analysis for refactoring, architecture decisions, technical debt |

### Specialist Recommendations

**For Rust-Specific Development:**
- Use `rust-backend-expert` for daemon core, async operations, cryptographic implementations, and protocol handling
- Use `rust-tui-developer` for all terminal UI improvements, event handling, and user experience enhancements
- Always involve `code-reviewer` for any cryptographic or security-critical changes due to sensitive nature of SSH key handling
- Use `performance-optimizer` for crypto performance, memory management, and daemon efficiency optimizations

**Task Examples:**
- New SSH protocol features → `@rust-backend-expert`
- Management TUI improvements → `@rust-tui-developer`
- Crypto implementation review → `@code-reviewer`
- Daemon performance issues → `@performance-optimizer`
- User documentation → `@documentation-specialist`
- Architecture analysis → `@code-archaeologist`

Try: `@rust-backend-expert implement key generation with Ed25519 support`
