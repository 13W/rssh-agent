# rssh-agent Project Overview

## Purpose
rssh-agent is a secure SSH agent daemon for Linux that provides drop-in compatibility with OpenSSH agent protocol while adding enhanced security features:
- Encrypted key storage with master password protection
- Management TUI for administrative tasks
- AEAD encryption for keys in RAM
- Strict file permissions and socket ACLs

## Tech Stack
- **Language**: Rust 2024 edition (MSRV 1.89)
- **Platform**: Linux (Ubuntu ≥ 22.04, Debian 12+)
- **Target architectures**: x86_64, aarch64 (gnu + optional musl)
- **License**: Dual MIT/Apache-2.0

## Key Dependencies
- **tokio**: Async runtime with full features
- **ssh-key**: SSH key parsing and serialization
- **argon2**: Password hashing for master password
- **chacha20poly1305**: AEAD encryption for key storage
- **ratatui + crossterm**: Terminal UI
- **clap**: Command-line argument parsing
- **tracing**: Structured logging
- **nix**: Unix system calls and signal handling
- **serde**: Serialization/deserialization

## Project Structure
```
rssh-agent/
├── crates/
│   ├── rssh-core/     # Core types, errors, crypto primitives
│   ├── rssh-proto/    # SSH protocol implementation
│   ├── rssh-daemon/   # Agent daemon and socket server
│   ├── rssh-cli/      # CLI entry point (bin: rssh-agent)
│   └── rssh-tui/      # Terminal UI for management
├── spec.md            # Technical specification (normative)
├── checklist.md       # Implementation TODO list
└── Cargo.toml         # Workspace configuration
```

## Supported Features (v0.1.0)
- Ed25519 and RSA (2048-8192 bits) key types
- OpenSSH agent protocol messages (11, 13, 17-19, 22-23, 25)
- Constraints: confirm and lifetime
- Master password with Argon2id KDF
- XChaCha20-Poly1305 encryption for stored keys
- Unix domain socket communication
- Daemon mode with signal handling