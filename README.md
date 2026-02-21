# rssh-agent

A secure SSH agent daemon for Linux that provides drop-in OpenSSH compatibility with hardened security: encrypted key storage, a management TUI, and strict memory protection.

## Features

- Drop-in replacement for `ssh-agent` — works with `ssh`, `ssh-add`, `ssh-keygen`, and other standard tools
- Keys encrypted at rest on disk (Argon2id KDF + XChaCha20-Poly1305 AEAD) and in RAM under an ephemeral memory key
- Private keys decrypted only for the duration of a signing operation, then zeroized
- Master password zeroized from memory on lock (both via `l` in TUI and SIGHUP)
- Fingerprint stored inside the encrypted payload and verified on read (prevents filename-based bypass)
- Per-key constraints: confirm-before-use, desktop notification, and lifetime expiry
- Management TUI (`rssh-agent manage`) for all key operations
- Anti-bruteforce protection on unlock: exponential backoff, max 5 attempts
- `mlockall()` prevents sensitive memory from being swapped to disk
- Unix socket with `SO_PEERCRED` UID check — owner-only access
- Systemd socket activation supported

## Key Types

- Ed25519 (recommended)
- RSA 2048–8192 bits

ECDSA and FIDO/WebAuthn are not supported in v0.1.0.

## Installation

### From source

```bash
cargo build --release
# Binary at: target/release/rssh-agent
```

### Debian package

```bash
cargo deb-pkg
# .deb file built under target/debian/
```

## Quick Start

```bash
# 1. Initialize storage (creates config and encrypted key store)
rssh-agent init --dir ~/.ssh/rssh-agent

# 2. Start the daemon (outputs SSH_AUTH_SOCK export line)
eval "$(rssh-agent daemon)"

# 3. Add keys via standard ssh-add
ssh-add ~/.ssh/id_ed25519

# 4. Open the management TUI
rssh-agent manage

# 5. Lock the agent (zeroizes MemKey and master password)
rssh-agent lock

# 6. Stop the daemon
rssh-agent stop
```

## CLI Reference

| Command | Description |
|---------|-------------|
| `rssh-agent init [--dir PATH]` | Initialize a new key store with master password |
| `rssh-agent daemon [--foreground]` | Start the agent daemon |
| `rssh-agent manage` | Open the management TUI |
| `rssh-agent lock` | Lock the agent (zeroizes secrets in memory) |
| `rssh-agent unlock` | Unlock the agent with the master password |
| `rssh-agent stop` | Stop the daemon gracefully |

## Management TUI

Launch with `rssh-agent manage`. A master password prompt appears on startup.

### Layout

- Left panel: key list with status icons
- Right panel: key details or help (toggle with `?`)
- Bottom bar: status messages

### Key status icons

| Icon | Meaning |
|------|---------|
| `●` | Loaded in RAM |
| `○` | On disk only |
| `↗` | External (added via ssh-add) |
| Shield icon | Password-protected key |
| `⚠` | Confirm-before-use enabled |
| `✉` | Desktop notification enabled |
| `⏳` | Lifetime expiry active |

### Keyboard shortcuts

#### Navigation

| Key | Action |
|-----|--------|
| `↓` / `↑` | Move selection |
| `Tab` | Switch focus between key list and detail panel |
| `?` | Toggle help / key details in right panel |

#### Key management

| Key | Action |
|-----|--------|
| `L` | Load selected disk key into memory |
| `U` | Unload selected key from memory |
| `i` | Import selected external key to disk |
| `n` | Generate a new key |
| `d` / `Delete` | Delete key from disk (with confirmation modal) |

#### Key operations (detail panel)

| Key | Action |
|-----|--------|
| `e` | Edit description |
| `C` | Update certificate |
| `P` | Set password protection |
| `R` | Remove password protection |
| `Enter` | Edit selected field (Description / Password / Confirmation / Expiration) |

#### Agent control

| Key | Action |
|-----|--------|
| `r` / `F5` | Refresh key list |
| `l` | Lock agent (zeroizes MemKey and master password) |
| `q` | Quit |

## Security Model

### Master Password

Required for all operations. Set during `rssh-agent init`. Uses Argon2id (256 MiB, 3 iterations) to derive storage and memory keys.

### Key Storage on Disk

Each key is stored as `sha256-<fingerprint>.json`. The JSON envelope contains Argon2id KDF parameters plus an XChaCha20-Poly1305-encrypted payload. The payload includes `pub_key_fingerprint_sha256`, which is verified against the filename on every read to prevent substitution attacks.

### Keys in RAM

Keys are kept AEAD-encrypted under an ephemeral MemKey (derived from master password + random persistent salt). The private key bytes are decrypted transiently only when signing, then immediately zeroized.

### Lock Behavior

Both `handle_lock()` (SSH LOCK message) and `lock_directly()` (SIGHUP signal) zeroize:
1. The MemKey from the RAM store
2. The master password from agent state

After locking, the agent cannot sign or load keys until unlocked with the master password again.

### Daemon Hardening

- `mlockall(MCL_CURRENT | MCL_FUTURE)` — prevents swap
- `PR_SET_DUMPABLE 0` — disables core dumps
- `RLIMIT_CORE = 0` — belt-and-suspenders no-core-dump
- Socket permission: `0600`, owner-UID checked via `SO_PEERCRED` per connection
- SIGTERM / SIGINT — graceful shutdown with secret zeroization
- SIGHUP — lock agent (zeroizes MemKey + master password)

### Anti-Bruteforce

Unlock attempts track consecutive failures with exponential backoff (starting 1 s, capped at 300 s). After 5 failures the store is permanently locked until the daemon is restarted.

## Protocol

### Standard SSH Agent Protocol

All standard OpenSSH agent messages are supported: `REQUEST_IDENTITIES`, `SIGN_REQUEST`, `ADD_IDENTITY`, `ADD_ID_CONSTRAINED`, `REMOVE_IDENTITY`, `REMOVE_ALL_IDENTITIES`, `LOCK`, `UNLOCK`.

`session-bind@openssh.com` is recognized and parsed but returns failure — not yet implemented.

### Custom CBOR Extensions (`rssh-agent@local`)

| Operation | Description |
|-----------|-------------|
| `manage.list` | List all keys with metadata |
| `manage.load` | Load a disk key into RAM |
| `manage.unload` | Unload a RAM key |
| `manage.import` | Save an external key to disk |
| `manage.create` | Generate a new key pair |
| `manage.set_desc` | Update key description |
| `control.shutdown` | Graceful daemon stop |

## Architecture

### Crate Structure

```
crates/
├── rssh-types/    # Shared types (KeyType, ManagedKey, etc.)
├── rssh-core/     # Crypto, disk storage, RAM key manager, constraints
├── rssh-proto/    # SSH wire protocol + CBOR extension parsing
├── rssh-daemon/   # Socket server, signal handling, extension handlers
└── rssh-cli/      # CLI binary (subcommands + management TUI)
```

`rssh-tui` was merged into `rssh-cli`. There is no separate TUI crate.

## Development

### Build

```bash
cargo build                          # debug, with TUI (default)
cargo build --release
cargo build --no-default-features    # without TUI
```

### Test

```bash
cargo test                 # unit tests
./test-full.sh             # integration tests (requires built binary)
```

### Lint

```bash
cargo fmt
cargo clippy -- -D warnings
```

## License

MIT OR Apache-2.0
