# rssh-agent Implementation Status

> Last updated: 2026-02-21. This document reflects the current state of the codebase.

## Completed Features

### Core Infrastructure

- Multi-crate Cargo workspace (`rssh-types`, `rssh-core`, `rssh-proto`, `rssh-daemon`, `rssh-cli`)
- Custom error types with structured error codes and exit code mapping
- Security hardening: `mlockall`, `PR_SET_DUMPABLE`, `RLIMIT_CORE` (with dev mode warnings)
- Atomic file writes with `fsync`, strict permission checks (0600/0700)

### Storage and Configuration

- `rssh-agent init`: creates storage directory, sets master password
- Config format: JSON with Argon2id KDF + XChaCha20-Poly1305 AEAD sentinel
- Key files: `sha256-<fingerprint>.json`, fingerprint embedded in encrypted payload and verified on read (prevents filename-based substitution attacks)
- Optional per-key password protection (stored as OpenSSH encrypted format)
- Default constraints per key: confirm, notification, lifetime

### SSH Agent Protocol

- Unix domain socket with `SO_PEERCRED` UID validation
- SSH agent length-prefixed framing, 1 MiB message limit
- `REQUEST_IDENTITIES` — lists loaded keys in insertion order
- `ADD_IDENTITY` — adds Ed25519 and RSA keys
- `ADD_ID_CONSTRAINED` — supports lifetime and confirm constraints
- `REMOVE_IDENTITY` — removes specific key
- `REMOVE_ALL_IDENTITIES` — clears all keys from RAM
- `LOCK` — zeroizes MemKey and master password from agent state
- `UNLOCK` — unlocks with master password
- `SIGN_REQUEST` — signs data with Ed25519 and RSA keys
- `session-bind@openssh.com` — parsed, returns failure (not yet implemented)

### Key Management (RAM Store)

- Keys kept AEAD-encrypted in RAM under ephemeral MemKey
- MemKey derived from master password + persistent salt (Argon2id, 256 MiB)
- Persistent salt across lock/unlock cycles ensures encrypted keys remain accessible after re-unlock
- Private keys decrypted transiently only for signing, then zeroized
- Anti-bruteforce: exponential backoff (1s base, 300s cap), 5-attempt lockout
- Per-key lifetime expiry with background cleanup task and clock-skew tolerance
- Per-key confirm and notification constraints
- External key tracking (added via `ssh-add`) vs managed keys
- Maximum 1024 loaded keys

### Lock Security

- `handle_lock()` (SSH LOCK message): zeroizes MemKey + master password
- `lock_directly()` (SIGHUP signal): zeroizes MemKey + master password
- Both paths use the same code path to ensure consistent behavior

### Daemon Operations

- Fork to background, print `SSH_AUTH_SOCK` environment export
- Shell auto-detection (sh/csh/fish) for environment export format
- Signal handling: SIGTERM/SIGINT for graceful shutdown with secret zeroization, SIGHUP for lock
- Systemd socket activation

### Custom CBOR Extensions (`rssh-agent@local`)

- `manage.list` — list all keys with metadata
- `manage.load` / `manage.unload` — RAM key management
- `manage.import` — save an external key to disk
- `manage.create` — generate new Ed25519 or RSA key pair
- `manage.set_desc` — update key description
- `manage.change_pass` — change key password
- `manage.set_constraints` / `manage.set_default_constraints`
- `manage.update_cert` — attach/update SSH certificate
- `manage.delete` — delete key from disk
- `control.shutdown` — graceful daemon stop

### Management TUI (`rssh-agent manage`)

The TUI is implemented in `rssh-cli` (the separate `rssh-tui` crate was merged into `rssh-cli`).

- Master password prompt on startup
- Three-panel layout: key list, key details / help, status bar
- Key list with status icons (loaded/unloaded/external, password-protected, confirm, notification, expiry)
- Detail panel: description, password, confirmation, expiration — all editable via modals
- Delete confirmation modal
- Create key modal (Ed25519 or RSA with configurable key size)
- Import key modal (for external keys)
- Inline certificate paste mode
- Navigation: arrow keys, Tab/Shift-Tab to switch frames, `?` to toggle help/details
- `l` locks the agent (zeroizes MemKey and master password)

## Not Implemented (v0.1.0)

- ECDSA key support
- FIDO/WebAuthn (sk-*) key support
- PKCS#11 smartcard operations
- Confirm prompts via external ASKPASS binary (desktop notification via D-Bus is implemented)
- Man pages and shell completions
- `session-bind@openssh.com` full implementation

## Testing

- Unit tests in each crate covering core functionality
- Integration test scripts: `test-full.sh`, `test_constraints.sh`, `test_signals.sh`, `test_certificates.sh`
- Python extension helper: `test_extension_helper.py`
- Master runner: `test_all_integration.sh`

See `TESTING.md` for details.
