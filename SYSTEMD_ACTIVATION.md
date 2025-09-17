# Systemd Socket Activation Support

This document describes the systemd socket activation support implemented for rssh-agent.

## Overview

rssh-agent now supports systemd socket activation, allowing the daemon to use a socket created and managed by systemd. This eliminates the "Socket already in use" error when systemd has already bound to the socket path.

## Implementation

### New Components

1. **`crates/rssh-daemon/src/systemd.rs`** - Systemd detection and socket activation module
2. **Modified `SocketServer`** - Enhanced to support both traditional and systemd-activated sockets
3. **Updated daemon logic** - Automatic detection and handling of systemd activation

### Key Features

- **Automatic Detection**: Detects systemd activation via `LISTEN_FDS` and `LISTEN_PID` environment variables
- **Socket Inheritance**: Takes over file descriptor 3 (SD_LISTEN_FDS_START) from systemd
- **Protocol Compliance**: Follows systemd socket activation protocol precisely
- **Backward Compatibility**: Existing non-systemd usage patterns continue to work unchanged
- **Clean Environment**: Properly cleans up systemd environment variables after use

### API Changes

#### SocketServer

- **New**: `SocketServer::from_listener(agent: Arc<Agent>)` - Creates server for pre-activated socket
- **New**: `run_with_listener(listener: UnixListener)` - Runs server with systemd socket
- **Modified**: `socket_path()` returns `Option<&Path>` instead of `&Path`
- **Enhanced**: `cleanup()` only cleans up path-based sockets (not systemd sockets)

#### Systemd Module

```rust
/// Check if running under systemd socket activation
pub fn is_systemd_activated() -> bool

/// Take systemd-activated socket (FD 3) and convert to UnixListener
pub fn take_systemd_socket() -> Result<UnixListener>
```

## Usage

### With systemd

The daemon automatically detects systemd activation and uses the provided socket:

```bash
# systemd manages the socket
systemctl start rssh-agent.socket
# Daemon started by systemd will use inherited socket
```

### Without systemd

Traditional usage continues to work unchanged:

```bash
# Manual daemon start
cargo run -- daemon --foreground
# Creates its own socket at specified or temporary path
```

### systemd Unit Files

Example `rssh-agent.socket`:
```ini
[Unit]
Description=rssh-agent socket

[Socket]
ListenStream=/run/user/%i/rssh-agent.sock
SocketMode=0600
SocketUser=%i

[Install]
WantedBy=sockets.target
```

Example `rssh-agent.service`:
```ini
[Unit]
Description=rssh SSH Agent
Requires=rssh-agent.socket

[Service]
Type=simple
ExecStart=/usr/bin/rssh-agent daemon --foreground
User=%i
Restart=on-failure

[Install]
WantedBy=default.target
```

## Implementation Details

### Detection Logic

1. Check `LISTEN_FDS` environment variable equals "1"
2. Check `LISTEN_PID` matches current process ID
3. If both match, systemd activation is confirmed

### Socket Handling

1. Inherit file descriptor 3 (systemd convention)
2. Convert to `std::os::unix::net::UnixListener`
3. Wrap as `tokio::net::UnixListener`
4. Use with existing server logic

### Environment Cleanup

Per systemd protocol, `LISTEN_FDS` and `LISTEN_PID` are removed after successful activation.

### Output Behavior

- **Normal mode**: Prints `SSH_AUTH_SOCK` export statements
- **systemd mode**: Suppresses output (systemd manages socket path)

## Security

- Maintains all existing security features (peer credential checking, etc.)
- Uses safe Rust patterns with explicit unsafe blocks only where required
- Validates systemd environment before trusting file descriptors

## Testing

Comprehensive test suite includes:
- Unit tests for systemd detection logic
- Integration tests for both activation modes
- Backward compatibility verification
- Error condition handling

Run tests with:
```bash
cargo test --package rssh-daemon
```

## Compatibility

- **Backward Compatible**: All existing usage patterns continue to work
- **Drop-in Replacement**: No configuration changes needed for non-systemd users
- **Protocol Compliant**: Follows OpenSSH agent protocol exactly as before