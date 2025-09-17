# rssh-agent Debian Package and systemd Integration

This document provides complete instructions for building, installing, and using the rssh-agent Debian package with systemd integration.

## Package Overview

The rssh-agent Debian package provides:
- Drop-in replacement for OpenSSH ssh-agent with enhanced security
- systemd user service integration for automatic startup
- Per-user socket management following systemd best practices
- Helper scripts for easy setup and management
- Comprehensive security hardening

## Building the Package

### Prerequisites

Install build dependencies:
```bash
sudo apt-get update
sudo apt-get install debhelper dh-cargo cargo rustc build-essential pkg-config libc6-dev
```

### Build Process

1. **Clone or download the rssh-agent source code**
2. **Build the package:**
   ```bash
   cd rssh-agent/
   ./build-deb.sh
   ```

The built package will be created as `../rssh-agent_*.deb`.

## Installation

### System Installation
```bash
# Install the package
sudo dpkg -i rssh-agent_*.deb

# Fix any dependency issues
sudo apt-get install -f
```

### User Setup

After system installation, each user needs to initialize and enable rssh-agent:

```bash
# 1. Initialize rssh-agent with master password
rssh-setup init

# 2. Enable systemd user service (starts on login)
rssh-setup enable

# 3. Configure shell environment
rssh-setup setup-env

# 4. Restart shell or source config
source ~/.bashrc  # or ~/.zshrc for zsh users
```

## Usage

### Automatic Operation
Once enabled, rssh-agent:
- Starts automatically when you log in
- Creates socket at `$XDG_RUNTIME_DIR/rssh-agent.socket`
- Sets `SSH_AUTH_SOCK` environment variable for SSH clients
- Handles graceful shutdown on logout

### Manual Control
```bash
# Check status
rssh-setup status

# Manual service control
systemctl --user start rssh-agent.socket
systemctl --user stop rssh-agent.socket
systemctl --user restart rssh-agent.socket

# View logs
journalctl --user -u rssh-agent.service -f
```

### Key Management
```bash
# Import existing SSH keys
rssh-agent import ~/.ssh/id_rsa

# Open management TUI (if built with tui feature)
rssh-agent manage

# Standard ssh-add commands work as normal
ssh-add -l              # List keys
ssh-add ~/.ssh/id_rsa   # Add key
```

## Architecture Details

### systemd Integration

#### Service Units
- **rssh-agent.socket**: Socket activation unit
  - Creates Unix domain socket at `$XDG_RUNTIME_DIR/rssh-agent.socket`
  - Socket permissions: 0600 (user-only)
  - Enables on-demand service startup

- **rssh-agent.service**: Main daemon service
  - Runs `rssh-agent daemon --foreground --socket=<path>`
  - Comprehensive security hardening (NoNewPrivileges, ProtectSystem, etc.)
  - Automatic restart on failure

#### Environment Integration
- `/usr/lib/environment.d/rssh-agent.conf` sets `SSH_AUTH_SOCK` for user sessions
- Shell integration via `rssh-setup setup-env` command
- Compatible with bash, zsh, and fish shells

### Security Features

#### systemd Security Hardening
The service runs with extensive security restrictions:
- `NoNewPrivileges=true` - Prevents privilege escalation
- `ProtectSystem=strict` - Read-only system directories
- `ProtectHome=read-only` - Protected home directory access
- `PrivateTmp=true` - Private temporary directories
- `MemoryDenyWriteExecute=true` - W^X memory protection
- `SystemCallFilter=@system-service` - Restricted system calls

#### rssh-agent Security
- Master password protection with Argon2id KDF
- XChaCha20-Poly1305 AEAD encryption for stored keys
- Memory protection via mlockall()
- Secret zeroization on shutdown
- Unix socket with proper ownership and permissions

## Files Installed

### Binaries
- `/usr/bin/rssh-agent` - Main rssh-agent binary
- `/usr/bin/rssh-setup` - User setup and management script

### systemd Units
- `/usr/lib/systemd/user/rssh-agent.service` - Main service
- `/usr/lib/systemd/user/rssh-agent.socket` - Socket activation

### Configuration
- `/usr/lib/environment.d/rssh-agent.conf` - Environment setup

### Completions
- `/usr/share/bash-completion/completions/rssh-agent` - Bash completion

## Migration from Manual Installation

If you have an existing manual rssh-agent installation:

1. **Stop existing agent:**
   ```bash
   rssh-agent stop  # or kill existing process
   ```

2. **Install package:**
   ```bash
   sudo dpkg -i rssh-agent_*.deb
   ```

3. **Enable systemd service:**
   ```bash
   rssh-setup enable
   ```

4. **Update shell configuration:**
   ```bash
   rssh-setup setup-env
   ```

Your existing `~/.ssh/rssh-agent/` directory and keys will be preserved.

## Troubleshooting

### Service Issues
```bash
# Check service status
systemctl --user status rssh-agent.socket rssh-agent.service

# View logs
journalctl --user -u rssh-agent.service

# Reset service
systemctl --user stop rssh-agent.socket rssh-agent.service
systemctl --user disable rssh-agent.socket
rssh-setup enable
```

### Environment Issues
```bash
# Check SSH_AUTH_SOCK
echo $SSH_AUTH_SOCK
# Should be: /run/user/1000/rssh-agent.socket

# Fix shell configuration
rssh-setup setup-env
source ~/.bashrc
```

### Permission Issues
```bash
# Check socket permissions
ls -la $XDG_RUNTIME_DIR/rssh-agent.socket
# Should be: srw------- 1 user user

# Check agent directory
ls -la ~/.ssh/rssh-agent/
# Should be: drwx------ user user
```

### Conflicts with Other Agents
```bash
# Disable gnome-keyring SSH agent
systemctl --user mask gnome-keyring-ssh.service

# Disable gpg-agent SSH support
echo 'enable-ssh-support' >> ~/.gnupg/gpg-agent.conf
# Then comment out or remove the line and restart gpg-agent
```

## Uninstallation

### Remove Package
```bash
# Stop services for all users (done automatically by prerm script)
sudo apt-get remove rssh-agent

# Purge configuration (optional)
sudo apt-get purge rssh-agent
```

### Clean User Data
Each user should manually clean their data if desired:
```bash
# Remove user data
rm -rf ~/.ssh/rssh-agent/

# Remove user service overrides (if any)
rm -f ~/.config/systemd/user/rssh-agent.service
rm -f ~/.config/systemd/user/rssh-agent.socket
systemctl --user daemon-reload
```

## Advanced Configuration

### Custom Socket Path
While not recommended, users can customize the socket path:
```bash
# Copy service files to user directory
cp /usr/lib/systemd/user/rssh-agent.* ~/.config/systemd/user/

# Edit socket path in rssh-agent.socket
systemctl --user edit rssh-agent.socket

# Update SSH_AUTH_SOCK in shell
export SSH_AUTH_SOCK="/custom/path/to/socket"
```

### Logging Configuration
```bash
# Enable debug logging
systemctl --user edit rssh-agent.service
```
Add:
```ini
[Service]
Environment=RUST_LOG=debug
```

### Integration with Desktop Environments
The systemd user service integrates automatically with:
- GNOME (disable gnome-keyring SSH agent if conflicts occur)
- KDE Plasma
- XFCE
- Most window managers with systemd user sessions

## Development and Testing

### Test Suite
Run the packaging test suite:
```bash
./test-systemd-packaging.sh
```

This validates:
- Package structure and metadata
- systemd service file syntax
- Security configuration
- Helper script functionality
- File permissions

### Manual Testing
```bash
# Build and install in test environment
./build-deb.sh
sudo dpkg -i ../rssh-agent_*.deb

# Test user workflow
rssh-setup init
rssh-setup enable
rssh-setup status

# Test SSH functionality
ssh-add -l
ssh user@host  # Should use rssh-agent
```

## Support and Maintenance

### Log Analysis
```bash
# View service logs
journalctl --user -u rssh-agent.service

# View socket logs
journalctl --user -u rssh-agent.socket

# View system logs for package operations
journalctl -u systemd-logind
```

### Performance Monitoring
```bash
# Check service resource usage
systemctl --user status rssh-agent.service

# Monitor socket activity
sudo ss -x | grep rssh-agent
```

This comprehensive Debian packaging and systemd integration provides a robust, secure, and user-friendly SSH agent solution that follows Linux distribution best practices while maintaining full OpenSSH compatibility.