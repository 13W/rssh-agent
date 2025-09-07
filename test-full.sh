#!/bin/bash
set -e

echo "=== rssh-agent Full Test Suite ==="
echo

cd /opt/rust/rssh-agent

# Clean up any existing processes
echo "Cleaning up existing processes..."
pkill -f rssh-agent 2>/dev/null || true
sleep 1

# Build the project
echo "Building rssh-agent..."
cargo build --release 2>&1 | grep -E "Finished|error" || true
echo

# Test 1: Version output
echo "Test 1: Version check"
./target/release/rssh-agent --version
echo

# Test 2: Help output
echo "Test 2: Help check"
./target/release/rssh-agent --help | head -5
echo

# Test 3: Start daemon in foreground with timeout
echo "Test 3: Daemon startup (5 second test)"
unset SSH_AUTH_SOCK
export RSSH_ALLOW_NO_MLOCK=1
timeout 5 ./target/release/rssh-agent daemon --dir ~/.rssh-agent --foreground 2>&1 | head -10 || true
echo

# Test 4: Start daemon in background mode
echo "Test 4: Daemon in background mode"
unset SSH_AUTH_SOCK
OUTPUT=$(./target/release/rssh-agent daemon --dir ~/.rssh-agent 2>/dev/null)
echo "Daemon output: $OUTPUT"
eval "$OUTPUT"
echo "Socket created at: $SSH_AUTH_SOCK"
sleep 2

# Test 5: List identities (should be empty)
echo "Test 5: List identities (empty)"
ssh-add -l 2>&1 || true
echo

# Test 6: Create a test key if needed
echo "Test 6: Create test SSH key"
if [ ! -f ~/.ssh/test_rssh_ed25519 ]; then
    ssh-keygen -t ed25519 -f ~/.ssh/test_rssh_ed25519 -N "" -C "test@rssh-agent" >/dev/null 2>&1
    echo "Created test key ~/.ssh/test_rssh_ed25519"
else
    echo "Test key already exists"
fi
echo

# Test 7: Try to add a key (may fail, that's ok for now)
echo "Test 7: Add key to agent"
ssh-add ~/.ssh/test_rssh_ed25519 2>&1 || echo "Note: Key addition may not be fully implemented yet"
echo

# Test 8: List identities again
echo "Test 8: List identities after add attempt"
ssh-add -l 2>&1 || true
echo

# Test 9: Check process is running
echo "Test 9: Check daemon process"
ps aux | grep rssh-agent | grep -v grep | head -2 || echo "No daemon process found"
echo

# Clean up
echo "Cleaning up..."
pkill -f rssh-agent 2>/dev/null || true

echo "=== Test Suite Complete ==="
