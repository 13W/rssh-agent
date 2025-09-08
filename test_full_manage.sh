#!/bin/bash

set -e

echo "=== Full Manage Test ==="

# Kill any existing daemon
pkill -f "rssh-agent daemon" 2>/dev/null || true
sleep 1

# Build fresh
echo "Building..."
cargo build -q

TEMP_DIR="/tmp/rssh-full-test-$$"
SOCKET="$TEMP_DIR/test.sock"
CONFIG_DIR="$TEMP_DIR/config"

mkdir -p "$CONFIG_DIR"

# Initialize with master password
echo "Initializing agent..."
echo "test123" | ./target/debug/rssh-agent init --dir "$CONFIG_DIR" > /dev/null 2>&1

# Start daemon
echo "Starting daemon..."
./target/debug/rssh-agent daemon --socket "$SOCKET" --dir "$CONFIG_DIR" --foreground > /dev/null 2>&1 &
DAEMON_PID=$!

sleep 2

export SSH_AUTH_SOCK="$SOCKET"

# Try to unlock first
echo "Unlocking agent..."
echo "test123" | ssh-add -U 2>/dev/null || echo "Unlock not supported via ssh-add"

# Test raw request
echo ""
echo "Testing raw manage.list request..."
python3 test_manage_raw.py

echo ""
echo "Testing actual manage command..."
timeout 2 ./target/debug/rssh-agent manage 2>&1 || true

# Clean up
kill $DAEMON_PID 2>/dev/null || true
rm -rf "$TEMP_DIR"

echo ""
echo "=== Test completed ==="
