#!/bin/bash

set -e

echo "=== Testing manage command with debug ==="

# Kill any existing daemon
pkill -f "rssh-agent daemon" 2>/dev/null || true
sleep 1

TEMP_DIR="/tmp/rssh-manage-test-$$"
SOCKET="$TEMP_DIR/test.sock"
LOG_FILE="$TEMP_DIR/daemon.log"

mkdir -p "$TEMP_DIR"

# Start daemon with debug logging
echo "Starting daemon with debug logging..."
RUST_LOG=debug ./target/debug/rssh-agent daemon --socket "$SOCKET" --foreground > "$LOG_FILE" 2>&1 &
DAEMON_PID=$!

# Wait for daemon to start
sleep 2

# Set the socket environment
export SSH_AUTH_SOCK="$SOCKET"

echo "Running manage command..."
timeout 2 ./target/debug/rssh-agent manage 2>&1 || true

echo ""
echo "=== Checking daemon logs ==="
echo "Extension-related entries:"
grep -E "extension|Extension|CBOR|manage" "$LOG_FILE" | tail -10 || echo "No extension entries found"

echo ""
echo "Errors in log:"
grep -E "ERROR|WARN|Failed" "$LOG_FILE" | tail -5 || echo "No errors found"

# Clean up
kill $DAEMON_PID 2>/dev/null || true
rm -rf "$TEMP_DIR"

echo ""
echo "=== Test completed ==="
