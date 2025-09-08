#!/bin/bash

echo "=== Simple Manage Test ==="

# Kill any existing daemon
pkill -f "rssh-agent daemon" 2>/dev/null || true
sleep 1

SOCKET="/tmp/rssh-simple-test.sock"
LOG_FILE="/tmp/rssh-daemon-test.log"

# Start daemon
echo "Starting daemon..."
RUST_LOG=debug ./target/debug/rssh-agent daemon --socket "$SOCKET" --foreground > "$LOG_FILE" 2>&1 &
DAEMON_PID=$!

sleep 2

export SSH_AUTH_SOCK="$SOCKET"

# Test raw request
echo "Testing raw manage.list request..."
python3 test_manage_raw.py 2>&1 | tail -5

echo ""
echo "Checking daemon logs for errors..."
grep -E "ERROR|WARN|Failed to parse" "$LOG_FILE" | grep -v "Memory locking\|PR_SET_NO_NEW_PRIVS" | tail -3 || echo "No parsing errors"

# Clean up
kill $DAEMON_PID 2>/dev/null || true
rm -f "$SOCKET" "$LOG_FILE"

echo ""
echo "=== Test completed ==="
