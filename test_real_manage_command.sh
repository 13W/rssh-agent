#!/bin/bash

echo "=== Testing Real Manage Command ==="

# Kill any existing daemon
pkill -f "rssh-agent daemon" 2>/dev/null || true
sleep 1

SOCKET="/tmp/rssh-final.sock"
LOG_FILE="/tmp/rssh-final.log"

# Start daemon
echo "Starting daemon..."
RUST_LOG=debug ./target/debug/rssh-agent daemon --socket "$SOCKET" --foreground > "$LOG_FILE" 2>&1 &
DAEMON_PID=$!

sleep 2

export SSH_AUTH_SOCK="$SOCKET"

# Test with Python first to see exact response
echo "Testing with Python client..."
python3 test_final_manage.py

echo ""
echo "Testing with real manage command (will timeout due to TUI)..."
timeout 1 ./target/debug/rssh-agent manage 2>&1 | head -5 || true

echo ""
echo "Checking daemon logs for errors..."
grep -E "Failed to parse|CBOR.*error|invalid type" "$LOG_FILE" | tail -3 || echo "✓ No parsing errors found"

echo ""
echo "Checking for successful extension handling..."
grep -E "Extension request raw data|extension|manage" "$LOG_FILE" | tail -3 || echo "No extension logs"

# Clean up
kill $DAEMON_PID 2>/dev/null || true
rm -f "$SOCKET" "$LOG_FILE"

echo ""
echo "=== Test Completed ==="
