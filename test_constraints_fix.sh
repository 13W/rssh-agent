#!/bin/bash
# Test script to verify default constraints display fix

set -e

# Create a temporary directory for testing
TEST_DIR=$(mktemp -d)
trap "rm -rf $TEST_DIR" EXIT

echo "Testing default constraints display fix..."
echo "Using test directory: $TEST_DIR"

# Initialize the agent with a test directory
echo "Initializing rssh-agent..."
echo -e "test123\ntest123" | cargo run --release -- init --dir "$TEST_DIR"

# Create a key with default constraints
echo "Creating a test key with default constraints..."
echo -e "test123\n1d\ny" | cargo run --release -- manage create-key ed25519 "Test Key With Defaults" --dir "$TEST_DIR"

# Start the daemon in background
echo "Starting daemon..."
export SSH_AUTH_SOCK="$TEST_DIR/rssh-agent.sock"
cargo run --release -- daemon --dir "$TEST_DIR" --foreground &
DAEMON_PID=$!
trap "kill $DAEMON_PID 2>/dev/null || true; rm -rf $TEST_DIR" EXIT

# Give daemon time to start
sleep 2

# Test the TUI display (capture output)
echo "Testing TUI display..."
timeout 5 cargo run --release -- manage --dir "$TEST_DIR" || true

# Check if daemon is still running
if kill -0 $DAEMON_PID 2>/dev/null; then
    echo "Daemon is running. Stopping..."
    kill $DAEMON_PID
    wait $DAEMON_PID 2>/dev/null || true
fi

echo "Test completed. Check TUI output above to verify default constraints are displayed in gray for unloaded keys."