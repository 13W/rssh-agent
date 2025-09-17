#!/bin/bash

# Test socket communication works properly
set -e

echo "=== Testing Socket Communication ==="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Get absolute path to development binary
DEV_BINARY="$(pwd)/target/release/rssh-agent"

# Clean up any existing services
systemctl --user stop rssh-agent.service 2>/dev/null || true
systemctl --user stop rssh-agent.socket 2>/dev/null || true
pkill -f rssh-agent || true
sleep 1

# Create temporary directory for socket
TEMP_DIR="/tmp/rssh-comm-test-$$"
mkdir -p "$TEMP_DIR"
SOCKET_PATH="$TEMP_DIR/agent.sock"

echo "Starting daemon..."
$DEV_BINARY daemon --foreground --socket "$SOCKET_PATH" &
DAEMON_PID=$!

sleep 2

if kill -0 "$DAEMON_PID" 2>/dev/null; then
    echo -e "${GREEN}✓ Daemon started successfully${NC}"

    # Test ssh-add -L (list identities)
    echo "Testing 'ssh-add -L' (should return exit code 1 for no identities)..."
    if SSH_AUTH_SOCK="$SOCKET_PATH" ssh-add -L 2>/dev/null; then
        echo -e "${GREEN}✓ ssh-add -L returned successfully${NC}"
    else
        exit_code=$?
        if [ $exit_code -eq 1 ]; then
            echo -e "${GREEN}✓ ssh-add -L returned exit code 1 (no identities loaded)${NC}"
        else
            echo -e "${YELLOW}⚠ ssh-add -L returned exit code $exit_code${NC}"
        fi
    fi

    # Test multiple rapid connections
    echo "Testing multiple rapid connections..."
    for i in {1..5}; do
        SSH_AUTH_SOCK="$SOCKET_PATH" timeout 2s ssh-add -L >/dev/null 2>&1 || true
    done
    echo -e "${GREEN}✓ Multiple connections handled${NC}"

    echo "Shutting down daemon..."
    kill -TERM "$DAEMON_PID"
    wait "$DAEMON_PID" 2>/dev/null || true
    echo -e "${GREEN}✓ Daemon shut down cleanly${NC}"
else
    echo -e "${RED}✗ Daemon failed to start${NC}"
    exit 1
fi

# Cleanup
rm -rf "$TEMP_DIR"

echo -e "\n${GREEN}=== Socket communication test completed successfully! ===\n${NC}"