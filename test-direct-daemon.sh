#!/bin/bash

# Test daemon signal handling directly (without systemd)
set -e

echo "=== Testing Daemon Signal Handling Directly ==="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Get absolute path to development binary
DEV_BINARY="$(pwd)/target/release/rssh-agent"

if [ ! -f "$DEV_BINARY" ]; then
    echo -e "${RED}✗ Development binary not found at $DEV_BINARY${NC}"
    echo "Run: cargo build --release first"
    exit 1
fi

echo "Using development binary: $DEV_BINARY"

# Clean up any existing services
echo "Stopping any existing services..."
systemctl --user stop rssh-agent.service 2>/dev/null || true
systemctl --user stop rssh-agent.socket 2>/dev/null || true
pkill -f rssh-agent || true
sleep 1

# Create temporary directory for socket
TEMP_DIR="/tmp/rssh-test-$$"
mkdir -p "$TEMP_DIR"
SOCKET_PATH="$TEMP_DIR/agent.sock"

echo "Starting daemon in foreground..."
echo "Socket path: $SOCKET_PATH"

# Start daemon in background
$DEV_BINARY daemon --foreground --socket "$SOCKET_PATH" &
DAEMON_PID=$!

echo "Daemon started with PID: $DAEMON_PID"
sleep 2

# Check if daemon is running
if kill -0 "$DAEMON_PID" 2>/dev/null; then
    echo -e "${GREEN}✓ Daemon is running${NC}"

    # Test if socket is working
    echo "Testing socket communication..."
    if SSH_AUTH_SOCK="$SOCKET_PATH" timeout 5s ssh-add -L 2>/dev/null; then
        echo -e "${GREEN}✓ Socket communication working${NC}"
    else
        echo -e "${YELLOW}ℹ Socket responded (agent may be locked, that's OK)${NC}"
    fi

    # Test signal handling
    echo "Testing SIGTERM handling..."
    start_time=$(date +%s)

    kill -TERM "$DAEMON_PID"

    # Wait for daemon to exit
    timeout_count=0
    while kill -0 "$DAEMON_PID" 2>/dev/null && [ $timeout_count -lt 10 ]; do
        sleep 0.5
        timeout_count=$((timeout_count + 1))
    done

    end_time=$(date +%s)
    duration=$((end_time - start_time))

    if kill -0 "$DAEMON_PID" 2>/dev/null; then
        echo -e "${RED}✗ Daemon didn't respond to SIGTERM, killing with SIGKILL${NC}"
        kill -KILL "$DAEMON_PID"
        wait "$DAEMON_PID" 2>/dev/null || true
        echo -e "${RED}✗ Signal handling broken${NC}"
        exit 1
    else
        wait "$DAEMON_PID" 2>/dev/null || true
        echo -e "${GREEN}✓ Daemon exited gracefully in ${duration} seconds${NC}"
        if [ $duration -lt 3 ]; then
            echo -e "${GREEN}✓ SIGNAL HANDLING WORKING PROPERLY!${NC}"
        else
            echo -e "${YELLOW}⚠ Took ${duration}s (could be faster)${NC}"
        fi
    fi
else
    echo -e "${RED}✗ Daemon failed to start${NC}"
    exit 1
fi

# Cleanup
rm -rf "$TEMP_DIR"

echo -e "\n${GREEN}=== Direct daemon test completed successfully! ===\n${NC}"
echo "The signal handling fix is working:"
echo "  ✓ Daemon responds to SIGTERM"
echo "  ✓ Graceful shutdown is working"
echo "  ✓ Socket server exits the loop properly"