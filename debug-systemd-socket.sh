#!/bin/bash

# Debug script to test systemd socket activation step by step
set -e

echo "=== Debugging Systemd Socket Activation ==="

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Clean up any existing services
echo "Stopping any existing rssh-agent services..."
systemctl --user stop rssh-agent.service 2>/dev/null || true
systemctl --user stop rssh-agent.socket 2>/dev/null || true
pkill -f rssh-agent || true
sleep 1

# Setup test directory
TEST_DIR="/tmp/rssh-agent-debug-test"
rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR"

echo "Initializing agent with test configuration..."
cargo run --release -p rssh-cli --bin rssh-agent -- init --dir "$TEST_DIR" <<< "test_master_password_12345"

echo "Starting systemd socket..."
systemctl --user start rssh-agent.socket

echo "Checking socket file descriptor state..."
SOCKET_PATH="/run/user/$(id -u)/rssh-agent.socket"

echo "Socket path: $SOCKET_PATH"
if [ -S "$SOCKET_PATH" ]; then
    echo -e "${GREEN}✓ Socket file exists${NC}"
    ls -la "$SOCKET_PATH"
else
    echo -e "${RED}✗ Socket file not found${NC}"
    exit 1
fi

echo "Testing direct socket communication with nc..."
start_time=$(date +%s)
echo -n "test" | timeout 5s nc -U "$SOCKET_PATH" &
NC_PID=$!

sleep 1
if kill -0 "$NC_PID" 2>/dev/null; then
    echo -e "${YELLOW}⚠ nc is still running (socket not responding)${NC}"
    kill "$NC_PID" 2>/dev/null || true
    wait "$NC_PID" 2>/dev/null || true

    echo "This confirms the socket activation bug!"
    echo "The socket exists but doesn't activate the service properly."

    # Try to manually start the service
    echo "Manually starting service..."
    systemctl --user start rssh-agent.service &
    SERVICE_PID=$!

    sleep 3

    echo "Testing again after manual service start..."
    start_time=$(date +%s)
    if echo -n "test" | timeout 2s nc -U "$SOCKET_PATH"; then
        end_time=$(date +%s)
        duration=$((end_time - start_time))
        echo -e "${GREEN}✓ Socket responds in ${duration}s after manual service start${NC}"
    else
        echo -e "${RED}✗ Socket still not responding${NC}"
    fi

    wait "$SERVICE_PID" 2>/dev/null || true
else
    end_time=$(date +%s)
    duration=$((end_time - start_time))
    echo -e "${GREEN}✓ Socket responded immediately in ${duration}s${NC}"
fi

echo "Checking systemd status..."
systemctl --user status rssh-agent.socket || true
systemctl --user status rssh-agent.service || true

# Cleanup
echo "Cleaning up..."
systemctl --user stop rssh-agent.service 2>/dev/null || true
systemctl --user stop rssh-agent.socket 2>/dev/null || true
rm -rf "$TEST_DIR"

echo "Debug test complete."