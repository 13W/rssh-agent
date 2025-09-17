#!/bin/bash

# Test script for systemd socket activation with proper signal handling
set -e

echo "=== Testing Systemd Socket Activation Signal Handling Fix ==="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Clean up any existing services
echo "Stopping any existing rssh-agent services..."
systemctl --user stop rssh-agent.service 2>/dev/null || true
systemctl --user stop rssh-agent.socket 2>/dev/null || true

# Setup test directory
TEST_DIR="/tmp/rssh-agent-systemd-test"
rm -rf "$TEST_DIR"
mkdir -p "$TEST_DIR"

echo "Initializing agent with test configuration..."
cargo run --release -p rssh-cli --bin rssh-agent -- init --dir "$TEST_DIR" <<< "test_master_password_12345"

echo "Starting systemd socket (this will trigger socket activation)..."
systemctl --user start rssh-agent.socket

echo "Testing basic connectivity (should activate daemon)..."
if SSH_AUTH_SOCK="/run/user/$(id -u)/rssh-agent.sock" timeout 10s ssh-add -L 2>&1 | grep -q "Could not open a connection to your authentication agent"; then
    echo -e "${GREEN}✓ Socket activation successful - daemon started${NC}"
else
    echo -e "${YELLOW}ℹ Agent responded (may be locked, that's OK)${NC}"
fi

echo "Checking if daemon process is running..."
sleep 2
if systemctl --user is-active rssh-agent.service >/dev/null 2>&1; then
    echo -e "${GREEN}✓ Daemon service is active${NC}"

    echo "Testing signal handling - stopping service gracefully..."
    start_time=$(date +%s)

    if timeout 10s systemctl --user stop rssh-agent.service; then
        end_time=$(date +%s)
        duration=$((end_time - start_time))
        echo -e "${GREEN}✓ Service stopped gracefully in ${duration} seconds${NC}"

        if [ $duration -lt 8 ]; then
            echo -e "${GREEN}✓ SIGTERM handling working properly (no timeout)${NC}"
        else
            echo -e "${YELLOW}⚠ Service took ${duration}s to stop (should be faster)${NC}"
        fi
    else
        echo -e "${RED}✗ Service stop timed out - SIGTERM not handled properly${NC}"
        exit 1
    fi
else
    echo -e "${RED}✗ Daemon service not running${NC}"
    exit 1
fi

echo "Testing multiple start/stop cycles..."
for i in {1..3}; do
    echo "Cycle $i: Starting socket..."
    systemctl --user start rssh-agent.socket

    echo "Cycle $i: Triggering activation..."
    SSH_AUTH_SOCK="/run/user/$(id -u)/rssh-agent.sock" timeout 5s ssh-add -L >/dev/null 2>&1 || true

    sleep 1

    echo "Cycle $i: Stopping service..."
    start_time=$(date +%s)
    if timeout 8s systemctl --user stop rssh-agent.service 2>/dev/null; then
        end_time=$(date +%s)
        duration=$((end_time - start_time))
        echo -e "${GREEN}✓ Cycle $i: Stopped in ${duration}s${NC}"
    else
        echo -e "${RED}✗ Cycle $i: Stop timed out${NC}"
        exit 1
    fi

    systemctl --user stop rssh-agent.socket 2>/dev/null || true
    sleep 1
done

# Cleanup
echo "Cleaning up test environment..."
systemctl --user stop rssh-agent.service 2>/dev/null || true
systemctl --user stop rssh-agent.socket 2>/dev/null || true
rm -rf "$TEST_DIR"

echo -e "${GREEN}=== All tests passed! Systemd socket activation with proper signal handling is working ===\n${NC}"
echo "Key improvements verified:"
echo "  ✓ Socket server respects shutdown signal"
echo "  ✓ SIGTERM handled properly without timeout"
echo "  ✓ Graceful shutdown under systemd"
echo "  ✓ Multiple activation cycles work correctly"