#!/bin/bash

# Minimal debug test for systemd socket activation issue
set -e

echo "=== Minimal Systemd Socket Activation Debug ==="

# Clean up
systemctl --user stop rssh-agent.service 2>/dev/null || true
systemctl --user stop rssh-agent.socket 2>/dev/null || true
pkill -f rssh-agent || true
sleep 2

# Start socket
echo "Starting systemd socket..."
systemctl --user start rssh-agent.socket

# Check if socket exists
SOCKET_PATH="/run/user/$(id -u)/rssh-agent.socket"
if [ -S "$SOCKET_PATH" ]; then
    echo "✓ Socket exists: $SOCKET_PATH"
else
    echo "✗ Socket doesn't exist"
    exit 1
fi

echo "Testing with ssh-add (should activate daemon)..."
start_time=$(date +%s)

# Try using ssh-add instead of nc for a more realistic test
if timeout 10s env SSH_AUTH_SOCK="$SOCKET_PATH" ssh-add -L 2>&1; then
    end_time=$(date +%s)
    duration=$((end_time - start_time))
    echo "✓ ssh-add responded in ${duration}s"
else
    exit_code=$?
    end_time=$(date +%s)
    duration=$((end_time - start_time))
    echo "⚠ ssh-add exit code: $exit_code, duration: ${duration}s"

    if [ $duration -gt 5 ]; then
        echo "✗ TIMEOUT: This confirms the socket activation bug!"
    else
        echo "✓ Quick response (exit code is expected for no keys)"
    fi
fi

echo "Checking service status..."
if systemctl --user is-active rssh-agent.service >/dev/null 2>&1; then
    echo "✓ Service is running"

    # Try one more test now that service is active
    echo "Testing again with active service..."
    start_time=$(date +%s)
    if timeout 3s env SSH_AUTH_SOCK="$SOCKET_PATH" ssh-add -L 2>&1 >/dev/null; then
        end_time=$(date +%s)
        duration=$((end_time - start_time))
        echo "✓ Second test responded in ${duration}s"
    else
        end_time=$(date +%s)
        duration=$((end_time - start_time))
        echo "⚠ Second test took ${duration}s"
    fi
else
    echo "✗ Service not running"
fi

# Show logs
echo "Recent service logs:"
journalctl --user -u rssh-agent.service --no-pager -n 10

# Cleanup
systemctl --user stop rssh-agent.service 2>/dev/null || true
systemctl --user stop rssh-agent.socket 2>/dev/null || true

echo "Debug complete."