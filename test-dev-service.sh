#!/bin/bash

# Test with development binary
set -e

echo "=== Testing Signal Handling with Development Binary ==="

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
echo "Stopping any existing rssh-agent services..."
systemctl --user stop rssh-agent.service 2>/dev/null || true
systemctl --user stop rssh-agent.socket 2>/dev/null || true

# Create temporary systemd service that uses our dev binary
TEMP_SERVICE_DIR="$HOME/.config/systemd/user"
mkdir -p "$TEMP_SERVICE_DIR"

# Create temporary service file
cat > "$TEMP_SERVICE_DIR/rssh-agent-dev.service" << EOF
[Unit]
Description=rssh-agent SSH authentication agent (development)
Requires=rssh-agent.socket
After=graphical-session.target

[Service]
Type=simple
Environment=SSH_AUTH_SOCK=%t/rssh-agent.socket
ExecStart=$DEV_BINARY daemon --socket=%t/rssh-agent.socket
Restart=on-failure
RestartSec=5
TimeoutStopSec=10

[Install]
WantedBy=default.target
Also=rssh-agent.socket
EOF

# Reload systemd and start our dev service with the existing socket
systemctl --user daemon-reload

echo "Starting socket..."
systemctl --user start rssh-agent.socket

# Start our development service
echo "Starting development service..."
systemctl --user start rssh-agent-dev.service

sleep 2

if systemctl --user is-active rssh-agent-dev.service >/dev/null 2>&1; then
    echo -e "${GREEN}✓ Development service is running${NC}"

    echo "Testing graceful shutdown..."
    start_time=$(date +%s)

    if timeout 8s systemctl --user stop rssh-agent-dev.service; then
        end_time=$(date +%s)
        duration=$((end_time - start_time))
        echo -e "${GREEN}✓ Service stopped in ${duration} seconds${NC}"

        if [ $duration -lt 5 ]; then
            echo -e "${GREEN}✓ SIGNAL HANDLING FIXED! No timeout!${NC}"
        else
            echo -e "${YELLOW}⚠ Service took ${duration}s (better but could be faster)${NC}"
        fi
    else
        echo -e "${RED}✗ Service stop timed out - fix didn't work${NC}"
        systemctl --user kill rssh-agent-dev.service 2>/dev/null || true
        exit 1
    fi

    # Check the logs for our new messages
    echo -e "\n${YELLOW}Recent logs:${NC}"
    journalctl --user -u rssh-agent-dev.service --since "30 seconds ago" --no-pager | tail -10
else
    echo -e "${RED}✗ Development service failed to start${NC}"
    journalctl --user -u rssh-agent-dev.service --since "30 seconds ago" --no-pager
    exit 1
fi

# Cleanup
echo -e "\nCleaning up..."
systemctl --user stop rssh-agent-dev.service 2>/dev/null || true
systemctl --user stop rssh-agent.socket 2>/dev/null || true
rm -f "$TEMP_SERVICE_DIR/rssh-agent-dev.service"
systemctl --user daemon-reload

echo -e "\n${GREEN}=== Test completed! ===\n${NC}"