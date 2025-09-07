#!/bin/bash
# Test script for rssh-agent daemon

cd /opt/rust/rssh-agent
export HOME=$(pwd)/tmp

echo "Starting daemon in foreground mode..."
timeout 2 ./target/debug/rssh-agent daemon --foreground --socket tmp/test.sock 2>&1 &
DAEMON_PID=$!

sleep 1

echo "Checking if socket was created..."
if [ -S tmp/test.sock ]; then
    echo "✓ Socket created"
else
    echo "✗ Socket not created"
    kill $DAEMON_PID 2>/dev/null
    exit 1
fi

echo "Testing connection to daemon..."
export SSH_AUTH_SOCK=$(pwd)/tmp/test.sock

# Test with ssh-add -l (list keys)
ssh-add -l 2>&1 | head -5

kill $DAEMON_PID 2>/dev/null
wait $DAEMON_PID 2>/dev/null

echo "Daemon test completed"
