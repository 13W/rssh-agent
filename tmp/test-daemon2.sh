#!/bin/bash
# Test script for rssh-agent daemon with proper config

cd /opt/rust/rssh-agent
export HOME=$(pwd)/tmp

# Clean up any previous sockets
rm -f tmp/test.sock tmp/test2.sock

echo "Testing daemon with storage directory..."
# Start daemon with explicit storage dir
timeout 2 ./target/debug/rssh-agent daemon --foreground --socket tmp/test2.sock --dir tmp/.ssh/rssh-agent 2>&1 &
DAEMON_PID=$!

sleep 1

echo "Checking if socket was created..."
if [ -S tmp/test2.sock ]; then
    echo "✓ Socket created at tmp/test2.sock"
    ls -l tmp/test2.sock
else
    echo "✗ Socket not created"
fi

# Check if daemon is running
if kill -0 $DAEMON_PID 2>/dev/null; then
    echo "✓ Daemon is running (PID $DAEMON_PID)"
else
    echo "✗ Daemon is not running"
fi

# Kill the daemon
kill $DAEMON_PID 2>/dev/null
wait $DAEMON_PID 2>/dev/null

echo "Daemon test completed"
