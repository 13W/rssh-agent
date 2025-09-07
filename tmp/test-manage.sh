#!/bin/bash
# Test manage TUI

cd /opt/rust/rssh-agent
export HOME=$(pwd)/tmp
unset SSH_AUTH_SOCK

echo "=== Starting daemon ==="
rm -f tmp/test.sock
./target/debug/rssh-agent daemon --foreground --socket tmp/test.sock --dir tmp/.ssh/rssh-agent 2>&1 &
DAEMON_PID=$!
sleep 1

export SSH_AUTH_SOCK=$(pwd)/tmp/test.sock
export SSH_ASKPASS=$(pwd)/tmp/unlock_askpass.sh
export SSH_ASKPASS_REQUIRE=force
export DISPLAY=:0

echo "=== Unlocking and adding keys ==="
./target/debug/rssh-agent unlock --socket tmp/test.sock
ssh-add tmp/test_key 2>&1
ssh-add tmp/test_key2 2>&1

echo "=== Current keys loaded ==="
ssh-add -l

echo "=== Testing manage command (will prompt for password) ==="
echo "Note: The TUI would open here in an interactive session"
echo "Since we're in a non-interactive environment, testing the command availability:"

# Test that the manage command exists and can be invoked
timeout 1 ./target/debug/rssh-agent manage --socket tmp/test.sock 2>&1 | head -10 || true

echo "=== Cleaning up ==="
kill $DAEMON_PID 2>/dev/null
wait $DAEMON_PID 2>/dev/null

echo "=== Test completed ==="
