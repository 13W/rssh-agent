#!/bin/bash
# Full test script for rssh-agent

cd /opt/rust/rssh-agent
export HOME=$(pwd)/tmp
unset SSH_AUTH_SOCK  # Ensure no existing agent

echo "=== Starting daemon ==="
./target/debug/rssh-agent daemon --foreground --socket tmp/test.sock --dir tmp/.ssh/rssh-agent 2>&1 &
DAEMON_PID=$!
sleep 1

export SSH_AUTH_SOCK=$(pwd)/tmp/test.sock

echo "=== Testing ssh-add -l (list keys) ==="
ssh-add -l 2>&1

echo "=== Generating test key if needed ==="
if [ ! -f tmp/test_key ]; then
    ssh-keygen -t ed25519 -f tmp/test_key -N "" -q
    echo "Generated test key"
fi

echo "=== Testing unlock (should fail - locked by default) ==="
timeout 2 ssh-add tmp/test_key 2>&1 || echo "Expected failure - agent is locked"

echo "=== Unlocking agent ==="
# Create askpass script for unlock
cat > tmp/unlock_askpass.sh << 'EOF'
#!/bin/bash
echo "TestPassword123!"
EOF
chmod +x tmp/unlock_askpass.sh

export SSH_ASKPASS=$(pwd)/tmp/unlock_askpass.sh
export SSH_ASKPASS_REQUIRE=force
export DISPLAY=:0

./target/debug/rssh-agent unlock --socket tmp/test.sock 2>&1

echo "=== Testing ssh-add after unlock ==="
ssh-add tmp/test_key 2>&1

echo "=== Listing keys after add ==="
ssh-add -l 2>&1

echo "=== Testing lock ==="
./target/debug/rssh-agent lock --socket tmp/test.sock 2>&1

echo "=== Testing list after lock (should fail) ==="
ssh-add -l 2>&1 || echo "Expected failure - agent is locked"

echo "=== Stopping daemon ==="
./target/debug/rssh-agent stop --socket tmp/test.sock 2>&1 &
STOP_PID=$!

sleep 1
kill $DAEMON_PID 2>/dev/null
wait $DAEMON_PID 2>/dev/null
wait $STOP_PID 2>/dev/null

echo "=== Test completed ==="
