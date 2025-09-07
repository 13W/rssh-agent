#!/bin/bash
# Test script for rssh-agent key storage

cd /opt/rust/rssh-agent
export HOME=$(pwd)/tmp
unset SSH_AUTH_SOCK  # Ensure no existing agent

echo "=== Starting daemon ==="
./target/debug/rssh-agent daemon --foreground --socket tmp/test.sock --dir tmp/.ssh/rssh-agent 2>&1 &
DAEMON_PID=$!
sleep 1

export SSH_AUTH_SOCK=$(pwd)/tmp/test.sock

echo "=== Testing ssh-add -l (should fail - locked) ==="
ssh-add -l 2>&1 || echo "Expected: agent is locked"

echo "=== Unlocking agent ==="
cat > tmp/unlock_askpass.sh << 'EOF'
#!/bin/bash
echo "TestPassword123!"
EOF
chmod +x tmp/unlock_askpass.sh

export SSH_ASKPASS=$(pwd)/tmp/unlock_askpass.sh
export SSH_ASKPASS_REQUIRE=force
export DISPLAY=:0

./target/debug/rssh-agent unlock --socket tmp/test.sock 2>&1

echo "=== Testing ssh-add -l (should be empty) ==="
ssh-add -l 2>&1

echo "=== Adding test key ==="
if [ ! -f tmp/test_key ]; then
    ssh-keygen -t ed25519 -f tmp/test_key -N "" -q
fi
ssh-add tmp/test_key 2>&1

echo "=== Listing keys after add ==="
ssh-add -l 2>&1

echo "=== Testing with second key ==="
if [ ! -f tmp/test_key2 ]; then
    ssh-keygen -t rsa -b 3072 -f tmp/test_key2 -N "" -q
fi
ssh-add tmp/test_key2 2>&1

echo "=== Listing both keys ==="
ssh-add -l 2>&1

echo "=== Removing all keys ==="
ssh-add -D 2>&1

echo "=== Listing after remove all ==="
ssh-add -l 2>&1

echo "=== Stopping daemon ==="
kill $DAEMON_PID 2>/dev/null
wait $DAEMON_PID 2>/dev/null

echo "=== Test completed ==="
