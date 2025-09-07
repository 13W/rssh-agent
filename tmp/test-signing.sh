#!/bin/bash
# Test signing functionality directly

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

echo "=== Unlocking and adding key ==="
./target/debug/rssh-agent unlock --socket tmp/test.sock
ssh-add tmp/test_key 2>&1

echo "=== Creating test data ==="
echo "Hello, World! This is test data for signing." > tmp/data_to_sign.txt

echo "=== Testing signature with ssh-keygen ==="
# ssh-keygen can use the agent to sign data
ssh-keygen -Y sign -f tmp/test_key.pub -n file tmp/data_to_sign.txt 2>&1 | head -20

echo "=== Checking if signature was created ==="
if [ -f tmp/data_to_sign.txt.sig ]; then
    echo "✓ Signature file created"
    echo "Signature content (first 5 lines):"
    head -5 tmp/data_to_sign.txt.sig
else
    echo "✗ No signature file found"
fi

echo "=== Testing actual SSH authentication challenge (simulated) ==="
# Try to connect via SSH to see if signing works
ssh -v -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=1 -o PasswordAuthentication=no localhost exit 2>&1 | grep -E "Offering|Authentications|debug1: identity|Trying private key"

echo "=== Cleaning up ==="
kill $DAEMON_PID 2>/dev/null
wait $DAEMON_PID 2>/dev/null
rm -f tmp/data_to_sign.txt.sig

echo "=== Test completed ==="
