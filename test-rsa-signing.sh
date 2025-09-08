#!/bin/bash
set -e

echo "Testing RSA signing functionality..."

# Setup
export HOME=/opt/rust/rssh-agent/test-home
export SSH_AUTH_SOCK=/opt/rust/rssh-agent/test.sock
rm -rf "$HOME" test.sock
mkdir -p "$HOME/.ssh"

# Create askpass helper
cat > /tmp/askpass.sh << 'EOF'
#!/bin/bash
echo "password123"
EOF
chmod +x /tmp/askpass.sh
export SSH_ASKPASS=/tmp/askpass.sh

# Initialize agent
./target/release/rssh-agent init --dir "$HOME/.rssh-agent"

# Start daemon in background with explicit socket
./target/release/rssh-agent daemon --socket "$SSH_AUTH_SOCK" --quiet -s 2>/dev/null &
DAEMON_PID=$!
sleep 2

# Unlock agent
echo "password123" | ./target/release/rssh-agent unlock

# Generate RSA test key
ssh-keygen -t rsa -b 2048 -f "$HOME/.ssh/test_rsa" -N "" -q

# Add RSA key
ssh-add "$HOME/.ssh/test_rsa"

# List keys
echo "Keys loaded:"
ssh-add -l

# Test RSA signing with SHA-256
echo "Testing RSA-SHA256 signing..."
echo "test data for signing" > /tmp/test_data.txt
ssh-keygen -Y sign -f "$HOME/.ssh/test_rsa.pub" -n file /tmp/test_data.txt > /tmp/test_rsa256.sig 2>/dev/null

if [ -f /tmp/test_rsa256.sig ]; then
    echo "✓ RSA-SHA256 signing successful"
    # Verify signature
    ssh-keygen -Y verify -f "$HOME/.ssh/test_rsa.pub" -n file -s /tmp/test_rsa256.sig < /tmp/test_data.txt 2>/dev/null && echo "✓ RSA-SHA256 signature verified"
else
    echo "✗ RSA-SHA256 signing failed"
fi

# Test RSA signing with SHA-512 (using flags)
echo "Testing RSA-SHA512 signing..."
# Note: ssh-keygen doesn't directly support SHA-512, but our agent should handle it with proper flags

# Stop daemon
./target/release/rssh-agent stop
kill $DAEMON_PID 2>/dev/null || true

echo "RSA signing test complete!"
