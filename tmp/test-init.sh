#!/bin/bash
# Test script for rssh-agent init with password

cd /opt/rust/rssh-agent
export HOME=$(pwd)/tmp

# Clean up any previous state
rm -rf tmp/.ssh/rssh-agent

# Create a simple askpass script
cat > tmp/askpass.sh << 'EOF'
#!/bin/bash
echo "TestPassword123!"
EOF
chmod +x tmp/askpass.sh

# Test init with askpass
export SSH_ASKPASS=$(pwd)/tmp/askpass.sh
export SSH_ASKPASS_REQUIRE=force
export DISPLAY=:0  # Fake display to trigger askpass

echo "Testing init with askpass..."
./target/debug/rssh-agent init --dir tmp/.ssh/rssh-agent

echo "Checking if config was created..."
if [ -f tmp/.ssh/rssh-agent/config.json ]; then
    echo "✓ Config file created"
    ls -la tmp/.ssh/rssh-agent/
else
    echo "✗ Config file not created"
    exit 1
fi
