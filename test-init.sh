#!/bin/bash

# Test initialization script for rssh-agent
# This uses SSH_ASKPASS to provide the password non-interactively

cat > /tmp/test-askpass.sh << 'EOF'
#!/bin/bash
echo "testpassword123"
EOF

chmod +x /tmp/test-askpass.sh

export SSH_ASKPASS=/tmp/test-askpass.sh
export SSH_ASKPASS_REQUIRE=force
export DISPLAY=:0

# Initialize the agent
cargo run --bin rssh-agent -- init --dir ~/.rssh-agent

# Clean up
rm -f /tmp/test-askpass.sh
