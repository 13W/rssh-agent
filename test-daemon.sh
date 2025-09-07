#!/bin/bash

# Start the daemon in background and capture the socket
echo "Starting rssh-agent daemon..."
unset SSH_AUTH_SOCK
output=$(cargo run --bin rssh-agent -- daemon --dir ~/.rssh-agent 2>&1)
eval "$output"

echo "Socket created at: $SSH_AUTH_SOCK"

# Test listing identities
echo "Testing ssh-add -l (list identities)..."
ssh-add -l

# Generate a test key if it doesn't exist
if [ ! -f ~/.ssh/test_ed25519 ]; then
    echo "Generating test ED25519 key..."
    ssh-keygen -t ed25519 -f ~/.ssh/test_ed25519 -N "" -C "test@rssh-agent"
fi

# Try to add the key
echo "Adding test key to agent..."
ssh-add ~/.ssh/test_ed25519

# List identities again
echo "Listing identities after adding key..."
ssh-add -l

# Test signing (this will use the agent to sign data)
echo "Testing signature operation..."
echo "test data" | ssh-keygen -Y sign -f ~/.ssh/test_ed25519 -n test

echo "Test completed!"
