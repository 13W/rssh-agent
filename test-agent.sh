#!/bin/bash
set -e

echo "Building rssh-agent..."
cd /opt/rust/rssh-agent
cargo build --release 2>&1 | grep -E "Finished|error" || true

echo "Starting daemon..."
unset SSH_AUTH_SOCK
export RSSH_ALLOW_NO_MLOCK=1

# Start daemon and capture socket
OUTPUT=$(./target/release/rssh-agent daemon --dir ~/.rssh-agent --quiet 2>/dev/null)
eval "$OUTPUT"

echo "Daemon started with socket: $SSH_AUTH_SOCK"
sleep 2

echo "Testing list identities..."
ssh-add -l

echo "Test completed!"
