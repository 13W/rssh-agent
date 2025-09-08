#!/bin/bash

# Generate mock data for integration tests

MOCK_DIR="tests/mocks"
mkdir -p "$MOCK_DIR"

# Start daemon
echo "Starting daemon..."
cargo build --release --quiet
./target/release/rssh-agent daemon --socket /tmp/rssh-test.sock &
DAEMON_PID=$!
sleep 3

export SSH_AUTH_SOCK=/tmp/rssh-test.sock

# Function to capture raw protocol messages using socat
record_exchange() {
    local name="$1"
    local description="$2"
    shift 2

    echo "Recording: $description"

    # Run command and capture its exit code
    "$@"
    local exit_code=$?

    if [ $exit_code -eq 0 ]; then
        echo "  ✓ Success"
    else
        echo "  ✗ Failed with code $exit_code"
    fi

    # For now, we'll manually create mock data based on known protocol
    echo "$description" > "$MOCK_DIR/${name}.description"
}

# Test scenarios
echo "=== Recording mock exchanges ==="

# 1. List keys (empty)
record_exchange "01_list_empty" "List keys when agent is empty" ssh-add -l

# 2. Generate a key
record_exchange "02_generate_ed25519" "Generate ED25519 key" \
    ./target/release/rssh-agent manage generate --type ed25519 --comment "test-ed25519"

# 3. List keys (one key)
record_exchange "03_list_one_key" "List keys with one key present" ssh-add -l

# 4. Generate another key
record_exchange "04_generate_rsa" "Generate RSA key" \
    ./target/release/rssh-agent manage generate --type rsa --bits 2048 --comment "test-rsa"

# 5. List keys (two keys)
record_exchange "05_list_two_keys" "List keys with two keys present" ssh-add -l

# 6. Remove all keys
record_exchange "06_remove_all" "Remove all keys" ssh-add -D

# 7. List keys (empty again)
record_exchange "07_list_after_remove" "List keys after removing all" ssh-add -l

# Clean up
kill $DAEMON_PID 2>/dev/null
rm -f /tmp/rssh-test.sock

echo ""
echo "=== Mock recording complete ==="
echo "Now creating hardcoded mock files based on protocol spec..."
