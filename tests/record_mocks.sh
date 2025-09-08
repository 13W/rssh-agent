#!/bin/bash

# Script to record SSH agent protocol mocks

MOCK_DIR="tests/mocks"
mkdir -p "$MOCK_DIR"

# Start daemon in background
echo "Starting rssh-agent daemon..."
cargo build --release
./target/release/rssh-agent daemon --socket /tmp/rssh-test.sock &
DAEMON_PID=$!
sleep 2

export SSH_AUTH_SOCK=/tmp/rssh-test.sock

# Function to capture network traffic using strace
capture_messages() {
    local name="$1"
    shift
    echo "Recording: $name"
    strace -e trace=read,write -e read=all -e write=all -xx -s 65536 -o "$MOCK_DIR/${name}.strace" "$@" 2>/dev/null
}

# Test 1: List empty agent
capture_messages "01_list_empty" ssh-add -l

# Test 2: Generate and list keys
echo "Generating test keys..."
./target/release/rssh-agent manage generate --type ed25519 --comment "test-ed25519-key"
capture_messages "02_list_one_key" ssh-add -l

./target/release/rssh-agent manage generate --type rsa --bits 2048 --comment "test-rsa-key"
capture_messages "03_list_two_keys" ssh-add -l

# Test 3: Add external key
echo "Creating external SSH key..."
ssh-keygen -t ed25519 -f /tmp/test-external -N "" -C "external@test.com" -q
capture_messages "04_add_external_key" ssh-add /tmp/test-external

# Test 4: Remove keys
capture_messages "05_remove_all" ssh-add -D

# Test 5: Lock/unlock
./target/release/rssh-agent manage generate --type ed25519 --comment "lock-test"
echo "testpass" | capture_messages "06_lock" ssh-add -x
echo "testpass" | capture_messages "07_unlock" ssh-add -X

# Test 6: Sign request (requires key)
./target/release/rssh-agent manage generate --type ed25519 --comment "sign-test"
echo "test data to sign" > /tmp/test-data
# This would need ssh-keygen -Y sign, but that's more complex

# Clean up
kill $DAEMON_PID
rm -f /tmp/rssh-test.sock /tmp/test-external* /tmp/test-data

echo "Mock recording complete. Processing strace output..."

# Process strace files to extract actual messages
for strace_file in "$MOCK_DIR"/*.strace; do
    if [ -f "$strace_file" ]; then
        base=$(basename "$strace_file" .strace)
        echo "Processing $base..."

        # Extract hex data from strace output
        # This is a simplified extraction - real implementation would need proper parsing
        grep -E 'write\(.*\\x' "$strace_file" | sed 's/.*"\(\\x.*\)".*/\1/' > "$MOCK_DIR/${base}.request.hex" 2>/dev/null || true
        grep -E 'read\(.*\\x' "$strace_file" | sed 's/.*"\(\\x.*\)".*/\1/' > "$MOCK_DIR/${base}.response.hex" 2>/dev/null || true
    fi
done

echo "Done. Mocks saved in $MOCK_DIR"
