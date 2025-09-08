#!/bin/bash

# Final integration test with correct namespace

set -e

echo "=== Final Integration Test ==="

# Build
echo "Building rssh-agent..."
cargo build --bin rssh-agent -q

TEMP_DIR="/tmp/rssh-final-test-$$"
SOCKET="$TEMP_DIR/test.sock"
LOG_FILE="$TEMP_DIR/daemon.log"

mkdir -p "$TEMP_DIR"

# Start daemon with debug logging
echo "Starting daemon..."
RUST_LOG=debug ./target/debug/rssh-agent daemon --socket "$SOCKET" --foreground > "$LOG_FILE" 2>&1 &
DAEMON_PID=$!

sleep 2

# Test with correct namespace
echo "Testing extension with correct namespace (rssh-agent@local)..."
python3 -c "
import socket
import struct
import sys

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect('$SOCKET')

# CBOR for manage.list
cbor_data = bytes([
    0xA2,  # Map with 2 items
    0x69, 0x65, 0x78, 0x74, 0x65, 0x6E, 0x73, 0x69, 0x6F, 0x6E,  # 'extension'
    0x6B, 0x6D, 0x61, 0x6E, 0x61, 0x67, 0x65, 0x2E, 0x6C, 0x69, 0x73, 0x74,  # 'manage.list'
    0x64, 0x64, 0x61, 0x74, 0x61,  # 'data'
    0x40  # Empty byte string
])

# Build message with correct namespace
message = bytearray()
message.append(27)  # SSH_AGENTC_EXTENSION
ext_namespace = b'rssh-agent@local'
message.extend(struct.pack('>I', len(ext_namespace)))
message.extend(ext_namespace)
message.extend(cbor_data)

full_msg = struct.pack('>I', len(message)) + bytes(message)

sock.sendall(full_msg)
len_buf = sock.recv(4)
if len(len_buf) == 4:
    resp_len = struct.unpack('>I', len_buf)[0]
    response = sock.recv(resp_len)

    if response[0] == 5:  # SSH_AGENT_FAILURE
        print('✓ Got expected failure (agent is locked)')
    elif response[0] == 6:  # SSH_AGENT_SUCCESS
        print('✓ Got success response with CBOR data')
    else:
        print(f'✗ Unexpected response type: {response[0]}')
        sys.exit(1)
else:
    print('✗ Failed to read response')
    sys.exit(1)
sock.close()
"

echo ""
echo "Checking logs for errors..."

# Check for specific errors
ERRORS_FOUND=0

if grep -q "Unknown extension namespace" "$LOG_FILE"; then
    echo "✗ Found 'Unknown extension namespace' error"
    ERRORS_FOUND=1
fi

if grep -q "invalid type: integer" "$LOG_FILE"; then
    echo "✗ Found CBOR parsing error"
    ERRORS_FOUND=1
fi

if grep -q "Failed to parse extension request" "$LOG_FILE"; then
    echo "✗ Found extension parsing failure"
    grep "Failed to parse extension request" "$LOG_FILE" | tail -1
    ERRORS_FOUND=1
fi

if [ $ERRORS_FOUND -eq 0 ]; then
    echo "✓ No errors found in logs"
fi

# Show successful extension handling
if grep -q "Extension request raw data" "$LOG_FILE"; then
    echo "✓ Extension request was received and processed"
fi

# Clean up
kill $DAEMON_PID 2>/dev/null || true
rm -rf "$TEMP_DIR"

echo ""
if [ $ERRORS_FOUND -eq 0 ]; then
    echo "=== ✓ All tests passed successfully ==="
    exit 0
else
    echo "=== ✗ Tests failed with errors ==="
    exit 1
fi
