#!/bin/bash

# Test that CBOR parsing works correctly with both old and new formats

set -e

echo "Testing CBOR parsing..."

TEMP_DIR="/tmp/rssh-cbor-test-$$"
SOCKET="$TEMP_DIR/test.sock"
LOG_FILE="$TEMP_DIR/daemon.log"

mkdir -p "$TEMP_DIR"

# Start daemon with debug logging
echo "Starting daemon with debug logging..."
RUST_LOG=debug ./target/debug/rssh-agent daemon --socket "$SOCKET" --foreground > "$LOG_FILE" 2>&1 &
DAEMON_PID=$!

sleep 2

# Test 1: Old format (direct CBOR) - should fail gracefully
echo "Test 1: Old format (direct CBOR)..."
python3 -c "
import socket
import struct

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect('$SOCKET')

# Old format: direct CBOR after message type
cbor_data = bytes([
    0xA2,  # Map with 2 items
    0x69, 0x65, 0x78, 0x74, 0x65, 0x6E, 0x73, 0x69, 0x6F, 0x6E,  # 'extension'
    0x6B, 0x6D, 0x61, 0x6E, 0x61, 0x67, 0x65, 0x2E, 0x6C, 0x69, 0x73, 0x74,  # 'manage.list'
    0x64, 0x64, 0x61, 0x74, 0x61,  # 'data'
    0x40  # Empty byte string
])

message = bytes([27]) + cbor_data  # SSH_AGENTC_EXTENSION + direct CBOR
full_msg = struct.pack('>I', len(message)) + message

sock.sendall(full_msg)
len_buf = sock.recv(4)
if len(len_buf) == 4:
    resp_len = struct.unpack('>I', len_buf)[0]
    response = sock.recv(resp_len)
    print(f'Old format response type: {response[0]}')
sock.close()
"

# Test 2: New format (with namespace) - should work
echo "Test 2: New format (with namespace)..."
python3 -c "
import socket
import struct

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect('$SOCKET')

# New format: namespace + CBOR
cbor_data = bytes([
    0xA2,  # Map with 2 items
    0x69, 0x65, 0x78, 0x74, 0x65, 0x6E, 0x73, 0x69, 0x6F, 0x6E,  # 'extension'
    0x6B, 0x6D, 0x61, 0x6E, 0x61, 0x67, 0x65, 0x2E, 0x6C, 0x69, 0x73, 0x74,  # 'manage.list'
    0x64, 0x64, 0x61, 0x74, 0x61,  # 'data'
    0x40  # Empty byte string
])

message = bytearray()
message.append(27)  # SSH_AGENTC_EXTENSION
ext_namespace = b'rssh.manage'
message.extend(struct.pack('>I', len(ext_namespace)))
message.extend(ext_namespace)
message.extend(cbor_data)

full_msg = struct.pack('>I', len(message)) + bytes(message)

sock.sendall(full_msg)
len_buf = sock.recv(4)
if len(len_buf) == 4:
    resp_len = struct.unpack('>I', len_buf)[0]
    response = sock.recv(resp_len)
    print(f'New format response type: {response[0]}')
sock.close()
"

# Check logs for CBOR errors
echo "Checking for CBOR parsing errors..."
if grep -q "invalid type: integer" "$LOG_FILE"; then
    echo "✗ CBOR parsing error found in logs"
    grep "CBOR" "$LOG_FILE" | tail -5
    RESULT=1
else
    echo "✓ No CBOR parsing errors"
    RESULT=0
fi

# Clean up
kill $DAEMON_PID 2>/dev/null || true
rm -rf "$TEMP_DIR"

exit $RESULT
