#!/bin/bash

# Script to capture manage operation mocks

set -e

MOCK_DIR="tests/mocks"
TEMP_DIR="/tmp/rssh-test-$$"
SOCKET="$TEMP_DIR/test.sock"

# Create temp directory
mkdir -p "$TEMP_DIR"

echo "Building rssh-agent..."
cargo build --bin rssh-agent --bin record_mocks

echo "Starting mock recorder..."
./target/debug/record_mocks "$SOCKET" &
RECORDER_PID=$!

# Give it time to start
sleep 2

echo "Capturing manage.list request..."
# Build the manage.list request manually
python3 -c "
import socket
import struct

# Create CBOR for ExtensionRequest { extension: 'manage.list', data: [] }
# This is a CBOR map with 2 entries
cbor_data = bytes([
    0xA2,  # Map with 2 items
    0x69, 0x65, 0x78, 0x74, 0x65, 0x6E, 0x73, 0x69, 0x6F, 0x6E,  # 'extension' (10 bytes)
    0x6B, 0x6D, 0x61, 0x6E, 0x61, 0x67, 0x65, 0x2E, 0x6C, 0x69, 0x73, 0x74,  # 'manage.list' (11 bytes)
    0x64, 0x64, 0x61, 0x74, 0x61,  # 'data' (4 bytes)
    0x40  # Empty byte string
])

# SSH agent message format
msg_type = 27  # SSH_AGENTC_EXTENSION
ext_name = b'rssh.manage'

# Build the full message
message = bytearray()
message.append(msg_type)
message.extend(struct.pack('>I', len(ext_name)))
message.extend(ext_name)
message.extend(cbor_data)

# Add length prefix
full_msg = struct.pack('>I', len(message)) + bytes(message)

# Save as mock
with open('$MOCK_DIR/06_manage_list.request', 'wb') as f:
    f.write(full_msg)

print(f'Wrote manage.list request ({len(full_msg)} bytes)')
"

echo "Creating other manage operation mocks..."

# manage.add mock
python3 -c "
import socket
import struct

# CBOR for ExtensionRequest { extension: 'manage.add', data: [test_key_data] }
cbor_data = bytes([
    0xA2,  # Map with 2 items
    0x69, 0x65, 0x78, 0x74, 0x65, 0x6E, 0x73, 0x69, 0x6F, 0x6E,  # 'extension'
    0x6A, 0x6D, 0x61, 0x6E, 0x61, 0x67, 0x65, 0x2E, 0x61, 0x64, 0x64,  # 'manage.add' (10 bytes)
    0x64, 0x64, 0x61, 0x74, 0x61,  # 'data'
    0x44, 0x01, 0x02, 0x03, 0x04  # Byte string with 4 bytes
])

msg_type = 27  # SSH_AGENTC_EXTENSION
ext_name = b'rssh.manage'

message = bytearray()
message.append(msg_type)
message.extend(struct.pack('>I', len(ext_name)))
message.extend(ext_name)
message.extend(cbor_data)

full_msg = struct.pack('>I', len(message)) + bytes(message)

with open('$MOCK_DIR/07_manage_add.request', 'wb') as f:
    f.write(full_msg)

print(f'Wrote manage.add request ({len(full_msg)} bytes)')
"

# manage.remove mock
python3 -c "
import socket
import struct

# CBOR for ExtensionRequest { extension: 'manage.remove', data: [fingerprint] }
# Using a test fingerprint
test_fingerprint = b'SHA256:test-fingerprint'

cbor_data = bytes([
    0xA2,  # Map with 2 items
    0x69, 0x65, 0x78, 0x74, 0x65, 0x6E, 0x73, 0x69, 0x6F, 0x6E,  # 'extension'
    0x6D,  # Text string of length 13
    0x6D, 0x61, 0x6E, 0x61, 0x67, 0x65, 0x2E, 0x72, 0x65, 0x6D, 0x6F, 0x76, 0x65,  # 'manage.remove'
    0x64, 0x64, 0x61, 0x74, 0x61,  # 'data'
    0x57,  # Byte string of length 23
]) + test_fingerprint

msg_type = 27
ext_name = b'rssh.manage'

message = bytearray()
message.append(msg_type)
message.extend(struct.pack('>I', len(ext_name)))
message.extend(ext_name)
message.extend(cbor_data)

full_msg = struct.pack('>I', len(message)) + bytes(message)

with open('$MOCK_DIR/08_manage_remove.request', 'wb') as f:
    f.write(full_msg)

print(f'Wrote manage.remove request ({len(full_msg)} bytes)')
"

# Clean up
kill $RECORDER_PID 2>/dev/null || true
rm -rf "$TEMP_DIR"

echo "Mock files created successfully!"
ls -la $MOCK_DIR/*.request | tail -3
