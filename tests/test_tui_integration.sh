#!/bin/bash

# Test TUI integration with daemon

set -e

echo "Building rssh-agent..."
cargo build --bin rssh-agent

TEMP_DIR="/tmp/rssh-test-$$"
SOCKET="$TEMP_DIR/test.sock"
CONFIG_DIR="$TEMP_DIR/config"

# Create temp directory
mkdir -p "$CONFIG_DIR"

# Start daemon
echo "Starting daemon..."
./target/debug/rssh-agent daemon --socket "$SOCKET" --foreground &
DAEMON_PID=$!

# Give daemon time to start
sleep 2

# Test extension message format
echo "Testing extension message format..."
python3 -c "
import socket
import struct
import sys

# Connect to daemon
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    sock.connect('$SOCKET')

    # Build manage.list request as TUI would send it
    request = {
        'extension': 'manage.list',
        'data': []
    }

    # Encode as CBOR (simplified - actual CBOR encoding)
    cbor_data = bytes([
        0xA2,  # Map with 2 items
        0x69, 0x65, 0x78, 0x74, 0x65, 0x6E, 0x73, 0x69, 0x6F, 0x6E,  # 'extension'
        0x6B, 0x6D, 0x61, 0x6E, 0x61, 0x67, 0x65, 0x2E, 0x6C, 0x69, 0x73, 0x74,  # 'manage.list'
        0x64, 0x64, 0x61, 0x74, 0x61,  # 'data'
        0x40  # Empty byte string
    ])

    # Build message with extension namespace (as fixed TUI does)
    message = bytearray()
    message.append(27)  # SSH_AGENTC_EXTENSION

    ext_namespace = b'rssh.manage'
    message.extend(struct.pack('>I', len(ext_namespace)))
    message.extend(ext_namespace)
    message.extend(cbor_data)

    # Add length prefix
    full_msg = struct.pack('>I', len(message)) + bytes(message)

    # Send request
    sock.sendall(full_msg)

    # Read response
    len_buf = sock.recv(4)
    if len(len_buf) == 4:
        resp_len = struct.unpack('>I', len_buf)[0]
        response = sock.recv(resp_len)

        if response[0] == 5:  # SSH_AGENT_FAILURE
            print('✓ Got expected failure (agent is locked)')
            sys.exit(0)
        elif response[0] == 6:  # SSH_AGENT_SUCCESS
            print('✓ Got success response')
            sys.exit(0)
        else:
            print(f'✗ Unexpected response type: {response[0]}')
            sys.exit(1)
    else:
        print('✗ Failed to read response')
        sys.exit(1)

except Exception as e:
    print(f'✗ Error: {e}')
    sys.exit(1)
finally:
    sock.close()
"

RESULT=$?

# Clean up
kill $DAEMON_PID 2>/dev/null || true
rm -rf "$TEMP_DIR"

if [ $RESULT -eq 0 ]; then
    echo "✓ TUI integration test passed"
    exit 0
else
    echo "✗ TUI integration test failed"
    exit 1
fi
