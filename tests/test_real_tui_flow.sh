#!/bin/bash

# Test real TUI flow with actual CBOR parsing

set -e

echo "=== Testing Real TUI Flow ==="

# Build
cargo build --bin rssh-agent -q

TEMP_DIR="/tmp/rssh-tui-test-$$"
SOCKET="$TEMP_DIR/test.sock"
LOG_FILE="$TEMP_DIR/daemon.log"

mkdir -p "$TEMP_DIR"

# Start daemon
echo "Starting daemon..."
RUST_LOG=debug ./target/debug/rssh-agent daemon --socket "$SOCKET" --foreground > "$LOG_FILE" 2>&1 &
DAEMON_PID=$!

sleep 2

# Test exact TUI flow
echo "Testing TUI manage.list flow..."
python3 -c "
import struct
import sys

# This replicates EXACTLY what the fixed TUI sends

# 1. Build ExtensionRequest CBOR
cbor_request = bytes([
    0xA2,  # Map with 2 items
    0x69, 0x65, 0x78, 0x74, 0x65, 0x6E, 0x73, 0x69, 0x6F, 0x6E,  # 'extension' (10 bytes)
    0x6B, 0x6D, 0x61, 0x6E, 0x61, 0x67, 0x65, 0x2E, 0x6C, 0x69, 0x73, 0x74,  # 'manage.list' (11 bytes)
    0x64, 0x64, 0x61, 0x74, 0x61,  # 'data' (4 bytes)
    0x40  # Empty byte string
])

# 2. Build message with namespace (as fixed TUI does)
message = bytearray()
message.append(27)  # SSH_AGENTC_EXTENSION
ext_namespace = b'rssh-agent@local'
message.extend(struct.pack('>I', len(ext_namespace)))
message.extend(ext_namespace)
message.extend(cbor_request)

# 3. Add length prefix
full_msg = struct.pack('>I', len(message)) + bytes(message)

print(f'Sending {len(full_msg)} bytes...')

# 4. Send via socket
import socket
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect('$SOCKET')
sock.sendall(full_msg)

# 5. Read response
len_buf = sock.recv(4)
if len(len_buf) != 4:
    print('✗ Failed to read response length')
    sys.exit(1)

resp_len = struct.unpack('>I', len_buf)[0]
response = sock.recv(resp_len)

print(f'Got response: type={response[0]}, len={resp_len}')

# 6. Parse response as TUI would
if response[0] == 6:  # SSH_AGENT_SUCCESS
    # Parse wire-encoded CBOR
    offset = 1
    if len(response) >= offset + 4:
        data_len = struct.unpack('>I', response[offset:offset+4])[0]
        offset += 4

        if len(response) >= offset + data_len:
            cbor_data = response[offset:offset + data_len]
            print(f'Got CBOR data: {len(cbor_data)} bytes')

            # Try to parse as ExtensionResponse
            try:
                import cbor2
                ext_resp = cbor2.loads(cbor_data)
                print(f'Parsed response: {ext_resp}')

                # Check for 'success' field
                if 'success' in ext_resp:
                    print('✓ Response has success field')
                else:
                    print('✗ Response missing success field!')
                    sys.exit(1)

            except Exception as e:
                print(f'✗ Failed to parse CBOR: {e}')
                sys.exit(1)
        else:
            print('✗ Response data truncated')
            sys.exit(1)
    else:
        print('✗ Response too short for data length')
        sys.exit(1)

elif response[0] == 5:  # SSH_AGENT_FAILURE
    print('✓ Got expected failure (agent locked)')
else:
    print(f'✗ Unexpected response type: {response[0]}')
    sys.exit(1)

sock.close()
print('✓ Test completed successfully')
"

RESULT=$?

# Check logs
echo ""
echo "Checking logs..."
if grep -q "Failed to parse extension request" "$LOG_FILE"; then
    echo "✗ Found parsing errors:"
    grep "Failed to parse extension request" "$LOG_FILE" | tail -2
else
    echo "✓ No parsing errors"
fi

# Clean up
kill $DAEMON_PID 2>/dev/null || true
rm -rf "$TEMP_DIR"

if [ $RESULT -eq 0 ]; then
    echo ""
    echo "=== ✓ Real TUI flow test passed ==="
    exit 0
else
    echo ""
    echo "=== ✗ Real TUI flow test failed ==="
    exit 1
fi
