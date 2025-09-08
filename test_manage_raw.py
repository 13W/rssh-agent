#!/usr/bin/env python3

import socket
import struct
import sys
import os

# Test raw manage request/response

socket_path = os.environ.get('SSH_AUTH_SOCK', '/tmp/rssh-test.sock')

if not os.path.exists(socket_path):
    print(f"Socket not found: {socket_path}")
    sys.exit(1)

print(f"Connecting to: {socket_path}")

# Build manage.list request
cbor_request = bytes([
    0xA2,  # Map with 2 items
    0x69, 0x65, 0x78, 0x74, 0x65, 0x6E, 0x73, 0x69, 0x6F, 0x6E,  # 'extension'
    0x6B, 0x6D, 0x61, 0x6E, 0x61, 0x67, 0x65, 0x2E, 0x6C, 0x69, 0x73, 0x74,  # 'manage.list'
    0x64, 0x64, 0x61, 0x74, 0x61,  # 'data'
    0x40  # Empty byte string
])

# Build message with namespace
message = bytearray()
message.append(27)  # SSH_AGENTC_EXTENSION
ext_namespace = b'rssh-agent@local'
message.extend(struct.pack('>I', len(ext_namespace)))
message.extend(ext_namespace)
message.extend(cbor_request)

# Add length prefix
full_msg = struct.pack('>I', len(message)) + bytes(message)

print(f"Request: {len(full_msg)} bytes")
print(f"Message hex: {full_msg.hex()}")

# Send via socket
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect(socket_path)
sock.sendall(full_msg)

# Read response
len_buf = sock.recv(4)
if len(len_buf) != 4:
    print('Failed to read response length')
    sys.exit(1)

resp_len = struct.unpack('>I', len_buf)[0]
response = sock.recv(resp_len)

print(f"\nResponse: {resp_len} bytes, type={response[0]}")
print(f"Response hex: {response.hex()}")

if response[0] == 6:  # SSH_AGENT_SUCCESS
    # Parse wire-encoded CBOR
    offset = 1
    if len(response) >= offset + 4:
        data_len = struct.unpack('>I', response[offset:offset+4])[0]
        offset += 4

        if len(response) >= offset + data_len:
            cbor_data = response[offset:offset + data_len]
            print(f"\nCBOR data: {len(cbor_data)} bytes")
            print(f"CBOR hex: {cbor_data.hex()}")

            # Try to parse CBOR
            try:
                import cbor2
                parsed = cbor2.loads(cbor_data)
                print(f"\nParsed CBOR: {parsed}")

                if 'success' in parsed:
                    print("✓ Has 'success' field")
                else:
                    print("✗ Missing 'success' field")

            except Exception as e:
                print(f"CBOR parse error: {e}")

elif response[0] == 5:  # SSH_AGENT_FAILURE
    print("Got SSH_AGENT_FAILURE (agent locked or error)")
else:
    print(f"Unexpected response type: {response[0]}")

sock.close()
