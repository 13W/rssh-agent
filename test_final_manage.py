#!/usr/bin/env python3

import socket
import struct
import sys
import os
import cbor2

# Final test of manage.list with correct format

socket_path = os.environ.get('SSH_AUTH_SOCK', '/tmp/rssh-test.sock')

if not os.path.exists(socket_path):
    print(f"Socket not found: {socket_path}")
    print("Start daemon first with: ./target/debug/rssh-agent daemon --socket /tmp/rssh-test.sock --foreground")
    sys.exit(1)

print(f"Testing manage.list on: {socket_path}")

# Build manage.list request
ext_request = {
    "extension": "manage.list",
    "data": b""
}

cbor_request = cbor2.dumps(ext_request)

# Build message with namespace
message = bytearray()
message.append(27)  # SSH_AGENTC_EXTENSION
ext_namespace = b'rssh-agent@local'
message.extend(struct.pack('>I', len(ext_namespace)))
message.extend(ext_namespace)
message.extend(cbor_request)

# Add length prefix
full_msg = struct.pack('>I', len(message)) + bytes(message)

print(f"Sending request ({len(full_msg)} bytes)...")

# Send via socket
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect(socket_path)
sock.sendall(full_msg)

# Read response
len_buf = sock.recv(4)
resp_len = struct.unpack('>I', len_buf)[0]
response = sock.recv(resp_len)

print(f"Got response: {resp_len} bytes, type={response[0]}")

if response[0] == 6:  # SSH_AGENT_SUCCESS
    # Parse wire-encoded CBOR
    offset = 1
    data_len = struct.unpack('>I', response[offset:offset+4])[0]
    offset += 4

    cbor_data = response[offset:offset + data_len]

    # Parse ExtensionResponse
    ext_response = cbor2.loads(cbor_data)
    print(f"ExtensionResponse: success={ext_response.get('success')}")

    if ext_response.get('success'):
        # Parse ManageListResponse from data field
        list_response = cbor2.loads(ext_response['data'])
        print(f"ManageListResponse: ok={list_response.get('ok')}, keys={len(list_response.get('keys', []))}")

        if list_response.get('ok'):
            print("✓ Successfully parsed manage.list response!")
            for i, key in enumerate(list_response.get('keys', [])):
                print(f"  Key {i+1}: {key.get('fingerprint')} ({key.get('key_type')})")
        else:
            print("✗ Server returned error in list response")
    else:
        print("✗ ExtensionResponse indicates failure")

elif response[0] == 5:  # SSH_AGENT_FAILURE
    print("Got SSH_AGENT_FAILURE (agent is locked)")
    print("This is expected when agent is locked")
else:
    print(f"✗ Unexpected response type: {response[0]}")

sock.close()
