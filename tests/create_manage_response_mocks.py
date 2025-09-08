#!/usr/bin/env python3

import struct
import cbor2

# Create response mocks for manage operations

# 06_manage_list.response - Success with empty list
response_data = {
    "ok": True,
    "keys": []
}
cbor_response = cbor2.dumps(response_data)

# SSH agent response format
msg_type = 6  # SSH_AGENT_SUCCESS (for extension responses)
message = bytes([msg_type]) + struct.pack('>I', len(cbor_response)) + cbor_response
full_response = struct.pack('>I', len(message)) + message

with open('tests/mocks/06_manage_list.response', 'wb') as f:
    f.write(full_response)
print(f"Created 06_manage_list.response ({len(full_response)} bytes)")

# 07_manage_add.response - Success
response_data = {
    "ok": True
}
cbor_response = cbor2.dumps(response_data)
message = bytes([msg_type]) + struct.pack('>I', len(cbor_response)) + cbor_response
full_response = struct.pack('>I', len(message)) + message

with open('tests/mocks/07_manage_add.response', 'wb') as f:
    f.write(full_response)
print(f"Created 07_manage_add.response ({len(full_response)} bytes)")

# 08_manage_remove.response - Success
response_data = {
    "ok": True
}
cbor_response = cbor2.dumps(response_data)
message = bytes([msg_type]) + struct.pack('>I', len(cbor_response)) + cbor_response
full_response = struct.pack('>I', len(message)) + message

with open('tests/mocks/08_manage_remove.response', 'wb') as f:
    f.write(full_response)
print(f"Created 08_manage_remove.response ({len(full_response)} bytes)")

# Also create a response with keys for testing
response_data = {
    "ok": True,
    "keys": [
        {
            "fingerprint": "SHA256:test1",
            "key_type": "ssh-ed25519",
            "description": "Test key 1",
            "has_cert": False,
            "confirm": False,
            "lifetime_expires_at": None
        }
    ]
}
cbor_response = cbor2.dumps(response_data)
message = bytes([msg_type]) + struct.pack('>I', len(cbor_response)) + cbor_response
full_response = struct.pack('>I', len(message)) + message

with open('tests/mocks/09_manage_list_with_keys.response', 'wb') as f:
    f.write(full_response)
print(f"Created 09_manage_list_with_keys.response ({len(full_response)} bytes)")
