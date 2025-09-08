#!/usr/bin/env python3

import struct
import cbor2

# Update response mocks to match new unified format

def create_extension_response(success, data_dict):
    """Create ExtensionResponse with nested CBOR data"""
    # First encode the inner data
    inner_cbor = cbor2.dumps(data_dict)

    # Then create ExtensionResponse
    ext_response = {
        "success": success,
        "data": inner_cbor
    }

    # Encode ExtensionResponse to CBOR
    ext_cbor = cbor2.dumps(ext_response)

    # Build SSH wire format response
    msg_type = 6  # SSH_AGENT_SUCCESS
    message = bytes([msg_type]) + struct.pack('>I', len(ext_cbor)) + ext_cbor
    full_response = struct.pack('>I', len(message)) + message

    return full_response

# 06_manage_list.response - Empty list
list_response = {
    "ok": True,
    "keys": []
}

with open('tests/mocks/06_manage_list.response', 'wb') as f:
    f.write(create_extension_response(True, list_response))
print("Updated 06_manage_list.response")

# 07_manage_add.response - Success
op_response = {
    "ok": True
}

with open('tests/mocks/07_manage_add.response', 'wb') as f:
    f.write(create_extension_response(True, op_response))
print("Updated 07_manage_add.response")

# 08_manage_remove.response - Success
with open('tests/mocks/08_manage_remove.response', 'wb') as f:
    f.write(create_extension_response(True, op_response))
print("Updated 08_manage_remove.response")

# 09_manage_list_with_keys.response - List with keys
list_with_keys = {
    "ok": True,
    "keys": [
        {
            "fingerprint": "SHA256:test1",
            "key_type": "ssh-ed25519",
            "comment": "Test key 1",
            "locked": False,
            "last_used": None,
            "use_count": 0,
            "constraints": []
        },
        {
            "fingerprint": "SHA256:test2",
            "key_type": "ssh-rsa",
            "comment": "Test key 2",
            "locked": False,
            "last_used": 1234567890,
            "use_count": 42,
            "constraints": ["confirm"]
        }
    ]
}

with open('tests/mocks/09_manage_list_with_keys.response', 'wb') as f:
    f.write(create_extension_response(True, list_with_keys))
print("Updated 09_manage_list_with_keys.response")
