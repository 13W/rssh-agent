#!/usr/bin/env python3

import struct

# Update manage mocks with correct namespace

def create_manage_mock(extension_name, cbor_data):
    """Create a mock request with correct namespace"""
    message = bytearray()
    message.append(27)  # SSH_AGENTC_EXTENSION

    # Use correct namespace
    ext_namespace = b'rssh-agent@local'
    message.extend(struct.pack('>I', len(ext_namespace)))
    message.extend(ext_namespace)
    message.extend(cbor_data)

    # Add length prefix
    full_msg = struct.pack('>I', len(message)) + bytes(message)
    return full_msg

# Update manage.list mock
cbor_data = bytes([
    0xA2,  # Map with 2 items
    0x69, 0x65, 0x78, 0x74, 0x65, 0x6E, 0x73, 0x69, 0x6F, 0x6E,  # 'extension'
    0x6B, 0x6D, 0x61, 0x6E, 0x61, 0x67, 0x65, 0x2E, 0x6C, 0x69, 0x73, 0x74,  # 'manage.list'
    0x64, 0x64, 0x61, 0x74, 0x61,  # 'data'
    0x40  # Empty byte string
])

with open('tests/mocks/06_manage_list.request', 'wb') as f:
    f.write(create_manage_mock('manage.list', cbor_data))
print("Updated 06_manage_list.request")

# Update manage.add mock
cbor_data = bytes([
    0xA2,  # Map with 2 items
    0x69, 0x65, 0x78, 0x74, 0x65, 0x6E, 0x73, 0x69, 0x6F, 0x6E,  # 'extension'
    0x6A, 0x6D, 0x61, 0x6E, 0x61, 0x67, 0x65, 0x2E, 0x61, 0x64, 0x64,  # 'manage.add'
    0x64, 0x64, 0x61, 0x74, 0x61,  # 'data'
    0x44, 0x01, 0x02, 0x03, 0x04  # Byte string with 4 bytes
])

with open('tests/mocks/07_manage_add.request', 'wb') as f:
    f.write(create_manage_mock('manage.add', cbor_data))
print("Updated 07_manage_add.request")

# Update manage.remove mock
test_fingerprint = b'SHA256:test-fingerprint'
cbor_data = bytes([
    0xA2,  # Map with 2 items
    0x69, 0x65, 0x78, 0x74, 0x65, 0x6E, 0x73, 0x69, 0x6F, 0x6E,  # 'extension'
    0x6D,  # Text string of length 13
    0x6D, 0x61, 0x6E, 0x61, 0x67, 0x65, 0x2E, 0x72, 0x65, 0x6D, 0x6F, 0x76, 0x65,  # 'manage.remove'
    0x64, 0x64, 0x61, 0x74, 0x61,  # 'data'
    0x57,  # Byte string of length 23
]) + test_fingerprint

with open('tests/mocks/08_manage_remove.request', 'wb') as f:
    f.write(create_manage_mock('manage.remove', cbor_data))
print("Updated 08_manage_remove.request")
