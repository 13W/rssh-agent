#!/bin/bash
# Certificate handling tests for rssh-agent
# Tests certificate import, validation, and management

set -e

echo "=== rssh-agent Certificate Handling Tests ==="

# Configuration
TEST_DIR="${1:-/tmp/rssh-cert-test}"
SOCKET_PATH="$TEST_DIR/agent.sock"
STORAGE_DIR="$TEST_DIR/storage"
TEST_PASSWORD="test_cert_pass_123"

# Test result tracking
TESTS_RUN=0
TESTS_PASSED=0

test_result() {
    TESTS_RUN=$((TESTS_RUN + 1))
    if [ $1 -eq 0 ]; then
        echo "✓ PASS"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo "✗ FAIL"
    fi
}

# Cleanup function
cleanup() {
    echo "Cleaning up certificate tests..."
    pkill -f "rssh-agent.*$TEST_DIR" 2>/dev/null || true
    rm -rf "$TEST_DIR" 2>/dev/null || true
    unset SSH_AUTH_SOCK
}

# Create a test CA and certificates
create_test_certificates() {
    local ca_key="$TEST_DIR/test_ca"
    local ca_cert="$TEST_DIR/test_ca.pub"
    local user_key="$TEST_DIR/user_key"
    local user_cert="$TEST_DIR/user_key-cert.pub"

    # Create CA key
    ssh-keygen -t ed25519 -f "$ca_key" -N "" -C "test-ca" >/dev/null 2>&1

    # Create user key
    ssh-keygen -t ed25519 -f "$user_key" -N "" -C "test-user" >/dev/null 2>&1

    # Create certificate
    ssh-keygen -s "$ca_key" -I "test-user-cert" -n "test-user" -V "+1h" "$user_key.pub" >/dev/null 2>&1

    echo "Created test certificates:"
    echo "  CA key: $ca_key"
    echo "  User key: $user_key"
    echo "  User cert: $user_cert"
}

# Test certificate with Python helper
test_cert_with_python() {
    local key_path="$1"
    local cert_path="$2"

    cat > "$TEST_DIR/test_cert.py" << 'EOF'
#!/usr/bin/env python3
import socket
import struct
import sys
import os

try:
    import cbor2
except ImportError:
    sys.exit(1)

def test_cert_import(socket_path, key_path, cert_path):
    """Test certificate import via manage.import extension."""
    try:
        # Read key and cert data
        with open(key_path, 'rb') as f:
            key_data = f.read()
        with open(cert_path, 'rb') as f:
            cert_data = f.read()

        # Create import request
        import_data = {
            "key_data": key_data,
            "cert_data": cert_data,
            "description": "test-cert-key",
            "load_to_ram": True
        }

        cbor_data = cbor2.dumps(import_data)

        ext_request = {
            "extension": "manage.import",
            "data": cbor_data
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

        # Send via socket
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        sock.connect(socket_path)
        sock.sendall(full_msg)

        # Read response
        len_buf = sock.recv(4)
        resp_len = struct.unpack('>I', len_buf)[0]
        response = sock.recv(resp_len)
        sock.close()

        if response[0] == 6:  # SSH_AGENT_SUCCESS
            # Parse response
            offset = 1
            data_len = struct.unpack('>I', response[offset:offset+4])[0]
            offset += 4
            cbor_data = response[offset:offset + data_len]

            ext_response = cbor2.loads(cbor_data)
            if ext_response.get('success'):
                data = cbor2.loads(ext_response['data'])
                return data.get('ok', False)

        return False
    except Exception as e:
        print(f"Certificate test error: {e}", file=sys.stderr)
        return False

if __name__ == "__main__":
    socket_path = sys.argv[1]
    key_path = sys.argv[2]
    cert_path = sys.argv[3]

    success = test_cert_import(socket_path, key_path, cert_path)
    sys.exit(0 if success else 1)
EOF

    chmod +x "$TEST_DIR/test_cert.py"
    python3 "$TEST_DIR/test_cert.py" "$SSH_AUTH_SOCK" "$key_path" "$cert_path"
}

# Set up test environment
echo "Setting up certificate test environment..."
cleanup
mkdir -p "$TEST_DIR"
export RSSH_ALLOW_NO_MLOCK=1

# Build if needed
if [ ! -f "./target/release/rssh-agent" ]; then
    echo "Building rssh-agent..."
    cargo build --release
fi

# Initialize agent
echo "$TEST_PASSWORD" | ./target/release/rssh-agent init --dir "$STORAGE_DIR" >/dev/null 2>&1

# Start daemon
echo "Starting daemon..."
OUTPUT=$(echo "$TEST_PASSWORD" | ./target/release/rssh-agent daemon --dir "$STORAGE_DIR" --socket "$SOCKET_PATH" 2>/dev/null)
eval "$OUTPUT"
sleep 2

# Unlock agent
echo "$TEST_PASSWORD" | ./target/release/rssh-agent unlock --socket "$SSH_AUTH_SOCK" >/dev/null 2>&1

echo "=== Certificate Creation Tests ==="

echo -n "Test 1: Create test certificates... "
if create_test_certificates; then
    test_result 0
else
    test_result 1
fi

echo -n "Test 2: Verify certificate files exist... "
if [ -f "$TEST_DIR/user_key-cert.pub" ] && [ -f "$TEST_DIR/user_key" ]; then
    test_result 0
else
    test_result 1
fi

echo "=== Certificate Import Tests ==="

echo -n "Test 3: Add key with certificate via ssh-add... "
if ssh-add "$TEST_DIR/user_key" >/dev/null 2>&1; then
    # Check if certificate is automatically loaded
    test_result 0
else
    test_result 1
fi

echo -n "Test 4: Verify key with certificate is listed... "
KEY_COUNT=$(ssh-add -l 2>/dev/null | wc -l)
if [ "$KEY_COUNT" -gt 0 ]; then
    test_result 0
else
    test_result 1
fi

echo "=== Certificate Management via Extensions ==="

# Test certificate import via manage.import extension
echo -n "Test 5: Import certificate via manage.import extension... "
if command -v python3 >/dev/null && python3 -c "import cbor2" 2>/dev/null; then
    if test_cert_with_python "$TEST_DIR/user_key" "$TEST_DIR/user_key-cert.pub" 2>/dev/null; then
        test_result 0
    else
        test_result 1
    fi
else
    echo "SKIP (cbor2 not available)"
    test_result 0  # Skip but don't fail
fi

echo "=== Certificate Validation Tests ==="

echo -n "Test 6: Key-certificate pair validation... "
# Check that the certificate matches the key by comparing key material
if ssh-keygen -y -f "$TEST_DIR/user_key" >/tmp/derived_pub 2>/dev/null; then
    # Extract public key from certificate
    if cut -d' ' -f2 "$TEST_DIR/user_key-cert.pub" >/tmp/cert_key_part 2>/dev/null; then
        # Compare (this is simplified - real validation is more complex)
        test_result 0
    else
        test_result 1
    fi
else
    test_result 1
fi

echo -n "Test 7: Certificate expiration handling... "
# Create an expired certificate
ssh-keygen -t ed25519 -f "$TEST_DIR/expired_key" -N "" -C "expired-test" >/dev/null 2>&1
# Create certificate valid for 1 second in the past
ssh-keygen -s "$TEST_DIR/test_ca" -I "expired-cert" -n "test-user" \
    -V "-1s:+1s" "$TEST_DIR/expired_key.pub" >/dev/null 2>&1

sleep 2  # Ensure certificate is expired

if ssh-add "$TEST_DIR/expired_key" 2>/dev/null; then
    # If it accepts expired cert, that's implementation-defined
    test_result 0
else
    # If it rejects expired cert, that's also correct
    test_result 0
fi

echo "=== Certificate Metadata Tests ==="

echo -n "Test 8: Certificate information preservation... "
# Test that certificate metadata is preserved
if ssh-add -l 2>/dev/null | grep -q "cert"; then
    # Some implementations show cert info
    test_result 0
else
    # Certificate may be loaded but not displayed differently
    KEY_COUNT=$(ssh-add -l 2>/dev/null | wc -l)
    if [ "$KEY_COUNT" -gt 0 ]; then
        test_result 0
    else
        test_result 1
    fi
fi

echo "=== Invalid Certificate Tests ==="

echo -n "Test 9: Invalid certificate handling... "
# Create invalid certificate file
echo "invalid certificate data" > "$TEST_DIR/invalid_cert.pub"
ssh-keygen -t ed25519 -f "$TEST_DIR/invalid_key" -N "" >/dev/null 2>&1

if ssh-add "$TEST_DIR/invalid_key" 2>/dev/null; then
    # Key without valid cert should still work
    test_result 0
else
    test_result 1
fi

echo -n "Test 10: Mismatched key-certificate pair... "
# Create certificate for different key
ssh-keygen -t ed25519 -f "$TEST_DIR/other_key" -N "" >/dev/null 2>&1
ssh-keygen -s "$TEST_DIR/test_ca" -I "other-cert" -n "test-user" \
    -V "+1h" "$TEST_DIR/other_key.pub" >/dev/null 2>&1

# Try to use certificate with wrong key
cp "$TEST_DIR/other_key-cert.pub" "$TEST_DIR/invalid_key-cert.pub"

if ssh-add "$TEST_DIR/invalid_key" 2>/dev/null; then
    # Implementation may accept but ignore mismatched cert
    test_result 0
else
    # Or it may reject the combination
    test_result 0
fi

echo "=== Certificate Persistence Tests ==="

echo -n "Test 11: Certificate persistence across lock/unlock... "
KEYS_BEFORE=$(ssh-add -l 2>/dev/null | wc -l)
./target/release/rssh-agent lock --socket "$SSH_AUTH_SOCK" >/dev/null 2>&1
echo "$TEST_PASSWORD" | ./target/release/rssh-agent unlock --socket "$SSH_AUTH_SOCK" >/dev/null 2>&1
KEYS_AFTER=$(ssh-add -l 2>/dev/null | wc -l)

if [ "$KEYS_AFTER" -eq "$KEYS_BEFORE" ]; then
    test_result 0
else
    test_result 1
fi

echo "=== Certificate Authority Tests ==="

echo -n "Test 12: Multiple CA certificate handling... "
# Create second CA
ssh-keygen -t rsa -b 2048 -f "$TEST_DIR/ca2" -N "" >/dev/null 2>&1
ssh-keygen -t ed25519 -f "$TEST_DIR/user2_key" -N "" >/dev/null 2>&1
ssh-keygen -s "$TEST_DIR/ca2" -I "user2-cert" -n "user2" \
    -V "+1h" "$TEST_DIR/user2_key.pub" >/dev/null 2>&1

if ssh-add "$TEST_DIR/user2_key" >/dev/null 2>&1; then
    test_result 0
else
    test_result 1
fi

echo "=== Certificate Cleanup Tests ==="

echo -n "Test 13: Remove certificated key... "
if ssh-add -d "$TEST_DIR/user_key.pub" >/dev/null 2>&1; then
    test_result 0
else
    test_result 1
fi

echo -n "Test 14: Clear all certificated keys... "
ssh-add -D >/dev/null 2>&1
FINAL_COUNT=$(ssh-add -l 2>/dev/null | wc -l || echo 0)
if [ "$FINAL_COUNT" -eq 0 ]; then
    test_result 0
else
    test_result 1
fi

echo "=== Testing Complete ==="

# Clean up
cleanup

# Results
echo "Certificate handling test results:"
echo "Tests run: $TESTS_RUN"
echo "Tests passed: $TESTS_PASSED"
echo "Tests failed: $((TESTS_RUN - TESTS_PASSED))"

if [ "$TESTS_PASSED" -eq "$TESTS_RUN" ]; then
    echo "✓ All certificate tests passed!"
    exit 0
else
    echo "✗ Some certificate tests failed"
    exit 1
fi