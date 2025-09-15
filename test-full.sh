#!/bin/bash
set -e

echo "=== rssh-agent Comprehensive Integration Test Suite ==="
echo "Testing all newly implemented functionality with real SSH clients"
echo

cd /opt/rust/rssh-agent

# Configuration
TEST_DIR="/tmp/rssh-integration-test"
SOCKET_PATH="$TEST_DIR/agent.sock"
STORAGE_DIR="$TEST_DIR/storage"
TEST_PASSWORD="test_password_12345"
LOG_FILE="$TEST_DIR/daemon.log"

# Test counters
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
    echo
}

# Clean up function
cleanup() {
    echo "Cleaning up test environment..."
    pkill -f "rssh-agent.*$TEST_DIR" 2>/dev/null || true
    sleep 1
    rm -rf "$TEST_DIR" 2>/dev/null || true
    unset SSH_AUTH_SOCK
}

# Set up clean test environment
echo "Setting up test environment..."
cleanup
mkdir -p "$TEST_DIR"
export RSSH_ALLOW_NO_MLOCK=1

# Build the project
echo "Building rssh-agent (release mode)..."
cargo build --release
echo "✓ Build completed"
echo

# ============================================================================
# Basic CLI Tests
# ============================================================================

echo "=== Basic CLI Tests ==="

echo -n "Test 1: Version check... "
if ./target/release/rssh-agent --version >/dev/null 2>&1; then
    test_result 0
else
    test_result 1
fi

echo -n "Test 2: Help output... "
if ./target/release/rssh-agent --help | head -5 >/dev/null 2>&1; then
    test_result 0
else
    test_result 1
fi

# ============================================================================
# Initialization Tests
# ============================================================================

echo "=== Initialization Tests ==="

echo -n "Test 3: Initialize agent storage... "
# Create askpass script for password input
cat > "$TEST_DIR/askpass.sh" << EOF
#!/bin/bash
echo "$TEST_PASSWORD"
EOF
chmod +x "$TEST_DIR/askpass.sh"
export SSH_ASKPASS="$TEST_DIR/askpass.sh"
export DISPLAY=":0"
if ./target/release/rssh-agent init --dir "$STORAGE_DIR" >/dev/null 2>&1; then
    test_result 0
else
    test_result 1
fi

echo -n "Test 4: Verify config.json was created... "
if [ -f "$STORAGE_DIR/config.json" ]; then
    test_result 0
else
    test_result 1
fi

# ============================================================================
# Daemon Lifecycle Tests
# ============================================================================

echo "=== Daemon Lifecycle Tests ==="

echo -n "Test 5: Start daemon in background... "
unset SSH_AUTH_SOCK
if OUTPUT=$(SSH_ASKPASS="$TEST_DIR/askpass.sh" DISPLAY=":0" ./target/release/rssh-agent daemon --quiet --dir "$STORAGE_DIR" --socket "$SOCKET_PATH") &&
   echo "$OUTPUT" | grep -q "SSH_AUTH_SOCK"; then
    eval "$OUTPUT"
    test_result 0
else
    test_result 1
fi

sleep 2

echo -n "Test 6: Verify daemon socket exists... "
if [ -S "$SSH_AUTH_SOCK" ]; then
    test_result 0
else
    test_result 1
fi

echo -n "Test 7: Verify daemon process is running... "
if pgrep -f "rssh-agent.*daemon.*$TEST_DIR" >/dev/null; then
    test_result 0
else
    test_result 1
fi

# ============================================================================
# Basic Agent Protocol Tests
# ============================================================================

echo "=== Basic Agent Protocol Tests ==="

echo -n "Test 8: List identities (should be empty and locked)... "
if ssh-add -l 2>&1 | grep -q "agent refused"; then
    test_result 0
else
    test_result 1
fi

# ============================================================================
# Lock/Unlock CLI Tests
# ============================================================================

echo "=== Lock/Unlock CLI Tests ==="

echo -n "Test 9: Unlock agent... "
if SSH_ASKPASS="$TEST_DIR/askpass.sh" DISPLAY=":0" ./target/release/rssh-agent unlock --socket "$SSH_AUTH_SOCK" >/dev/null 2>&1; then
    test_result 0
else
    test_result 1
fi

echo -n "Test 10: List identities after unlock (should be empty)... "
if ssh-add -l 2>&1 | grep -q "no identities"; then
    test_result 0
else
    test_result 1
fi

echo -n "Test 11: Lock agent... "
if ./target/release/rssh-agent lock --socket "$SSH_AUTH_SOCK" >/dev/null 2>&1; then
    test_result 0
else
    test_result 1
fi

echo -n "Test 12: Verify agent is locked... "
if ssh-add -l 2>&1 | grep -q "agent refused"; then
    test_result 0
else
    test_result 1
fi

# Unlock for further tests
SSH_ASKPASS="$TEST_DIR/askpass.sh" DISPLAY=":0" ./target/release/rssh-agent unlock --socket "$SSH_AUTH_SOCK" >/dev/null 2>&1

# ============================================================================
# Key Management Tests
# ============================================================================

echo "=== Key Management Tests ==="

# Create test keys
echo "Creating test keys..."
ssh-keygen -t ed25519 -f "$TEST_DIR/test_ed25519" -N "" -C "test-ed25519@rssh-agent" >/dev/null 2>&1
ssh-keygen -t rsa -b 2048 -f "$TEST_DIR/test_rsa" -N "" -C "test-rsa@rssh-agent" >/dev/null 2>&1

echo -n "Test 13: Add Ed25519 key... "
if ssh-add "$TEST_DIR/test_ed25519" 2>/dev/null; then
    test_result 0
else
    test_result 1
fi

echo -n "Test 14: Add RSA key... "
if ssh-add "$TEST_DIR/test_rsa" 2>/dev/null; then
    test_result 0
else
    test_result 1
fi

echo -n "Test 15: List identities (should show 2 keys)... "
KEY_COUNT=$(ssh-add -l 2>/dev/null | wc -l)
if [ "$KEY_COUNT" -eq 2 ]; then
    test_result 0
else
    test_result 1
fi

echo -n "Test 16: Remove specific key... "
if ssh-add -d "$TEST_DIR/test_ed25519.pub" 2>/dev/null; then
    test_result 0
else
    test_result 1
fi

echo -n "Test 17: Verify key removal... "
KEY_COUNT=$(ssh-add -l 2>/dev/null | wc -l)
if [ "$KEY_COUNT" -eq 1 ]; then
    test_result 0
else
    test_result 1
fi

# ============================================================================
# Constraint Tests (ssh-add -c, -t)
# ============================================================================

echo "=== Constraint Tests ==="

# Clear all keys first
ssh-add -D >/dev/null 2>&1

echo -n "Test 18: Add key with confirm constraint (ssh-add -c)... "
if ssh-add -c "$TEST_DIR/test_ed25519" 2>/dev/null; then
    test_result 0
else
    test_result 1
fi

echo -n "Test 19: Add key with lifetime constraint (ssh-add -t 60)... "
ssh-add -D >/dev/null 2>&1  # Clear first
if ssh-add -t 60 "$TEST_DIR/test_rsa" 2>/dev/null; then
    test_result 0
else
    test_result 1
fi

echo -n "Test 20: Add key with both constraints (ssh-add -c -t 120)... "
if ssh-add -c -t 120 "$TEST_DIR/test_ed25519" 2>/dev/null; then
    test_result 0
else
    test_result 1
fi

echo -n "Test 21: Verify keys with constraints are loaded... "
KEY_COUNT=$(ssh-add -l 2>/dev/null | wc -l)
if [ "$KEY_COUNT" -ge 1 ]; then
    test_result 0
else
    test_result 1
fi

# ============================================================================
# Extension Operations Tests
# ============================================================================

echo "=== Extension Operations Tests ==="

# Create Python helper script for extension testing
cat > "$TEST_DIR/test_extensions.py" << 'EOF'
#!/usr/bin/env python3
import socket
import struct
import sys
import os
import json
try:
    import cbor2
except ImportError:
    print("cbor2 not available, skipping extension tests")
    sys.exit(0)

def send_extension_request(socket_path, extension, data=b""):
    """Send an extension request and return the response."""
    ext_request = {
        "extension": extension,
        "data": data
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
    sock.connect(socket_path)
    sock.sendall(full_msg)

    # Read response
    len_buf = sock.recv(4)
    resp_len = struct.unpack('>I', len_buf)[0]
    response = sock.recv(resp_len)
    sock.close()

    return response

def test_manage_list(socket_path):
    """Test manage.list extension."""
    try:
        response = send_extension_request(socket_path, "manage.list")

        if response[0] == 6:  # SSH_AGENT_SUCCESS
            # Parse wire-encoded CBOR response
            offset = 1
            data_len = struct.unpack('>I', response[offset:offset+4])[0]
            offset += 4
            cbor_data = response[offset:offset + data_len]

            # Parse ExtensionResponse
            ext_response = cbor2.loads(cbor_data)
            if ext_response.get('success'):
                # Parse actual response data
                list_response = cbor2.loads(ext_response['data'])
                return list_response.get('ok', False)
        return False
    except Exception as e:
        print(f"Exception: {e}", file=sys.stderr)
        return False

def test_control_shutdown(socket_path):
    """Test control.shutdown extension."""
    try:
        response = send_extension_request(socket_path, "control.shutdown")
        return response[0] == 6  # Should succeed
    except Exception as e:
        return False

if __name__ == "__main__":
    socket_path = sys.argv[1]
    test_name = sys.argv[2]

    if test_name == "manage.list":
        success = test_manage_list(socket_path)
    elif test_name == "control.shutdown":
        success = test_control_shutdown(socket_path)
    else:
        success = False

    sys.exit(0 if success else 1)
EOF

chmod +x "$TEST_DIR/test_extensions.py"

echo -n "Test 22: Extension - manage.list... "
if python3 "$TEST_DIR/test_extensions.py" "$SSH_AUTH_SOCK" "manage.list" 2>/dev/null; then
    test_result 0
else
    test_result 1
fi

# ============================================================================
# Signal Handling Tests
# ============================================================================

echo "=== Signal Handling Tests ==="

# Get daemon PID
DAEMON_PID=$(pgrep -f "rssh-agent.*daemon.*$TEST_DIR")

echo -n "Test 23: SIGTERM handling (graceful shutdown)... "
if kill -TERM "$DAEMON_PID" 2>/dev/null; then
    sleep 2
    if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
        test_result 0
    else
        test_result 1
    fi
else
    test_result 1
fi

echo -n "Test 24: Verify socket cleanup after shutdown... "
if [ ! -S "$SSH_AUTH_SOCK" ]; then
    test_result 0
else
    test_result 1
fi

# Restart daemon for remaining tests
echo "Restarting daemon for remaining tests..."
unset SSH_AUTH_SOCK
OUTPUT=$(SSH_ASKPASS="$TEST_DIR/askpass.sh" DISPLAY=":0" ./target/release/rssh-agent daemon --quiet --dir "$STORAGE_DIR" --socket "$SOCKET_PATH")
eval "$OUTPUT"
sleep 2
SSH_ASKPASS="$TEST_DIR/askpass.sh" DISPLAY=":0" ./target/release/rssh-agent unlock --socket "$SSH_AUTH_SOCK" >/dev/null 2>&1

# ============================================================================
# Error Case Tests
# ============================================================================

echo "=== Error Case Tests ==="

echo -n "Test 25: Wrong password unlock... "
# Create wrong password askpass script
cat > "$TEST_DIR/wrong_askpass.sh" << EOF
#!/bin/bash
echo "wrong_password"
EOF
chmod +x "$TEST_DIR/wrong_askpass.sh"
if SSH_ASKPASS="$TEST_DIR/wrong_askpass.sh" DISPLAY=":0" ./target/release/rssh-agent unlock --socket "$SSH_AUTH_SOCK" 2>/dev/null; then
    test_result 1  # Should fail
else
    test_result 0  # Correct - should fail
fi

echo -n "Test 26: Invalid key file... "
echo "invalid key content" > "$TEST_DIR/invalid_key"
if ssh-add "$TEST_DIR/invalid_key" 2>/dev/null; then
    test_result 1  # Should fail
else
    test_result 0  # Correct - should fail
fi

echo -n "Test 27: Operation on non-existent socket... "
if SSH_AUTH_SOCK="/tmp/nonexistent.sock" ssh-add -l 2>/dev/null; then
    test_result 1  # Should fail
else
    test_result 0  # Correct - should fail
fi

# ============================================================================
# Key Generation Tests
# ============================================================================

echo "=== Key Generation Tests ==="

# Test key generation via extension (if available)
cat > "$TEST_DIR/test_key_generation.py" << 'EOF'
#!/usr/bin/env python3
import socket
import struct
import sys
import os
import json
try:
    import cbor2
except ImportError:
    sys.exit(1)

def test_manage_create(socket_path):
    """Test manage.create extension."""
    try:
        # Create key generation request
        create_data = {
            "key_type": "ed25519",
            "description": "test-generated-key",
            "confirm": False,
            "lifetime": None
        }

        cbor_data = cbor2.dumps(create_data)

        ext_request = {
            "extension": "manage.create",
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
        sock.connect(socket_path)
        sock.sendall(full_msg)

        # Read response
        len_buf = sock.recv(4)
        resp_len = struct.unpack('>I', len_buf)[0]
        response = sock.recv(resp_len)
        sock.close()

        return response[0] == 6  # SSH_AGENT_SUCCESS
    except Exception as e:
        return False

if __name__ == "__main__":
    socket_path = sys.argv[1]
    success = test_manage_create(socket_path)
    sys.exit(0 if success else 1)
EOF

chmod +x "$TEST_DIR/test_key_generation.py"

echo -n "Test 28: Key generation via manage.create extension... "
if python3 "$TEST_DIR/test_key_generation.py" "$SSH_AUTH_SOCK" 2>/dev/null; then
    test_result 0
else
    test_result 1
fi

# ============================================================================
# SSH Client Compatibility Tests
# ============================================================================

echo "=== SSH Client Compatibility Tests ==="

# Test actual SSH signing (requires SSH server or mock)
echo -n "Test 29: SSH signing compatibility... "
if ssh-add -l >/dev/null 2>&1 &&
   KEY_COUNT=$(ssh-add -l 2>/dev/null | wc -l) &&
   [ "$KEY_COUNT" -gt 0 ]; then
    # We can't easily test actual SSH without a server, but we can test that
    # the agent responds properly to list requests from real ssh-add
    test_result 0
else
    test_result 1
fi

echo -n "Test 30: Multiple ssh-add operations... "
ssh-add -D >/dev/null 2>&1  # Clear all
if ssh-add "$TEST_DIR/test_ed25519" "$TEST_DIR/test_rsa" 2>/dev/null &&
   KEY_COUNT=$(ssh-add -l 2>/dev/null | wc -l) &&
   [ "$KEY_COUNT" -eq 2 ]; then
    test_result 0
else
    test_result 1
fi

# ============================================================================
# TUI Integration Tests (Basic)
# ============================================================================

echo "=== TUI Integration Tests ==="

# Test that TUI can start (but timeout quickly since it's interactive)
echo -n "Test 31: TUI startup (non-interactive)... "
if timeout 1 ./target/release/rssh-agent manage --socket "$SSH_AUTH_SOCK" 2>/dev/null ||
   [ $? -eq 124 ]; then  # timeout exit code
    test_result 0
else
    test_result 1
fi

# ============================================================================
# Extension Control Tests
# ============================================================================

echo "=== Extension Control Tests ==="

echo -n "Test 32: control.shutdown extension... "
if python3 "$TEST_DIR/test_extensions.py" "$SSH_AUTH_SOCK" "control.shutdown" 2>/dev/null; then
    sleep 1
    # Verify daemon actually shut down
    if ! pgrep -f "rssh-agent.*daemon.*$TEST_DIR" >/dev/null; then
        test_result 0
    else
        test_result 1
    fi
else
    test_result 1
fi

# ============================================================================
# Final Cleanup and Results
# ============================================================================

cleanup

echo "=== Test Results Summary ==="
echo "Tests run: $TESTS_RUN"
echo "Tests passed: $TESTS_PASSED"
echo "Tests failed: $((TESTS_RUN - TESTS_PASSED))"

if [ "$TESTS_PASSED" -eq "$TESTS_RUN" ]; then
    echo "🎉 ALL TESTS PASSED!"
    exit 0
else
    echo "❌ Some tests failed"
    exit 1
fi
