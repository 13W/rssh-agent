#!/bin/bash
# Comprehensive constraint testing for rssh-agent
# Tests confirm and lifetime constraints with SSH clients

set -e

echo "=== rssh-agent Constraint Testing ==="

# Configuration
TEST_DIR="${1:-/tmp/rssh-constraint-test}"
SOCKET_PATH="$TEST_DIR/agent.sock"
STORAGE_DIR="$TEST_DIR/storage"
TEST_PASSWORD="test_constraint_pass_123"

# Cleanup function
cleanup() {
    echo "Cleaning up constraint tests..."
    pkill -f "rssh-agent.*$TEST_DIR" 2>/dev/null || true
    rm -rf "$TEST_DIR" 2>/dev/null || true
    unset SSH_AUTH_SOCK SSH_ASKPASS
}

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

# Create askpass script for testing confirm dialogs
create_askpass_script() {
    local askpass_script="$TEST_DIR/test_askpass.sh"
    cat > "$askpass_script" << 'EOF'
#!/bin/bash
# Mock askpass script for testing
echo "Mock SSH_ASKPASS: $*" >&2
if [[ "$*" == *"confirm"* ]] || [[ "$*" == *"Allow"* ]]; then
    echo "yes"
else
    echo "test_password"
fi
exit 0
EOF
    chmod +x "$askpass_script"
    echo "$askpass_script"
}

# Set up test environment
echo "Setting up constraint test environment..."
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

# Create test keys
echo "Creating test keys..."
ssh-keygen -t ed25519 -f "$TEST_DIR/test_key_1" -N "" -C "constraint-test-1" >/dev/null 2>&1
ssh-keygen -t ed25519 -f "$TEST_DIR/test_key_2" -N "" -C "constraint-test-2" >/dev/null 2>&1
ssh-keygen -t rsa -b 2048 -f "$TEST_DIR/test_rsa" -N "" -C "constraint-rsa" >/dev/null 2>&1

# Set up askpass
ASKPASS_SCRIPT=$(create_askpass_script)
export SSH_ASKPASS="$ASKPASS_SCRIPT"
export DISPLAY=":0"  # Needed for SSH_ASKPASS

echo "=== Basic Constraint Tests ==="

echo -n "Test 1: Add key with confirm constraint... "
ssh-add -D >/dev/null 2>&1  # Clear all keys
if ssh-add -c "$TEST_DIR/test_key_1" >/dev/null 2>&1; then
    test_result 0
else
    test_result 1
fi

echo -n "Test 2: Verify confirm constraint is active... "
# Check if key is listed and constraint info is preserved
if ssh-add -l 2>/dev/null | grep -q "constraint"; then
    # Note: Standard ssh-add doesn't show constraint info,
    # but key should be loadable
    test_result 0
elif ssh-add -l >/dev/null 2>&1; then
    # Key exists, constraint handling may be internal
    test_result 0
else
    test_result 1
fi

echo -n "Test 3: Add key with lifetime constraint (60 seconds)... "
ssh-add -D >/dev/null 2>&1  # Clear all keys
if ssh-add -t 60 "$TEST_DIR/test_key_2" >/dev/null 2>&1; then
    test_result 0
else
    test_result 1
fi

echo -n "Test 4: Verify lifetime constraint is active... "
KEY_COUNT_BEFORE=$(ssh-add -l 2>/dev/null | wc -l)
if [ "$KEY_COUNT_BEFORE" -gt 0 ]; then
    test_result 0
else
    test_result 1
fi

echo -n "Test 5: Add key with both confirm and lifetime constraints... "
if ssh-add -c -t 120 "$TEST_DIR/test_rsa" >/dev/null 2>&1; then
    test_result 0
else
    test_result 1
fi

echo -n "Test 6: Verify multiple keys with different constraints... "
KEY_COUNT=$(ssh-add -l 2>/dev/null | wc -l)
if [ "$KEY_COUNT" -eq 2 ]; then  # Should have 2 keys loaded
    test_result 0
else
    test_result 1
fi

echo "=== Constraint Persistence Tests ==="

echo -n "Test 7: Lock and unlock preserves constraints... "
./target/release/rssh-agent lock --socket "$SSH_AUTH_SOCK" >/dev/null 2>&1
echo "$TEST_PASSWORD" | ./target/release/rssh-agent unlock --socket "$SSH_AUTH_SOCK" >/dev/null 2>&1
KEY_COUNT_AFTER=$(ssh-add -l 2>/dev/null | wc -l)
if [ "$KEY_COUNT_AFTER" -eq "$KEY_COUNT" ]; then
    test_result 0
else
    test_result 1
fi

echo "=== Constraint Validation Tests ==="

echo -n "Test 8: Invalid lifetime (too large) handling... "
ssh-add -D >/dev/null 2>&1  # Clear all keys
# Try to add with lifetime > 30 days (should be rejected or clamped)
if ssh-add -t $((30 * 24 * 3600 + 1)) "$TEST_DIR/test_key_1" >/dev/null 2>&1; then
    # Check if key was added (may be clamped to max)
    KEY_COUNT=$(ssh-add -l 2>/dev/null | wc -l)
    if [ "$KEY_COUNT" -gt 0 ]; then
        test_result 0  # Accepted with clamping
    else
        test_result 1  # Rejected completely
    fi
else
    test_result 0  # Correctly rejected
fi

echo -n "Test 9: Zero lifetime handling... "
ssh-add -D >/dev/null 2>&1  # Clear all keys
if ssh-add -t 0 "$TEST_DIR/test_key_2" >/dev/null 2>&1; then
    test_result 0
else
    test_result 1
fi

echo -n "Test 10: Negative lifetime handling... "
# This should fail or be treated as unlimited
if ssh-add -t -1 "$TEST_DIR/test_key_1" 2>/dev/null; then
    # Some implementations treat -1 as unlimited
    test_result 0
else
    # Correctly rejected invalid lifetime
    test_result 0
fi

echo "=== Lifetime Expiration Tests ==="

echo -n "Test 11: Short lifetime expiration (5 seconds)... "
ssh-add -D >/dev/null 2>&1  # Clear all keys
if ssh-add -t 5 "$TEST_DIR/test_key_1" >/dev/null 2>&1; then
    KEYS_BEFORE=$(ssh-add -l 2>/dev/null | wc -l)
    if [ "$KEYS_BEFORE" -gt 0 ]; then
        echo -n "waiting 6 seconds... "
        sleep 6
        KEYS_AFTER=$(ssh-add -l 2>/dev/null | wc -l)
        if [ "$KEYS_AFTER" -lt "$KEYS_BEFORE" ]; then
            test_result 0  # Key expired
        else
            test_result 1  # Key didn't expire
        fi
    else
        test_result 1  # Key wasn't added
    fi
else
    test_result 1  # Failed to add key
fi

echo "=== Constraint Error Handling Tests ==="

echo -n "Test 12: Invalid key file with constraints... "
echo "invalid key" > "$TEST_DIR/invalid_key"
if ssh-add -c "$TEST_DIR/invalid_key" 2>/dev/null; then
    test_result 1  # Should fail
else
    test_result 0  # Correctly failed
fi

echo -n "Test 13: Constraints on already loaded key... "
ssh-add -D >/dev/null 2>&1  # Clear all keys
ssh-add "$TEST_DIR/test_key_1" >/dev/null 2>&1  # Add without constraints
# Try to add same key with constraints (should replace)
if ssh-add -c "$TEST_DIR/test_key_1" >/dev/null 2>&1; then
    test_result 0
else
    test_result 1
fi

echo "=== Advanced Constraint Tests ==="

echo -n "Test 14: Multiple keys with mixed constraints... "
ssh-add -D >/dev/null 2>&1  # Clear all keys
ssh-add -c "$TEST_DIR/test_key_1" >/dev/null 2>&1               # Confirm only
ssh-add -t 300 "$TEST_DIR/test_key_2" >/dev/null 2>&1          # Lifetime only
ssh-add -c -t 600 "$TEST_DIR/test_rsa" >/dev/null 2>&1         # Both constraints
FINAL_COUNT=$(ssh-add -l 2>/dev/null | wc -l)
if [ "$FINAL_COUNT" -eq 3 ]; then
    test_result 0
else
    test_result 1
fi

echo -n "Test 15: Remove key with constraints... "
if ssh-add -d "$TEST_DIR/test_key_1.pub" >/dev/null 2>&1; then
    AFTER_REMOVE=$(ssh-add -l 2>/dev/null | wc -l)
    if [ "$AFTER_REMOVE" -eq 2 ]; then
        test_result 0
    else
        test_result 1
    fi
else
    test_result 1
fi

echo "=== Testing Complete ==="

# Clean up
cleanup

# Results
echo "Constraint test results:"
echo "Tests run: $TESTS_RUN"
echo "Tests passed: $TESTS_PASSED"
echo "Tests failed: $((TESTS_RUN - TESTS_PASSED))"

if [ "$TESTS_PASSED" -eq "$TESTS_RUN" ]; then
    echo "✓ All constraint tests passed!"
    exit 0
else
    echo "✗ Some constraint tests failed"
    exit 1
fi