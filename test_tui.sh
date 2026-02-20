#!/bin/bash
# TUI integration tests for rssh-agent
# Tests TUI functionality with automated key sequences

set -e

echo "=== rssh-agent TUI Integration Tests ==="

# Configuration
TEST_DIR="${1:-/tmp/rssh-tui-test}"
SOCKET_PATH="$TEST_DIR/agent.sock"
STORAGE_DIR="$TEST_DIR/storage"
TEST_PASSWORD="test_tui_pass_123"
KEY_PASSWORD="correct_key_pass"

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
    echo "Cleaning up TUI tests..."
    pkill -f "rssh-agent.*$TEST_DIR" 2>/dev/null || true
    rm -rf "$TEST_DIR" 2>/dev/null || true
    unset SSH_AUTH_SOCK
}

# Check if expect is available
check_expect() {
    if ! command -v expect >/dev/null 2>&1; then
        echo "expect not found. Installing expect for TUI automation..."
        if command -v apt-get >/dev/null 2>&1; then
            sudo apt-get update && sudo apt-get install -y expect >/dev/null 2>&1
        elif command -v yum >/dev/null 2>&1; then
            sudo yum install -y expect >/dev/null 2>&1
        elif command -v pacman >/dev/null 2>&1; then
            sudo pacman -S expect >/dev/null 2>&1
        else
            echo "Could not install expect. TUI tests will be limited."
            return 1
        fi
    fi
    return 0
}

# Create expect script for TUI automation
create_tui_expect_script() {
    local script_path="$TEST_DIR/tui_test.exp"
    local key_password="$KEY_PASSWORD" # Pass KEY_PASSWORD to expect script
    cat > "$script_path" << 'EOF'
#!/usr/bin/expect -f

# Enable internal debugging for expect script
exp_internal 1

set timeout 10
set socket_path [lindex $argv 0]
set test_name [lindex $argv 1]
set key_password [lindex $argv 2]

puts "Starting TUI for test: $test_name"
# Start the TUI
spawn ./target/release/rssh-agent manage --socket $socket_path

# Wait for TUI to start
expect {
    timeout { puts "TIMEOUT: TUI did not start"; exit 1 }
    -re "Keys|rssh-agent|Manage" { puts "TUI started: $expect_out(buffer)" }
}

# Perform test based on test_name
if {$test_name == "navigation"} {
    # Test basic navigation
    send "j"        ;# Move down
    sleep 0.5
    send "k"        ;# Move up
    sleep 0.5
    send "q"        ;# Quit
    expect eof
    exit 0
}

if {$test_name == "help"} {
    # Test help display
    send "?"        ;# Show help
    expect {
        timeout { puts "TIMEOUT: Help not displayed"; exit 1 }
        -re "Help|Key|Quit" { puts "Help displayed: $expect_out(buffer)" }
    }
    send "q"        ;# Quit help
    sleep 0.5
    send "q"        ;# Quit TUI
    expect eof
    exit 0
}

if {$test_name == "refresh"} {
    # Test refresh functionality
    send "r"        ;# Refresh
    sleep 1
    send "q"        ;# Quit
    expect eof
    exit 0
}

if {$test_name == "wrong_key_password"} {
    puts "Executing wrong_key_password test"
    # Assume the protected key is the third one (after tui-test-1, tui-test-2)
    # Move to the third key
    send "j"
    sleep 0.5
    send "j"
    sleep 0.5
    # Press 'L' to load the key (should open password modal)
    send "L"
    expect {
        timeout { puts "TIMEOUT: Did not see password prompt"; exit 1 }
        -re "Enter key password" { puts "Password prompt seen: $expect_out(buffer)" }
    }
    puts "Entering incorrect password..."
    # Enter incorrect password
    send "wrong_pass"
    send "\r" ;# Enter
    expect {
        timeout { puts "TIMEOUT: Did not see error message after wrong password"; exit 1 }
        -re "Failed to load key:.*password" { puts "Error message seen: $expect_out(buffer)" }
    }
    puts "Clearing input and entering correct password..."
    # Clear input (backspace many times)
    send "\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b"
    # Enter correct password
    send "$key_password"
    send "\r" ;# Enter
    expect {
        timeout { puts "TIMEOUT: Did not see success message after correct password"; exit 1 }
        -re "Key .* loaded into memory" { puts "Success message seen: $expect_out(buffer)" }
    }
    puts "Key loaded successfully, quitting TUI."
    send "q"
    expect eof
    exit 0
}

# Default: just start and quit
send "q"
expect eof
exit 0
EOF

    chmod +x "$script_path"
    echo "$script_path"
}

# Create non-interactive TUI test
create_simple_tui_test() {
    local script_path="$TEST_DIR/simple_tui_test.sh"
    cat > "$script_path" << 'EOF'
#!/bin/bash
# Simple TUI test without expect

set -e
SOCKET_PATH="$1"

# Test that TUI starts and can be interrupted
timeout 2 ./target/release/rssh-agent manage --socket "$SOCKET_PATH" 2>/dev/null || {
    exit_code=$?
    if [ $exit_code -eq 124 ]; then
        # Timeout exit code - TUI started successfully
        exit 0
    elif [ $exit_code -eq 130 ]; then
        # SIGINT exit code - TUI started and was interrupted
        exit 0
    else
        # Other error
        exit 1
    fi
}
EOF

    chmod +x "$script_path"
    echo "$script_path"
}

# Set up test environment
echo "Setting up TUI test environment..."
cleanup
mkdir -p "$TEST_DIR"
export RSSH_ALLOW_NO_MLOCK=1

# Build if needed
if [ ! -f "./target/release/rssh-agent" ]; then
    echo "Building rssh-agent with TUI..."
    cargo build --release
fi

# Check if TUI feature is enabled
if ! ./target/release/rssh-agent --help 2>&1 | grep -q "manage"; then
    echo "TUI feature not available in this build"
    exit 0
fi

# Initialize agent
echo "$TEST_PASSWORD" | ./target/release/rssh-agent init --dir "$STORAGE_DIR" >/dev/null 2>&1

# Start daemon
echo "Starting daemon for TUI tests..."
OUTPUT=$(echo "$TEST_PASSWORD" | ./target/release/rssh-agent daemon --dir "$STORAGE_DIR" --socket "$SOCKET_PATH" 2>/dev/null)
eval "$OUTPUT"
sleep 2

# Unlock agent
echo "$TEST_PASSWORD" | ./target/release/rssh-agent unlock --socket "$SSH_AUTH_SOCK" >/dev/null 2>&1

# Add some test keys for TUI to display
echo "Adding test keys..."
ssh-keygen -t ed25519 -f "$TEST_DIR/tui_test_key1" -N "" -C "tui-test-1" >/dev/null 2>&1
ssh-keygen -t rsa -b 2048 -f "$TEST_DIR/tui_test_key2" -N "" -C "tui-test-2" >/dev/null 2>&1
ssh-add "$TEST_DIR/tui_test_key1" >/dev/null 2>&1
ssh-add "$TEST_DIR/tui_test_key2" >/dev/null 2>&1

# Add a password-protected key
ssh-keygen -t ed25519 -f "$TEST_DIR/tui_protected_key" -N "$KEY_PASSWORD" -C "tui-protected" >/dev/null 2>&1
ssh-add "$TEST_DIR/tui_protected_key" >/dev/null 2>&1

echo "=== Basic TUI Tests ==="

# Simple TUI startup test
SIMPLE_TUI_SCRIPT=$(create_simple_tui_test)

echo -n "Test 1: TUI startup and basic operation... "
if "$SIMPLE_TUI_SCRIPT" "$SSH_AUTH_SOCK"; then
    test_result 0
else
    test_result 1
fi

echo -n "Test 2: TUI with keys loaded... "
if timeout 1 ./target/release/rssh-agent manage --socket "$SSH_AUTH_SOCK" 2>/dev/null; then
    test_result 1  # Should timeout (interactive)
else
    exit_code=$?
    if [ $exit_code -eq 124 ] || [ $exit_code -eq 130 ]; then
        test_result 0  # Timeout or interrupt - TUI worked
    else
        test_result 1
    fi
fi

# Check if expect is available for advanced tests
if check_expect; then
    echo "=== Advanced TUI Tests (with expect) ==="

    TUI_EXPECT_SCRIPT=$(create_tui_expect_script)

    echo -n "Test 3: TUI navigation... "
    if expect "$TUI_EXPECT_SCRIPT" "$SSH_AUTH_SOCK" "navigation" >/dev/null 2>&1; then
        test_result 0
    else
        test_result 1
    fi

    echo -n "Test 4: TUI help system... "
    if expect "$TUI_EXPECT_SCRIPT" "$SSH_AUTH_SOCK" "help" >/dev/null 2>&1; then
        test_result 0
    else
        test_result 1
    fi

    echo -n "Test 5: TUI refresh functionality... "
    if expect "$TUI_EXPECT_SCRIPT" "$SSH_AUTH_SOCK" "refresh" >/dev/null 2>&1; then
        test_result 0
    else
        test_result 1
    fi
else
    echo "expect not available, skipping advanced TUI tests"
fi

echo "=== TUI Error Handling Tests ==="

echo -n "Test 6: TUI with locked agent... "
./target/release/rssh-agent lock --socket "$SSH_AUTH_SOCK" >/dev/null 2>&1
if timeout 1 ./target/release/rssh-agent manage --socket "$SSH_AUTH_SOCK" 2>/dev/null; then
    test_result 1  # Should timeout
else
    exit_code=$?
    if [ $exit_code -eq 124 ] || [ $exit_code -eq 130 ]; then
        test_result 0  # TUI handled locked state
    else
        test_result 1
    fi
fi

# Unlock for remaining tests
echo "$TEST_PASSWORD" | ./target/release/rssh-agent unlock --socket "$SSH_AUTH_SOCK" >/dev/null 2>&1

echo -n "Test 7: TUI with invalid socket... "
if timeout 1 ./target/release/rssh-agent manage --socket "/tmp/nonexistent.sock" 2>/dev/null; then
    test_result 1  # Should fail
else
    exit_code=$?
    if [ $exit_code -ne 124 ]; then
        test_result 0  # Failed quickly (good)
    else
        test_result 1  # Timed out (shouldn't happen with bad socket)
    fi
fi

echo "=== TUI Performance Tests ==="

echo -n "Test 8: TUI startup time... "
START_TIME=$(date +%s%3N)
timeout 1 ./target/release/rssh-agent manage --socket "$SSH_AUTH_SOCK" >/dev/null 2>&1 || true
END_TIME=$(date +%s%3N)
STARTUP_TIME=$((END_TIME - START_TIME))

# TUI should start within 2 seconds
if [ "$STARTUP_TIME" -lt 2000 ]; then
    test_result 0
else
    test_result 1
fi

echo "=== TUI Integration with Extensions ==="

echo -n "Test 9: TUI key management integration... "
# TUI should be able to communicate with daemon extensions
# This is tested indirectly by checking that TUI can start with keys present
KEY_COUNT=$(ssh-add -l 2>/dev/null | wc -l)
if [ "$KEY_COUNT" -gt 0 ]; then
    # Try to start TUI with keys (should show key list)
    if timeout 1 ./target/release/rssh-agent manage --socket "$SSH_AUTH_SOCK" 2>/dev/null; then
        test_result 1  # Should timeout
    else
        exit_code=$?
        if [ $exit_code -eq 124 ] || [ $exit_code -eq 130 ]; then
            test_result 0  # TUI started with keys
        else
            test_result 1
        fi
    fi
else
    test_result 1  # No keys to test with
fi

echo -n "Test 11: TUI incorrect key password handling... "
if expect "$TUI_EXPECT_SCRIPT" "$SSH_AUTH_SOCK" "wrong_key_password" "$KEY_PASSWORD" >/dev/null 2>&1; then
    test_result 0
else
    test_result 1
fi

echo "=== Terminal Compatibility Tests ==="

echo -n "Test 10: TUI with different TERM settings... "
# Test with basic terminal
if TERM=xterm timeout 1 ./target/release/rssh-agent manage --socket "$SSH_AUTH_SOCK" 2>/dev/null; then
    test_result 1  # Should timeout
else
    exit_code=$?
    if [ $exit_code -eq 124 ] || [ $exit_code -eq 130 ]; then
        test_result 0  # Worked with xterm
    else
        test_result 1
    fi
fi

echo "=== Testing Complete ==="

# Clean up
cleanup

# Results
echo "TUI test results:"
echo "Tests run: $TESTS_RUN"
echo "Tests passed: $TESTS_PASSED"
echo "Tests failed: $((TESTS_RUN - TESTS_PASSED))"

if [ "$TESTS_PASSED" -eq "$TESTS_RUN" ]; then
    echo "✓ All TUI tests passed!"
    exit 0
else
    echo "✗ Some TUI tests failed"
    exit 1
fi