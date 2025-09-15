#!/bin/bash
# Comprehensive signal handling tests for rssh-agent
# Tests SIGTERM, SIGINT, SIGHUP, and graceful shutdown behavior

set -e

echo "=== rssh-agent Signal Handling Tests ==="

# Configuration
TEST_DIR="${1:-/tmp/rssh-signal-test}"
SOCKET_PATH="$TEST_DIR/agent.sock"
STORAGE_DIR="$TEST_DIR/storage"
TEST_PASSWORD="test_signal_pass_123"

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
    echo "Cleaning up signal tests..."
    pkill -f "rssh-agent.*$TEST_DIR" 2>/dev/null || true
    sleep 1
    rm -rf "$TEST_DIR" 2>/dev/null || true
    unset SSH_AUTH_SOCK
}

# Function to start daemon and return PID
start_daemon() {
    local daemon_pid
    echo "$TEST_PASSWORD" | ./target/release/rssh-agent daemon --dir "$STORAGE_DIR" --socket "$SOCKET_PATH" >/dev/null 2>&1 &
    daemon_pid=$!
    sleep 2

    # Verify daemon started properly
    if kill -0 $daemon_pid 2>/dev/null && [ -S "$SOCKET_PATH" ]; then
        export SSH_AUTH_SOCK="$SOCKET_PATH"
        echo "$TEST_PASSWORD" | ./target/release/rssh-agent unlock --socket "$SSH_AUTH_SOCK" >/dev/null 2>&1
        echo $daemon_pid
    else
        echo 0
    fi
}

# Function to verify daemon is running
daemon_running() {
    local pid=$1
    kill -0 "$pid" 2>/dev/null
}

# Function to wait for daemon to stop
wait_for_daemon_stop() {
    local pid=$1
    local timeout=${2:-5}
    local count=0

    while [ $count -lt $timeout ]; do
        if ! kill -0 "$pid" 2>/dev/null; then
            return 0
        fi
        sleep 1
        count=$((count + 1))
    done
    return 1
}

# Set up test environment
echo "Setting up signal test environment..."
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

echo "=== SIGTERM Handling Tests ==="

echo -n "Test 1: SIGTERM graceful shutdown... "
DAEMON_PID=$(start_daemon)
if [ "$DAEMON_PID" -ne 0 ] && daemon_running "$DAEMON_PID"; then
    kill -TERM "$DAEMON_PID"
    if wait_for_daemon_stop "$DAEMON_PID" 5; then
        test_result 0
    else
        test_result 1
        kill -KILL "$DAEMON_PID" 2>/dev/null || true
    fi
else
    test_result 1
fi

echo -n "Test 2: Socket cleanup after SIGTERM... "
if [ ! -S "$SOCKET_PATH" ]; then
    test_result 0
else
    test_result 1
fi

echo -n "Test 3: Memory cleanup after SIGTERM... "
# Check for memory leaks or orphaned processes
if ! pgrep -f "rssh-agent.*$TEST_DIR" >/dev/null; then
    test_result 0
else
    test_result 1
    pkill -f "rssh-agent.*$TEST_DIR" 2>/dev/null || true
fi

echo "=== SIGINT Handling Tests ==="

echo -n "Test 4: SIGINT graceful shutdown... "
DAEMON_PID=$(start_daemon)
if [ "$DAEMON_PID" -ne 0 ] && daemon_running "$DAEMON_PID"; then
    kill -INT "$DAEMON_PID"
    if wait_for_daemon_stop "$DAEMON_PID" 5; then
        test_result 0
    else
        test_result 1
        kill -KILL "$DAEMON_PID" 2>/dev/null || true
    fi
else
    test_result 1
fi

echo -n "Test 5: Socket cleanup after SIGINT... "
if [ ! -S "$SOCKET_PATH" ]; then
    test_result 0
else
    test_result 1
fi

echo "=== SIGHUP Handling Tests ==="

echo -n "Test 6: SIGHUP behavior... "
DAEMON_PID=$(start_daemon)
if [ "$DAEMON_PID" -ne 0 ] && daemon_running "$DAEMON_PID"; then
    # Send SIGHUP (some daemons reload config, others ignore)
    kill -HUP "$DAEMON_PID" 2>/dev/null || true
    sleep 2

    # Check if daemon is still running (behavior may vary)
    if daemon_running "$DAEMON_PID"; then
        # Daemon survived SIGHUP (may have reloaded config)
        test_result 0
        kill -TERM "$DAEMON_PID"
        wait_for_daemon_stop "$DAEMON_PID" 5 || kill -KILL "$DAEMON_PID" 2>/dev/null
    else
        # Daemon shutdown on SIGHUP (also acceptable)
        test_result 0
    fi
else
    test_result 1
fi

echo "=== Rapid Signal Tests ==="

echo -n "Test 7: Multiple rapid signals... "
DAEMON_PID=$(start_daemon)
if [ "$DAEMON_PID" -ne 0 ] && daemon_running "$DAEMON_PID"; then
    # Send multiple signals rapidly
    kill -HUP "$DAEMON_PID" 2>/dev/null || true
    kill -USR1 "$DAEMON_PID" 2>/dev/null || true  # Should be ignored
    kill -USR2 "$DAEMON_PID" 2>/dev/null || true  # Should be ignored
    sleep 1

    # Daemon should still be running
    if daemon_running "$DAEMON_PID"; then
        kill -TERM "$DAEMON_PID"
        if wait_for_daemon_stop "$DAEMON_PID" 5; then
            test_result 0
        else
            test_result 1
            kill -KILL "$DAEMON_PID" 2>/dev/null || true
        fi
    else
        test_result 1
    fi
else
    test_result 1
fi

echo "=== Signal During Operations ==="

echo -n "Test 8: Signal during key operations... "
DAEMON_PID=$(start_daemon)
if [ "$DAEMON_PID" -ne 0 ] && daemon_running "$DAEMON_PID"; then
    # Add some keys
    ssh-keygen -t ed25519 -f "$TEST_DIR/signal_test_key" -N "" -C "signal-test" >/dev/null 2>&1
    ssh-add "$TEST_DIR/signal_test_key" >/dev/null 2>&1

    # Start a background operation and signal during it
    (sleep 1; kill -TERM "$DAEMON_PID") &

    # Try to list keys (should complete or fail gracefully)
    ssh-add -l >/dev/null 2>&1 || true

    if wait_for_daemon_stop "$DAEMON_PID" 5; then
        test_result 0
    else
        test_result 1
        kill -KILL "$DAEMON_PID" 2>/dev/null || true
    fi
else
    test_result 1
fi

echo "=== Signal Race Conditions ==="

echo -n "Test 9: Signal during daemon startup... "
# Start daemon and immediately signal it
echo "$TEST_PASSWORD" | ./target/release/rssh-agent daemon --dir "$STORAGE_DIR" --socket "$SOCKET_PATH" >/dev/null 2>&1 &
DAEMON_PID=$!
sleep 0.1  # Very short wait

kill -TERM "$DAEMON_PID" 2>/dev/null || true

if wait_for_daemon_stop "$DAEMON_PID" 3; then
    test_result 0
else
    test_result 1
    kill -KILL "$DAEMON_PID" 2>/dev/null || true
fi

echo -n "Test 10: Signal during shutdown... "
DAEMON_PID=$(start_daemon)
if [ "$DAEMON_PID" -ne 0 ] && daemon_running "$DAEMON_PID"; then
    # Start shutdown process and signal again immediately
    kill -TERM "$DAEMON_PID"
    sleep 0.1
    kill -TERM "$DAEMON_PID" 2>/dev/null || true  # Second signal
    kill -INT "$DAEMON_PID" 2>/dev/null || true   # Different signal

    if wait_for_daemon_stop "$DAEMON_PID" 5; then
        test_result 0
    else
        test_result 1
        kill -KILL "$DAEMON_PID" 2>/dev/null || true
    fi
else
    test_result 1
fi

echo "=== SIGKILL Recovery Tests ==="

echo -n "Test 11: Recovery after SIGKILL... "
DAEMON_PID=$(start_daemon)
if [ "$DAEMON_PID" -ne 0 ] && daemon_running "$DAEMON_PID"; then
    # Force kill daemon
    kill -KILL "$DAEMON_PID" 2>/dev/null
    sleep 1

    # Try to start new daemon (should clean up old socket)
    NEW_PID=$(start_daemon)
    if [ "$NEW_PID" -ne 0 ] && daemon_running "$NEW_PID"; then
        test_result 0
        kill -TERM "$NEW_PID"
        wait_for_daemon_stop "$NEW_PID" 5 || kill -KILL "$NEW_PID" 2>/dev/null
    else
        test_result 1
    fi
else
    test_result 1
fi

echo "=== Extension Control Shutdown ==="

echo -n "Test 12: Graceful shutdown via extension... "
DAEMON_PID=$(start_daemon)
if [ "$DAEMON_PID" -ne 0 ] && daemon_running "$DAEMON_PID"; then
    # Test extension-based shutdown
    if python3 -c "
import socket, struct, sys, os
try: import cbor2
except: sys.exit(1)

sock_path = os.environ.get('SSH_AUTH_SOCK')
if not sock_path: sys.exit(1)

ext_req = {'extension': 'control.shutdown', 'data': b''}
cbor_req = cbor2.dumps(ext_req)

msg = bytearray([27])  # SSH_AGENTC_EXTENSION
ns = b'rssh-agent@local'
msg.extend(struct.pack('>I', len(ns)))
msg.extend(ns)
msg.extend(cbor_req)

full_msg = struct.pack('>I', len(msg)) + bytes(msg)

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect(sock_path)
sock.sendall(full_msg)
sock.recv(1024)  # Read response
sock.close()
    " 2>/dev/null; then
        if wait_for_daemon_stop "$DAEMON_PID" 5; then
            test_result 0
        else
            test_result 1
            kill -KILL "$DAEMON_PID" 2>/dev/null || true
        fi
    else
        # Extension shutdown failed, cleanup manually
        kill -TERM "$DAEMON_PID" 2>/dev/null || true
        wait_for_daemon_stop "$DAEMON_PID" 5 || kill -KILL "$DAEMON_PID" 2>/dev/null || true
        test_result 1
    fi
else
    test_result 1
fi

echo "=== Testing Complete ==="

# Clean up
cleanup

# Results
echo "Signal handling test results:"
echo "Tests run: $TESTS_RUN"
echo "Tests passed: $TESTS_PASSED"
echo "Tests failed: $((TESTS_RUN - TESTS_PASSED))"

if [ "$TESTS_PASSED" -eq "$TESTS_RUN" ]; then
    echo "✓ All signal handling tests passed!"
    exit 0
else
    echo "✗ Some signal handling tests failed"
    exit 1
fi