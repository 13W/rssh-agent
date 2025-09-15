#!/bin/bash
set -e

echo "Testing new direct import functionality"
echo "======================================"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Test directory
TEST_DIR=$(mktemp -d)
echo "Using test directory: $TEST_DIR"

# Cleanup on exit
cleanup() {
    echo "Cleaning up..."
    pkill -f "rssh-agent daemon" 2>/dev/null || true
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

# Kill any existing daemon
pkill -f "rssh-agent daemon" 2>/dev/null || true
unset SSH_AUTH_SOCK
sleep 1

# Build the project
echo -e "${YELLOW}Building rssh-agent...${NC}"
cargo build --release

# Create askpass script
ASKPASS_SCRIPT="$TEST_DIR/askpass.sh"
cat > "$ASKPASS_SCRIPT" << 'ASKPASS_EOF'
#!/bin/bash
echo "testpassword"
ASKPASS_EOF
chmod +x "$ASKPASS_SCRIPT"

export SSH_ASKPASS="$ASKPASS_SCRIPT"
export SSH_ASKPASS_REQUIRE="force"

# Initialize the agent
echo -e "${YELLOW}Initializing agent...${NC}"
./target/release/rssh-agent init --dir "$TEST_DIR"

# Start the daemon and capture output
echo -e "${YELLOW}Starting daemon...${NC}"
DAEMON_OUTPUT=$(./target/release/rssh-agent daemon --dir "$TEST_DIR" 2>&1)
eval "$DAEMON_OUTPUT"

if [ -z "$SSH_AUTH_SOCK" ]; then
    echo -e "${RED}Failed to start daemon. Output: $DAEMON_OUTPUT${NC}"
    exit 1
fi

echo "Agent socket: $SSH_AUTH_SOCK"

# Unlock the agent
echo -e "${YELLOW}Unlocking agent...${NC}"
./target/release/rssh-agent unlock

# Generate a test SSH key
TEST_KEY="$TEST_DIR/test_key"
echo -e "${YELLOW}Generating test SSH key...${NC}"
ssh-keygen -t ed25519 -f "$TEST_KEY" -N "" -C "test@example.com"

# Test the new import command without password protection
echo -e "${YELLOW}Testing import without password protection...${NC}"
echo "n" | ./target/release/rssh-agent import "$TEST_KEY" --description "Test imported key"

echo ""
echo -e "${GREEN}Import test completed successfully!${NC}"
