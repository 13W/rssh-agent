#!/bin/bash
set -e

echo "Testing rssh-agent import functionality fixes"
echo "=============================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

# Build the project
echo -e "${YELLOW}Building rssh-agent...${NC}"
cargo build

# Create test keys
echo -e "${YELLOW}Creating test SSH keys...${NC}"

# Create unprotected Ed25519 key
UNPROTECTED_KEY="$TEST_DIR/unprotected_key"
ssh-keygen -t ed25519 -f "$UNPROTECTED_KEY" -N "" -C "unprotected@test.com"

# Create password-protected Ed25519 key
PROTECTED_KEY="$TEST_DIR/protected_key"
ssh-keygen -t ed25519 -f "$PROTECTED_KEY" -N "mypassword" -C "protected@test.com"

echo -e "${BLUE}Created test keys:${NC}"
echo "  Unprotected: $UNPROTECTED_KEY"
echo "  Protected: $PROTECTED_KEY"

# Create askpass script for agent initialization
ASKPASS_SCRIPT="$TEST_DIR/askpass.sh"
cat > "$ASKPASS_SCRIPT" << 'EOF'
#!/bin/bash
echo "agentmaster123"
EOF
chmod +x "$ASKPASS_SCRIPT"

export SSH_ASKPASS="$ASKPASS_SCRIPT"
export SSH_ASKPASS_REQUIRE="force"

# Initialize the agent
echo -e "${YELLOW}Initializing agent...${NC}"
./target/debug/rssh-agent init --dir "$TEST_DIR"

# Start the daemon in the background
echo -e "${YELLOW}Starting daemon...${NC}"
./target/debug/rssh-agent daemon --dir "$TEST_DIR" --foreground &
DAEMON_PID=$!
sleep 2

# Find the socket
export SSH_AUTH_SOCK=$(find /tmp -name "agent.*" -path "*/ssh-*" 2>/dev/null | head -1)
if [ -z "$SSH_AUTH_SOCK" ]; then
    echo -e "${RED}Failed to find agent socket${NC}"
    exit 1
fi
echo "Agent socket: $SSH_AUTH_SOCK"

# Unlock the agent
echo -e "${YELLOW}Unlocking agent...${NC}"
./target/debug/rssh-agent unlock

echo ""
echo "=== TESTING IMPORT FIXES ==="
echo ""

# Test 1: Import unprotected key with custom description
echo -e "${BLUE}Test 1: Import unprotected key with custom description${NC}"
./target/debug/rssh-agent import "$UNPROTECTED_KEY" --description "My Custom Unprotected Key" << 'EOF'
n
EOF

# Test 2: Import protected key preserving original protection
echo -e "${BLUE}Test 2: Import protected key preserving original protection${NC}"
./target/debug/rssh-agent import "$PROTECTED_KEY" --description "My Custom Protected Key" << 'EOF'
n
EOF

# Test 3: Import unprotected key with --protect flag
echo -e "${BLUE}Test 3: Import unprotected key with --protect flag${NC}"
./target/debug/rssh-agent import "$UNPROTECTED_KEY" --description "Protected Version" --protect << 'EOF'
newpassword123
n
EOF

echo ""
echo -e "${GREEN}All tests completed! Check the output above to verify:${NC}"
echo "1. Custom descriptions are preserved (not overwritten with 'Imported from...')"
echo "2. Password protection is detected and preserved"
echo "3. No password prompts during import (only when loading to memory)"
echo "4. Import asks if you want to load to memory after saving to disk"
echo ""

echo -e "${YELLOW}Checking agent status...${NC}"
./target/debug/rssh-agent manage --list-keys