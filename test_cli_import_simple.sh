#!/bin/bash
set -e

echo "Testing CLI import functionality fixes (simple)"
echo "==============================================="

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

# Create test keys first
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
echo ""

# Verify key encryption status
echo -e "${YELLOW}Verifying key protection status:${NC}"
if grep -q "ENCRYPTED" "$UNPROTECTED_KEY"; then
    echo "Unprotected key: ENCRYPTED (unexpected)"
else
    echo "Unprotected key: NOT ENCRYPTED (expected)"
fi

if grep -q "ENCRYPTED" "$PROTECTED_KEY"; then
    echo "Protected key: ENCRYPTED (expected)"
else
    echo "Protected key: NOT ENCRYPTED (unexpected)"
fi

echo ""
echo -e "${YELLOW}Key contents preview:${NC}"
echo "Unprotected key header:"
head -2 "$UNPROTECTED_KEY"
echo ""
echo "Protected key header:"
head -2 "$PROTECTED_KEY"
echo ""

echo -e "${GREEN}Test setup completed!${NC}"
echo ""
echo "Now you can manually test the import fixes:"
echo "1. Initialize agent: ./target/debug/rssh-agent init --dir $TEST_DIR"
echo "2. Start daemon: ./target/debug/rssh-agent daemon --dir $TEST_DIR --foreground &"
echo "3. Unlock agent: ./target/debug/rssh-agent unlock"
echo "4. Test imports:"
echo "   # Test custom description preservation:"
echo "   ./target/debug/rssh-agent import $UNPROTECTED_KEY --description \"My Custom Description\""
echo ""
echo "   # Test password protection preservation:"
echo "   ./target/debug/rssh-agent import $PROTECTED_KEY --description \"My Protected Key\""
echo ""
echo "Expected behavior:"
echo "- No password prompts during import (unless --protect used)"
echo "- Custom descriptions preserved"
echo "- Password protection status preserved"
echo "- Only prompts for password when loading to memory"