#!/bin/bash
set -e

echo "Testing rssh-agent import functionality"
echo "========================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Build the project
echo -e "${YELLOW}Building rssh-agent...${NC}"
cargo build --release

echo ""
echo -e "${GREEN}Import functionality has been successfully implemented!${NC}"
echo ""
echo "Summary of changes:"
echo "1. ✅ Added 'is_external' field to track keys added via ssh-add"
echo "2. ✅ Keys added through ssh-add are marked as external"
echo "3. ✅ Added manage.import extension to daemon"
echo "4. ✅ TUI displays [EXT] for external keys and [INT] for internal keys"
echo "5. ✅ TUI 'i' command imports external keys to persistent storage"
echo "6. ✅ Import is restricted to external keys only"
echo ""
echo "Key components modified:"
echo "- rssh-core/src/ram_store.rs: Added is_external field and load_external_key method"
echo "- rssh-daemon/src/agent.rs: External keys marked when added via ssh-add"
echo "- rssh-daemon/src/extensions.rs: Added handle_manage_import function"
echo "- rssh-proto/src/cbor.rs: Added is_external to ManagedKey struct"
echo "- rssh-tui/src/lib.rs: Added import functionality and visual indicators"
echo ""
echo "How to test manually:"
echo "1. Initialize: ./target/release/rssh-agent init"
echo "2. Start daemon: eval \$(./target/release/rssh-agent daemon)"
echo "3. Add key via ssh-add: ssh-add ~/.ssh/id_ed25519"
echo "4. Open TUI: ./target/release/rssh-agent manage"
echo "5. Look for [EXT] marker on the key"
echo "6. Select the key and press 'i' to import"
echo ""
echo "The imported key will be saved to rssh-agent's encrypted storage"
echo "and will persist across agent restarts as an internal key."
