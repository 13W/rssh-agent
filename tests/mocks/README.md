Mock Data Files
===============

SSH Agent Protocol Mocks:
01_list_empty: Request identities when agent is empty
02_list_one_key: Request identities with one ED25519 key
03_remove_all: Remove all identities
04_sign_request: Sign data with ED25519 key
05_extension_list: Extension request for manage list command

Manage Extension Mocks:
06_manage_list: List keys via manage extension (CBOR format)
07_manage_add: Add key via manage extension (CBOR format)
08_manage_remove: Remove key via manage extension (CBOR format)
09_manage_list_with_keys: Response with key list (CBOR format)

Each mock has:
- .request file: The SSH agent protocol request message
- .response file: The expected response message (where applicable)

Message format:
- 4 bytes: message length (big-endian)
- N bytes: message data (first byte is message type)

Extension format (for manage operations):
- Message type: 27 (SSH_AGENTC_EXTENSION)
- Extension namespace: "rssh.manage" (length-prefixed string)
- CBOR data: ExtensionRequest { extension: str, data: bytes }
