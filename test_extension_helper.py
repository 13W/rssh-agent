#!/usr/bin/env python3
"""
Comprehensive extension test helper for rssh-agent.
Tests all implemented extension operations with proper CBOR protocol handling.
"""

import socket
import struct
import sys
import os
import json
import tempfile
import subprocess
import time
from pathlib import Path

try:
    import cbor2
    CBOR_AVAILABLE = True
except ImportError:
    CBOR_AVAILABLE = False
    print("Warning: cbor2 not available, extension tests will be skipped")

class ExtensionTester:
    """Helper class for testing rssh-agent extensions."""

    def __init__(self, socket_path):
        self.socket_path = socket_path

    def send_extension_request(self, extension, data=b""):
        """Send an extension request and return the parsed response."""
        if not CBOR_AVAILABLE:
            raise RuntimeError("cbor2 not available")

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
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(5.0)  # 5 second timeout
            sock.connect(self.socket_path)
            sock.sendall(full_msg)

            # Read response
            len_buf = sock.recv(4)
            if len(len_buf) != 4:
                raise RuntimeError("Failed to read response length")

            resp_len = struct.unpack('>I', len_buf)[0]
            response = sock.recv(resp_len)
            sock.close()

            return self._parse_response(response)
        except Exception as e:
            raise RuntimeError(f"Socket communication failed: {e}")

    def _parse_response(self, response):
        """Parse SSH agent response and extract extension data."""
        if len(response) < 1:
            raise RuntimeError("Empty response")

        response_type = response[0]

        if response_type == 5:  # SSH_AGENT_FAILURE
            return {"success": False, "error": "SSH_AGENT_FAILURE", "data": None}
        elif response_type == 6:  # SSH_AGENT_SUCCESS
            try:
                # Parse wire-encoded CBOR response
                offset = 1
                data_len = struct.unpack('>I', response[offset:offset+4])[0]
                offset += 4
                cbor_data = response[offset:offset + data_len]

                # Parse ExtensionResponse
                ext_response = cbor2.loads(cbor_data)

                if ext_response.get('success'):
                    # Try to parse the data field if it exists
                    parsed_data = None
                    if 'data' in ext_response:
                        try:
                            parsed_data = cbor2.loads(ext_response['data'])
                        except:
                            parsed_data = ext_response['data']  # Raw data

                    return {"success": True, "data": parsed_data}
                else:
                    return {"success": False, "error": "Extension returned failure", "data": ext_response.get('data')}
            except Exception as e:
                return {"success": False, "error": f"Failed to parse response: {e}", "data": None}
        else:
            return {"success": False, "error": f"Unknown response type: {response_type}", "data": None}

    def test_manage_list(self):
        """Test manage.list extension."""
        response = self.send_extension_request("manage.list")
        if response["success"] and response["data"]:
            data = response["data"]
            return data.get("ok", False), data.get("keys", [])
        return False, []

    def test_manage_load(self, fingerprint):
        """Test manage.load extension."""
        load_data = {"fingerprint": fingerprint}
        cbor_data = cbor2.dumps(load_data)
        response = self.send_extension_request("manage.load", cbor_data)
        if response["success"] and response["data"]:
            return response["data"].get("ok", False)
        return False

    def test_manage_unload(self, fingerprint):
        """Test manage.unload extension."""
        unload_data = {"fingerprint": fingerprint}
        cbor_data = cbor2.dumps(unload_data)
        response = self.send_extension_request("manage.unload", cbor_data)
        if response["success"] and response["data"]:
            return response["data"].get("ok", False)
        return False

    def test_manage_set_desc(self, fingerprint, description):
        """Test manage.set_desc extension."""
        desc_data = {
            "fingerprint": fingerprint,
            "description": description
        }
        cbor_data = cbor2.dumps(desc_data)
        response = self.send_extension_request("manage.set_desc", cbor_data)
        if response["success"] and response["data"]:
            return response["data"].get("ok", False)
        return False

    def test_manage_create(self, key_type="ed25519", description="test-key", confirm=False, lifetime=None):
        """Test manage.create extension."""
        create_data = {
            "key_type": key_type,
            "description": description,
            "confirm": confirm,
            "lifetime": lifetime
        }
        cbor_data = cbor2.dumps(create_data)
        response = self.send_extension_request("manage.create", cbor_data)
        if response["success"] and response["data"]:
            data = response["data"]
            return data.get("ok", False), data.get("fingerprint")
        return False, None

    def test_manage_import(self, key_path, description="imported-key", load_to_ram=True):
        """Test manage.import extension."""
        with open(key_path, 'rb') as f:
            key_data = f.read()

        import_data = {
            "key_data": key_data,
            "description": description,
            "load_to_ram": load_to_ram
        }
        cbor_data = cbor2.dumps(import_data)
        response = self.send_extension_request("manage.import", cbor_data)
        if response["success"] and response["data"]:
            data = response["data"]
            return data.get("ok", False), data.get("fingerprint")
        return False, None

    def test_manage_change_pass(self, old_password, new_password):
        """Test manage.change_pass extension."""
        change_data = {
            "old_password": old_password,
            "new_password": new_password
        }
        cbor_data = cbor2.dumps(change_data)
        response = self.send_extension_request("manage.change_pass", cbor_data)
        if response["success"] and response["data"]:
            return response["data"].get("ok", False)
        return False

    def test_control_shutdown(self):
        """Test control.shutdown extension."""
        response = self.send_extension_request("control.shutdown")
        return response["success"]


def run_extension_tests(socket_path, test_dir):
    """Run comprehensive extension tests."""
    if not CBOR_AVAILABLE:
        print("CBOR not available, skipping extension tests")
        return True

    tester = ExtensionTester(socket_path)
    tests_passed = 0
    tests_total = 0

    def test(name, func):
        nonlocal tests_passed, tests_total
        tests_total += 1
        print(f"  {name}... ", end="")
        try:
            result = func()
            if result:
                print("✓ PASS")
                tests_passed += 1
            else:
                print("✗ FAIL")
        except Exception as e:
            print(f"✗ ERROR: {e}")

    print("Running extension tests:")

    # Test manage.list
    test("manage.list", lambda: tester.test_manage_list()[0])

    # Create a test key for other operations
    created_fp = None
    try:
        success, fp = tester.test_manage_create("ed25519", "test-extension-key")
        if success and fp:
            created_fp = fp
            print(f"  Created test key: {fp[:16]}...")
    except:
        pass

    # Test manage operations with created key
    if created_fp:
        test("manage.unload", lambda: tester.test_manage_unload(created_fp))
        test("manage.load", lambda: tester.test_manage_load(created_fp))
        test("manage.set_desc", lambda: tester.test_manage_set_desc(created_fp, "updated-description"))

    # Test with imported key
    try:
        # Create a temporary key for import testing
        import_key_path = os.path.join(test_dir, "import_test_key")
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-f", import_key_path,
                       "-N", "", "-C", "import-test"],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)

        test("manage.import", lambda: tester.test_manage_import(import_key_path)[0])
    except:
        print("  manage.import... SKIP (key generation failed)")
        tests_total += 1

    print(f"\nExtension tests: {tests_passed}/{tests_total} passed")
    return tests_passed == tests_total


def create_test_signing_script(test_dir):
    """Create a script to test SSH signing functionality."""
    script_path = os.path.join(test_dir, "test_signing.sh")

    script_content = """#!/bin/bash
# Test SSH signing functionality

echo "Testing SSH signing with rssh-agent..."

# Test data to sign
TEST_DATA="Hello, rssh-agent signing test!"

# Create test data file
echo "$TEST_DATA" > "$1/sign_test_data"

# Test signing with ssh-keygen
if ssh-keygen -Y sign -n test -f "$1/test_ed25519" "$1/sign_test_data" >/dev/null 2>&1; then
    echo "✓ SSH signing test passed"
    exit 0
else
    echo "✗ SSH signing test failed"
    exit 1
fi
"""

    with open(script_path, 'w') as f:
        f.write(script_content)

    os.chmod(script_path, 0o755)
    return script_path


def main():
    """Main test function."""
    if len(sys.argv) < 2:
        print("Usage: test_extension_helper.py <socket_path> [test_dir]")
        sys.exit(1)

    socket_path = sys.argv[1]
    test_dir = sys.argv[2] if len(sys.argv) > 2 else "/tmp"

    if not os.path.exists(socket_path):
        print(f"Socket not found: {socket_path}")
        sys.exit(1)

    print(f"Testing extensions on: {socket_path}")
    print(f"Test directory: {test_dir}")

    # Run extension tests
    success = run_extension_tests(socket_path, test_dir)

    # Test signing functionality if keys are available
    try:
        signing_script = create_test_signing_script(test_dir)
        result = subprocess.run([signing_script, test_dir],
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print("✓ SSH signing test passed")
        else:
            print("✗ SSH signing test failed")
    except:
        print("~ SSH signing test skipped")

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()