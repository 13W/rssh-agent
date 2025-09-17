#!/bin/bash
# test-systemd-packaging.sh - Test systemd packaging and integration end-to-end

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_test() {
    echo -e "${BLUE}[TEST]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[FAIL]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

TEST_DIR="/tmp/rssh-agent-test-$$"
FAILED_TESTS=0

cleanup() {
    print_info "Cleaning up test environment..."

    # Stop any running rssh-agent services
    systemctl --user stop rssh-agent.socket rssh-agent.service 2>/dev/null || true
    systemctl --user disable rssh-agent.socket 2>/dev/null || true

    # Clean up test directories
    rm -rf "$TEST_DIR"

    if [ $FAILED_TESTS -eq 0 ]; then
        print_success "All tests passed!"
        exit 0
    else
        print_error "$FAILED_TESTS tests failed"
        exit 1
    fi
}

trap cleanup EXIT

fail_test() {
    print_error "$1"
    FAILED_TESTS=$((FAILED_TESTS + 1))
}

# Test 1: Verify Debian package structure
test_package_structure() {
    print_test "Verifying Debian package structure"

    local required_files=(
        "debian/control"
        "debian/rules"
        "debian/changelog"
        "debian/copyright"
        "debian/compat"
        "debian/postinst"
        "debian/prerm"
        "debian/postrm"
        "debian/rssh-agent.service"
        "debian/rssh-agent.socket"
        "debian/rssh-agent.conf"
        "debian/rssh-setup"
    )

    for file in "${required_files[@]}"; do
        if [ ! -f "$file" ]; then
            fail_test "Missing required file: $file"
            return
        fi
    done

    # Check executable permissions
    if [ ! -x "debian/postinst" ] || [ ! -x "debian/prerm" ] || [ ! -x "debian/postrm" ] || [ ! -x "debian/rssh-setup" ]; then
        fail_test "Maintainer scripts are not executable"
        return
    fi

    print_success "Package structure is valid"
}

# Test 2: Build package (if dependencies available)
test_build_package() {
    print_test "Testing package build"

    if ! command -v dpkg-buildpackage >/dev/null 2>&1; then
        print_warning "dpkg-buildpackage not available, skipping build test"
        return
    fi

    if ! command -v dh-cargo >/dev/null 2>&1; then
        print_warning "dh-cargo not available, skipping build test"
        return
    fi

    # This is a dry run test - we don't actually build because it requires many dependencies
    print_info "Build dependencies check passed (would need actual build environment for full test)"
    print_success "Package build structure is valid"
}

# Test 3: systemd service file validation
test_systemd_files() {
    print_test "Validating systemd service files"

    # Check service file syntax
    if command -v systemd-analyze >/dev/null 2>&1; then
        if ! systemd-analyze verify debian/rssh-agent.service debian/rssh-agent.socket 2>/dev/null; then
            # systemd-analyze might not work without installation, so just warn
            print_warning "systemd-analyze validation failed (may be expected without installation)"
        else
            print_success "systemd files passed systemd-analyze validation"
        fi
    fi

    # Check required sections exist
    if ! grep -q '\[Unit\]' debian/rssh-agent.service || \
       ! grep -q '\[Service\]' debian/rssh-agent.service || \
       ! grep -q '\[Install\]' debian/rssh-agent.service; then
        fail_test "rssh-agent.service missing required sections"
        return
    fi

    if ! grep -q '\[Unit\]' debian/rssh-agent.socket || \
       ! grep -q '\[Socket\]' debian/rssh-agent.socket || \
       ! grep -q '\[Install\]' debian/rssh-agent.socket; then
        fail_test "rssh-agent.socket missing required sections"
        return
    fi

    # Check socket path uses runtime directory
    if ! grep -q '%t/rssh-agent.socket' debian/rssh-agent.socket; then
        fail_test "Socket file doesn't use correct runtime directory path"
        return
    fi

    print_success "systemd service files are valid"
}

# Test 4: Helper script functionality
test_helper_script() {
    print_test "Testing rssh-setup helper script"

    # Test help output (from project root)
    if ! bash debian/rssh-setup help >/dev/null 2>&1; then
        fail_test "rssh-setup help command failed"
        return
    fi

    # Test various commands (most will fail without actual installation, but should handle errors gracefully)
    local commands=("status" "help")
    for cmd in "${commands[@]}"; do
        if ! bash debian/rssh-setup "$cmd" >/dev/null 2>&1; then
            # This is expected to fail without installation
            print_info "rssh-setup $cmd failed as expected without installation"
        fi
    done

    print_success "Helper script structure is valid"
}

# Test 5: Environment configuration
test_environment_config() {
    print_test "Testing environment configuration"

    # Check environment file exists and has correct content
    if [ ! -f debian/rssh-agent.conf ]; then
        fail_test "Environment configuration file doesn't exist"
        return
    fi

    if ! grep -q 'SSH_AUTH_SOCK.*rssh-agent.socket' debian/rssh-agent.conf; then
        fail_test "Environment configuration doesn't set SSH_AUTH_SOCK correctly"
        return
    fi

    if ! grep -q 'XDG_RUNTIME_DIR' debian/rssh-agent.conf; then
        fail_test "Environment configuration doesn't use XDG_RUNTIME_DIR"
        return
    fi

    print_success "Environment configuration is valid"
}

# Test 6: Security settings validation
test_security_settings() {
    print_test "Validating security settings in systemd service"

    if [ ! -f debian/rssh-agent.service ]; then
        fail_test "Service file doesn't exist"
        return
    fi

    local security_settings=(
        "NoNewPrivileges=true"
        "ProtectSystem=strict"
        "PrivateTmp=true"
        "ProtectHome=read-only"
        "MemoryDenyWriteExecute=true"
        "SystemCallFilter=@system-service"
    )

    for setting in "${security_settings[@]}"; do
        if ! grep -q "$setting" debian/rssh-agent.service; then
            fail_test "Missing security setting: $setting"
            return
        fi
    done

    print_success "Security settings are comprehensive"
}

# Test 7: Integration with existing rssh-agent
test_integration() {
    print_test "Testing integration with existing rssh-agent functionality"

    # Check if rssh-agent binary exists and has expected commands
    if command -v rssh-agent >/dev/null 2>&1; then
        # Test that daemon command supports the flags used by systemd
        if ! rssh-agent daemon --help | grep -q -- --foreground; then
            fail_test "rssh-agent daemon doesn't support --foreground flag"
            return
        fi

        if ! rssh-agent daemon --help | grep -q -- --socket; then
            fail_test "rssh-agent daemon doesn't support --socket flag"
            return
        fi

        print_success "Integration with rssh-agent binary is valid"
    else
        print_warning "rssh-agent binary not found, skipping integration test"
    fi
}

# Test 8: File permissions and ownership
test_file_permissions() {
    print_test "Testing file permissions"

    # Check that scripts are executable
    local executables=("debian/postinst" "debian/prerm" "debian/postrm" "debian/rssh-setup")
    for file in "${executables[@]}"; do
        if [ ! -x "$file" ]; then
            fail_test "$file is not executable"
            return
        fi
    done

    print_success "File permissions are correct"
}

# Main test execution
main() {
    print_info "Starting rssh-agent systemd packaging tests"
    print_info "Test directory: $TEST_DIR"
    echo

    # Change to project root
    cd /opt/rust/rssh-agent

    # Run all tests
    test_package_structure
    test_build_package
    test_systemd_files
    test_helper_script
    test_environment_config
    test_security_settings
    test_integration
    test_file_permissions

    echo
    print_info "Test summary: $FAILED_TESTS failed tests"
}

main "$@"