# rssh-agent Integration Testing Guide

This document describes the comprehensive integration test suite for rssh-agent, covering all newly implemented functionality with real SSH client compatibility verification.

## Test Suite Overview

The integration test suite consists of multiple specialized test scripts that verify different aspects of rssh-agent functionality:

### Core Test Scripts

- **`test-full.sh`** - Enhanced comprehensive integration tests (32 tests)
  - Basic CLI functionality (version, help)
  - Daemon lifecycle (init, start, stop)
  - Lock/unlock operations
  - Key management with ssh-add
  - SSH client compatibility
  - Error handling

- **`test_constraints.sh`** - SSH key constraint testing (15 tests)
  - Confirm constraint (`ssh-add -c`)
  - Lifetime constraint (`ssh-add -t`)
  - Combined constraints
  - Constraint persistence across lock/unlock
  - Constraint validation and error handling

- **`test_signals.sh`** - Signal handling tests (12 tests)
  - SIGTERM graceful shutdown
  - SIGINT handling
  - SIGHUP behavior
  - Signal race conditions
  - Extension-based shutdown

- **`test_tui.sh`** - Terminal UI integration tests (10 tests)
  - TUI startup and basic operation
  - Navigation and help system (with expect)
  - Error handling and performance
  - Terminal compatibility

- **`test_certificates.sh`** - Certificate handling tests (14 tests)
  - Certificate creation and import
  - Key-certificate pair validation
  - Certificate metadata preservation
  - Invalid certificate handling

### Helper Scripts

- **`test_extension_helper.py`** - Python extension testing utility
  - Tests all manage.* extensions (list, load, unload, set_desc, create, import)
  - Tests control.* extensions (shutdown)
  - Proper CBOR protocol handling
  - SSH signing compatibility tests

- **`test_all_integration.sh`** - Master test runner
  - Orchestrates all test suites
  - Provides detailed reporting with timestamps
  - Creates comprehensive test logs
  - Generates OpenSSH compatibility summary

## Running Tests

### Quick Test (Enhanced Original)
```bash
./test-full.sh
```

### Individual Test Suites
```bash
./test_constraints.sh [test_dir]
./test_signals.sh [test_dir]
./test_tui.sh [test_dir]
./test_certificates.sh [test_dir]
```

### Comprehensive Test Suite
```bash
./test_all_integration.sh
```

This runs all test suites and generates detailed reports in `/tmp/rssh-integration-tests/`.

### Extension Testing
```bash
# Requires running daemon
export SSH_AUTH_SOCK=/path/to/agent.sock
./test_extension_helper.py $SSH_AUTH_SOCK /tmp/test_dir
```

## Test Environment

### Requirements
- Rust toolchain with rssh-agent built
- `ssh-add` and `ssh-keygen` tools
- Python 3 with `cbor2` for extension tests
- `expect` for advanced TUI tests (auto-installed)

### Environment Variables
- `RSSH_ALLOW_NO_MLOCK=1` - Disable memory locking for tests
- `SSH_AUTH_SOCK` - Set automatically by daemon
- `SSH_ASKPASS` - Mock askpass for constraint testing

### Test Isolation
Each test suite:
- Uses isolated temporary directories
- Runs independent daemon instances
- Cleans up processes and files
- Uses unique sockets and storage

## Test Coverage

### SSH Protocol Compatibility
- ✅ Standard OpenSSH agent protocol
- ✅ `ssh-add` key management
- ✅ Constraint handling (`-c`, `-t` flags)
- ✅ Identity listing and removal
- ✅ Socket communication and permissions

### rssh-agent Extensions
- ✅ `manage.list` - List stored keys with metadata
- ✅ `manage.load/unload` - RAM key management
- ✅ `manage.import` - Import external keys
- ✅ `manage.create` - Generate new keys
- ✅ `manage.set_desc` - Update key descriptions
- ✅ `control.shutdown` - Graceful daemon shutdown

### Security Features
- ✅ Master password protection
- ✅ Agent lock/unlock
- ✅ Memory protection (where available)
- ✅ Signal handling security
- ✅ Socket permission restrictions

### Error Handling
- ✅ Invalid passwords and keys
- ✅ Network and socket errors
- ✅ Constraint validation
- ✅ Resource cleanup on failures

## Test Results

The master test runner produces:
- Real-time colored output with pass/fail indicators
- Detailed log files with timestamps
- Comprehensive results summary
- OpenSSH compatibility report
- Performance timing information

Results are saved to `/tmp/rssh-integration-tests/results/` with:
- Individual test suite logs
- Build logs
- Compatibility summaries
- Test timing data

## CI/CD Integration

For automated testing:

```bash
# Run all tests with exit codes
./test_all_integration.sh

# Check specific functionality
./test-full.sh && echo "Core functionality: PASS"
./test_constraints.sh && echo "Constraints: PASS"
./test_signals.sh && echo "Signal handling: PASS"
```

## Troubleshooting

### Common Issues
- **Build failures**: Check `build_*.log` in results directory
- **Socket errors**: Ensure no conflicting daemons running
- **Extension test failures**: Verify `cbor2` Python package installed
- **TUI test failures**: Check terminal compatibility and `expect` availability

### Manual Testing
For manual verification:
1. Initialize: `echo "password" | ./target/release/rssh-agent init --dir ~/.rssh-test`
2. Start daemon: `eval "$(echo "password" | ./target/release/rssh-agent daemon --dir ~/.rssh-test)"`
3. Test operations: `ssh-add`, `ssh-add -l`, constraints, TUI
4. Cleanup: `pkill rssh-agent; rm -rf ~/.rssh-test`

## Implementation Status

All major rssh-agent functionality is covered by integration tests:
- ✅ Core SSH agent protocol
- ✅ Key constraints and lifetime management
- ✅ Extension-based management operations
- ✅ Terminal UI functionality
- ✅ Signal handling and graceful shutdown
- ✅ Certificate import and validation
- ✅ Error cases and edge conditions
- ✅ OpenSSH client compatibility

Total test coverage: **97+ individual test cases** across **6 test suites**.