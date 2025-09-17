#!/bin/bash
# build-deb.sh - Build Debian package for rssh-agent using cargo-deb

set -e

echo "Building rssh-agent Debian package with cargo-deb..."

# Check if we're in the right directory
if [ ! -f "Cargo.toml" ] || [ ! -d "crates/rssh-cli" ]; then
    echo "Error: Must be run from rssh-agent project root" >&2
    exit 1
fi

# Check dependencies
echo "Checking build dependencies..."
missing_deps=""

for cmd in cargo rustc; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        missing_deps="$missing_deps $cmd"
    fi
done

if [ -n "$missing_deps" ]; then
    echo "Missing dependencies:$missing_deps"
    echo "Please ensure cargo and rustc are installed (via rustup recommended)"
    exit 1
fi

# Install cargo-deb if not present
if ! cargo deb --help >/dev/null 2>&1; then
    echo "Installing cargo-deb..."
    cargo install cargo-deb
fi

# Clean any previous builds
echo "Cleaning previous builds..."
cargo clean

# Update Cargo.lock if needed
echo "Updating dependencies..."
cargo update

# Build in release mode first
echo "Building binary in release mode..."
cargo build --release --bin rssh-agent

# Build the Debian package using cargo-deb
echo "Building Debian package..."
cd crates/rssh-cli
cargo deb --no-build

echo ""
echo "Build completed successfully!"
echo "Package files:"
ls -la target/debian/*.deb 2>/dev/null || echo "  (no .deb files found - check for errors above)"

# Move deb file to project root for convenience
if ls target/debian/*.deb >/dev/null 2>&1; then
    echo ""
    echo "Moving package to project root..."
    cp target/debian/*.deb ../../
    cd ../../
    ls -la *.deb
fi

echo ""
echo "To install the package:"
echo "  sudo dpkg -i rssh-agent*.deb"
echo "  sudo apt-get install -f  # Fix any dependency issues"
