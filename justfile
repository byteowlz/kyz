# kyz justfile (Rust workspace)

# Default recipe - show help
default:
    @just --list

# === Development ===

# Install all binaries
install:
    cargo install --path .

# Install all binaries with interactive confirmation
install-all:
    #!/usr/bin/env bash
    set -euo pipefail
    
    echo "kyz Installation"
    echo "================"
    echo ""
    
    # Show toolchain info
    if command -v rustup &>/dev/null; then
        rustup show active-toolchain
    else
        cargo --version || { echo "Error: cargo not found"; exit 1; }
    fi
    echo ""
    
    # List binaries to install
    echo "Binaries to install:"
    cargo metadata --no-deps --format-version 1 |\
        jq -r '.packages[] | select(.targets[] | .kind[] == "bin") | "  - \(.name) (\(.manifest_path | split("/") | .[-2]))"'
    echo ""
    
    # Check if we should enable mask-output feature
    echo "Features:"
    echo "  mask-output  (default: ON)  - redacts sensitive fields in console output"
    echo "  --no-default-features       - disable masking (prints raw values)"
    echo ""
    
    read -rp "Proceed? [Y=default/n=skip/1=default/2=no-mask]: " choice
    FEATURE_FLAG=""
    case "${choice:-y}" in
        [Yy]|""|1)
            FEATURE_FLAG=""
            ;;
        2)
            FEATURE_FLAG="--no-default-features"
            echo "Using --no-default-features (no masking)"
            ;;
        [Nn]*)
            echo "Installation cancelled"
            exit 0
            ;;
        *)
            echo "Invalid choice, installing with default features"
            FEATURE_FLAG=""
            ;;
    esac
    
    echo "Installing with: $FEATURE_FLAG"
    for crate in $(cargo metadata --no-deps --format-version 1 | jq -r '.packages[] | select(.targets[] | .kind[] == "bin") | .manifest_path | split("/") | .[-2]'); do
        echo "  Installing $crate..."
        cargo install --path crates/$crate $FEATURE_FLAG
    done
    
    echo ""
    echo "Installation complete!"

# Install a specific crate
install-crate CRATE:
    cargo install --path crates/{{CRATE}}

# Uninstall all binaries
uninstall:
    @for crate in $(cargo metadata --no-deps --format-version 1 | jq -r '.packages[] | select(.targets[] | .kind[] == "bin") | .name'); do \
        echo "Uninstalling $crate..."; \
        cargo uninstall $crate 2>/dev/null || true; \
    done

# === Building ===

# Debug build (all crates)
build:
    cargo build --workspace

# Release build (all crates)
build-release:
    cargo build --workspace --release

# Build a specific crate
build-crate CRATE:
    cargo build -p {{CRATE}}

# Build with all features
build-all:
    cargo build --workspace --all-features

# Fast compile check
check:
    cargo check --workspace

# Check a specific crate
check-crate CRATE:
    cargo check -p {{CRATE}}

# Clean build artifacts
clean:
    cargo clean

# === Testing ===

# Run all tests
test:
    cargo test --workspace

# Run tests for a specific crate
test-crate CRATE:
    cargo test -p {{CRATE}}

# Run tests with all features
test-all:
    cargo test --workspace --all-features

# Run tests verbosely
test-v:
    cargo test --workspace -- --nocapture

# Run a specific test
test-one TEST:
    cargo test --workspace {{TEST}}

# === Code Quality ===

# Format all code
fmt:
    cargo fmt --all

# Check formatting
fmt-check:
    cargo fmt --all -- --check

# Run clippy on all crates
clippy:
    cargo clippy --workspace -- -D warnings

# Alias for clippy
lint: clippy

# Clippy on a specific crate
clippy-crate CRATE:
    cargo clippy -p {{CRATE}} -- -D warnings

# Auto-fix clippy warnings
fix:
    cargo clippy --workspace --fix --allow-dirty

# Run ast-grep rules (no-unwrap, no-debug, no-clippy-allow)
ast-grep:
    ast-grep scan -c .ast-grep/sgconfig.yml

# Run all checks
check-all: fmt-check clippy ast-grep test

# === Config Generation ===

# Generate config.toml and schema from Rust structs
generate-config:
    cargo run -p kyz-core --example generate_config

# Validate that examples/ config files are up to date
validate-config:
    cargo test -p kyz-core validate_examples_are_up_to_date

# === Documentation ===

# Generate docs for all crates
docs:
    cargo doc --workspace --no-deps

# Generate and open docs
docs-open:
    cargo doc --workspace --no-deps --open

# Docs for a specific crate
docs-crate CRATE:
    cargo doc -p {{CRATE}} --no-deps --open

# === Dependencies ===

# Update all dependencies
update:
    cargo update

# Check for outdated dependencies
outdated:
    cargo outdated --workspace

# === Workspace Info ===

# List all crates in workspace
list:
    @cargo metadata --no-deps --format-version 1 | jq -r '.packages[] | "\(.name) (\(.version))"'

# List binary crates
list-bins:
    @cargo metadata --no-deps --format-version 1 | jq -r '.packages[] | select(.targets[] | .kind[] == "bin") | .name'

# List library crates
list-libs:
    @cargo metadata --no-deps --format-version 1 | jq -r '.packages[] | select(.targets[] | .kind[] == "lib") | .name'

# === Release ===

# Release build and show binary sizes
release: build-release
    @echo "Binary sizes:"
    @find target/release -maxdepth 1 -type f -perm +111 ! -name "*.d" -exec ls -lh {} \; 2>/dev/null || true

# Tag and push a release
release-tag VERSION:
    git tag v{{VERSION}}
    git push --tags

# Set up GitHub secrets for automated releases (requires byt)
setup-secrets:
    byt secrets setup kyz
