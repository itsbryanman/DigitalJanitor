#!/bin/bash

# Digital Janitor Build Script
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
REGISTRY="${REGISTRY:-digitaljanitor}"
TAG="${TAG:-latest}"
PLATFORM="${PLATFORM:-linux/amd64,linux/arm64}"

log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

success() {
    echo -e "${GREEN}[SUCCESS] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}"
    exit 1
}

check_dependencies() {
    log "Checking dependencies..."

    if ! command -v docker &> /dev/null; then
        error "Docker is not installed"
    fi

    if ! command -v cargo &> /dev/null; then
        error "Rust/Cargo is not installed"
    fi

    success "All dependencies found"
}

run_tests() {
    log "Running tests..."

    cargo test --all-features

    success "All tests passed"
}

lint_code() {
    log "Running linter..."

    if command -v cargo-clippy &> /dev/null; then
        cargo clippy --all-features --all-targets -- -D warnings
    else
        warn "clippy not found, skipping lint"
    fi

    if command -v cargo-fmt &> /dev/null; then
        cargo fmt --all -- --check
    else
        warn "rustfmt not found, skipping format check"
    fi

    success "Code quality checks passed"
}

build_local() {
    log "Building locally..."

    cargo build --release --all-features

    success "Local build completed"
}

build_docker() {
    log "Building Docker image..."

    # Build multi-platform image
    docker buildx build \
        --platform ${PLATFORM} \
        --tag ${REGISTRY}/dj:${TAG} \
        --tag ${REGISTRY}/dj:latest \
        --push \
        .

    success "Docker image built and pushed: ${REGISTRY}/dj:${TAG}"
}

build_docker_local() {
    log "Building Docker image locally..."

    docker build -t ${REGISTRY}/dj:${TAG} .

    success "Docker image built locally: ${REGISTRY}/dj:${TAG}"
}

create_release() {
    local version=$1

    log "Creating release $version..."

    # Update version in Cargo.toml
    sed -i "s/^version = \".*\"/version = \"$version\"/" Cargo.toml

    # Build release binaries for different targets
    local targets=("x86_64-unknown-linux-gnu" "aarch64-unknown-linux-gnu" "x86_64-pc-windows-gnu" "x86_64-apple-darwin")

    mkdir -p releases

    for target in "${targets[@]}"; do
        log "Building for $target..."

        if cargo build --release --target $target; then
            # Create archive
            local archive_name="dj-$version-$target"
            mkdir -p "releases/$archive_name"

            if [[ $target == *"windows"* ]]; then
                cp "target/$target/release/dj.exe" "releases/$archive_name/"
                cp "target/$target/release/dj-pve-agent.exe" "releases/$archive_name/"
            else
                cp "target/$target/release/dj" "releases/$archive_name/"
                cp "target/$target/release/dj-pve-agent" "releases/$archive_name/"
            fi

            # Create tar.gz
            cd releases
            tar -czf "$archive_name.tar.gz" "$archive_name"
            rm -rf "$archive_name"
            cd ..

            success "Created release/$archive_name.tar.gz"
        else
            warn "Failed to build for $target"
        fi
    done

    success "Release $version created"
}

show_help() {
    cat << EOF
Digital Janitor Build Script

Usage: $0 [COMMAND] [OPTIONS]

Commands:
    check       Check dependencies
    test        Run tests
    lint        Run linter and formatter
    build       Build locally
    docker      Build Docker image and push
    docker-local Build Docker image locally
    release     Create release binaries
    all         Run all build steps
    help        Show this help

Options:
    REGISTRY    Docker registry (default: digitaljanitor)
    TAG         Docker tag (default: latest)
    PLATFORM    Docker platforms (default: linux/amd64,linux/arm64)

Examples:
    $0 all                           # Run full build pipeline
    $0 docker                        # Build and push Docker image
    REGISTRY=myregistry $0 docker    # Push to custom registry
    $0 release v1.0.0               # Create release v1.0.0

EOF
}

main() {
    case "${1:-help}" in
        check)
            check_dependencies
            ;;
        test)
            run_tests
            ;;
        lint)
            lint_code
            ;;
        build)
            build_local
            ;;
        docker)
            build_docker
            ;;
        docker-local)
            build_docker_local
            ;;
        release)
            if [[ -z "${2:-}" ]]; then
                error "Version required for release command"
            fi
            create_release "$2"
            ;;
        all)
            check_dependencies
            run_tests
            lint_code
            build_local
            build_docker_local
            success "Full build pipeline completed"
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            error "Unknown command: $1. Use '$0 help' for usage information."
            ;;
    esac
}

main "$@"