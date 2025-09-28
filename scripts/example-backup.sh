#!/bin/bash

# Example backup script for Digital Janitor
# This script demonstrates how to use dj for automated backups

set -euo pipefail

# Configuration
REPO_PATH="${DJ_REPO:-/data/repository}"
BACKUP_PATHS="${BACKUP_PATHS:-/home /etc /var/log}"
TAGS="${BACKUP_TAGS:-daily,automated}"
EXCLUDE_PATTERNS="${BACKUP_EXCLUDE:-*.tmp,*.log,*~,.git}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() {
    echo -e "$(date +'%Y-%m-%d %H:%M:%S') $1"
}

success() {
    echo -e "${GREEN}[SUCCESS] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}"
    exit 1
}

warn() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

# Check if dj is available
if ! command -v dj &> /dev/null; then
    error "dj command not found. Please install Digital Janitor."
fi

# Check if repository exists
if ! dj repo check --repo "$REPO_PATH" &> /dev/null; then
    warn "Repository not found or unhealthy. Attempting to initialize..."

    if [[ -z "${DJ_PASSWORD:-}" ]]; then
        error "DJ_PASSWORD environment variable is required for initialization"
    fi

    dj repo init --repo "$REPO_PATH"
    success "Repository initialized at $REPO_PATH"
fi

log "Starting backup..."

# Convert comma-separated values to arrays
IFS=',' read -ra PATHS_ARRAY <<< "$BACKUP_PATHS"
IFS=',' read -ra TAGS_ARRAY <<< "$TAGS"
IFS=',' read -ra EXCLUDE_ARRAY <<< "$EXCLUDE_PATTERNS"

# Build command arguments
BACKUP_ARGS=()
BACKUP_ARGS+=(--repo "$REPO_PATH")

for path in "${PATHS_ARRAY[@]}"; do
    if [[ -d "$path" ]]; then
        BACKUP_ARGS+=("$path")
    else
        warn "Path does not exist: $path"
    fi
done

for tag in "${TAGS_ARRAY[@]}"; do
    BACKUP_ARGS+=(--tags "$tag")
done

for pattern in "${EXCLUDE_ARRAY[@]}"; do
    BACKUP_ARGS+=(--exclude "$pattern")
done

# Run backup
log "Backup command: dj backup create ${BACKUP_ARGS[*]}"

if dj backup create "${BACKUP_ARGS[@]}"; then
    success "Backup completed successfully"

    # Show latest snapshot
    log "Latest snapshot:"
    dj snapshot list --repo "$REPO_PATH" | head -3

    # Run repository check
    log "Running repository check..."
    if dj repo check --repo "$REPO_PATH"; then
        success "Repository check passed"
    else
        error "Repository check failed"
    fi

else
    error "Backup failed"
fi

log "Backup script completed"