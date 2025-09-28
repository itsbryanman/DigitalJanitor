# Multi-stage Dockerfile for Digital Janitor
# Stage 1: Builder
FROM rust:1.75-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    libssh2-1-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy manifests first for layer caching
COPY Cargo.toml Cargo.lock ./

# Pre-fetch dependencies (kept in cache unless Cargo.toml changes)
RUN cargo fetch --locked

# Copy the actual source code
COPY src/ src/

# Build the application (release profile)
RUN cargo build --release --locked --bin dj --bin dj-pve-agent

# Stage 2: Runtime image
FROM debian:bookworm-slim AS runtime

# Install minimal runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    libssh2-1 \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get autoremove -y \
    && apt-get clean

# Create non-root user
RUN groupadd -r dj && useradd -r -g dj -s /bin/false dj

# Create directories
RUN mkdir -p /data /config /tmp/dj && \
    chown -R dj:dj /data /config /tmp/dj

# Copy binaries from builder
COPY --from=builder /app/target/release/dj /usr/local/bin/dj
COPY --from=builder /app/target/release/dj-pve-agent /usr/local/bin/dj-pve-agent

# Make binaries executable
RUN chmod +x /usr/local/bin/dj /usr/local/bin/dj-pve-agent

# Set up volumes
VOLUME ["/data", "/config"]

# Switch to non-root user
USER dj

# Set working directory
WORKDIR /data

# Set default environment variables
ENV RUST_LOG=info
ENV DJ_REPO=/data/repository

# Expose default ports
EXPOSE 8080 8081

# Default command
ENTRYPOINT ["/usr/local/bin/dj"]
CMD ["--help"]

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD /usr/local/bin/dj repo check --repo $DJ_REPO || exit 1

# Labels for metadata
LABEL org.opencontainers.image.title="Digital Janitor"
LABEL org.opencontainers.image.description="CLI-first backup solution with content-addressable storage"
LABEL org.opencontainers.image.vendor="Digital Janitor Team"
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.source="https://github.com/digitaljanitor/dj"
LABEL org.opencontainers.image.documentation="https://docs.digitaljanitor.io"
LABEL org.opencontainers.image.licenses="MIT"
