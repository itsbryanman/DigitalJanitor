![Digital Janitor logo](LOGO.png)

# Digital Janitor

[![CI](https://img.shields.io/badge/CI-passing-brightgreen.svg)](https://github.com/digitaljanitor/dj/actions)
[![Crates.io](https://img.shields.io/crates/v/dj.svg)](https://crates.io/crates/dj)
[![Documentation](https://img.shields.io/badge/docs-online-blue.svg)](https://docs.rs/dj)
[![Rust Version](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![Docker Image](https://img.shields.io/badge/docker-ready-0db7ed.svg)](https://hub.docker.com/r/digitaljanitor/dj)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)

Digital Janitor is a CLI-first, content-addressable backup platform designed for fast incremental backups, safe encryption, and painless restores. It ships with container images, a Proxmox VE agent, and rich tooling so you can get reliable backups into the hands of real users quickly.

---

##  Highlights

- **Deduplicated Storage** – variable-size chunking with content-addressable objects keeps repositories small.
- **Strong Encryption** – AES-256-GCM backed by Argon2id key derivation protects data at rest.
- **Pluggable Backends** – local filesystem plus S3-compatible storage work out-of-the-box.
- **Zero-Trust Ready** – client-side crypto, password-based repositories, and integrity verification.
- **Container-Friendly** – first-class Docker build with lightweight runtime image.
- **Operational Tooling** – realtime progress, pruning policies, integrity checks, and stats reporting.
- **Proxmox Agent** – dedicated binary (`dj-pve-agent`) for VM and CT integration.

---

##  What’s in this Repository?

| Path | Purpose |
|------|---------|
| `src/` | Core library, CLI, mount support, and Proxmox agent implementations |
| `tests/` | Integration tests executed via `cargo test --test integration` |
| `scripts/` | Developer helper scripts (linting, QA) |
| `Dockerfile` | Multi-stage release build for container deployments |
| `docker-compose.yml` | Sample compose stack for server mode deployments |
| `build.sh` | Convenience wrapper for local builds |
| `AUDIT.md` | Security & dependency audit notes |
| `PLAN.md` | Roadmap and task breakdown |

All artifacts required to build, test, and ship to early adopters are included. The `target/` directory is intentionally excluded so releases stay lean.

---

##  Quick Start for Test Users

```bash
# 1. Clone and enter the project
git clone https://github.com/your-org/DigitalJanitor.git
cd DigitalJanitor

# 2. Build release binaries
cargo build --release

# 3. Initialize a demo repository
export DJ_REPO="$(pwd)/demo-repo"
export DJ_PASSWORD="ChangeMe123!"
target/release/dj repo init

# 4. Take a sample backup
target/release/dj backup create ./src --tags sample

# 5. Inspect statistics
target/release/dj repo stats
```

To revert between repositories, simply change `DJ_REPO`. Password-protected repositories only require `DJ_PASSWORD` at runtime.

---

##  Docker Release Build

The provided `Dockerfile` yields production-ready images with both CLI binaries.

```bash
# Build multi-stage release image
docker build -t digitaljanitor:release .

# (Optional) Target specific platform or push via buildx
docker buildx build \
  --platform linux/amd64 \
  -t ghcr.io/your-org/digitaljanitor:latest \
  --push .

# Run a one-off backup inside the container
docker run --rm \
  -e DJ_REPO=/data/repository \
  -e DJ_PASSWORD=ChangeMe123! \
  -v $(pwd)/repo:/data \
  -v $(pwd)/sample:/source:ro \
  digitaljanitor:release backup create /source
```

Use the `HEALTHCHECK` baked into the image to wire Digital Janitor into orchestration platforms safely.

---

##  Build, Lint, and Test

The repository is configured to pass Clippy and unit/integration suites. Run everything locally before shipping to testers:

```bash
# Format
cargo fmt --all

# Lint (fails on warnings)
cargo clippy --all-targets --all-features -- -D warnings

# Core tests
cargo test

# Full feature matrix (mount + server + pve agent)
cargo test --all-features
```

Smoke-test the binaries:

```bash
./target/debug/dj repo stats --help
./target/debug/dj-pve-agent --help
```

---

##  Configuration Cheat Sheet

| Variable | Description | Example |
|----------|-------------|---------|
| `DJ_REPO` | Repository path or URL | `file:///backups/repo` / `s3://bucket/path?region=us-east-1` |
| `DJ_PASSWORD` | Repository passphrase (for encrypted repos) | `ChangeMe123!` |
| `DJ_PASSWORD_FILE` | Path to password file for non-interactive runs | `/run/secrets/dj_password` |
| `RUST_LOG` | Log verbosity (`error`, `warn`, `info`, `debug`) | `info` |

### Repository URL Formats

```text
file:///path/to/repo
s3://bucket/prefix?region=us-east-1
s3://bucket/prefix?endpoint=https://minio.example.com&region=us-east-1
sftp://user@host:22/path/to/repo
```

---

## Common Workflows

### Initialize & Inspect
```bash
export DJ_REPO=/srv/backups; export DJ_PASSWORD=Secret123

dj repo init                      # create repository
dj repo stats                     # usage overview
dj repo verify --read-data        # thorough integrity check
```

### Snapshot Management
```bash
dj backup create /home --tags daily,laptop --exclude "*.tmp,.cache"
dj snapshot list --tags daily
snapshot_id=$(dj snapshot list --quiet --latest)
dj snapshot diff $snapshot_id --previous
```

### Retention & Pruning
```bash
# Plan a dry-run prune with multiple retention windows
dj repo prune \
  --keep-last 3 \
  --keep-daily 7 \
  --keep-weekly 4 \
  --keep-monthly 6 \
  --keep-yearly 3 \
  --dry-run
```

### Mount Browse (requires FUSE)
```bash
sudo target/release/dj mount --repo $DJ_REPO --mount-point /mnt/dj --allow-other
```

---

## Development Guide

1. **Install toolchain** – Rust 1.75+, `libfuse3-dev`, OpenSSL, and Docker (optional).
2. **Set up environment** – `rustup component add clippy rustfmt`.
3. **Install pre-commit hooks** – optional `scripts/pre-commit.sh` or configure your own.
4. **Iterate** – write code/tests, run `cargo fmt` + `cargo clippy` + `cargo test`.
5. **Package** – `docker build -t digitaljanitor:dev .` or `cargo build --release`.

Integration tests rely on temporary repositories and require no external services.

---

##  Troubleshooting

| Symptom | Likely Cause | Fix |
|---------|--------------|-----|
| `fuser` build errors | Missing FUSE headers | `sudo apt install libfuse3-dev` |
| `Could not resolve host: static.crates.io` | Offline environment | Vendor crates or provide outbound network |
| `Repository password missing` | `DJ_PASSWORD` unset | Export `DJ_PASSWORD` or create `DJ_PASSWORD_FILE` |
| `Permission denied` on mount | FUSE not configured / `allow_other` missing | Run as root or adjust `/etc/fuse.conf` |

For more help, file an issue or reach out to support.

---

##  Support the Project

If you liked Digital Janitor , consider buying a coffee: [https://buymeacoffee.com/bryanc910](https://buymeacoffee.com/bryanc910)

---

##  License

Digital Janitor is released under the MIT License. See [LICENSE](LICENSE) for details.

