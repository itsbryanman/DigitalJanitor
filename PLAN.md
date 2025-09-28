# **The Digital Janitor: Technical Design Document (CLI-First Edition)**

Project Codename: Velox  
Version: 1.0  
Date: September 27, 2025

## **1\. Introduction & Guiding Principles**

### **1.1. Mission**

To build a next-generation, CLI-first backup solution that is uncompromisingly reliable, highly performant, flexible, and easily deployable via containers. This program, "The Digital Janitor," is designed to be the definitive tool for power users and automated environments.

### **1.2. Core Principles**

The architecture is guided by the following non-negotiable principles:

* **Reliability Above All:** The repository is the single source of truth. The system must be resilient to client-side failures and provide fast, trustworthy verification.  
* **Performance by Design:** The entire data pipeline will be parallelized to leverage modern multi-core hardware and high-speed networks.  
* **Flexibility Without Compromise:** Users should have broad choices for storage backends without sacrificing performance.  
* **CLI as the Primary Interface:** The Command-Line Interface is the complete and only interface, designed for power, scriptability, and automation.  
* **Security by Default:** All data must be client-side encrypted with no exceptions.

## **2\. Core Architecture & Data Model**

The system's foundation is a content-addressable storage model, similar to Git, where data chunks are identified by a cryptographic hash of their content.

### **2.1. The Repository Structure**

The repository is a self-contained directory structure stored on the backend. It requires no client-side state to be fully operational.

/  
├── config        \# Main repository configuration file (e.g., repo version, default compression)  
├── keys/         \# Contains encrypted repository keys  
│   └── ...  
├── data/         \# Contains packfiles, which hold the actual data blobs  
│   ├── 0a/  
│   │   └── 0a1b2c...  
│   └── 0b/  
│       └── 0b3d4e...  
├── index/        \# Contains index files mapping blob hashes to packfiles  
│   └── ...  
├── snapshots/    \# Contains snapshot files, which are pointers to a backup state  
│   └── ...  
└── locks/        \# Manages concurrent access to the repository  
    └── ...

### **2.2. Data Model Primitives**

* **Blob:** A variable-sized chunk of raw user data. After being read, data is passed through a content-defined chunking algorithm (FastCDC) to create blobs. Each blob is identified by the **BLAKE3 hash** of its content.  
* **Tree:** A data structure that represents a directory. It contains a list of entries, where each entry is a file (a list of blob hashes) or another tree (a subdirectory). Trees are also stored as versioned, hashed objects.  
* **Snapshot:** A JSON object that represents a single point-in-time backup. It contains metadata and a pointer to the root tree hash for that backup.  
  * id: A unique hash of the snapshot object.  
  * time: ISO 8601 timestamp.  
  * tree: The hash of the root tree object.  
  * paths: An array of file paths included in this backup.  
  * host: The hostname where the backup was created.  
  * tags: User-defined tags for filtering.  
* **Packfile:** To avoid storing millions of small files on the backend, multiple blobs, trees, and other objects are bundled together into larger container files called packfiles. These are stored in the data/ directory.  
* **Index:** An index file contains a mapping of object hashes to the packfile they are stored in, along with their offset and length. This allows for extremely fast lookups without scanning every packfile.

### **2.3. Data Processing Pipeline**

The backup process is a heavily parallelized pipeline:

1. **File Scanner:** Walks the filesystem to be backed up, feeding files into the pipeline.  
2. **Chunker:** Reads file data and uses **FastCDC** to split it into variable-sized blobs.  
3. **Processor:**  
   * Calculates the **BLAKE3 hash** of each blob's content.  
   * Checks a local cache and then the repository index to see if the blob hash already exists (deduplication).  
   * If the blob is new:  
     * Compresses the blob using **Zstandard (zstd)**.  
     * Encrypts the compressed blob using **AES-265-GCM**.  
4. **Packer:** Collects new, encrypted blobs and bundles them into packfiles.  
5. **Uploader:** Uploads completed packfiles, index files, and the final snapshot file to the backend.

### **2.4. Encryption Model**

* **Password Derivation:** The user's password is run through a strong Key Derivation Function (**Argon2id**) to generate a master encryption key.  
* **Key Storage:** The repository has its own set of encryption and MAC keys. These keys are encrypted by the master key and stored in the /keys directory.  
* **Benefit:** This allows a user to change their password without re-encrypting the entire repository. They only need to re-encrypt the repository keys with the new master key.

## **3\. Backend & Protocol Specification**

### **3.1. Pluggable Backend Trait**

A Rust trait will define the storage backend interface, abstracting away the implementation details.

pub trait Backend {  
    async fn list\_files(\&self, file\_type: FileType) \-\> Result\<Vec\<String\>\>;  
    async fn read\_range(\&self, file\_type: FileType, id: \&str, offset: u64, length: u64) \-\> Result\<Vec\<u8\>\>;  
    async fn write(\&self, file\_type: FileType, id: \&str, data: Vec\<u8\>) \-\> Result\<()\>;  
    async fn delete(\&self, file\_type: FileType, id: \&str) \-\> Result\<()\>;  
}

Implementations will be provided for S3, Backblaze B2, SFTP, and the local filesystem.

### **3.2. Hybrid Intelligence Protocol**

This protocol solves the performance vs. flexibility trade-off.

* **Phase 1: Discovery**  
  * When a client connects, it attempts to read a well-known file from the repository's root (e.g., /.dj\_server\_info).  
  * If the file exists and is valid, the client knows it can switch to the optimized protocol.  
  * If the file does not exist (or the request fails), the client operates in standard "dumb backend" mode.  
* **Phase 2: Optimized Communication (if server is present)**  
  * The client establishes a secure RPC connection (e.g., gRPC or a custom protocol over TLS) to the server endpoint specified in the info file.  
  * The client can now offload operations to the server:  
    * CheckHashes(\[hash1, hash2, ...\]): Server checks its indexes and returns a list of hashes it already has. This is vastly more efficient for deduplication than the client checking one-by-one.  
    * GetIndex(): Server can send a compiled, up-to-date index directly to the client.  
    * RunPrune(policy): The server performs the expensive garbage collection analysis locally and only returns the list of files to be deleted.

## **4\. Command-Line Interface (CLI) Specification**

The CLI is the primary interface for power users and automation. The executable will be named dj. All configuration (credentials, repository URL) will be passed via environment variables or command-line flags to ensure container-friendliness.

* **User Feedback & Progress Indication:** All long-running commands (backup create, repo check, restore, repo prune) **must** provide real-time feedback to the user. This should include a dynamic progress bar, ETA, current transfer speed, and the current file being processed. This is critical for user trust and diagnosing stalls.  
* **dj repo init \--repo \<path/url\>**  
  * Initializes a new repository. Reads password from DJ\_PASSWORD environment variable or prompts if not set.  
* **dj backup create \<path1\> \[path2...\] \--tags \<tag1,tag2\>**  
  * Creates a new snapshot of the specified local paths.  
* **dj snapshot list \[--tags \<tag1,tag2\>\]**  
  * Lists all snapshots, optionally filtered by tags.  
* **dj restore \<snapshot\_id\> \--target \<dest\_path\> \[--include \<pattern\>\]**  
  * Restores a snapshot to a target directory. Can filter to include only specific files/patterns.  
* **dj repo check \[--read-data\]**  
  * Verifies the integrity of the repository. \--read-data performs a full verification of all data blobs, which is slower but exhaustive.  
* **dj repo prune \--keep-daily 7 \--keep-weekly 4 \--keep-monthly 6**  
  * Applies a retention policy and garbage-collects any data that is no longer referenced by a snapshot.  
* **dj mount \<mount\_point\>**  
  * Uses FUSE to mount the repository as a read-only filesystem, allowing you to browse all snapshots.  
* **dj server start \--repo \<path/url\> \--listen 0.0.0.0:8080**  
  * Runs the dj binary in server mode to enable the Hybrid Intelligence Protocol.

## **5\. Proxmox VE Integration**

### **5.1. Architecture**

A dedicated agent binary, dj-pve-agent, will be installed on the Proxmox host. This agent can be a simple static binary or run within a container.

### **5.2. Backup Workflow**

1. The user runs dj backup create \--source-type proxmox \--source-host \<pve\_host\> ...  
2. The dj client connects to the dj-pve-agent on the Proxmox host.  
3. The agent authenticates and uses the Proxmox API (pvesh) to trigger a guest-consistent snapshot of the target VM/container.  
4. For VMs, the agent leverages QEMU's dirty-bitmap feature to get a list of changed blocks since the last backup.  
5. The agent uses qemu-img to expose the snapshot's block device over the network.  
6. The dj client reads this block device stream, chunks it, and runs it through the standard backup pipeline. For incremental backups, it only reads the dirty blocks.  
7. Upon completion, the agent instructs the Proxmox API to remove the temporary snapshot.

## **6\. Containerization & Deployment**

The entire application will be designed for seamless containerized deployment.

### **6.1. Dockerfile**

A multi-stage Dockerfile will be used to produce a minimal, secure final image.

* **Stage 1: Builder**  
  * Uses the official Rust Docker image.  
  * Copies the source code in.  
  * Compiles the dj binary as a static, MUSL-linked executable to remove dependencies on libc.  
* **Stage 2: Final Image**  
  * Starts from a minimal base image like scratch or alpine.  
  * Copies the single, static dj binary from the builder stage.  
  * Sets dj as the ENTRYPOINT.

This results in a final image that is extremely small (likely \< 20MB) and has a minimal attack surface.

### **6.2. Usage Examples**

* **Running a Local Backup:**  
  docker run \--rm \\  
    \-v /path/to/data:/data:ro \\  
    \-v /path/to/config:/config \\  
    \-e DJ\_PASSWORD="supersecret" \\  
    \-e DJ\_REPO="s3:my-bucket/backups" \\  
    your-repo/dj:latest \\  
    backup create /data \--tags local-files

* **Running the Server Component:**  
  docker run \-d \--name dj-server \\  
    \-p 8080:8080 \\  
    \-v /path/to/repo:/repo \\  
    \-e DJ\_PASSWORD="supersecret" \\  
    your-repo/dj:latest \\  
    server start \--repo /repo \--listen 0.0.0.0:8080

## **7\. Development Roadmap**

Development must be prioritized to ensure the core is flawless before building the user-facing features.

1. **Phase 1: The Core Engine**  
   * Implement the repository format, data structures, and the full data processing pipeline (chunk, hash, compress, encrypt).  
   * Create a rock-solid implementation of the Local Filesystem and S3 backends.  
   * Establish a comprehensive testing suite for data integrity and resilience.  
2. **Phase 2: The CLI & Containerization**  
   * Build out the full CLI with all commands specified in Section 4\.  
   * Focus heavily on the performance and reliability of repo check and repo prune.  
   * Develop the multi-stage Dockerfile and establish a container build/publish pipeline.  
3. **Phase 3: Integrations**  
   * Implement the dj-pve-agent and the Proxmox VE integration logic.  
   * Implement the optional dj server component and the Hybrid Intelligence Protocol.

Upon completion of Phase 3, development will focus on the advanced features outlined in Section 8 to solidify the project as a market leader.

## **8\. Future Enhancements & Advanced Features (v2.0+)**

This section outlines the roadmap beyond the initial v1.0 release. These features are designed to elevate the project from a solid tool to a best-in-class platform.

### **8.1. Performance Optimizations**

* **Adaptive Chunking:** Implement logic that adjusts chunk sizes based on file type (larger chunks for media files), network conditions, and storage backend characteristics.  
* **Multi-tier Caching:** Develop a sophisticated caching layer using local SSDs for hot data, memory-mapped index files, and Bloom filters for rapid negative lookups.  
* **Pipeline Improvements:** Optimize the parallel pipeline with work-stealing queues, SIMD optimizations for hashing (BLAKE3), and io\_uring on Linux for zero-copy I/O.

### **8.2. Resilience & Recovery**

* **Progressive Verification:** Enhance repo check with sampling-based verification (check a random subset), priority-based verification (recent snapshots first), and a continuous low-priority background verification mode.  
* **Partial Restore Capability:** Introduce Reed-Solomon error correction codes to packfiles, allowing for the reconstruction of data from partially corrupted files.  
* **Repository Repair Tools:** Build advanced recovery tools, including dj repo repair \--deep to rebuild indexes from packfiles and a transaction log to enable rollback of repository modifications.

### **8.3. Operational Excellence**

* **Observability:** Integrate with standard monitoring tools via OpenTelemetry for tracing and Prometheus metrics export. Implement structured logging with adjustable verbosity.  
* **Bandwidth Management:** Introduce adaptive rate limiting based on time of day, bandwidth pooling across jobs, and modern congestion control like TCP BBR.  
* **Multi-Repository Support:** Add features for repository federation (backup to multiple repos simultaneously) and repository mirroring with automatic failover.

### **8.4. Advanced Features**

* **Intelligent Scheduling:** Develop an ML-based scheduler to predict optimal backup windows based on file change frequency and system load.  
* **Smart Pruning:** Evolve the pruning logic to keep snapshots based on data uniqueness (retaining historically significant but small deltas) rather than just time.  
* **Application-Aware Backups:** Implement pre/post snapshot script hooks to allow for quiescing databases (e.g., PostgreSQL, MySQL) for application-consistent snapshots.

### **8.5. Proxmox Integration Improvements**

* **Cluster-Wide Coordination:** For Proxmox clusters, implement a distributed lock manager for safe concurrent operations and automatically load balance backup jobs across cluster nodes.  
* **Cross-VM Deduplication:** In server mode, enable deduplication across all VMs in a cluster, significantly reducing storage for similar base OS images.

### **8.6. Development & Testing**

* **Chaos Engineering:** Build a "chaos monkey" mode to test resilience by intentionally injecting faults, such as simulated storage backend failures and network partitions.  
* **Formal Verification & Fuzzing:** Use formal methods like TLA+ to verify critical algorithms and employ fuzz testing on all input parsers to ensure security and robustness.