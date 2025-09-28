use crate::{
    data::{Blob, HashId, ObjectType, Packfile, Snapshot, Tree, TreeEntry},
    repository::Repository,
    utils::{Chunker, ProgressTracker},
    Error, Result, PACKFILE_MAX_SIZE,
};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::fs;
use walkdir::WalkDir;

#[derive(Debug, Clone)]
pub struct BackupOptions {
    pub paths: Vec<PathBuf>,
    pub tags: Vec<String>,
    pub exclude_patterns: Vec<String>,
    pub parent_snapshot: Option<HashId>,
    pub dry_run: bool,
    pub verbose: bool,
}

#[derive(Debug, Clone)]
pub struct BackupPipeline {
    pub repository: Arc<Repository>,
    chunker: Chunker,
    progress: Arc<Mutex<ProgressTracker>>,
}

#[derive(Debug, Clone)]
struct FileInfo {
    path: PathBuf,
    relative_path: PathBuf,
    size: u64,
    modified: chrono::DateTime<chrono::Utc>,
    mode: u32,
    is_dir: bool,
    is_symlink: bool,
    target: Option<String>,
}

#[derive(Debug)]
struct ProcessedFile {
    info: FileInfo,
    chunks: Vec<HashId>,
}

impl BackupPipeline {
    pub fn new(repository: Repository) -> Self {
        Self {
            repository: Arc::new(repository),
            chunker: Chunker::new(),
            progress: Arc::new(Mutex::new(ProgressTracker::new(0, 0))),
        }
    }

    pub async fn backup(&self, options: BackupOptions) -> Result<Snapshot> {
        tracing::info!("Starting backup of {} paths", options.paths.len());

        let start_time = std::time::Instant::now();

        // Phase 1: Discover all files
        let files = self.discover_files(&options).await?;
        let total_files = files.len() as u64;
        let total_bytes: u64 = files.iter().map(|f| f.size).sum();

        {
            let mut progress = self.progress.lock().unwrap();
            *progress = ProgressTracker::new(total_files, total_bytes);
        }

        tracing::info!(
            "Discovered {} files ({} bytes)",
            total_files,
            crate::utils::format_bytes(total_bytes)
        );

        if options.dry_run {
            tracing::info!("Dry run mode - no actual backup performed");
            return self.create_dry_run_snapshot(&options, total_files, total_bytes);
        }

        // Phase 2: Process files sequentially and collect new blobs
        let mut processed_files = Vec::new();
        let mut new_blobs = Vec::new();
        let mut pending_hashes = HashSet::new();

        for file_info in files {
            let (processed, mut blobs) = self.process_file(file_info).await?;

            // Track newly discovered blobs to avoid duplicates in this batch
            blobs.retain(|blob| pending_hashes.insert(blob.id));

            {
                let mut progress = self.progress.lock().unwrap();
                progress.update_file(
                    processed.info.path.to_string_lossy().to_string(),
                    processed.info.size,
                );
            }

            new_blobs.extend(blobs);
            processed_files.push(processed);
        }

        // Phase 3: Package blobs into packfiles and store them
        let packfiles = self.create_packfiles(new_blobs)?;
        self.store_packfiles(packfiles).await?;

        // Phase 5: Build directory tree
        let root_tree = self.build_directory_tree(processed_files).await?;

        // Phase 6: Create and store snapshot
        let snapshot = self.create_snapshot(options, root_tree).await?;
        self.repository.save_snapshot(&snapshot).await?;

        let elapsed = start_time.elapsed();
        tracing::info!(
            "Backup completed in {}",
            crate::utils::format_duration(elapsed)
        );

        Ok(snapshot)
    }

    async fn discover_files(&self, options: &BackupOptions) -> Result<Vec<FileInfo>> {
        let mut files = Vec::new();

        for base_path in &options.paths {
            if !base_path.exists() {
                return Err(Error::validation(format!(
                    "Path does not exist: {}",
                    base_path.display()
                )));
            }

            for entry in WalkDir::new(base_path)
                .follow_links(false)
                .into_iter()
                .filter_entry(|e| !self.should_exclude(e.path(), &options.exclude_patterns))
            {
                let entry = entry.map_err(std::io::Error::other)?;
                let path = entry.path().to_path_buf();

                let relative_path = path.strip_prefix(base_path).unwrap_or(&path).to_path_buf();

                let metadata = entry.metadata().map_err(|e| Error::Io(e.into()))?;
                let modified = metadata.modified().map_err(Error::Io)?.into();

                let (is_symlink, target) = if metadata.file_type().is_symlink() {
                    let target = fs::read_link(&path)
                        .await
                        .map(|t| t.to_string_lossy().to_string())
                        .ok();
                    (true, target)
                } else {
                    (false, None)
                };

                let file_info = FileInfo {
                    path,
                    relative_path,
                    size: metadata.len(),
                    modified,
                    mode: self.get_file_mode(&metadata),
                    is_dir: metadata.is_dir(),
                    is_symlink,
                    target,
                };

                files.push(file_info);
            }
        }

        // Sort files to ensure deterministic processing order
        files.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));

        Ok(files)
    }

    fn should_exclude(&self, path: &Path, patterns: &[String]) -> bool {
        let path_str = path.to_string_lossy();

        for pattern in patterns {
            if path_str.contains(pattern) {
                return true;
            }
        }

        // Always exclude some system files
        let excluded_names = [".DS_Store", "Thumbs.db", "desktop.ini"];
        if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
            if excluded_names.contains(&filename) {
                return true;
            }
        }

        false
    }

    async fn process_file(&self, file_info: FileInfo) -> Result<(ProcessedFile, Vec<Blob>)> {
        if file_info.is_dir || file_info.is_symlink {
            return Ok((
                ProcessedFile {
                    info: file_info,
                    chunks: Vec::new(),
                },
                Vec::new(),
            ));
        }

        let mut chunks = Vec::new();
        let mut new_blobs = Vec::new();

        if file_info.size > 0 {
            let file_data = fs::read(&file_info.path).await?;
            let file_chunks = self.chunker.chunk_data(&file_data);

            for (hash, chunk_data) in file_chunks {
                if !self.repository.has_object(&hash).await {
                    new_blobs.push(Blob::new(chunk_data));
                }
                chunks.push(hash);
            }
        }

        Ok((
            ProcessedFile {
                info: file_info,
                chunks,
            },
            new_blobs,
        ))
    }

    fn create_packfiles(&self, blobs: Vec<Blob>) -> Result<Vec<Packfile>> {
        let mut packfiles = Vec::new();
        let mut current_entries = Vec::new();
        let mut current_size = 0usize;

        for blob in blobs {
            let blob_size = blob.data.len();

            if current_size + blob_size > PACKFILE_MAX_SIZE && !current_entries.is_empty() {
                let packfile = Packfile::new(current_entries)?;
                packfiles.push(packfile);
                current_entries = Vec::new();
                current_size = 0;
            }

            current_entries.push((blob.id, blob.data, ObjectType::Blob));
            current_size += blob_size;
        }

        if !current_entries.is_empty() {
            let packfile = Packfile::new(current_entries)?;
            packfiles.push(packfile);
        }

        Ok(packfiles)
    }

    async fn store_packfiles(&self, packfiles: Vec<Packfile>) -> Result<()> {
        for packfile in packfiles {
            self.repository.save_packfile(packfile).await?;
        }
        Ok(())
    }

    async fn build_directory_tree(&self, mut files: Vec<ProcessedFile>) -> Result<HashId> {
        // Sort files by path to build tree bottom-up
        files.sort_by(|a, b| a.info.relative_path.cmp(&b.info.relative_path));

        let mut directories: HashMap<PathBuf, Vec<TreeEntry>> = HashMap::new();

        // Process all files and directories
        for processed_file in files {
            let parent_dir = processed_file
                .info
                .relative_path
                .parent()
                .unwrap_or(Path::new(""))
                .to_path_buf();

            let name = processed_file
                .info
                .relative_path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();

            let entry = if processed_file.info.is_symlink {
                TreeEntry::Symlink {
                    name,
                    target: processed_file.info.target.unwrap_or_default(),
                    mtime: processed_file.info.modified,
                }
            } else if processed_file.info.is_dir {
                if processed_file.info.relative_path.as_os_str().is_empty() {
                    // Skip the root directory; it is represented by the tree itself
                    continue;
                }
                // We'll fill in the tree hash later
                TreeEntry::Directory {
                    name,
                    tree: HashId::new(&[]), // Placeholder
                    mode: processed_file.info.mode,
                    mtime: processed_file.info.modified,
                }
            } else {
                TreeEntry::File {
                    name,
                    size: processed_file.info.size,
                    chunks: processed_file.chunks,
                    mode: processed_file.info.mode,
                    mtime: processed_file.info.modified,
                }
            };

            directories.entry(parent_dir).or_default().push(entry);
        }

        // Build trees from bottom up
        let mut tree_hashes: HashMap<PathBuf, HashId> = HashMap::new();

        // Sort directory paths by depth (deepest first)
        let mut dir_paths: Vec<_> = directories.keys().cloned().collect();
        dir_paths.sort_by(|a, b| {
            let depth_a = a.components().count();
            let depth_b = b.components().count();
            depth_b.cmp(&depth_a) // Reverse order (deepest first)
        });

        for dir_path in dir_paths {
            let mut entries = directories.remove(&dir_path).unwrap();

            // Update directory entries with their tree hashes
            for entry in &mut entries {
                if let TreeEntry::Directory { name, tree, .. } = entry {
                    let child_path = dir_path.join(name);

                    if let Some(child_tree_hash) = tree_hashes.get(&child_path) {
                        *tree = *child_tree_hash;
                    }
                }
            }

            // Sort entries for deterministic tree creation
            entries.sort_by(|a, b| a.name().cmp(b.name()));

            let tree = Tree::new(entries);
            let tree_data = serde_json::to_vec(&tree)?;

            // Store tree object using the precomputed tree hash
            if !self.repository.has_object(&tree.id).await {
                let packfile = Packfile::new(vec![(tree.id, tree_data, ObjectType::Tree)])?;
                self.repository.save_packfile(packfile).await?;
            }

            tree_hashes.insert(dir_path, tree.id);
        }

        // Return root tree hash
        tree_hashes
            .get(Path::new(""))
            .cloned()
            .ok_or_else(|| Error::repository("Failed to create root tree"))
    }

    async fn create_snapshot(&self, options: BackupOptions, root_tree: HashId) -> Result<Snapshot> {
        let hostname = hostname::get()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        let username = std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .unwrap_or_else(|_| "unknown".to_string());

        let paths = options
            .paths
            .into_iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect();

        Ok(Snapshot::new(
            root_tree,
            paths,
            hostname,
            username,
            options.tags,
            options.parent_snapshot,
        ))
    }

    fn create_dry_run_snapshot(
        &self,
        options: &BackupOptions,
        total_files: u64,
        total_bytes: u64,
    ) -> Result<Snapshot> {
        let hostname = hostname::get()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        let username = std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .unwrap_or_else(|_| "unknown".to_string());

        let paths = options
            .paths
            .iter()
            .map(|p| p.to_string_lossy().to_string())
            .collect();

        let mut snapshot = Snapshot::new(
            HashId::new(&[]), // Dummy tree hash for dry run
            paths,
            hostname,
            username,
            options.tags.clone(),
            options.parent_snapshot,
        );

        snapshot.summary.total_files_processed = total_files;
        snapshot.summary.total_bytes_processed = total_bytes;

        Ok(snapshot)
    }

    #[cfg(unix)]
    fn get_file_mode(&self, metadata: &std::fs::Metadata) -> u32 {
        use std::os::unix::fs::MetadataExt;
        metadata.mode()
    }

    #[cfg(not(unix))]
    fn get_file_mode(&self, _metadata: &std::fs::Metadata) -> u32 {
        0o644 // Default permissions for non-Unix systems
    }

    pub fn get_progress(&self) -> ProgressTracker {
        self.progress.lock().unwrap().clone()
    }
}

#[derive(Debug, Clone)]
pub struct RestoreOptions {
    pub snapshot_id: String,
    pub target_path: PathBuf,
    pub include_patterns: Vec<String>,
    pub exclude_patterns: Vec<String>,
    pub overwrite: bool,
    pub verify: bool,
}

pub struct RestorePipeline {
    repository: Repository,
}

impl RestorePipeline {
    pub fn new(repository: Repository) -> Self {
        Self { repository }
    }

    pub async fn restore(&self, options: RestoreOptions) -> Result<()> {
        tracing::info!(
            "Starting restore of snapshot {} to {}",
            options.snapshot_id,
            options.target_path.display()
        );

        let snapshot = self.repository.load_snapshot(&options.snapshot_id).await?;
        let root_tree_data = self.repository.get_object(&snapshot.tree).await?;
        let root_tree: Tree = serde_json::from_slice(&root_tree_data)?;

        self.restore_tree(&root_tree, &options.target_path, &options)
            .await?;

        tracing::info!("Restore completed successfully");
        Ok(())
    }

    fn restore_tree<'a>(
        &'a self,
        tree: &'a Tree,
        base_path: &'a Path,
        options: &'a RestoreOptions,
    ) -> futures_util::future::BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            fs::create_dir_all(base_path).await?;

            for entry in &tree.entries {
                let entry_path = base_path.join(entry.name());

                match entry {
                    TreeEntry::File {
                        chunks, size, mode, ..
                    } => {
                        if self.should_include(&entry_path, options) {
                            self.restore_file(chunks, &entry_path, *size, *mode, options)
                                .await?;
                        }
                    }
                    TreeEntry::Directory {
                        tree: dir_tree_hash,
                        mode,
                        ..
                    } => {
                        if self.should_include(&entry_path, options) {
                            let dir_tree_data = self.repository.get_object(dir_tree_hash).await?;
                            let dir_tree: Tree = serde_json::from_slice(&dir_tree_data)?;

                            fs::create_dir_all(&entry_path).await?;
                            self.set_permissions(&entry_path, *mode).await?;
                            self.restore_tree(&dir_tree, &entry_path, options).await?;
                        }
                    }
                    TreeEntry::Symlink { target, .. } => {
                        if self.should_include(&entry_path, options) {
                            self.restore_symlink(&entry_path, target).await?;
                        }
                    }
                }
            }

            Ok(())
        })
    }

    async fn restore_file(
        &self,
        chunks: &[HashId],
        path: &Path,
        _size: u64,
        mode: u32,
        options: &RestoreOptions,
    ) -> Result<()> {
        if path.exists() && !options.overwrite {
            tracing::warn!("File already exists, skipping: {}", path.display());
            return Ok(());
        }

        let mut file_data = Vec::new();

        for chunk_hash in chunks {
            let chunk_data = self.repository.get_object(chunk_hash).await?;
            file_data.extend_from_slice(&chunk_data);
        }

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await?;
        }

        fs::write(path, file_data).await?;
        self.set_permissions(path, mode).await?;

        if options.verify {
            // Verify the restored file by re-chunking and comparing hashes
            let restored_data = fs::read(path).await?;
            let chunker = Chunker::new();
            let restored_chunks = chunker.chunk_data(&restored_data);

            if restored_chunks.len() != chunks.len() {
                return Err(Error::corrupted_data(format!(
                    "Chunk count mismatch for {}: expected {}, got {}",
                    path.display(),
                    chunks.len(),
                    restored_chunks.len()
                )));
            }

            for (i, (restored_hash, _)) in restored_chunks.iter().enumerate() {
                if restored_hash != &chunks[i] {
                    return Err(Error::corrupted_data(format!(
                        "Chunk hash mismatch for {} at index {}: expected {}, got {}",
                        path.display(),
                        i,
                        chunks[i],
                        restored_hash
                    )));
                }
            }
        }

        Ok(())
    }

    async fn restore_symlink(&self, path: &Path, target: &str) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await?;
        }

        #[cfg(unix)]
        {
            tokio::fs::symlink(target, path).await?;
        }

        #[cfg(windows)]
        {
            // On Windows, we need to determine if the target is a file or directory
            let target_path = if std::path::Path::new(target).is_absolute() {
                std::path::PathBuf::from(target)
            } else {
                path.parent()
                    .unwrap_or(std::path::Path::new("."))
                    .join(target)
            };

            if target_path.is_dir() {
                tokio::fs::symlink_dir(target, path).await?;
            } else {
                tokio::fs::symlink_file(target, path).await?;
            }
        }

        Ok(())
    }

    fn should_include(&self, path: &Path, options: &RestoreOptions) -> bool {
        let path_str = path.to_string_lossy();

        // Check exclude patterns first
        for pattern in &options.exclude_patterns {
            if path_str.contains(pattern) {
                return false;
            }
        }

        // If no include patterns are specified, include everything
        if options.include_patterns.is_empty() {
            return true;
        }

        // Check include patterns
        for pattern in &options.include_patterns {
            if path_str.contains(pattern) {
                return true;
            }
        }

        false
    }

    #[cfg(unix)]
    async fn set_permissions(&self, path: &Path, mode: u32) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let permissions = std::fs::Permissions::from_mode(mode);
        fs::set_permissions(path, permissions).await?;
        Ok(())
    }

    #[cfg(not(unix))]
    async fn set_permissions(&self, _path: &Path, _mode: u32) -> Result<()> {
        // On non-Unix systems, we can't set arbitrary permissions
        Ok(())
    }
}
