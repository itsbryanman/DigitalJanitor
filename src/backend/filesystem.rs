use crate::{
    backend::{Backend, FileMetadata, FileType, Lock},
    Error, Result,
};
use async_trait::async_trait;
use std::fs as stdfs;
use std::path::{Path, PathBuf};
use tokio::fs;

#[derive(Debug, Clone)]
pub struct FilesystemBackend {
    base_path: PathBuf,
}

impl FilesystemBackend {
    pub fn new<P: AsRef<Path>>(base_path: P) -> Result<Self> {
        let base_path = base_path.as_ref().to_path_buf();

        if !base_path.exists() {
            stdfs::create_dir_all(&base_path).map_err(|e| {
                Error::backend(format!(
                    "Failed to create base path {}: {}",
                    base_path.display(),
                    e
                ))
            })?;
        }

        Ok(Self { base_path })
    }

    fn get_file_path(&self, file_type: FileType, id: &str) -> PathBuf {
        let subdir = file_type.subdir();
        if subdir.is_empty() {
            self.base_path.join(id)
        } else {
            let hash_prefix = if id.len() >= 2 { &id[..2] } else { id };
            self.base_path.join(subdir).join(hash_prefix).join(id)
        }
    }

    fn get_dir_path(&self, file_type: FileType) -> PathBuf {
        let subdir = file_type.subdir();
        if subdir.is_empty() {
            self.base_path.clone()
        } else {
            self.base_path.join(subdir)
        }
    }

    async fn ensure_dir_exists(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).await.map_err(|e| {
                Error::backend(format!(
                    "Failed to create directory {}: {}",
                    parent.display(),
                    e
                ))
            })?;
        }
        Ok(())
    }
}

#[async_trait]
impl Backend for FilesystemBackend {
    async fn list_files(&self, file_type: FileType) -> Result<Vec<String>> {
        let dir_path = self.get_dir_path(file_type);

        if !dir_path.exists() {
            return Ok(Vec::new());
        }

        let mut files = Vec::new();
        let mut read_dir = fs::read_dir(&dir_path).await.map_err(|e| {
            Error::backend(format!(
                "Failed to read directory {}: {}",
                dir_path.display(),
                e
            ))
        })?;

        while let Some(entry) = read_dir
            .next_entry()
            .await
            .map_err(|e| Error::backend(format!("Failed to read directory entry: {}", e)))?
        {
            let path = entry.path();

            if path.is_file() {
                if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
                    files.push(filename.to_string());
                }
            } else if path.is_dir() {
                // For data files stored in subdirectories
                let mut subdir_read = fs::read_dir(&path).await.map_err(|e| {
                    Error::backend(format!(
                        "Failed to read subdirectory {}: {}",
                        path.display(),
                        e
                    ))
                })?;

                while let Some(subentry) = subdir_read.next_entry().await.map_err(|e| {
                    Error::backend(format!("Failed to read subdirectory entry: {}", e))
                })? {
                    let subpath = subentry.path();
                    if subpath.is_file() {
                        if let Some(filename) = subpath.file_name().and_then(|n| n.to_str()) {
                            files.push(filename.to_string());
                        }
                    }
                }
            }
        }

        files.sort();
        Ok(files)
    }

    async fn read_range(
        &self,
        file_type: FileType,
        id: &str,
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>> {
        use std::io::SeekFrom;
        use tokio::io::{AsyncReadExt, AsyncSeekExt};

        let file_path = self.get_file_path(file_type, id);
        let mut file = fs::File::open(&file_path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Error::ObjectNotFound {
                    hash: id.to_string(),
                }
            } else {
                Error::backend(format!(
                    "Failed to open file {}: {}",
                    file_path.display(),
                    e
                ))
            }
        })?;

        file.seek(SeekFrom::Start(offset)).await.map_err(|e| {
            Error::backend(format!(
                "Failed to seek in file {}: {}",
                file_path.display(),
                e
            ))
        })?;

        let mut buffer = vec![0u8; length as usize];
        let bytes_read = file.read_exact(&mut buffer).await.map_err(|e| {
            Error::backend(format!(
                "Failed to read from file {}: {}",
                file_path.display(),
                e
            ))
        })?;

        if bytes_read != length as usize {
            return Err(Error::backend(format!(
                "Expected to read {} bytes, but read {}",
                length, bytes_read
            )));
        }

        Ok(buffer)
    }

    async fn read_full(&self, file_type: FileType, id: &str) -> Result<Vec<u8>> {
        let file_path = self.get_file_path(file_type, id);
        fs::read(&file_path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Error::ObjectNotFound {
                    hash: id.to_string(),
                }
            } else {
                Error::backend(format!(
                    "Failed to read file {}: {}",
                    file_path.display(),
                    e
                ))
            }
        })
    }

    async fn write(&self, file_type: FileType, id: &str, data: Vec<u8>) -> Result<()> {
        let file_path = self.get_file_path(file_type, id);
        self.ensure_dir_exists(&file_path).await?;

        fs::write(&file_path, data).await.map_err(|e| {
            Error::backend(format!(
                "Failed to write file {}: {}",
                file_path.display(),
                e
            ))
        })
    }

    async fn delete(&self, file_type: FileType, id: &str) -> Result<()> {
        let file_path = self.get_file_path(file_type, id);
        if file_path.exists() {
            fs::remove_file(&file_path).await.map_err(|e| {
                Error::backend(format!(
                    "Failed to delete file {}: {}",
                    file_path.display(),
                    e
                ))
            })?;
        }
        Ok(())
    }

    async fn exists(&self, file_type: FileType, id: &str) -> Result<bool> {
        let file_path = self.get_file_path(file_type, id);
        Ok(file_path.exists())
    }

    async fn metadata(&self, file_type: FileType, id: &str) -> Result<FileMetadata> {
        let file_path = self.get_file_path(file_type, id);
        let metadata = fs::metadata(&file_path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Error::ObjectNotFound {
                    hash: id.to_string(),
                }
            } else {
                Error::backend(format!(
                    "Failed to get metadata for {}: {}",
                    file_path.display(),
                    e
                ))
            }
        })?;

        let modified = metadata
            .modified()
            .map_err(|e| Error::backend(format!("Failed to get modification time: {}", e)))?
            .into();

        Ok(FileMetadata {
            size: metadata.len(),
            modified,
            etag: None,
        })
    }

    async fn create_lock(&self, lock_name: &str, timeout_secs: u64) -> Result<Lock> {
        let lock_path = self.get_file_path(FileType::Locks, lock_name);
        self.ensure_dir_exists(&lock_path).await?;

        // Check if lock already exists
        if lock_path.exists() {
            let lock_data = fs::read_to_string(&lock_path)
                .await
                .map_err(|e| Error::backend(format!("Failed to read existing lock: {}", e)))?;

            if let Ok(existing_lock) = serde_json::from_str::<Lock>(&lock_data) {
                if !existing_lock.is_expired() {
                    return Err(Error::lock(format!(
                        "Lock '{}' is already held by {}",
                        lock_name, existing_lock.holder_id
                    )));
                } else {
                    // Lock is expired, so we can delete it
                    fs::remove_file(&lock_path).await.map_err(|e| {
                        Error::backend(format!("Failed to remove stale lock file: {}", e))
                    })?;
                }
            }
        }

        let lock = Lock::new(lock_name.to_string(), timeout_secs);
        let lock_data = serde_json::to_string(&lock)
            .map_err(|e| Error::backend(format!("Failed to serialize lock: {}", e)))?;

        fs::write(&lock_path, lock_data)
            .await
            .map_err(|e| Error::backend(format!("Failed to write lock file: {}", e)))?;

        Ok(lock)
    }

    async fn test_connection(&self) -> Result<()> {
        if !self.base_path.exists() {
            return Err(Error::backend(format!(
                "Base path does not exist: {}",
                self.base_path.display()
            )));
        }

        if !self.base_path.is_dir() {
            return Err(Error::backend(format!(
                "Base path is not a directory: {}",
                self.base_path.display()
            )));
        }

        // Test write access
        let test_file = self.base_path.join(".dj_test");
        fs::write(&test_file, b"test")
            .await
            .map_err(|e| Error::backend(format!("No write access to repository: {}", e)))?;

        fs::remove_file(&test_file)
            .await
            .map_err(|e| Error::backend(format!("Failed to clean up test file: {}", e)))?;

        Ok(())
    }
}
