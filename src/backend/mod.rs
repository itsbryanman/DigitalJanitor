use crate::{Error, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

/// Represents the type of a file in the repository.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileType {
    Config,
    Keys,
    Data,
    Index,
    Snapshots,
    Locks,
}

impl FileType {
    /// Returns the string representation of the file type.
    pub fn as_str(&self) -> &'static str {
        match self {
            FileType::Config => "config",
            FileType::Keys => "keys",
            FileType::Data => "data",
            FileType::Index => "index",
            FileType::Snapshots => "snapshots",
            FileType::Locks => "locks",
        }
    }

    /// Returns the subdirectory for the file type.
    pub fn subdir(&self) -> &'static str {
        match self {
            FileType::Config => "",
            FileType::Keys => "keys",
            FileType::Data => "data",
            FileType::Index => "index",
            FileType::Snapshots => "snapshots",
            FileType::Locks => "locks",
        }
    }
}

/// The `Backend` trait defines the interface for a storage backend.
#[async_trait]
pub trait Backend: Send + Sync + Debug {
    /// Lists all files of a given type.
    async fn list_files(&self, file_type: FileType) -> Result<Vec<String>>;
    /// Reads a range of bytes from a file.
    async fn read_range(
        &self,
        file_type: FileType,
        id: &str,
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>>;
    /// Reads the full content of a file.
    async fn read_full(&self, file_type: FileType, id: &str) -> Result<Vec<u8>>;
    /// Writes data to a file.
    async fn write(&self, file_type: FileType, id: &str, data: Vec<u8>) -> Result<()>;
    /// Deletes a file.
    async fn delete(&self, file_type: FileType, id: &str) -> Result<()>;
    /// Checks if a file exists.
    async fn exists(&self, file_type: FileType, id: &str) -> Result<bool>;
    /// Gets the metadata of a file.
    async fn metadata(&self, file_type: FileType, id: &str) -> Result<FileMetadata>;
    /// Creates a lock.
    async fn create_lock(&self, lock_name: &str, timeout_secs: u64) -> Result<Lock>;
    /// Tests the connection to the backend.
    async fn test_connection(&self) -> Result<()>;
}

/// Represents the metadata of a file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadata {
    pub size: u64,
    pub modified: chrono::DateTime<chrono::Utc>,
    pub etag: Option<String>,
}

/// Represents a lock.
#[derive(Debug, Serialize, Deserialize)]
pub struct Lock {
    pub name: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub holder_id: String,
}

impl Lock {
    /// Creates a new lock.
    pub fn new(name: String, timeout_secs: u64) -> Self {
        let holder_id = uuid::Uuid::new_v4().to_string();
        let expires_at = chrono::Utc::now() + chrono::Duration::seconds(timeout_secs as i64);
        Self {
            name,
            expires_at,
            holder_id,
        }
    }

    /// Checks if the lock is expired.
    pub fn is_expired(&self) -> bool {
        chrono::Utc::now() > self.expires_at
    }
}

mod filesystem;
mod s3;
mod sftp;

pub use filesystem::FilesystemBackend;
#[cfg(feature = "s3")]
pub use s3::S3Backend;
#[cfg(feature = "sftp")]
pub use sftp::SftpBackend;

/// Represents the configuration for a backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BackendConfig {
    Filesystem {
        path: String,
    },
    #[cfg(feature = "s3")]
    S3 {
        bucket: String,
        prefix: Option<String>,
        region: String,
        access_key_id: Option<String>,
        secret_access_key: Option<String>,
        endpoint: Option<String>,
    },
    #[cfg(feature = "sftp")]
    Sftp {
        host: String,
        port: u16,
        username: String,
        password: Option<String>,
        private_key_path: Option<String>,
        path: String,
    },
}

impl BackendConfig {
    /// Creates a new backend from the configuration.
    pub async fn create_backend(&self) -> Result<Box<dyn Backend>> {
        match self {
            BackendConfig::Filesystem { path } => {
                Ok(Box::new(FilesystemBackend::new(path.clone())?))
            }
            #[cfg(feature = "s3")]
            BackendConfig::S3 {
                bucket,
                prefix,
                region,
                access_key_id,
                secret_access_key,
                endpoint,
            } => Ok(Box::new(
                S3Backend::new(
                    bucket.clone(),
                    prefix.clone(),
                    region.clone(),
                    access_key_id.clone(),
                    secret_access_key.clone(),
                    endpoint.clone(),
                )
                .await?,
            )),
            #[cfg(feature = "sftp")]
            BackendConfig::Sftp {
                host,
                port,
                username,
                password,
                private_key_path,
                path,
            } => Ok(Box::new(
                SftpBackend::new(
                    host.clone(),
                    *port,
                    username.clone(),
                    password.clone(),
                    private_key_path.clone(),
                    path.clone(),
                )
                .await?,
            )),
        }
    }

    /// Creates a new backend configuration from a URL.
    pub fn from_url(url: &str) -> Result<Self> {
        let parsed = url::Url::parse(url)
            .map_err(|e| Error::configuration(format!("Invalid URL: {}", e)))?;

        match parsed.scheme() {
            "file" => Ok(BackendConfig::Filesystem {
                path: parsed.path().to_string(),
            }),
            #[cfg(feature = "s3")]
            "s3" => {
                let bucket = parsed
                    .host_str()
                    .ok_or_else(|| Error::configuration("S3 URL must specify bucket as host"))?
                    .to_string();

                let prefix = if parsed.path().len() > 1 {
                    Some(parsed.path()[1..].to_string()) // Remove leading "/"
                } else {
                    None
                };

                let query_pairs: std::collections::HashMap<String, String> = parsed
                    .query_pairs()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect();

                Ok(BackendConfig::S3 {
                    bucket,
                    prefix,
                    region: query_pairs
                        .get("region")
                        .cloned()
                        .unwrap_or_else(|| "us-east-1".to_string()),
                    access_key_id: query_pairs.get("access_key_id").cloned(),
                    secret_access_key: query_pairs.get("secret_access_key").cloned(),
                    endpoint: query_pairs.get("endpoint").cloned(),
                })
            }
            #[cfg(feature = "sftp")]
            "sftp" => {
                let host = parsed
                    .host_str()
                    .ok_or_else(|| Error::configuration("SFTP URL must specify host"))?
                    .to_string();

                let port = parsed.port().unwrap_or(22);
                let username = parsed.username().to_string();
                let password = parsed.password().map(|p| p.to_string());

                Ok(BackendConfig::Sftp {
                    host,
                    port,
                    username,
                    password,
                    private_key_path: None,
                    path: parsed.path().to_string(),
                })
            }
            scheme => Err(Error::configuration(format!(
                "Unsupported URL scheme: {}",
                scheme
            ))),
        }
    }
}
