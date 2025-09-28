use crate::{
    backend::{Backend, FileMetadata, FileType, Lock},
    Error, Result,
};
use async_trait::async_trait;

#[derive(Debug, Clone)]
pub struct SftpBackend;

impl SftpBackend {
    pub async fn new(
        _host: String,
        _port: u16,
        _username: String,
        _password: Option<String>,
        _private_key_path: Option<String>,
        _path: String,
    ) -> Result<Self> {
        let _ = (_host, _port, _username, _password, _private_key_path, _path);
        Err(Error::backend(
            "SFTP backend support is not available in this build",
        ))
    }
}

#[async_trait]
impl Backend for SftpBackend {
    async fn list_files(&self, _file_type: FileType) -> Result<Vec<String>> {
        Err(Error::backend(
            "SFTP backend support is not available in this build",
        ))
    }

    async fn read_range(
        &self,
        _file_type: FileType,
        _id: &str,
        _offset: u64,
        _length: u64,
    ) -> Result<Vec<u8>> {
        Err(Error::backend(
            "SFTP backend support is not available in this build",
        ))
    }

    async fn read_full(&self, _file_type: FileType, _id: &str) -> Result<Vec<u8>> {
        Err(Error::backend(
            "SFTP backend support is not available in this build",
        ))
    }

    async fn write(&self, _file_type: FileType, _id: &str, _data: Vec<u8>) -> Result<()> {
        Err(Error::backend(
            "SFTP backend support is not available in this build",
        ))
    }

    async fn delete(&self, _file_type: FileType, _id: &str) -> Result<()> {
        Err(Error::backend(
            "SFTP backend support is not available in this build",
        ))
    }

    async fn exists(&self, _file_type: FileType, _id: &str) -> Result<bool> {
        Err(Error::backend(
            "SFTP backend support is not available in this build",
        ))
    }

    async fn metadata(&self, _file_type: FileType, _id: &str) -> Result<FileMetadata> {
        Err(Error::backend(
            "SFTP backend support is not available in this build",
        ))
    }

    async fn create_lock(&self, _lock_name: &str, _timeout_secs: u64) -> Result<Lock> {
        Err(Error::backend(
            "SFTP backend support is not available in this build",
        ))
    }

    async fn test_connection(&self) -> Result<()> {
        Err(Error::backend(
            "SFTP backend support is not available in this build",
        ))
    }
}
