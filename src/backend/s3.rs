use crate::{
    backend::{Backend, FileMetadata, FileType, Lock},
    Error, Result,
};
use async_trait::async_trait;

#[derive(Debug, Clone)]
pub struct S3Backend;

impl S3Backend {
    pub async fn new(
        _bucket: String,
        _prefix: Option<String>,
        _region: String,
        _access_key_id: Option<String>,
        _secret_access_key: Option<String>,
        _endpoint: Option<String>,
    ) -> Result<Self> {
        let _ = (
            _bucket,
            _prefix,
            _region,
            _access_key_id,
            _secret_access_key,
            _endpoint,
        );
        Err(Error::backend(
            "S3 backend support is not available in this build",
        ))
    }
}

#[async_trait]
impl Backend for S3Backend {
    async fn list_files(&self, _file_type: FileType) -> Result<Vec<String>> {
        Err(Error::backend(
            "S3 backend support is not available in this build",
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
            "S3 backend support is not available in this build",
        ))
    }

    async fn read_full(&self, _file_type: FileType, _id: &str) -> Result<Vec<u8>> {
        Err(Error::backend(
            "S3 backend support is not available in this build",
        ))
    }

    async fn write(&self, _file_type: FileType, _id: &str, _data: Vec<u8>) -> Result<()> {
        Err(Error::backend(
            "S3 backend support is not available in this build",
        ))
    }

    async fn delete(&self, _file_type: FileType, _id: &str) -> Result<()> {
        Err(Error::backend(
            "S3 backend support is not available in this build",
        ))
    }

    async fn exists(&self, _file_type: FileType, _id: &str) -> Result<bool> {
        Err(Error::backend(
            "S3 backend support is not available in this build",
        ))
    }

    async fn metadata(&self, _file_type: FileType, _id: &str) -> Result<FileMetadata> {
        Err(Error::backend(
            "S3 backend support is not available in this build",
        ))
    }

    async fn create_lock(&self, _lock_name: &str, _timeout_secs: u64) -> Result<Lock> {
        Err(Error::backend(
            "S3 backend support is not available in this build",
        ))
    }

    async fn test_connection(&self) -> Result<()> {
        Err(Error::backend(
            "S3 backend support is not available in this build",
        ))
    }
}
