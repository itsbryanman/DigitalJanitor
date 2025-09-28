#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Encryption error: {message}")]
    Encryption { message: String },

    #[error("Decryption error: {message}")]
    Decryption { message: String },

    #[error("Repository error: {message}")]
    Repository { message: String },

    #[error("Backend error: {message}")]
    Backend { message: String },

    #[error("Index error: {message}")]
    Index { message: String },

    #[error("Snapshot not found: {id}")]
    SnapshotNotFound { id: String },

    #[error("Object not found: {hash}")]
    ObjectNotFound { hash: String },

    #[error("Invalid hash: {hash}")]
    InvalidHash { hash: String },

    #[error("Corrupted data: {message}")]
    CorruptedData { message: String },

    #[error("Authentication failed: {message}")]
    Authentication { message: String },

    #[error("Permission denied: {message}")]
    PermissionDenied { message: String },

    #[error("Network error: {message}")]
    Network { message: String },

    #[error("Configuration error: {message}")]
    Configuration { message: String },

    #[error("Lock error: {message}")]
    Lock { message: String },

    #[error("Validation error: {message}")]
    Validation { message: String },

    #[error("Operation cancelled")]
    Cancelled,

    #[error("Operation timeout")]
    Timeout,

    #[error("Generic error: {0}")]
    Generic(#[from] anyhow::Error),
}

impl Error {
    pub fn encryption<S: Into<String>>(message: S) -> Self {
        Self::Encryption {
            message: message.into(),
        }
    }

    pub fn decryption<S: Into<String>>(message: S) -> Self {
        Self::Decryption {
            message: message.into(),
        }
    }

    pub fn repository<S: Into<String>>(message: S) -> Self {
        Self::Repository {
            message: message.into(),
        }
    }

    pub fn backend<S: Into<String>>(message: S) -> Self {
        Self::Backend {
            message: message.into(),
        }
    }

    pub fn index<S: Into<String>>(message: S) -> Self {
        Self::Index {
            message: message.into(),
        }
    }

    pub fn corrupted_data<S: Into<String>>(message: S) -> Self {
        Self::CorruptedData {
            message: message.into(),
        }
    }

    pub fn authentication<S: Into<String>>(message: S) -> Self {
        Self::Authentication {
            message: message.into(),
        }
    }

    pub fn network<S: Into<String>>(message: S) -> Self {
        Self::Network {
            message: message.into(),
        }
    }

    pub fn configuration<S: Into<String>>(message: S) -> Self {
        Self::Configuration {
            message: message.into(),
        }
    }

    pub fn lock<S: Into<String>>(message: S) -> Self {
        Self::Lock {
            message: message.into(),
        }
    }

    pub fn validation<S: Into<String>>(message: S) -> Self {
        Self::Validation {
            message: message.into(),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
