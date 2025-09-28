pub mod backend;
pub mod client;
pub mod crypto;
pub mod data;
pub mod error;
pub mod index;
pub mod pipeline;
pub mod repository;
pub mod snapshot;
pub mod storage;
pub mod utils;

#[cfg(feature = "mount")]
pub mod fuse_mount;

#[cfg(feature = "server")]
pub mod server;

pub use error::{Error, Result};

pub const CHUNK_MIN_SIZE: usize = 64 * 1024; // 64KB
pub const CHUNK_MAX_SIZE: usize = 4 * 1024 * 1024; // 4MB
pub const CHUNK_NORMAL_SIZE: usize = 1024 * 1024; // 1MB

pub const BLAKE3_HASH_SIZE: usize = 32;
pub const AES_KEY_SIZE: usize = 32;
pub const AES_NONCE_SIZE: usize = 12;

pub const PACKFILE_MAX_SIZE: usize = 128 * 1024 * 1024; // 128MB
pub const INDEX_VERSION: u32 = 1;
pub const REPOSITORY_VERSION: u32 = 1;
