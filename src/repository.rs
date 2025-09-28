use crate::{
    backend::{Backend, FileType},
    crypto::{KeyFile, RepositoryKeys},
    data::{HashId, Index, Packfile, PackfileHeader, Snapshot},
    Error, Result,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Represents the configuration of a repository.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepositoryConfig {
    pub version: u32,
    pub id: String,
    pub compression_level: i32,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub chunk_policy: ChunkPolicy,
    pub encryption_enabled: bool,
}

/// Represents the chunking policy for a repository.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkPolicy {
    pub min_size: usize,
    pub normal_size: usize,
    pub max_size: usize,
}

impl Default for ChunkPolicy {
    fn default() -> Self {
        Self {
            min_size: crate::CHUNK_MIN_SIZE,
            normal_size: crate::CHUNK_NORMAL_SIZE,
            max_size: crate::CHUNK_MAX_SIZE,
        }
    }
}

impl Default for RepositoryConfig {
    fn default() -> Self {
        Self {
            version: crate::REPOSITORY_VERSION,
            id: uuid::Uuid::new_v4().to_string(),
            compression_level: 3,
            created_at: chrono::Utc::now(),
            chunk_policy: ChunkPolicy::default(),
            encryption_enabled: true,
        }
    }
}

/// Represents a repository.
#[derive(Debug, Clone)]
pub struct Repository {
    backend: Arc<dyn Backend>,
    config: RepositoryConfig,
    keys: Option<RepositoryKeys>,
    index: Arc<RwLock<Index>>,
    packfile_cache: Arc<RwLock<HashMap<HashId, Arc<Packfile>>>>,
}

impl Repository {
    /// Lists all packfiles stored in the repository backend.
    pub async fn list_packfiles(&self) -> Result<Vec<HashId>> {
        let ids = self.backend.list_files(FileType::Data).await?;
        let mut packfiles = Vec::with_capacity(ids.len());

        for id in ids {
            match HashId::from_hex(&id) {
                Ok(hash) => packfiles.push(hash),
                Err(_) => {
                    tracing::warn!("Ignoring invalid packfile identifier: {}", id);
                }
            }
        }

        Ok(packfiles)
    }

    /// Initializes a new repository.
    pub async fn init(backend: Arc<dyn Backend>, password: Option<&str>) -> Result<Self> {
        // Test backend connection
        backend.test_connection().await?;

        // Check if repository already exists
        if backend.exists(FileType::Config, "config").await? {
            return Err(Error::repository("Repository already exists"));
        }

        let config = RepositoryConfig::default();
        let keys = if config.encryption_enabled {
            if password.is_none() {
                return Err(Error::repository(
                    "Password required for encrypted repository",
                ));
            }
            Some(RepositoryKeys::new())
        } else {
            None
        };

        // Create directory structure
        for dir_type in [
            FileType::Keys,
            FileType::Data,
            FileType::Index,
            FileType::Snapshots,
            FileType::Locks,
        ] {
            let test_file = format!(".dj_{}_dir", dir_type.as_str());
            backend.write(dir_type, &test_file, vec![]).await?;
            backend.delete(dir_type, &test_file).await?;
        }

        // Save configuration
        let config_data = serde_json::to_vec(&config)?;
        backend
            .write(FileType::Config, "config", config_data)
            .await?;

        // Save keys if encryption is enabled
        if let (Some(keys), Some(password)) = (&keys, password) {
            let keyfile = keys.encrypt_with_password(password)?;
            let keyfile_data = serde_json::to_vec(&keyfile)?;
            backend
                .write(FileType::Keys, "master", keyfile_data)
                .await?;
        }

        // Create empty index
        let index = Index::new();
        let index_data = serde_json::to_vec(&index)?;
        backend.write(FileType::Index, "master", index_data).await?;

        Ok(Self {
            backend,
            config,
            keys,
            index: Arc::new(RwLock::new(index)),
            packfile_cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Opens an existing repository.
    pub async fn open(backend: Arc<dyn Backend>, password: Option<&str>) -> Result<Self> {
        // Test backend connection
        backend.test_connection().await?;

        // Load configuration
        let config_data = backend
            .read_full(FileType::Config, "config")
            .await
            .map_err(|_| Error::repository("Repository not found or invalid"))?;
        let config: RepositoryConfig = serde_json::from_slice(&config_data)?;

        // Validate repository version
        if config.version > crate::REPOSITORY_VERSION {
            return Err(Error::repository(format!(
                "Repository version {} is newer than supported version {}",
                config.version,
                crate::REPOSITORY_VERSION
            )));
        }

        // Load keys if encryption is enabled
        let keys = if config.encryption_enabled {
            if password.is_none() {
                return Err(Error::repository(
                    "Password required for encrypted repository",
                ));
            }

            let keyfile_data = backend.read_full(FileType::Keys, "master").await?;
            let keyfile: KeyFile = serde_json::from_slice(&keyfile_data)?;
            Some(RepositoryKeys::decrypt_from_keyfile(
                &keyfile,
                password.unwrap(),
            )?)
        } else {
            None
        };

        // Load index
        let index_data = backend.read_full(FileType::Index, "master").await?;
        let index: Index = serde_json::from_slice(&index_data)?;

        Ok(Self {
            backend,
            config,
            keys,
            index: Arc::new(RwLock::new(index)),
            packfile_cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Saves a packfile to the repository.
    pub async fn save_packfile(&self, packfile: Packfile) -> Result<()> {
        let packfile_id = packfile.id;

        // Encrypt packfile data if encryption is enabled
        let data_to_store = if let Some(keys) = &self.keys {
            let encrypted = keys.encryption_key.encrypt(&packfile.data)?;
            serde_json::to_vec(&encrypted)?
        } else {
            packfile.data.clone()
        };

        // Store packfile
        self.backend
            .write(FileType::Data, &packfile_id.to_hex(), data_to_store)
            .await?;

        // Update index
        {
            let mut index = self.index.write().await;
            index.add_packfile(&packfile);

            // Save updated index
            let index_data = serde_json::to_vec(&*index)?;
            self.backend
                .write(FileType::Index, "master", index_data)
                .await?;
        }

        // Cache the packfile
        {
            let mut cache = self.packfile_cache.write().await;
            cache.insert(packfile_id, Arc::new(packfile));
        }

        Ok(())
    }

    /// Loads a packfile from the repository.
    pub async fn load_packfile(&self, packfile_id: &HashId) -> Result<Arc<Packfile>> {
        // Check cache first
        {
            let cache = self.packfile_cache.read().await;
            if let Some(packfile) = cache.get(packfile_id) {
                return Ok(packfile.clone());
            }
        }

        // Load from backend
        let stored_data = self
            .backend
            .read_full(FileType::Data, &packfile_id.to_hex())
            .await?;

        // Decrypt if necessary
        let packfile_data = if let Some(keys) = &self.keys {
            let encrypted: crate::crypto::EncryptedData = serde_json::from_slice(&stored_data)?;
            keys.encryption_key.decrypt(&encrypted)?
        } else {
            stored_data
        };

        // Parse packfile
        let header_len_bytes = 4;
        if packfile_data.len() < header_len_bytes {
            return Err(Error::corrupted_data("Packfile too small"));
        }

        let header_bytes_len = u32::from_le_bytes([
            packfile_data[0],
            packfile_data[1],
            packfile_data[2],
            packfile_data[3],
        ]) as usize;

        if packfile_data.len() < header_len_bytes + header_bytes_len {
            return Err(Error::corrupted_data("Packfile header extends beyond data"));
        }

        let header_bytes = &packfile_data[header_len_bytes..header_len_bytes + header_bytes_len];
        let header = serde_json::from_slice(header_bytes)?;

        let packfile = Packfile {
            id: *packfile_id,
            header,
            data: packfile_data,
        };

        let packfile_arc = Arc::new(packfile);

        // Cache the packfile
        {
            let mut cache = self.packfile_cache.write().await;
            cache.insert(*packfile_id, packfile_arc.clone());
        }

        Ok(packfile_arc)
    }

    /// Returns the header metadata for a specific packfile.
    pub async fn packfile_header(&self, packfile_id: &HashId) -> Result<PackfileHeader> {
        let packfile = self.load_packfile(packfile_id).await?;
        Ok(packfile.header.clone())
    }

    /// Gets an object from the repository.
    pub async fn get_object(&self, hash: &HashId) -> Result<Vec<u8>> {
        let index = self.index.read().await;
        let entry = index.get(hash).ok_or_else(|| Error::ObjectNotFound {
            hash: hash.to_hex(),
        })?;

        let packfile = self.load_packfile(&entry.packfile_id).await?;

        // Find the specific entry in the packfile
        let packfile_entry = packfile
            .header
            .entries
            .iter()
            .find(|e| e.hash == *hash)
            .ok_or_else(|| Error::corrupted_data("Object not found in packfile"))?;

        packfile.extract_object(packfile_entry)
    }

    /// Checks if an object exists in the repository.
    pub async fn has_object(&self, hash: &HashId) -> bool {
        let index = self.index.read().await;
        index.contains(hash)
    }

    /// Saves a snapshot to the repository.
    pub async fn save_snapshot(&self, snapshot: &Snapshot) -> Result<()> {
        let snapshot_data = serde_json::to_vec(snapshot)?;

        // Encrypt snapshot if encryption is enabled
        let data_to_store = if let Some(keys) = &self.keys {
            let encrypted = keys.encryption_key.encrypt(&snapshot_data)?;
            serde_json::to_vec(&encrypted)?
        } else {
            snapshot_data
        };

        self.backend
            .write(FileType::Snapshots, &snapshot.id.to_string(), data_to_store)
            .await?;

        Ok(())
    }

    /// Loads a snapshot from the repository.
    pub async fn load_snapshot(&self, snapshot_id: &str) -> Result<Snapshot> {
        let stored_data = self
            .backend
            .read_full(FileType::Snapshots, snapshot_id)
            .await
            .map_err(|_| Error::SnapshotNotFound {
                id: snapshot_id.to_string(),
            })?;

        // Decrypt if necessary
        let snapshot_data = if let Some(keys) = &self.keys {
            let encrypted: crate::crypto::EncryptedData = serde_json::from_slice(&stored_data)?;
            keys.encryption_key.decrypt(&encrypted)?
        } else {
            stored_data
        };

        let snapshot: Snapshot = serde_json::from_slice(&snapshot_data)?;
        Ok(snapshot)
    }

    /// Lists all snapshots in the repository.
    pub async fn list_snapshots(&self) -> Result<Vec<String>> {
        let snapshot_ids = self.backend.list_files(FileType::Snapshots).await?;
        Ok(snapshot_ids)
    }

    /// Deletes a snapshot from the repository.
    pub async fn delete_snapshot(&self, snapshot_id: &str) -> Result<()> {
        self.backend.delete(FileType::Snapshots, snapshot_id).await
    }

    /// Checks the integrity of the repository.
    pub async fn check_integrity(&self, check_data: bool) -> Result<RepositoryCheckResult> {
        let mut result = RepositoryCheckResult::default();

        // Check configuration
        match self.backend.read_full(FileType::Config, "config").await {
            Ok(_) => result.config_ok = true,
            Err(e) => {
                result.config_ok = false;
                result.errors.push(format!("Config check failed: {}", e));
            }
        }

        // Check keys (if encryption enabled)
        if self.config.encryption_enabled {
            match self.backend.read_full(FileType::Keys, "master").await {
                Ok(_) => result.keys_ok = true,
                Err(e) => {
                    result.keys_ok = false;
                    result.errors.push(format!("Keys check failed: {}", e));
                }
            }
        } else {
            result.keys_ok = true;
        }

        // Check index
        match self.backend.read_full(FileType::Index, "master").await {
            Ok(_) => result.index_ok = true,
            Err(e) => {
                result.index_ok = false;
                result.errors.push(format!("Index check failed: {}", e));
            }
        }

        // Check snapshots
        let snapshot_ids = self.backend.list_files(FileType::Snapshots).await?;
        result.snapshots_checked = snapshot_ids.len() as u64;

        for snapshot_id in snapshot_ids {
            match self.load_snapshot(&snapshot_id).await {
                Ok(_) => result.snapshots_ok += 1,
                Err(e) => {
                    result
                        .errors
                        .push(format!("Snapshot {} check failed: {}", snapshot_id, e));
                }
            }
        }

        // Check packfiles and data integrity
        if check_data {
            let index = self.index.read().await;
            result.packfiles_checked = index.packfiles.len() as u64;

            for packfile_id in &index.packfiles {
                match self.load_packfile(packfile_id).await {
                    Ok(packfile) => {
                        result.packfiles_ok += 1;

                        // Verify each object in the packfile
                        for entry in &packfile.header.entries {
                            match packfile.extract_object(entry) {
                                Ok(data) => {
                                    let computed_hash = crate::data::HashId::new(&data);
                                    if computed_hash == entry.hash {
                                        result.objects_ok += 1;
                                    } else {
                                        result.errors.push(format!(
                                            "Hash mismatch for object {} in packfile {}",
                                            entry.hash, packfile_id
                                        ));
                                    }
                                }
                                Err(e) => {
                                    result.errors.push(format!(
                                        "Failed to extract object {} from packfile {}: {}",
                                        entry.hash, packfile_id, e
                                    ));
                                }
                            }
                            result.objects_checked += 1;
                        }
                    }
                    Err(e) => {
                        result
                            .errors
                            .push(format!("Packfile {} check failed: {}", packfile_id, e));
                    }
                }
            }
        }

        Ok(result)
    }

    /// Returns the repository configuration.
    pub fn config(&self) -> &RepositoryConfig {
        &self.config
    }

    /// Returns the repository backend.
    pub fn backend(&self) -> Arc<dyn Backend> {
        self.backend.clone()
    }

    /// Creates a lock in the repository.
    pub async fn create_lock(&self, name: &str, timeout_secs: u64) -> Result<crate::backend::Lock> {
        self.backend.create_lock(name, timeout_secs).await
    }
}

/// Represents the result of a repository check.
#[derive(Debug, Default)]
pub struct RepositoryCheckResult {
    pub config_ok: bool,
    pub keys_ok: bool,
    pub index_ok: bool,
    pub snapshots_checked: u64,
    pub snapshots_ok: u64,
    pub packfiles_checked: u64,
    pub packfiles_ok: u64,
    pub objects_checked: u64,
    pub objects_ok: u64,
    pub errors: Vec<String>,
}

impl RepositoryCheckResult {
    /// Checks if the repository is healthy.
    pub fn is_healthy(&self) -> bool {
        self.errors.is_empty()
            && self.config_ok
            && self.keys_ok
            && self.index_ok
            && self.snapshots_checked == self.snapshots_ok
            && self.packfiles_checked == self.packfiles_ok
            && (self.objects_checked == 0 || self.objects_checked == self.objects_ok)
    }
}
