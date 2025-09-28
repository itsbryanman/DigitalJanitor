use crate::{
    data::{HashId, ObjectType},
    repository::Repository,
    Result,
};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct StorageStatistics {
    pub total_objects: u64,
    pub total_size: u64,
    pub blob_count: u64,
    pub blob_size: u64,
    pub tree_count: u64,
    pub tree_size: u64,
    pub snapshot_count: u64,
    pub snapshot_size: u64,
    pub packfile_count: u64,
    pub compression_ratio: f64,
    pub deduplication_ratio: f64,
}

pub struct StorageManager {
    repository: Arc<Repository>,
}

impl StorageManager {
    pub fn new(repository: Arc<Repository>) -> Self {
        Self { repository }
    }

    pub async fn get_statistics(&self) -> Result<StorageStatistics> {
        let snapshots = self.repository.list_snapshots().await?;
        let mut stats = StorageStatistics {
            total_objects: 0,
            total_size: 0,
            blob_count: 0,
            blob_size: 0,
            tree_count: 0,
            tree_size: 0,
            snapshot_count: snapshots.len() as u64,
            snapshot_size: 0,
            packfile_count: 0,
            compression_ratio: 0.0,
            deduplication_ratio: 0.0,
        };

        // Calculate snapshot sizes
        for snapshot_id in &snapshots {
            if let Ok(snapshot) = self.repository.load_snapshot(snapshot_id).await {
                stats.snapshot_size += serde_json::to_vec(&snapshot)?.len() as u64;
            }
        }

        // Analyse packfiles to gather detailed statistics
        let packfile_ids = self.repository.list_packfiles().await?;
        let mut compressed_total = 0u64;
        let mut unique_hashes: HashSet<String> = HashSet::new();
        let mut unique_uncompressed = 0u64;

        for pack_id in packfile_ids {
            stats.packfile_count += 1;

            let packfile = self.repository.load_packfile(&pack_id).await?;
            for entry in &packfile.header.entries {
                stats.total_objects += 1;
                stats.total_size += entry.uncompressed_length;
                compressed_total += entry.length;

                match entry.object_type {
                    ObjectType::Blob => {
                        stats.blob_count += 1;
                        stats.blob_size += entry.uncompressed_length;
                    }
                    ObjectType::Tree => {
                        stats.tree_count += 1;
                        stats.tree_size += entry.uncompressed_length;
                    }
                    ObjectType::Snapshot => {
                        // Snapshots are stored separately; no action needed here.
                    }
                }

                let key = entry.hash.to_hex();
                if unique_hashes.insert(key) {
                    unique_uncompressed += entry.uncompressed_length;
                }
            }
        }

        if stats.total_size > 0 {
            stats.compression_ratio = 1.0 - (compressed_total as f64 / stats.total_size as f64);
            stats.deduplication_ratio =
                1.0 - (unique_uncompressed as f64 / stats.total_size as f64);
        }

        Ok(stats)
    }

    pub async fn optimize_storage(&self, aggressive: bool) -> Result<OptimizationResult> {
        tracing::info!("Storage optimisation is not implemented; returning default metrics");
        if aggressive {
            tracing::debug!("Aggressive flag set, but optimisation is still a no-op");
        }
        Ok(OptimizationResult::default())
    }

    pub async fn verify_storage(&self, read_data: bool) -> Result<VerificationResult> {
        let mut result = VerificationResult::default();
        tracing::info!("Starting storage verification (read_data: {})", read_data);

        let packfile_ids = self.repository.list_packfiles().await?;

        for pack_id in packfile_ids {
            match self.repository.load_packfile(&pack_id).await {
                Ok(packfile) => {
                    for entry in &packfile.header.entries {
                        result.total_objects += 1;
                        if read_data {
                            match packfile.extract_object(entry) {
                                Ok(_) => result.verified_objects += 1,
                                Err(e) => {
                                    result.corrupted_objects += 1;
                                    result.errors.push(format!(
                                        "Corrupted object {} in packfile {}: {}",
                                        entry.hash.to_hex(),
                                        pack_id.to_hex(),
                                        e
                                    ));
                                }
                            }
                        } else {
                            result.verified_objects += 1;
                        }
                    }
                }
                Err(e) => {
                    result.errors.push(format!(
                        "Failed to load packfile {}: {}",
                        pack_id.to_hex(),
                        e
                    ));
                    result.missing_objects += 1;
                }
            }
        }

        let snapshots = self.repository.list_snapshots().await?;
        for snapshot_id in snapshots {
            match self.repository.load_snapshot(&snapshot_id).await {
                Ok(_) => {
                    result.total_objects += 1;
                    result.verified_objects += 1;
                }
                Err(e) => {
                    result.total_objects += 1;
                    result.missing_objects += 1;
                    result
                        .errors
                        .push(format!("Snapshot {} could not be read: {}", snapshot_id, e));
                }
            }
        }

        Ok(result)
    }

    pub async fn garbage_collect(
        &self,
        referenced_objects: &[HashId],
    ) -> Result<GarbageCollectionResult> {
        let packfile_ids = self.repository.list_packfiles().await?;
        let mut result = GarbageCollectionResult::default();
        let referenced: HashSet<String> = referenced_objects
            .iter()
            .map(|hash| hash.to_hex())
            .collect();

        for pack_id in packfile_ids {
            if let Ok(packfile) = self.repository.load_packfile(&pack_id).await {
                for entry in &packfile.header.entries {
                    result.total_objects += 1;
                    let entry_hash = entry.hash.to_hex();

                    if referenced.is_empty() || referenced.contains(&entry_hash) {
                        result.referenced_objects += 1;
                    } else {
                        result.removed_objects += 1;
                        result.bytes_freed += entry.uncompressed_length;
                    }
                }
            }
        }

        Ok(result)
    }

    pub async fn repack_storage(
        &self,
        target_packfile_size: Option<usize>,
    ) -> Result<RepackResult> {
        let mut result = RepackResult::default();
        result.duration = std::time::Duration::from_millis(0);
        result.old_packfile_count = self.repository.list_packfiles().await?.len() as u32;
        result.new_packfile_count = result.old_packfile_count;
        result.bytes_saved = 0;
        tracing::info!("Repack operation is not implemented; returning current repository metrics");
        let _ = target_packfile_size;
        Ok(result)
    }
}

#[derive(Debug, Default)]
pub struct OptimizationResult {
    pub bytes_saved: u64,
    pub packfiles_merged: u32,
    pub orphaned_objects_removed: u32,
    pub duration: std::time::Duration,
}

#[derive(Debug, Default)]
pub struct VerificationResult {
    pub total_objects: u64,
    pub verified_objects: u64,
    pub corrupted_objects: u64,
    pub missing_objects: u64,
    pub errors: Vec<String>,
}

#[derive(Debug, Default)]
pub struct GarbageCollectionResult {
    pub total_objects: u64,
    pub referenced_objects: u64,
    pub removed_objects: u64,
    pub bytes_freed: u64,
    pub duration: std::time::Duration,
}

#[derive(Debug, Default)]
pub struct RepackResult {
    pub old_packfile_count: u32,
    pub new_packfile_count: u32,
    pub bytes_saved: u64,
    pub duration: std::time::Duration,
}

pub struct ObjectCache {
    cache: HashMap<HashId, Arc<Vec<u8>>>,
    max_size: usize,
    current_size: usize,
}

impl ObjectCache {
    pub fn new(max_size: usize) -> Self {
        Self {
            cache: HashMap::new(),
            max_size,
            current_size: 0,
        }
    }

    pub fn get(&self, hash: &HashId) -> Option<Arc<Vec<u8>>> {
        self.cache.get(hash).cloned()
    }

    pub fn insert(&mut self, hash: HashId, data: Vec<u8>) {
        let data_size = data.len();

        // Evict old entries if necessary
        while self.current_size + data_size > self.max_size && !self.cache.is_empty() {
            self.evict_lru();
        }

        if data_size <= self.max_size {
            self.cache.insert(hash, Arc::new(data));
            self.current_size += data_size;
        }
    }

    pub fn remove(&mut self, hash: &HashId) -> Option<Arc<Vec<u8>>> {
        if let Some(data) = self.cache.remove(hash) {
            self.current_size -= data.len();
            Some(data)
        } else {
            None
        }
    }

    pub fn clear(&mut self) {
        self.cache.clear();
        self.current_size = 0;
    }

    pub fn len(&self) -> usize {
        self.cache.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    pub fn current_size(&self) -> usize {
        self.current_size
    }

    pub fn max_size(&self) -> usize {
        self.max_size
    }

    fn evict_lru(&mut self) {
        // Simple eviction - remove first entry
        // In a real implementation, this would use proper LRU tracking
        if let Some((hash, data)) = self.cache.iter().next() {
            let hash = *hash;
            let size = data.len();
            self.cache.remove(&hash);
            self.current_size -= size;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::HashId;

    #[test]
    fn test_object_cache() {
        let mut cache = ObjectCache::new(1000);

        let hash1 = HashId::new(b"test1");
        let data1 = b"hello world".to_vec();

        let hash2 = HashId::new(b"test2");
        let data2 = vec![0u8; 500];

        // Insert first object
        cache.insert(hash1, data1.clone());
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.current_size(), data1.len());

        // Get object
        let retrieved = cache.get(&hash1).unwrap();
        assert_eq!(*retrieved, data1);

        // Insert second object
        cache.insert(hash2, data2.clone());
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.current_size(), data1.len() + data2.len());

        // Insert large object that would exceed max size
        let hash3 = HashId::new(b"test3");
        let data3 = vec![0u8; 600];
        cache.insert(hash3, data3.clone());

        // Cache should have evicted old entries
        assert!(cache.len() <= 2);
        assert!(cache.current_size() <= 1000);

        // Clear cache
        cache.clear();
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.current_size(), 0);
    }
}
