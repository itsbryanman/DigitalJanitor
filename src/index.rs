use crate::{
    data::{HashId, Index, IndexEntry, ObjectType},
    Result,
};
use std::collections::HashMap;
use std::path::Path;
use tokio::fs;

pub struct IndexManager {
    index: Index,
    dirty: bool,
}

impl Default for IndexManager {
    fn default() -> Self {
        Self::new()
    }
}

impl IndexManager {
    pub fn new() -> Self {
        Self {
            index: Index::new(),
            dirty: false,
        }
    }

    pub fn from_index(index: Index) -> Self {
        Self {
            index,
            dirty: false,
        }
    }

    pub async fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let data = fs::read(path).await?;
        let index: Index = serde_json::from_slice(&data)?;
        Ok(Self::from_index(index))
    }

    pub async fn save_to_file<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        if self.dirty {
            let data = serde_json::to_vec_pretty(&self.index)?;
            fs::write(path, data).await?;
            self.dirty = false;
        }
        Ok(())
    }

    pub fn add_entry(&mut self, entry: IndexEntry) {
        self.index.entries.insert(entry.hash.to_hex(), entry);
        self.dirty = true;
    }

    pub fn add_packfile(&mut self, packfile_id: HashId, entries: Vec<IndexEntry>) {
        if !self.index.packfiles.contains(&packfile_id) {
            self.index.packfiles.push(packfile_id);
        }

        for entry in entries {
            self.index.entries.insert(entry.hash.to_hex(), entry);
        }

        self.dirty = true;
    }

    pub fn remove_packfile(&mut self, packfile_id: &HashId) -> Result<()> {
        // Remove packfile from list
        self.index.packfiles.retain(|id| id != packfile_id);

        // Remove all entries for this packfile
        self.index
            .entries
            .retain(|_, entry| &entry.packfile_id != packfile_id);

        self.dirty = true;
        Ok(())
    }

    pub fn contains(&self, hash: &HashId) -> bool {
        self.index.contains(hash)
    }

    pub fn get(&self, hash: &HashId) -> Option<&IndexEntry> {
        self.index.get(hash)
    }

    pub fn get_packfile_entries(&self, packfile_id: &HashId) -> Vec<&IndexEntry> {
        self.index
            .entries
            .values()
            .filter(|entry| &entry.packfile_id == packfile_id)
            .collect()
    }

    pub fn list_packfiles(&self) -> &[HashId] {
        &self.index.packfiles
    }

    pub fn entry_count(&self) -> usize {
        self.index.entries.len()
    }

    pub fn packfile_count(&self) -> usize {
        self.index.packfiles.len()
    }

    pub fn get_statistics(&self) -> IndexStatistics {
        let mut stats = IndexStatistics::default();

        for entry in self.index.entries.values() {
            match entry.object_type {
                ObjectType::Blob => {
                    stats.blob_count += 1;
                    stats.blob_size += entry.length;
                }
                ObjectType::Tree => {
                    stats.tree_count += 1;
                    stats.tree_size += entry.length;
                }
                ObjectType::Snapshot => {
                    stats.snapshot_count += 1;
                    stats.snapshot_size += entry.length;
                }
            }
        }

        stats.total_objects = stats.blob_count + stats.tree_count + stats.snapshot_count;
        stats.total_size = stats.blob_size + stats.tree_size + stats.snapshot_size;
        stats.packfile_count = self.index.packfiles.len() as u64;

        stats
    }

    pub fn find_unreferenced_objects(&self, referenced_hashes: &[HashId]) -> Vec<HashId> {
        let referenced_set: std::collections::HashSet<_> = referenced_hashes.iter().collect();

        self.index
            .entries
            .values()
            .filter(|entry| !referenced_set.contains(&entry.hash))
            .map(|entry| entry.hash)
            .collect()
    }

    pub fn get_objects_by_type(&self, object_type: ObjectType) -> Vec<&IndexEntry> {
        self.index
            .entries
            .values()
            .filter(|entry| entry.object_type == object_type)
            .collect()
    }

    pub fn verify_integrity(&self) -> Result<Vec<String>> {
        let mut issues = Vec::new();

        // Check if all packfiles referenced in entries actually exist in the packfile list
        let packfile_set: std::collections::HashSet<_> = self.index.packfiles.iter().collect();

        for entry in self.index.entries.values() {
            if !packfile_set.contains(&entry.packfile_id) {
                issues.push(format!(
                    "Entry {} references unknown packfile {}",
                    entry.hash, entry.packfile_id
                ));
            }
        }

        // Check for duplicate entries (should not happen but worth checking)
        let mut hash_counts = HashMap::new();
        for hash in self.index.entries.keys() {
            *hash_counts.entry(hash).or_insert(0) += 1;
        }

        for (hash, count) in hash_counts {
            if count > 1 {
                issues.push(format!("Duplicate entries found for hash {}", hash));
            }
        }

        Ok(issues)
    }

    pub fn merge_with(&mut self, other: &Index) -> Result<()> {
        // Add all packfiles from other index
        for packfile_id in &other.packfiles {
            if !self.index.packfiles.contains(packfile_id) {
                self.index.packfiles.push(*packfile_id);
            }
        }

        // Add all entries from other index
        for (hash, entry) in &other.entries {
            if !self.index.entries.contains_key(hash) {
                self.index.entries.insert(hash.clone(), entry.clone());
            }
        }

        self.dirty = true;
        Ok(())
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    pub fn mark_clean(&mut self) {
        self.dirty = false;
    }

    pub fn inner(&self) -> &Index {
        &self.index
    }
}

#[derive(Debug, Default, Clone)]
pub struct IndexStatistics {
    pub blob_count: u64,
    pub blob_size: u64,
    pub tree_count: u64,
    pub tree_size: u64,
    pub snapshot_count: u64,
    pub snapshot_size: u64,
    pub total_objects: u64,
    pub total_size: u64,
    pub packfile_count: u64,
}

impl IndexStatistics {
    pub fn format_summary(&self) -> String {
        format!(
            "Index contains {} objects ({} blobs, {} trees, {} snapshots) in {} packfiles, total size: {}",
            self.total_objects,
            self.blob_count,
            self.tree_count,
            self.snapshot_count,
            self.packfile_count,
            crate::utils::format_bytes(self.total_size)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::HashId;

    fn create_test_entry(
        hash_str: &str,
        packfile_str: &str,
        object_type: ObjectType,
    ) -> IndexEntry {
        IndexEntry {
            hash: HashId::from_hex(hash_str).unwrap(),
            packfile_id: HashId::from_hex(packfile_str).unwrap(),
            offset: 0,
            length: 100,
            object_type,
        }
    }

    #[test]
    fn test_index_manager_basic_operations() {
        let mut manager = IndexManager::new();

        let entry1 = create_test_entry(
            "1111111111111111111111111111111111111111111111111111111111111111",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ObjectType::Blob,
        );

        let entry2 = create_test_entry(
            "2222222222222222222222222222222222222222222222222222222222222222",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ObjectType::Tree,
        );

        // Test adding entries
        manager.add_entry(entry1.clone());
        manager.add_entry(entry2.clone());

        assert!(manager.contains(&entry1.hash));
        assert!(manager.contains(&entry2.hash));
        assert_eq!(manager.entry_count(), 2);

        // Test getting entries
        assert_eq!(manager.get(&entry1.hash), Some(&entry1));
        assert_eq!(manager.get(&entry2.hash), Some(&entry2));

        // Test statistics
        let stats = manager.get_statistics();
        assert_eq!(stats.blob_count, 1);
        assert_eq!(stats.tree_count, 1);
        assert_eq!(stats.total_objects, 2);
    }

    #[test]
    fn test_index_manager_packfile_operations() {
        let mut manager = IndexManager::new();

        let packfile_id =
            HashId::from_hex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
                .unwrap();

        let entries = vec![
            create_test_entry(
                "1111111111111111111111111111111111111111111111111111111111111111",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                ObjectType::Blob,
            ),
            create_test_entry(
                "2222222222222222222222222222222222222222222222222222222222222222",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                ObjectType::Tree,
            ),
        ];

        manager.add_packfile(packfile_id, entries.clone());

        assert_eq!(manager.packfile_count(), 1);
        assert_eq!(manager.entry_count(), 2);

        let packfile_entries = manager.get_packfile_entries(&packfile_id);
        assert_eq!(packfile_entries.len(), 2);

        // Test removing packfile
        manager.remove_packfile(&packfile_id).unwrap();
        assert_eq!(manager.packfile_count(), 0);
        assert_eq!(manager.entry_count(), 0);
    }
}
