use crate::{Result, BLAKE3_HASH_SIZE};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

pub type Hash = [u8; BLAKE3_HASH_SIZE];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HashId(pub Hash);

impl HashId {
    pub fn new(data: &[u8]) -> Self {
        let hash = blake3::hash(data);
        Self(hash.into())
    }

    pub fn from_hex(hex: &str) -> Result<Self> {
        let bytes = hex::decode(hex).map_err(|_| crate::Error::InvalidHash {
            hash: hex.to_string(),
        })?;
        if bytes.len() != BLAKE3_HASH_SIZE {
            return Err(crate::Error::InvalidHash {
                hash: hex.to_string(),
            });
        }
        let mut hash = [0u8; BLAKE3_HASH_SIZE];
        hash.copy_from_slice(&bytes);
        Ok(Self(hash))
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Display for HashId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl std::str::FromStr for HashId {
    type Err = crate::Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::from_hex(s)
    }
}

impl std::cmp::Ord for HashId {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl std::cmp::PartialOrd for HashId {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Blob {
    pub id: HashId,
    pub size: u64,
    pub data: Vec<u8>,
}

impl Blob {
    pub fn new(data: Vec<u8>) -> Self {
        let id = HashId::new(&data);
        let size = data.len() as u64;
        Self { id, size, data }
    }

    pub fn verify(&self) -> bool {
        self.id == HashId::new(&self.data)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TreeEntry {
    File {
        name: String,
        size: u64,
        chunks: Vec<HashId>,
        mode: u32,
        mtime: DateTime<Utc>,
    },
    Directory {
        name: String,
        tree: HashId,
        mode: u32,
        mtime: DateTime<Utc>,
    },
    Symlink {
        name: String,
        target: String,
        mtime: DateTime<Utc>,
    },
}

impl TreeEntry {
    pub fn name(&self) -> &str {
        match self {
            TreeEntry::File { name, .. } => name,
            TreeEntry::Directory { name, .. } => name,
            TreeEntry::Symlink { name, .. } => name,
        }
    }

    pub fn mtime(&self) -> DateTime<Utc> {
        match self {
            TreeEntry::File { mtime, .. } => *mtime,
            TreeEntry::Directory { mtime, .. } => *mtime,
            TreeEntry::Symlink { mtime, .. } => *mtime,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tree {
    pub id: HashId,
    pub entries: Vec<TreeEntry>,
}

impl Tree {
    pub fn new(entries: Vec<TreeEntry>) -> Self {
        let data = serde_json::to_vec(&entries).unwrap();
        let id = HashId::new(&data);
        Self { id, entries }
    }

    pub fn find_entry(&self, name: &str) -> Option<&TreeEntry> {
        self.entries.iter().find(|entry| entry.name() == name)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub id: Uuid,
    pub time: DateTime<Utc>,
    pub tree: HashId,
    pub paths: Vec<String>,
    pub hostname: String,
    pub username: String,
    pub tags: Vec<String>,
    pub parent: Option<HashId>,
    pub summary: SnapshotSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotSummary {
    pub files_new: u64,
    pub files_changed: u64,
    pub files_unmodified: u64,
    pub dirs_new: u64,
    pub dirs_changed: u64,
    pub dirs_unmodified: u64,
    pub data_blobs: u64,
    pub tree_blobs: u64,
    pub data_added: u64,
    pub total_files_processed: u64,
    pub total_bytes_processed: u64,
    pub total_duration: std::time::Duration,
}

impl Default for SnapshotSummary {
    fn default() -> Self {
        Self {
            files_new: 0,
            files_changed: 0,
            files_unmodified: 0,
            dirs_new: 0,
            dirs_changed: 0,
            dirs_unmodified: 0,
            data_blobs: 0,
            tree_blobs: 0,
            data_added: 0,
            total_files_processed: 0,
            total_bytes_processed: 0,
            total_duration: std::time::Duration::from_secs(0),
        }
    }
}

impl Snapshot {
    pub fn new(
        tree: HashId,
        paths: Vec<String>,
        hostname: String,
        username: String,
        tags: Vec<String>,
        parent: Option<HashId>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            time: Utc::now(),
            tree,
            paths,
            hostname,
            username,
            tags,
            parent,
            summary: SnapshotSummary::default(),
        }
    }

    pub fn matches_tags(&self, filter_tags: &[String]) -> bool {
        if filter_tags.is_empty() {
            return true;
        }
        filter_tags.iter().all(|tag| self.tags.contains(tag))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackfileHeader {
    pub version: u32,
    pub entries: Vec<PackfileEntry>,
    pub total_size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackfileEntry {
    pub hash: HashId,
    pub offset: u64,
    pub length: u64,
    pub uncompressed_length: u64,
    pub object_type: ObjectType,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ObjectType {
    Blob,
    Tree,
    Snapshot,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Packfile {
    pub id: HashId,
    pub header: PackfileHeader,
    pub data: Vec<u8>,
}

impl Packfile {
    pub fn new(entries: Vec<(HashId, Vec<u8>, ObjectType)>) -> Result<Self> {
        let mut packfile_entries = Vec::new();
        let mut data = Vec::new();
        let mut current_offset = 0;

        for (hash, object_data, object_type) in entries {
            let uncompressed_length = object_data.len() as u64;
            let compressed = zstd::encode_all(&object_data[..], 3)?;
            let length = compressed.len() as u64;

            packfile_entries.push(PackfileEntry {
                hash,
                offset: current_offset,
                length,
                uncompressed_length,
                object_type,
            });

            data.extend_from_slice(&compressed);
            current_offset += length;
        }

        let header = PackfileHeader {
            version: crate::INDEX_VERSION,
            entries: packfile_entries,
            total_size: current_offset,
        };

        let header_bytes = serde_json::to_vec(&header)?;
        let mut packfile_data = Vec::new();
        packfile_data.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
        packfile_data.extend_from_slice(&header_bytes);
        packfile_data.extend_from_slice(&data);

        let id = HashId::new(&packfile_data);

        Ok(Self {
            id,
            header,
            data: packfile_data,
        })
    }

    pub fn extract_object(&self, entry: &PackfileEntry) -> Result<Vec<u8>> {
        let header_len_bytes = 4;
        let header_bytes_len =
            u32::from_le_bytes([self.data[0], self.data[1], self.data[2], self.data[3]]) as usize;
        let data_start = header_len_bytes + header_bytes_len;

        let start = data_start + entry.offset as usize;
        let end = start + entry.length as usize;

        if end > self.data.len() {
            return Err(crate::Error::corrupted_data(
                "Packfile entry extends beyond data",
            ));
        }

        let compressed_data = &self.data[start..end];
        let decompressed = zstd::decode_all(compressed_data)?;

        if decompressed.len() != entry.uncompressed_length as usize {
            return Err(crate::Error::corrupted_data("Decompressed length mismatch"));
        }

        Ok(decompressed)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IndexEntry {
    pub hash: HashId,
    pub packfile_id: HashId,
    pub offset: u64,
    pub length: u64,
    pub object_type: ObjectType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Index {
    pub version: u32,
    pub entries: HashMap<String, IndexEntry>,
    pub packfiles: Vec<HashId>,
}

impl Default for Index {
    fn default() -> Self {
        Self::new()
    }
}

impl Index {
    pub fn new() -> Self {
        Self {
            version: crate::INDEX_VERSION,
            entries: HashMap::new(),
            packfiles: Vec::new(),
        }
    }

    pub fn add_packfile(&mut self, packfile: &Packfile) {
        self.packfiles.push(packfile.id);

        for entry in &packfile.header.entries {
            self.entries.insert(
                entry.hash.to_hex(),
                IndexEntry {
                    hash: entry.hash,
                    packfile_id: packfile.id,
                    offset: entry.offset,
                    length: entry.length,
                    object_type: entry.object_type,
                },
            );
        }
    }

    pub fn contains(&self, hash: &HashId) -> bool {
        self.entries.contains_key(&hash.to_hex())
    }

    pub fn get(&self, hash: &HashId) -> Option<&IndexEntry> {
        self.entries.get(&hash.to_hex())
    }
}
