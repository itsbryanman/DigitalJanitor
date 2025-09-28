use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::runtime::Runtime;
use tracing::{debug, error, info};

use crate::{
    data::{HashId, Snapshot, Tree, TreeEntry},
    repository::Repository,
};

#[cfg(feature = "mount")]
use {
    fuser::{
        FileAttr, FileType, Filesystem, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry, Request,
    },
    libc::{EISDIR, ENOENT, ENOTDIR},
};

const TTL: Duration = Duration::from_secs(1);
const BLOCK_SIZE: u32 = 4096;

/// FUSE filesystem for read-only repository browsing
#[cfg(feature = "mount")]
pub struct RepositoryFS {
    repository: Arc<Repository>,
    runtime: Arc<Runtime>,
    snapshots: Vec<Snapshot>,
    inode_map: HashMap<u64, InodeEntry>,
    path_to_inode: HashMap<PathBuf, u64>,
    next_inode: u64,
    mount_time: SystemTime,
}

#[cfg(feature = "mount")]
#[derive(Clone, Debug)]
enum InodeEntry {
    Root,
    SnapshotList,
    Snapshot {
        index: usize,
    },
    #[allow(dead_code)]
    Tree {
        snapshot_idx: usize,
        tree_hash: HashId,
    },
    File {
        #[allow(dead_code)]
        snapshot_idx: usize,
        chunks: Vec<HashId>,
        size: u64,
    },
    Directory {
        snapshot_idx: usize,
        tree_hash: HashId,
        #[allow(dead_code)]
        name: String,
    },
    Symlink {
        target: PathBuf,
    },
}

#[cfg(feature = "mount")]
fn short_snapshot_id(snapshot: &Snapshot) -> String {
    let mut id = snapshot.id.simple().to_string();
    id.truncate(8);
    id
}

#[cfg(feature = "mount")]
impl RepositoryFS {
    pub async fn new(repository: Arc<Repository>) -> Result<Self> {
        let runtime = Arc::new(Runtime::new()?);
        let snapshot_ids = repository.list_snapshots().await?;
        let mut snapshots = Vec::with_capacity(snapshot_ids.len());
        for snapshot_id in snapshot_ids {
            let snapshot = repository
                .load_snapshot(&snapshot_id)
                .await
                .map_err(|err| anyhow!("Failed to load snapshot {}: {}", snapshot_id, err))?;
            snapshots.push(snapshot);
        }

        info!(
            "Initializing FUSE filesystem with {} snapshots",
            snapshots.len()
        );

        let mut fs = Self {
            repository,
            runtime,
            snapshots,
            inode_map: HashMap::new(),
            path_to_inode: HashMap::new(),
            next_inode: 1,
            mount_time: SystemTime::now(),
        };

        // Initialize root directory structure
        fs.init_inode_map();

        Ok(fs)
    }

    fn init_inode_map(&mut self) {
        // Root directory (inode 1)
        self.inode_map.insert(1, InodeEntry::Root);
        self.path_to_inode.insert(PathBuf::from("/"), 1);
        self.next_inode = 2;

        // Snapshots directory
        let snapshots_inode = self.next_inode;
        self.next_inode += 1;
        self.inode_map
            .insert(snapshots_inode, InodeEntry::SnapshotList);
        self.path_to_inode
            .insert(PathBuf::from("/snapshots"), snapshots_inode);

        // Individual snapshot directories
        for (idx, snapshot) in self.snapshots.iter().enumerate() {
            let inode = self.next_inode;
            self.next_inode += 1;

            self.inode_map
                .insert(inode, InodeEntry::Snapshot { index: idx });

            // Create friendly snapshot names
            let snapshot_name = format!(
                "{}-{}",
                snapshot.time.format("%Y%m%d-%H%M%S"),
                short_snapshot_id(snapshot)
            );
            let path = PathBuf::from("/snapshots").join(&snapshot_name);
            self.path_to_inode.insert(path, inode);
        }
    }

    fn get_or_create_inode(&mut self, entry: InodeEntry) -> u64 {
        // Check if we already have this inode
        for (inode, existing) in &self.inode_map {
            if self.entries_equal(existing, &entry) {
                return *inode;
            }
        }

        // Create new inode
        let inode = self.next_inode;
        self.next_inode += 1;
        self.inode_map.insert(inode, entry);
        inode
    }

    fn entries_equal(&self, a: &InodeEntry, b: &InodeEntry) -> bool {
        match (a, b) {
            (InodeEntry::Root, InodeEntry::Root) => true,
            (InodeEntry::SnapshotList, InodeEntry::SnapshotList) => true,
            (InodeEntry::Snapshot { index: a }, InodeEntry::Snapshot { index: b }) => a == b,
            (InodeEntry::Tree { tree_hash: a, .. }, InodeEntry::Tree { tree_hash: b, .. }) => {
                a == b
            }
            (InodeEntry::File { chunks: a, .. }, InodeEntry::File { chunks: b, .. }) => a == b,
            _ => false,
        }
    }

    fn make_attr(&self, inode: u64, entry: &InodeEntry) -> FileAttr {
        let kind = match entry {
            InodeEntry::File { .. } => FileType::RegularFile,
            InodeEntry::Symlink { .. } => FileType::Symlink,
            _ => FileType::Directory,
        };

        let size = match entry {
            InodeEntry::File { size, .. } => *size,
            _ => 0,
        };

        let blocks = size.div_ceil(BLOCK_SIZE as u64);

        FileAttr {
            ino: inode,
            size,
            blocks,
            atime: self.mount_time,
            mtime: self.mount_time,
            ctime: self.mount_time,
            crtime: self.mount_time,
            kind,
            perm: if kind == FileType::Directory {
                0o755
            } else {
                0o644
            },
            nlink: 1,
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
            rdev: 0,
            blksize: BLOCK_SIZE,
            flags: 0,
        }
    }

    async fn load_tree(&self, tree_hash: &HashId) -> Result<Tree> {
        let tree_bytes = self.repository.get_object(tree_hash).await?;
        let tree: Tree = serde_json::from_slice(&tree_bytes)?;
        Ok(tree)
    }

    async fn read_file_data(&self, chunks: &[HashId], offset: i64, size: u32) -> Result<Vec<u8>> {
        let mut result = Vec::new();
        let mut current_offset = 0u64;

        for chunk_hash in chunks {
            let chunk_data = self.repository.get_object(chunk_hash).await?;
            let chunk_size = chunk_data.len() as u64;

            let chunk_end = current_offset + chunk_size;

            if chunk_end > offset as u64 {
                let start = if current_offset < offset as u64 {
                    (offset as u64 - current_offset) as usize
                } else {
                    0
                };

                let end = std::cmp::min(
                    chunk_data.len(),
                    (offset as u64 + size as u64 - current_offset) as usize,
                );

                if start < end {
                    result.extend_from_slice(&chunk_data[start..end]);
                }
            }

            current_offset = chunk_end;

            if result.len() >= size as usize {
                break;
            }
        }

        Ok(result)
    }
}

#[cfg(feature = "mount")]
impl Filesystem for RepositoryFS {
    fn lookup(&mut self, _req: &Request, parent: u64, name: &OsStr, reply: ReplyEntry) {
        debug!("lookup: parent={}, name={:?}", parent, name);

        let parent_entry = match self.inode_map.get(&parent) {
            Some(entry) => entry.clone(),
            None => {
                reply.error(ENOENT);
                return;
            }
        };

        let name_str = name.to_str().unwrap_or("");

        match parent_entry {
            InodeEntry::Root => {
                if name_str == "snapshots" {
                    if let Some(inode) = self.path_to_inode.get(&PathBuf::from("/snapshots")) {
                        let attr = self.make_attr(*inode, &InodeEntry::SnapshotList);
                        reply.entry(&TTL, &attr, 0);
                    } else {
                        reply.error(ENOENT);
                    }
                } else {
                    reply.error(ENOENT);
                }
            }
            InodeEntry::SnapshotList => {
                // Look for snapshot by name
                for (idx, snapshot) in self.snapshots.iter().enumerate() {
                    let snapshot_name = format!(
                        "{}-{}",
                        snapshot.time.format("%Y%m%d-%H%M%S"),
                        short_snapshot_id(snapshot)
                    );

                    if snapshot_name == name_str {
                        let entry = InodeEntry::Snapshot { index: idx };
                        let inode = self.get_or_create_inode(entry.clone());
                        let attr = self.make_attr(inode, &entry);
                        reply.entry(&TTL, &attr, 0);
                        return;
                    }
                }
                reply.error(ENOENT);
            }
            InodeEntry::Snapshot { index } => {
                // Load snapshot root tree
                let snapshot = &self.snapshots[index];
                let tree = match self.runtime.block_on(self.load_tree(&snapshot.tree)) {
                    Ok(tree) => tree,
                    Err(e) => {
                        error!("Failed to load tree: {}", e);
                        reply.error(ENOENT);
                        return;
                    }
                };

                // Look for entry in tree
                for tree_entry in &tree.entries {
                    if tree_entry.name() == name_str {
                        let inode = match tree_entry {
                            TreeEntry::File { size, chunks, .. } => {
                                let entry = InodeEntry::File {
                                    snapshot_idx: index,
                                    chunks: chunks.clone(),
                                    size: *size,
                                };
                                self.get_or_create_inode(entry.clone())
                            }
                            TreeEntry::Directory { tree, .. } => {
                                let entry = InodeEntry::Directory {
                                    snapshot_idx: index,
                                    tree_hash: *tree,
                                    name: tree_entry.name().to_string(),
                                };
                                self.get_or_create_inode(entry.clone())
                            }
                            TreeEntry::Symlink { target, .. } => {
                                let entry = InodeEntry::Symlink {
                                    target: PathBuf::from(target),
                                };
                                self.get_or_create_inode(entry.clone())
                            }
                        };

                        let attr = self.make_attr(inode, &self.inode_map[&inode]);
                        reply.entry(&TTL, &attr, 0);
                        return;
                    }
                }
                reply.error(ENOENT);
            }
            InodeEntry::Directory { tree_hash, .. } => {
                // Similar logic for subdirectories
                let tree = match self.runtime.block_on(self.load_tree(&tree_hash)) {
                    Ok(tree) => tree,
                    Err(e) => {
                        error!("Failed to load tree: {}", e);
                        reply.error(ENOENT);
                        return;
                    }
                };

                for tree_entry in &tree.entries {
                    if tree_entry.name() == name_str {
                        let inode = match tree_entry {
                            TreeEntry::File { size, chunks, .. } => {
                                let entry = InodeEntry::File {
                                    snapshot_idx: 0, // Use snapshot index from parent
                                    chunks: chunks.clone(),
                                    size: *size,
                                };
                                self.get_or_create_inode(entry)
                            }
                            TreeEntry::Directory { tree, .. } => {
                                let entry = InodeEntry::Directory {
                                    snapshot_idx: 0,
                                    tree_hash: *tree,
                                    name: tree_entry.name().to_string(),
                                };
                                self.get_or_create_inode(entry)
                            }
                            TreeEntry::Symlink { target, .. } => {
                                let entry = InodeEntry::Symlink {
                                    target: PathBuf::from(target),
                                };
                                self.get_or_create_inode(entry)
                            }
                        };

                        let attr = self.make_attr(inode, &self.inode_map[&inode]);
                        reply.entry(&TTL, &attr, 0);
                        return;
                    }
                }
                reply.error(ENOENT);
            }
            _ => reply.error(ENOTDIR),
        }
    }

    fn getattr(&mut self, _req: &Request, ino: u64, reply: ReplyAttr) {
        debug!("getattr: ino={}", ino);

        match self.inode_map.get(&ino) {
            Some(entry) => {
                let attr = self.make_attr(ino, entry);
                reply.attr(&TTL, &attr);
            }
            None => reply.error(ENOENT),
        }
    }

    fn read(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        debug!("read: ino={}, offset={}, size={}", ino, offset, size);

        match self.inode_map.get(&ino) {
            Some(InodeEntry::File { chunks, .. }) => {
                match self
                    .runtime
                    .block_on(self.read_file_data(chunks, offset, size))
                {
                    Ok(data) => reply.data(&data),
                    Err(e) => {
                        error!("Failed to read file data: {}", e);
                        reply.error(libc::EIO);
                    }
                }
            }
            Some(InodeEntry::Symlink { target }) => {
                let target_str = target.to_string_lossy();
                let bytes = target_str.as_bytes();

                if offset as usize >= bytes.len() {
                    reply.data(&[]);
                } else {
                    let end = std::cmp::min(offset as usize + size as usize, bytes.len());
                    reply.data(&bytes[offset as usize..end]);
                }
            }
            _ => reply.error(EISDIR),
        }
    }

    fn readdir(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        debug!("readdir: ino={}, offset={}", ino, offset);

        let mut entries = vec![
            (ino, FileType::Directory, "."),
            (ino, FileType::Directory, ".."),
        ];

        match self.inode_map.get(&ino).cloned() {
            Some(InodeEntry::Root) => {
                entries.push((2, FileType::Directory, "snapshots"));
            }
            Some(InodeEntry::SnapshotList) => {
                for idx in 0..self.snapshots.len() {
                    let snapshot_name = {
                        let snapshot = &self.snapshots[idx];
                        format!(
                            "{}-{}",
                            snapshot.time.format("%Y%m%d-%H%M%S"),
                            short_snapshot_id(snapshot)
                        )
                    };

                    let inode = self.get_or_create_inode(InodeEntry::Snapshot { index: idx });
                    entries.push((
                        inode,
                        FileType::Directory,
                        Box::leak(snapshot_name.into_boxed_str()),
                    ));
                }
            }
            Some(InodeEntry::Snapshot { index })
            | Some(InodeEntry::Directory {
                snapshot_idx: index,
                ..
            }) => {
                let tree_hash = if let Some(InodeEntry::Snapshot { .. }) = self.inode_map.get(&ino)
                {
                    self.snapshots[index].tree
                } else if let Some(InodeEntry::Directory { tree_hash, .. }) =
                    self.inode_map.get(&ino)
                {
                    *tree_hash
                } else {
                    reply.error(ENOTDIR);
                    return;
                };

                let tree = match self.runtime.block_on(self.load_tree(&tree_hash)) {
                    Ok(tree) => tree,
                    Err(e) => {
                        error!("Failed to load tree: {}", e);
                        reply.error(libc::EIO);
                        return;
                    }
                };

                for tree_entry in &tree.entries {
                    let file_type = match tree_entry {
                        TreeEntry::File { .. } => FileType::RegularFile,
                        TreeEntry::Directory { .. } => FileType::Directory,
                        TreeEntry::Symlink { .. } => FileType::Symlink,
                    };

                    let inode = self.next_inode;
                    self.next_inode += 1;

                    entries.push((
                        inode,
                        file_type,
                        Box::leak(tree_entry.name().to_string().into_boxed_str()),
                    ));
                }
            }
            _ => {
                reply.error(ENOTDIR);
                return;
            }
        }

        for (i, (ino, file_type, name)) in entries.iter().enumerate().skip(offset as usize) {
            if reply.add(*ino, (i + 1) as i64, *file_type, name) {
                break;
            }
        }

        reply.ok();
    }
}

/// Mount the repository as a FUSE filesystem
#[cfg(feature = "mount")]
pub async fn mount_repository(repository: Arc<Repository>, mount_point: &Path) -> Result<()> {
    info!("Mounting repository at {:?}", mount_point);

    // Ensure mount point exists
    if !mount_point.exists() {
        std::fs::create_dir_all(mount_point)?;
    }

    let fs = RepositoryFS::new(repository).await?;

    let options = vec![
        fuser::MountOption::RO,
        fuser::MountOption::FSName("digital-janitor".to_string()),
        fuser::MountOption::AutoUnmount,
        fuser::MountOption::AllowOther,
    ];

    info!("FUSE filesystem ready, mounting...");

    // This will block until the filesystem is unmounted
    fuser::mount2(fs, mount_point, &options)?;

    Ok(())
}

#[cfg(not(feature = "mount"))]
pub async fn mount_repository(_repository: Arc<Repository>, _mount_point: &Path) -> Result<()> {
    Err(Error::Generic(anyhow::anyhow!(
        "FUSE mounting is not supported in this build. Enable the 'mount' feature."
    )))
}
