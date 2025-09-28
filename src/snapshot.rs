use crate::{
    data::{HashId, Snapshot, Tree, TreeEntry},
    repository::Repository,
    Result,
};
use chrono::Datelike;
use std::collections::HashMap;

#[derive(Debug, Clone, Default)]
pub struct SnapshotFilter {
    pub tags: Vec<String>,
    pub hosts: Vec<String>,
    pub paths: Vec<String>,
    pub before: Option<chrono::DateTime<chrono::Utc>>,
    pub after: Option<chrono::DateTime<chrono::Utc>>,
}

impl SnapshotFilter {
    pub fn matches(&self, snapshot: &Snapshot) -> bool {
        // Check tags
        if !self.tags.is_empty() && !self.tags.iter().all(|tag| snapshot.tags.contains(tag)) {
            return false;
        }

        // Check hosts
        if !self.hosts.is_empty() && !self.hosts.contains(&snapshot.hostname) {
            return false;
        }

        // Check paths
        if !self.paths.is_empty() {
            let has_matching_path = self.paths.iter().any(|filter_path| {
                snapshot.paths.iter().any(|snapshot_path| {
                    snapshot_path.starts_with(filter_path) || filter_path.starts_with(snapshot_path)
                })
            });
            if !has_matching_path {
                return false;
            }
        }

        // Check time range
        if let Some(before) = self.before {
            if snapshot.time >= before {
                return false;
            }
        }

        if let Some(after) = self.after {
            if snapshot.time <= after {
                return false;
            }
        }

        true
    }
}

pub struct SnapshotManager {
    repository: Repository,
}

impl SnapshotManager {
    pub fn new(repository: Repository) -> Self {
        Self { repository }
    }

    pub async fn list_snapshots(&self, filter: Option<SnapshotFilter>) -> Result<Vec<Snapshot>> {
        let snapshot_ids = self.repository.list_snapshots().await?;
        let mut snapshots = Vec::new();

        for snapshot_id in snapshot_ids {
            match self.repository.load_snapshot(&snapshot_id).await {
                Ok(snapshot) => {
                    if let Some(ref filter) = filter {
                        if filter.matches(&snapshot) {
                            snapshots.push(snapshot);
                        }
                    } else {
                        snapshots.push(snapshot);
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to load snapshot {}: {}", snapshot_id, e);
                }
            }
        }

        // Sort by timestamp (newest first)
        snapshots.sort_by(|a, b| b.time.cmp(&a.time));

        Ok(snapshots)
    }

    pub async fn get_snapshot(&self, snapshot_id: &str) -> Result<Snapshot> {
        self.repository.load_snapshot(snapshot_id).await
    }

    pub async fn delete_snapshot(&self, snapshot_id: &str) -> Result<()> {
        self.repository.delete_snapshot(snapshot_id).await
    }

    pub async fn get_snapshot_by_hash(&self, tree_hash: &HashId) -> Result<Option<Snapshot>> {
        let snapshots = self.list_snapshots(None).await?;

        for snapshot in snapshots {
            if snapshot.tree == *tree_hash {
                return Ok(Some(snapshot));
            }
        }

        Ok(None)
    }

    pub async fn find_latest_snapshot(
        &self,
        filter: Option<SnapshotFilter>,
    ) -> Result<Option<Snapshot>> {
        let snapshots = self.list_snapshots(filter).await?;
        Ok(snapshots.into_iter().next()) // Already sorted by timestamp
    }

    pub async fn get_snapshot_diff(
        &self,
        snapshot1_id: &str,
        snapshot2_id: &str,
    ) -> Result<SnapshotDiff> {
        let snapshot1 = self.repository.load_snapshot(snapshot1_id).await?;
        let snapshot2 = self.repository.load_snapshot(snapshot2_id).await?;

        let diff = self.compute_snapshot_diff(&snapshot1, &snapshot2).await?;
        Ok(diff)
    }

    pub async fn prune_snapshots(&self, policy: &PrunePolicy) -> Result<PruneResult> {
        let snapshots = self.list_snapshots(None).await?;
        let to_keep = policy.apply(&snapshots);
        let to_delete: Vec<_> = snapshots
            .iter()
            .filter(|s| !to_keep.contains(&s.id))
            .cloned()
            .collect();

        let mut deleted_count = 0;
        let mut errors = Vec::new();

        for snapshot in &to_delete {
            match self
                .repository
                .delete_snapshot(&snapshot.id.to_string())
                .await
            {
                Ok(()) => deleted_count += 1,
                Err(e) => errors.push(format!("Failed to delete snapshot {}: {}", snapshot.id, e)),
            }
        }

        Ok(PruneResult {
            total_snapshots: snapshots.len(),
            kept_snapshots: to_keep.len(),
            deleted_snapshots: deleted_count,
            errors,
        })
    }

    async fn compute_snapshot_diff(
        &self,
        snapshot1: &Snapshot,
        snapshot2: &Snapshot,
    ) -> Result<SnapshotDiff> {
        let files_a = self
            .collect_file_records(&snapshot1.tree, String::new())
            .await?;
        let files_b = self
            .collect_file_records(&snapshot2.tree, String::new())
            .await?;

        let mut diff = SnapshotDiff {
            added_files: Vec::new(),
            modified_files: Vec::new(),
            deleted_files: Vec::new(),
            size_change: 0,
        };

        for (path, record_a) in &files_a {
            match files_b.get(path) {
                Some(record_b) => {
                    if record_a.is_modified(record_b) {
                        diff.modified_files.push(path.clone());
                        diff.size_change += record_b.size_delta(record_a);
                    }
                }
                None => {
                    diff.deleted_files.push(path.clone());
                    diff.size_change -= record_a.size() as i64;
                }
            }
        }

        for (path, record_b) in &files_b {
            if !files_a.contains_key(path) {
                diff.added_files.push(path.clone());
                diff.size_change += record_b.size() as i64;
            }
        }

        Ok(diff)
    }

    async fn collect_file_records(
        &self,
        tree_hash: &HashId,
        base_path: String,
    ) -> Result<HashMap<String, FileRecord>> {
        let mut records = HashMap::new();
        let mut stack = vec![(*tree_hash, base_path)];

        while let Some((current_hash, current_path)) = stack.pop() {
            let tree_bytes = self.repository.get_object(&current_hash).await?;
            let tree: Tree = serde_json::from_slice(&tree_bytes)?;

            for entry in tree.entries {
                let entry_name = entry.name().to_string();
                let next_path = if current_path.is_empty() {
                    entry_name.clone()
                } else {
                    format!("{}/{}", current_path, entry_name)
                };

                match entry {
                    TreeEntry::File { size, chunks, .. } => {
                        records.insert(next_path, FileRecord::File { size, chunks });
                    }
                    TreeEntry::Directory { tree, .. } => {
                        stack.push((tree, next_path));
                    }
                    TreeEntry::Symlink { target, .. } => {
                        records.insert(next_path, FileRecord::Symlink { target });
                    }
                }
            }
        }

        Ok(records)
    }
}

#[derive(Debug, Clone)]
pub struct PrunePolicy {
    pub keep_hourly: Option<u32>,
    pub keep_daily: Option<u32>,
    pub keep_weekly: Option<u32>,
    pub keep_monthly: Option<u32>,
    pub keep_yearly: Option<u32>,
    pub keep_last: Option<u32>,
    pub keep_tags: Vec<String>,
}

impl Default for PrunePolicy {
    fn default() -> Self {
        Self {
            keep_hourly: None,
            keep_daily: Some(7),
            keep_weekly: Some(4),
            keep_monthly: Some(6),
            keep_yearly: Some(1),
            keep_last: Some(1),
            keep_tags: Vec::new(),
        }
    }
}

impl PrunePolicy {
    pub fn apply(&self, snapshots: &[Snapshot]) -> Vec<uuid::Uuid> {
        let mut to_keep = std::collections::HashSet::new();

        // Always keep snapshots with specific tags
        for snapshot in snapshots {
            for tag in &self.keep_tags {
                if snapshot.tags.contains(tag) {
                    to_keep.insert(snapshot.id);
                }
            }
        }

        // Keep last N snapshots
        if let Some(keep_last) = self.keep_last {
            let mut sorted_snapshots = snapshots.to_vec();
            sorted_snapshots.sort_by(|a, b| b.time.cmp(&a.time));

            for snapshot in sorted_snapshots.iter().take(keep_last as usize) {
                to_keep.insert(snapshot.id);
            }
        }

        // Group snapshots by time periods and keep the specified number
        self.apply_time_based_keeping(snapshots, &mut to_keep);

        to_keep.into_iter().collect()
    }

    fn apply_time_based_keeping(
        &self,
        snapshots: &[Snapshot],
        to_keep: &mut std::collections::HashSet<uuid::Uuid>,
    ) {
        let now = chrono::Utc::now();

        // Keep hourly
        if let Some(keep_hourly) = self.keep_hourly {
            let hourly = self.group_by_hour(snapshots, now);
            self.keep_latest_from_groups(&hourly, keep_hourly as usize, to_keep);
        }

        // Keep daily
        if let Some(keep_daily) = self.keep_daily {
            let daily = self.group_by_day(snapshots, now);
            self.keep_latest_from_groups(&daily, keep_daily as usize, to_keep);
        }

        // Keep weekly
        if let Some(keep_weekly) = self.keep_weekly {
            let weekly = self.group_by_week(snapshots, now);
            self.keep_latest_from_groups(&weekly, keep_weekly as usize, to_keep);
        }

        // Keep monthly
        if let Some(keep_monthly) = self.keep_monthly {
            let monthly = self.group_by_month(snapshots, now);
            self.keep_latest_from_groups(&monthly, keep_monthly as usize, to_keep);
        }

        // Keep yearly
        if let Some(keep_yearly) = self.keep_yearly {
            let yearly = self.group_by_year(snapshots, now);
            self.keep_latest_from_groups(&yearly, keep_yearly as usize, to_keep);
        }
    }

    fn group_by_hour<'a>(
        &self,
        snapshots: &'a [Snapshot],
        now: chrono::DateTime<chrono::Utc>,
    ) -> Vec<Vec<&'a Snapshot>> {
        let mut groups: std::collections::BTreeMap<i64, Vec<&'a Snapshot>> =
            std::collections::BTreeMap::new();

        for snapshot in snapshots {
            let hours_ago = (now - snapshot.time).num_hours();
            groups.entry(hours_ago).or_default().push(snapshot);
        }

        groups.into_values().collect()
    }

    fn group_by_day<'a>(
        &self,
        snapshots: &'a [Snapshot],
        now: chrono::DateTime<chrono::Utc>,
    ) -> Vec<Vec<&'a Snapshot>> {
        let mut groups: std::collections::BTreeMap<i64, Vec<&'a Snapshot>> =
            std::collections::BTreeMap::new();

        for snapshot in snapshots {
            let days_ago = (now - snapshot.time).num_days();
            groups.entry(days_ago).or_default().push(snapshot);
        }

        groups.into_values().collect()
    }

    fn group_by_week<'a>(
        &self,
        snapshots: &'a [Snapshot],
        now: chrono::DateTime<chrono::Utc>,
    ) -> Vec<Vec<&'a Snapshot>> {
        let mut groups: std::collections::BTreeMap<i64, Vec<&'a Snapshot>> =
            std::collections::BTreeMap::new();

        for snapshot in snapshots {
            let weeks_ago = (now - snapshot.time).num_weeks();
            groups.entry(weeks_ago).or_default().push(snapshot);
        }

        groups.into_values().collect()
    }

    fn group_by_month<'a>(
        &self,
        snapshots: &'a [Snapshot],
        _now: chrono::DateTime<chrono::Utc>,
    ) -> Vec<Vec<&'a Snapshot>> {
        let mut groups: std::collections::BTreeMap<(i32, u32), Vec<&'a Snapshot>> =
            std::collections::BTreeMap::new();

        for snapshot in snapshots {
            let key = (snapshot.time.year(), snapshot.time.month());
            groups.entry(key).or_default().push(snapshot);
        }

        groups.into_values().collect()
    }

    fn group_by_year<'a>(
        &self,
        snapshots: &'a [Snapshot],
        _now: chrono::DateTime<chrono::Utc>,
    ) -> Vec<Vec<&'a Snapshot>> {
        let mut groups: std::collections::BTreeMap<i32, Vec<&'a Snapshot>> =
            std::collections::BTreeMap::new();

        for snapshot in snapshots {
            groups
                .entry(snapshot.time.year())
                .or_default()
                .push(snapshot);
        }

        groups.into_values().collect()
    }

    fn keep_latest_from_groups(
        &self,
        groups: &[Vec<&Snapshot>],
        count: usize,
        to_keep: &mut std::collections::HashSet<uuid::Uuid>,
    ) {
        for group in groups.iter().take(count) {
            if let Some(latest) = group.iter().max_by_key(|s| s.time) {
                to_keep.insert(latest.id);
            }
        }
    }
}

#[derive(Debug)]
pub struct PruneResult {
    pub total_snapshots: usize,
    pub kept_snapshots: usize,
    pub deleted_snapshots: usize,
    pub errors: Vec<String>,
}

#[derive(Debug)]
pub struct SnapshotDiff {
    pub added_files: Vec<String>,
    pub modified_files: Vec<String>,
    pub deleted_files: Vec<String>,
    pub size_change: i64,
}

impl SnapshotDiff {}

#[derive(Debug, Clone)]
enum FileRecord {
    File { size: u64, chunks: Vec<HashId> },
    Symlink { target: String },
}

impl FileRecord {
    fn is_modified(&self, other: &Self) -> bool {
        match (self, other) {
            (FileRecord::File { chunks: a, .. }, FileRecord::File { chunks: b, .. }) => a != b,
            (FileRecord::Symlink { target: a }, FileRecord::Symlink { target: b }) => a != b,
            _ => true,
        }
    }

    fn size_delta(&self, previous: &Self) -> i64 {
        self.size() as i64 - previous.size() as i64
    }

    fn size(&self) -> u64 {
        match self {
            FileRecord::File { size, .. } => *size,
            FileRecord::Symlink { .. } => 0,
        }
    }
}
