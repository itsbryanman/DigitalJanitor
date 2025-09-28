use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

use crate::{backend::FileType, data::HashId, repository::Repository, storage::StorageManager};

#[cfg(feature = "server")]
use reqwest::Client;

pub struct HybridClient {
    repository: Arc<Repository>,
    storage_manager: Arc<StorageManager>,
    server_endpoint: Option<String>,
    server_capabilities: Vec<String>,
    #[cfg(feature = "server")]
    http_client: Client,
}

impl HybridClient {
    pub async fn new(
        repository: Arc<Repository>,
        storage_manager: Arc<StorageManager>,
    ) -> Result<Self> {
        #[cfg(feature = "server")]
        let http_client = Client::builder().timeout(Duration::from_secs(30)).build()?;

        let mut client = Self {
            repository,
            storage_manager,
            server_endpoint: None,
            server_capabilities: Vec::new(),
            #[cfg(feature = "server")]
            http_client,
        };

        // Try to discover server
        client.discover_server().await?;

        Ok(client)
    }

    async fn discover_server(&mut self) -> Result<()> {
        // Try to read .dj_server_info from repository
        if let Ok(data) = self
            .repository
            .backend()
            .read_full(FileType::Config, ".dj_server_info")
            .await
        {
            let info: ServerInfo = serde_json::from_slice(&data)?;

            if self.verify_server(&info.endpoint).await {
                info!(
                    "Discovered server at {} with capabilities: {:?}",
                    info.endpoint, info.capabilities
                );
                self.server_endpoint = Some(info.endpoint);
                self.server_capabilities = info.capabilities;
            } else {
                warn!("Server listed but not reachable");
                self.server_endpoint = None;
                self.server_capabilities.clear();
            }
        } else {
            debug!("No server info found, using direct backend access");
            self.server_endpoint = None;
            self.server_capabilities.clear();
        }

        Ok(())
    }

    #[cfg(feature = "server")]
    async fn verify_server(&self, endpoint: &str) -> bool {
        let url = format!("{}/health", endpoint);

        match self.http_client.get(&url).send().await {
            Ok(response) => response.status().is_success(),
            Err(_) => false,
        }
    }

    #[cfg(not(feature = "server"))]
    async fn verify_server(&self, _endpoint: &str) -> bool {
        false
    }

    /// Check multiple hashes efficiently using server or fallback to local
    pub async fn check_hashes(&self, hashes: &[HashId]) -> Result<HashSet<HashId>> {
        #[cfg(feature = "server")]
        {
            if let Some(endpoint) = &self.server_endpoint {
                if self
                    .server_capabilities
                    .iter()
                    .any(|capability| capability == "check_hashes")
                {
                    match self.check_hashes_via_server(endpoint, hashes).await {
                        Ok(existing) => return Ok(existing),
                        Err(e) => {
                            warn!("Server check failed, falling back to local: {}", e);
                        }
                    }
                } else {
                    debug!("Discovered server does not advertise check_hashes capability; using local check");
                }
            }
        }

        // Fallback to local checking
        let mut existing = HashSet::new();
        for hash in hashes {
            if self.repository.get_object(hash).await.is_ok() {
                existing.insert(*hash);
            }
        }

        Ok(existing)
    }

    #[cfg(feature = "server")]
    async fn check_hashes_via_server(
        &self,
        endpoint: &str,
        hashes: &[HashId],
    ) -> Result<HashSet<HashId>> {
        let url = format!("{}/api/v1/blobs/check", endpoint);

        let request = CheckHashesRequest {
            hashes: hashes.iter().map(|h| h.to_hex()).collect(),
        };

        let response = self.http_client.post(&url).json(&request).send().await?;

        if !response.status().is_success() {
            return Err(anyhow!("Server returned error: {}", response.status()));
        }

        let result: CheckHashesResponse = response.json().await?;

        if !result.missing.is_empty() {
            debug!("Server reports {} missing hashes", result.missing.len());
        }

        let existing: HashSet<HashId> = result
            .existing
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();

        Ok(existing)
    }

    /// Get merged index from server for better performance
    pub async fn get_merged_index(&self) -> Result<Vec<serde_json::Value>> {
        #[cfg(feature = "server")]
        {
            if let Some(endpoint) = &self.server_endpoint {
                match self.get_merged_index_via_server(endpoint).await {
                    Ok(entries) => return Ok(entries),
                    Err(e) => {
                        warn!("Failed to get index from server: {}", e);
                    }
                }
            }
        }

        // Fallback to local index building
        let packfiles = self.repository.list_packfiles().await?;
        let mut entries = Vec::new();

        for pack_id in packfiles {
            if let Ok(header) = self.repository.packfile_header(&pack_id).await {
                for entry in header.entries {
                    entries.push(serde_json::to_value(entry)?);
                }
            }
        }

        Ok(entries)
    }

    #[cfg(feature = "server")]
    async fn get_merged_index_via_server(&self, endpoint: &str) -> Result<Vec<serde_json::Value>> {
        let url = format!("{}/api/v1/indexes/merged", endpoint);

        let response = self.http_client.get(&url).send().await?;

        if !response.status().is_success() {
            return Err(anyhow!("Server returned error: {}", response.status()));
        }

        let result: serde_json::Value = response.json().await?;
        let entries: Vec<serde_json::Value> = serde_json::from_value(result["entries"].clone())?;

        Ok(entries)
    }

    /// Run prune on server for better performance
    pub async fn run_prune(&self, policy: &RetentionPolicy, dry_run: bool) -> Result<PruneReport> {
        #[cfg(feature = "server")]
        {
            if let Some(endpoint) = &self.server_endpoint {
                if self
                    .server_capabilities
                    .iter()
                    .any(|capability| capability == "run_prune")
                {
                    match self.run_prune_via_server(endpoint, policy, dry_run).await {
                        Ok(report) => return Ok(report),
                        Err(e) => {
                            warn!("Server prune failed, falling back to local: {}", e);
                        }
                    }
                } else {
                    debug!("Discovered server does not advertise run_prune capability; skipping remote prune");
                }
            }
        }

        // Fallback to local prune - this would need implementation in SnapshotManager
        Err(anyhow!("Local prune not yet implemented"))
    }

    #[cfg(feature = "server")]
    async fn run_prune_via_server(
        &self,
        endpoint: &str,
        policy: &RetentionPolicy,
        dry_run: bool,
    ) -> Result<PruneReport> {
        let url = format!("{}/api/v1/repo/prune", endpoint);

        let request = serde_json::json!({
            "keep_daily": policy.keep_daily,
            "keep_weekly": policy.keep_weekly,
            "keep_monthly": policy.keep_monthly,
            "keep_yearly": policy.keep_yearly,
            "keep_last": policy.keep_last,
            "keep_tags": policy.keep_tags.clone(),
            "dry_run": dry_run,
        });

        let response = self.http_client.post(&url).json(&request).send().await?;

        if !response.status().is_success() {
            return Err(anyhow!("Server returned error: {}", response.status()));
        }

        let result: PruneResponse = response.json().await?;

        Ok(PruneReport {
            kept_snapshots: result.kept_snapshots,
            removed_snapshots: result.removed_snapshots,
            space_freed: result.space_freed,
        })
    }

    /// Get repository statistics, preferring server if available
    pub async fn get_stats(&self) -> Result<serde_json::Value> {
        #[cfg(feature = "server")]
        {
            if let Some(endpoint) = &self.server_endpoint {
                match self.get_stats_via_server(endpoint).await {
                    Ok(stats) => return Ok(stats),
                    Err(e) => {
                        warn!("Failed to get stats from server: {}", e);
                    }
                }
            }
        }

        // Fallback to local stats
        let stats = self.storage_manager.get_statistics().await?;
        Ok(serde_json::json!({
            "snapshot_count": stats.snapshot_count,
            "total_size": stats.total_size,
            "packfile_count": stats.packfile_count,
            "blob_count": stats.blob_count,
            "tree_count": stats.tree_count,
            "compression_ratio": stats.compression_ratio,
            "deduplication_ratio": stats.deduplication_ratio,
        }))
    }

    #[cfg(feature = "server")]
    async fn get_stats_via_server(&self, endpoint: &str) -> Result<serde_json::Value> {
        let url = format!("{}/api/v1/repo/stats", endpoint);

        let response = self.http_client.get(&url).send().await?;

        if !response.status().is_success() {
            return Err(anyhow!("Server returned error: {}", response.status()));
        }

        let stats: serde_json::Value = response.json().await?;
        Ok(stats)
    }
}

#[derive(Deserialize)]
struct ServerInfo {
    endpoint: String,
    capabilities: Vec<String>,
}

#[cfg(feature = "server")]
#[derive(Serialize)]
struct CheckHashesRequest {
    hashes: Vec<String>,
}

#[cfg(feature = "server")]
#[derive(Deserialize)]
struct CheckHashesResponse {
    existing: Vec<String>,
    missing: Vec<String>,
}

#[derive(Deserialize)]
struct PruneResponse {
    kept_snapshots: Vec<String>,
    removed_snapshots: Vec<String>,
    space_freed: u64,
}

#[derive(Debug, Clone)]
pub struct RetentionPolicy {
    pub keep_daily: usize,
    pub keep_weekly: usize,
    pub keep_monthly: usize,
    pub keep_yearly: usize,
    pub keep_last: usize,
    pub keep_tags: Vec<String>,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            keep_daily: 7,
            keep_weekly: 4,
            keep_monthly: 6,
            keep_yearly: 3,
            keep_last: 3,
            keep_tags: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub struct PruneReport {
    pub kept_snapshots: Vec<String>,
    pub removed_snapshots: Vec<String>,
    pub space_freed: u64,
}
