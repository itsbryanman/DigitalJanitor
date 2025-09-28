use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{info, warn};

use crate::{
    data::HashId, repository::Repository, snapshot::PrunePolicy, snapshot::SnapshotManager,
    storage::StorageManager,
};

#[cfg(feature = "server")]
use {
    axum::{
        extract::{Path as AxumPath, State},
        http::StatusCode,
        response::{IntoResponse, Response},
        routing::{get, post},
        Json, Router,
    },
    tokio::net::TcpListener,
    tower::ServiceBuilder,
    tower_http::cors::CorsLayer,
    tower_http::trace::TraceLayer,
};

/// Server state shared across handlers
#[derive(Clone)]
pub struct ServerState {
    repository: Arc<Repository>,
    storage_manager: Arc<StorageManager>,
    snapshot_manager: Arc<SnapshotManager>,
    config: ServerConfig,
}

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub listen_addr: SocketAddr,
    pub max_concurrent_operations: usize,
    pub enable_write: bool,
    pub auth_token: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: ([0, 0, 0, 0], 8080).into(),
            max_concurrent_operations: 100,
            enable_write: false,
            auth_token: None,
        }
    }
}

/// Start the server for hybrid intelligence protocol
#[cfg(feature = "server")]
pub async fn start_server(
    repository: Arc<Repository>,
    storage_manager: Arc<StorageManager>,
    snapshot_manager: Arc<SnapshotManager>,
    config: ServerConfig,
) -> Result<()> {
    let state = ServerState {
        repository,
        storage_manager,
        snapshot_manager,
        config: config.clone(),
    };

    // Build the router
    let app = Router::new()
        // Health check
        .route("/health", get(health_check))
        // Server info endpoint (for discovery)
        .route("/.dj_server_info", get(server_info))
        // Blob operations
        .route("/api/v1/blobs/check", post(check_hashes))
        .route("/api/v1/blobs/:hash", get(get_blob))
        .route("/api/v1/blobs", post(upload_blob))
        // Index operations
        .route("/api/v1/indexes", get(list_indexes))
        .route("/api/v1/indexes/:id", get(get_index))
        .route("/api/v1/indexes/merged", get(get_merged_index))
        // Snapshot operations
        .route("/api/v1/snapshots", get(list_snapshots))
        .route("/api/v1/snapshots/:id", get(get_snapshot))
        // Repository operations
        .route("/api/v1/repo/stats", get(repo_stats))
        .route("/api/v1/repo/verify", post(verify_repo))
        .route("/api/v1/repo/gc", post(garbage_collect))
        .route("/api/v1/repo/optimize", post(optimize_storage))
        // Prune operation (server-side processing)
        .route("/api/v1/repo/prune", post(run_prune))
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(CorsLayer::permissive()),
        )
        .with_state(state);

    // Start the server
    let listener = TcpListener::bind(config.listen_addr).await?;
    info!("Server listening on {}", config.listen_addr);

    axum::serve(listener, app)
        .await
        .map_err(|e| anyhow!("Server error: {}", e))
}

#[cfg(not(feature = "server"))]
pub async fn start_server(
    _repository: Arc<Repository>,
    _storage_manager: Arc<StorageManager>,
    _snapshot_manager: Arc<SnapshotManager>,
    _config: ServerConfig,
) -> Result<()> {
    Err(Error::Generic(anyhow::anyhow!(
        "Server mode is not supported in this build. Enable the 'server' feature."
    )))
}

// Handler implementations
#[cfg(feature = "server")]
async fn health_check() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "healthy",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

#[cfg(feature = "server")]
async fn server_info(State(state): State<ServerState>) -> impl IntoResponse {
    Json(serde_json::json!({
        "server": "digital-janitor",
        "version": env!("CARGO_PKG_VERSION"),
        "protocol_version": "1.0",
        "capabilities": {
            "check_hashes": true,
            "get_index": true,
            "run_prune": true,
            "write_enabled": state.config.enable_write,
        },
        "endpoints": {
            "check_hashes": "/api/v1/blobs/check",
            "get_index": "/api/v1/indexes/merged",
            "run_prune": "/api/v1/repo/prune",
        }
    }))
}

#[cfg(feature = "server")]
#[derive(Deserialize)]
struct CheckHashesRequest {
    hashes: Vec<String>,
}

#[cfg(feature = "server")]
#[derive(Serialize)]
struct CheckHashesResponse {
    existing: Vec<String>,
    missing: Vec<String>,
}

#[cfg(feature = "server")]
async fn check_hashes(
    State(state): State<ServerState>,
    Json(request): Json<CheckHashesRequest>,
) -> Result<Json<CheckHashesResponse>, AppError> {
    let mut existing = Vec::new();
    let mut missing = Vec::new();

    for hash_str in request.hashes {
        let hash: HashId = hash_str
            .parse()
            .map_err(|_| AppError::BadRequest("Invalid hash format".to_string()))?;

        match state.repository.get_object(&hash).await {
            Ok(_) => existing.push(hash_str),
            Err(_) => missing.push(hash_str),
        }
    }

    Ok(Json(CheckHashesResponse { existing, missing }))
}

#[cfg(feature = "server")]
async fn get_blob(
    State(state): State<ServerState>,
    AxumPath(hash_str): AxumPath<String>,
) -> Result<Vec<u8>, AppError> {
    let hash: HashId = hash_str
        .parse()
        .map_err(|_| AppError::BadRequest("Invalid hash format".to_string()))?;

    let data = state
        .repository
        .get_object(&hash)
        .await
        .map_err(|_| AppError::NotFound)?;

    Ok(data)
}

#[cfg(feature = "server")]
async fn upload_blob(
    State(state): State<ServerState>,
    body: axum::body::Bytes,
) -> Result<Json<serde_json::Value>, AppError> {
    if !state.config.enable_write {
        return Err(AppError::Forbidden);
    }

    // Process the blob - this would need implementation in repository
    // For now, return a placeholder response
    Ok(Json(serde_json::json!({
        "message": "Upload not yet implemented",
        "size": body.len(),
    })))
}

#[cfg(feature = "server")]
async fn list_indexes(State(state): State<ServerState>) -> Result<Json<Vec<String>>, AppError> {
    let packfiles = state.repository.list_packfiles().await?;
    let index_ids: Vec<String> = packfiles.iter().map(|h| h.to_hex()).collect();
    Ok(Json(index_ids))
}

#[cfg(feature = "server")]
async fn get_index(
    State(state): State<ServerState>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let hash: HashId = id
        .parse()
        .map_err(|_| AppError::BadRequest("Invalid index ID format".to_string()))?;

    let header = state
        .repository
        .packfile_header(&hash)
        .await
        .map_err(|_| AppError::NotFound)?;

    Ok(Json(serde_json::to_value(header)?))
}

#[cfg(feature = "server")]
async fn get_merged_index(
    State(state): State<ServerState>,
) -> Result<Json<serde_json::Value>, AppError> {
    let packfiles = state.repository.list_packfiles().await?;
    let mut merged_entries = Vec::new();

    for pack_id in packfiles {
        if let Ok(header) = state.repository.packfile_header(&pack_id).await {
            merged_entries.extend(header.entries);
        }
    }

    // Remove duplicates by hash
    merged_entries.sort_by_key(|e| e.hash);
    merged_entries.dedup_by_key(|e| e.hash);

    Ok(Json(serde_json::json!({
        "version": 1,
        "entry_count": merged_entries.len(),
        "entries": merged_entries,
    })))
}

#[cfg(feature = "server")]
async fn list_snapshots(
    State(state): State<ServerState>,
) -> Result<Json<Vec<serde_json::Value>>, AppError> {
    let snapshot_ids = state.repository.list_snapshots().await?;
    let mut snapshots = Vec::new();

    for snapshot_id in snapshot_ids {
        if let Ok(snapshot) = state.repository.load_snapshot(&snapshot_id).await {
            snapshots.push(serde_json::json!({
                "id": snapshot.id,
                "time": snapshot.time,
                "paths": snapshot.paths,
                "tags": snapshot.tags,
                "host": snapshot.hostname,
            }));
        }
    }

    Ok(Json(snapshots))
}

#[cfg(feature = "server")]
async fn get_snapshot(
    State(state): State<ServerState>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<serde_json::Value>, AppError> {
    let snapshot = state
        .repository
        .load_snapshot(&id)
        .await
        .map_err(|_| AppError::NotFound)?;

    Ok(Json(serde_json::to_value(snapshot)?))
}

#[cfg(feature = "server")]
async fn repo_stats(State(state): State<ServerState>) -> Result<Json<serde_json::Value>, AppError> {
    let stats = state.storage_manager.get_statistics().await?;
    Ok(Json(serde_json::json!({
        "snapshot_count": stats.snapshot_count,
        "total_size": stats.total_size,
        "packfile_count": stats.packfile_count,
        "blob_count": stats.blob_count,
        "tree_count": stats.tree_count,
        "compression_ratio": stats.compression_ratio,
        "deduplication_ratio": stats.deduplication_ratio,
    })))
}

#[cfg(feature = "server")]
#[derive(Deserialize)]
struct VerifyRequest {
    read_data: bool,
}

#[cfg(feature = "server")]
async fn verify_repo(
    State(state): State<ServerState>,
    Json(request): Json<VerifyRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    info!(
        "Starting repository verification via API (read_data: {})",
        request.read_data
    );
    let report = state
        .storage_manager
        .verify_storage(request.read_data)
        .await?;
    Ok(Json(serde_json::json!({
        "total_objects": report.total_objects,
        "verified_objects": report.verified_objects,
        "corrupted_objects": report.corrupted_objects,
        "missing_objects": report.missing_objects,
        "errors": report.errors,
    })))
}

#[cfg(feature = "server")]
#[derive(Deserialize)]
struct GCRequest {
    dry_run: bool,
}

#[cfg(feature = "server")]
async fn garbage_collect(
    State(state): State<ServerState>,
    Json(request): Json<GCRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    if !state.config.enable_write && !request.dry_run {
        return Err(AppError::Forbidden);
    }

    let report = state.storage_manager.garbage_collect(&[]).await?;
    Ok(Json(serde_json::json!({
        "total_objects": report.total_objects,
        "referenced_objects": report.referenced_objects,
        "removed_objects": report.removed_objects,
        "bytes_freed": report.bytes_freed,
    })))
}

#[cfg(feature = "server")]
#[derive(Deserialize)]
struct OptimizeRequest {
    aggressive: bool,
}

#[cfg(feature = "server")]
async fn optimize_storage(
    State(state): State<ServerState>,
    Json(request): Json<OptimizeRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    if !state.config.enable_write {
        return Err(AppError::Forbidden);
    }

    info!(
        "Starting storage optimisation via API (aggressive: {})",
        request.aggressive
    );
    let report = state
        .storage_manager
        .optimize_storage(request.aggressive)
        .await?;

    Ok(Json(serde_json::json!({
        "bytes_saved": report.bytes_saved,
        "packfiles_merged": report.packfiles_merged,
        "orphaned_objects_removed": report.orphaned_objects_removed,
        "duration_seconds": report.duration.as_secs_f64(),
    })))
}

#[cfg(feature = "server")]
#[derive(Deserialize)]
struct PruneRequest {
    keep_daily: Option<usize>,
    keep_weekly: Option<usize>,
    keep_monthly: Option<usize>,
    keep_yearly: Option<usize>,
    keep_last: Option<usize>,
    keep_tags: Option<Vec<String>>,
    dry_run: bool,
}

#[cfg(feature = "server")]
#[derive(Serialize)]
struct PruneResponse {
    kept_snapshots: Vec<String>,
    removed_snapshots: Vec<String>,
    space_freed: u64,
}

#[cfg(feature = "server")]
async fn run_prune(
    State(state): State<ServerState>,
    Json(request): Json<PruneRequest>,
) -> Result<Json<PruneResponse>, AppError> {
    if !state.config.enable_write && !request.dry_run {
        return Err(AppError::Forbidden);
    }

    let mut snapshots = state.snapshot_manager.list_snapshots(None).await?;
    if snapshots.is_empty() {
        return Ok(Json(PruneResponse {
            kept_snapshots: Vec::new(),
            removed_snapshots: Vec::new(),
            space_freed: 0,
        }));
    }

    let mut policy = PrunePolicy::default();

    if let Some(value) = request.keep_daily {
        policy.keep_daily = Some(value as u32);
    }
    if let Some(value) = request.keep_weekly {
        policy.keep_weekly = Some(value as u32);
    }
    if let Some(value) = request.keep_monthly {
        policy.keep_monthly = Some(value as u32);
    }
    if let Some(value) = request.keep_yearly {
        policy.keep_yearly = Some(value as u32);
    }

    let keep_last = request.keep_last.unwrap_or(3).max(1) as u32;
    policy.keep_last = Some(keep_last);
    policy.keep_tags = request.keep_tags.unwrap_or_default();

    snapshots.sort_by(|a, b| b.time.cmp(&a.time));

    let mut kept_set: HashSet<uuid::Uuid> = policy.apply(&snapshots).into_iter().collect();
    if kept_set.is_empty() {
        warn!("Retention policy selected no snapshots; keeping the three most recent entries by default");
        for snapshot in snapshots.iter().take(3) {
            kept_set.insert(snapshot.id);
        }
    }

    let kept_snapshots: Vec<String> = snapshots
        .iter()
        .filter(|snapshot| kept_set.contains(&snapshot.id))
        .map(|snapshot| snapshot.id.to_string())
        .collect();

    let removed_snapshots: Vec<String> = snapshots
        .iter()
        .filter(|snapshot| !kept_set.contains(&snapshot.id))
        .map(|snapshot| snapshot.id.to_string())
        .collect();

    if !request.dry_run && removed_snapshots.len() == snapshots.len() {
        return Err(AppError::BadRequest(
            "Refusing to delete all snapshots".to_string(),
        ));
    }

    let mut space_freed = 0u64;

    if !request.dry_run {
        for snapshot_id in &removed_snapshots {
            if let Err(e) = state.snapshot_manager.delete_snapshot(snapshot_id).await {
                warn!("Failed to delete snapshot {}: {}", snapshot_id, e);
            }
        }

        let gc_report = state.storage_manager.garbage_collect(&[]).await?;
        space_freed = gc_report.bytes_freed;
    }

    Ok(Json(PruneResponse {
        kept_snapshots,
        removed_snapshots,
        space_freed,
    }))
}

// Error handling
#[cfg(feature = "server")]
#[derive(Debug)]
enum AppError {
    Internal(anyhow::Error),
    BadRequest(String),
    NotFound,
    Forbidden,
}

#[cfg(feature = "server")]
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AppError::Internal(e) => {
                tracing::error!("Internal error: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string(),
                )
            }
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            AppError::NotFound => (StatusCode::NOT_FOUND, "Resource not found".to_string()),
            AppError::Forbidden => (StatusCode::FORBIDDEN, "Operation not permitted".to_string()),
        };

        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}

#[cfg(feature = "server")]
impl From<anyhow::Error> for AppError {
    fn from(err: anyhow::Error) -> Self {
        AppError::Internal(err)
    }
}

impl From<crate::Error> for AppError {
    fn from(err: crate::Error) -> Self {
        AppError::Internal(err.into())
    }
}

#[cfg(feature = "server")]
impl From<serde_json::Error> for AppError {
    fn from(err: serde_json::Error) -> Self {
        AppError::Internal(err.into())
    }
}
