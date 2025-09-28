use clap::{Parser, Subcommand};
use dj::{
    backend::BackendConfig,
    data::HashId,
    pipeline::{BackupOptions, BackupPipeline, RestoreOptions, RestorePipeline},
    repository::Repository,
    snapshot::{PrunePolicy, SnapshotFilter, SnapshotManager},
    storage::StorageManager,
    utils::format_bytes,
    Error, Result,
};
use indicatif::{ProgressBar, ProgressStyle};
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::time::{interval, Duration};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use url::Url;

#[derive(Parser)]
#[command(name = "dj")]
#[command(about = "Digital Janitor - CLI-first backup solution")]
#[command(version = env!("CARGO_PKG_VERSION"))]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Repository URL or path
    #[arg(long, short = 'r', env = "DJ_REPO")]
    repo: Option<String>,

    /// Repository password
    #[arg(long, short = 'p', env = "DJ_PASSWORD")]
    password: Option<String>,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Quiet output (errors only)
    #[arg(short, long)]
    quiet: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Repository management
    Repo {
        #[command(subcommand)]
        command: RepoCommands,
    },
    /// Backup operations
    Backup {
        #[command(subcommand)]
        command: BackupCommands,
    },
    /// Snapshot management
    Snapshot {
        #[command(subcommand)]
        command: SnapshotCommands,
    },
    /// Restore operations
    Restore {
        /// Snapshot ID to restore
        snapshot_id: String,
        /// Target directory for restore
        #[arg(long, short)]
        target: PathBuf,
        /// Include only files matching these patterns
        #[arg(long)]
        include: Vec<String>,
        /// Exclude files matching these patterns
        #[arg(long)]
        exclude: Vec<String>,
        /// Overwrite existing files
        #[arg(long)]
        overwrite: bool,
        /// Verify restored files
        #[arg(long)]
        verify: bool,
    },
    /// Mount repository as filesystem
    #[cfg(feature = "mount")]
    Mount {
        /// Mount point
        mount_point: PathBuf,
        /// Allow other users to access the mount
        #[arg(long)]
        allow_other: bool,
    },
    /// Server mode
    #[cfg(feature = "server")]
    Server {
        #[command(subcommand)]
        command: ServerCommands,
    },
}

#[derive(Subcommand)]
enum RepoCommands {
    /// Initialize a new repository
    Init {
        /// Initialize without encryption
        #[arg(long)]
        no_encryption: bool,
    },
    /// Check repository integrity
    Check {
        /// Read and verify all data blobs
        #[arg(long)]
        read_data: bool,
    },
    /// Prune repository
    Prune {
        /// Keep daily snapshots for N days
        #[arg(long, default_value = "7")]
        keep_daily: u32,
        /// Keep weekly snapshots for N weeks
        #[arg(long, default_value = "4")]
        keep_weekly: u32,
        /// Keep monthly snapshots for N months
        #[arg(long, default_value = "6")]
        keep_monthly: u32,
        /// Keep yearly snapshots for N years
        #[arg(long, default_value = "1")]
        keep_yearly: u32,
        /// Keep last N snapshots
        #[arg(long, default_value = "1")]
        keep_last: u32,
        /// Always keep snapshots with these tags
        #[arg(long)]
        keep_tags: Vec<String>,
        /// Dry run - show what would be deleted
        #[arg(long)]
        dry_run: bool,
    },
    /// Show repository statistics
    Stats,
}

#[derive(Subcommand)]
enum BackupCommands {
    /// Create a new backup
    Create {
        /// Paths to backup
        paths: Vec<PathBuf>,
        /// Tags for this backup
        #[arg(long, short)]
        tags: Vec<String>,
        /// Exclude patterns
        #[arg(long)]
        exclude: Vec<String>,
        /// Parent snapshot ID for incremental backup
        #[arg(long)]
        parent: Option<String>,
        /// Dry run - don't actually backup
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Subcommand)]
enum SnapshotCommands {
    /// List snapshots
    List {
        /// Filter by tags
        #[arg(long)]
        tags: Vec<String>,
        /// Filter by hostname
        #[arg(long)]
        host: Vec<String>,
        /// Filter by paths
        #[arg(long)]
        path: Vec<String>,
        /// Show snapshots before this date (ISO 8601)
        #[arg(long)]
        before: Option<String>,
        /// Show snapshots after this date (ISO 8601)
        #[arg(long)]
        after: Option<String>,
    },
    /// Show snapshot details
    Show {
        /// Snapshot ID
        snapshot_id: String,
    },
    /// Delete a snapshot
    Delete {
        /// Snapshot ID
        snapshot_id: String,
        /// Force deletion without confirmation
        #[arg(long)]
        force: bool,
    },
    /// Compare two snapshots
    Diff {
        /// First snapshot ID
        snapshot1: String,
        /// Second snapshot ID
        snapshot2: String,
    },
}

#[cfg(feature = "server")]
#[derive(Subcommand)]
enum ServerCommands {
    /// Start server mode
    Start {
        /// Listen address
        #[arg(long, default_value = "127.0.0.1:8080")]
        listen: String,
        /// Enable write operations
        #[arg(long)]
        enable_write: bool,
        /// Authentication token
        #[arg(long, env = "DJ_AUTH_TOKEN")]
        auth_token: Option<String>,
        /// Number of worker threads
        #[arg(long)]
        workers: Option<usize>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Setup logging
    let log_level = if cli.quiet {
        tracing::Level::ERROR
    } else if cli.verbose {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| format!("dj={}", log_level).into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Parse backend config from repo URL
    let repo_url = match cli.repo.clone() {
        Some(repo) => repo,
        None => {
            let default = default_repo_url()?;
            tracing::info!(
                "DJ_REPO not provided, using default repository at {}",
                default
            );
            default
        }
    };

    let backend_config = BackendConfig::from_url(&repo_url)?;
    let backend: Arc<dyn dj::backend::Backend> = backend_config.create_backend().await?.into();

    match cli.command {
        Commands::Repo { command } => {
            handle_repo_command(command, backend.clone(), cli.password.clone()).await
        }
        Commands::Backup { command } => {
            handle_backup_command(command, backend.clone(), cli.password.clone()).await
        }
        Commands::Snapshot { command } => {
            handle_snapshot_command(command, backend.clone(), cli.password.clone()).await
        }
        Commands::Restore {
            snapshot_id,
            target,
            include,
            exclude,
            overwrite,
            verify,
        } => {
            let repository = Repository::open(backend.clone(), cli.password.as_deref()).await?;
            let restore_pipeline = RestorePipeline::new(repository);

            let options = RestoreOptions {
                snapshot_id,
                target_path: target,
                include_patterns: include,
                exclude_patterns: exclude,
                overwrite,
                verify,
            };

            restore_pipeline.restore(options).await?;
            println!("Restore completed successfully");
            Ok(())
        }
        #[cfg(feature = "mount")]
        Commands::Mount {
            mount_point,
            allow_other,
        } => {
            handle_mount_command(
                mount_point,
                allow_other,
                backend.clone(),
                cli.password.clone(),
            )
            .await
        }
        #[cfg(feature = "server")]
        Commands::Server { command } => handle_server_command(command, backend, cli.password).await,
    }
}

async fn handle_repo_command(
    command: RepoCommands,
    backend: Arc<dyn dj::backend::Backend>,
    cli_password: Option<String>,
) -> Result<()> {
    match command {
        RepoCommands::Init { no_encryption } => {
            let password = if no_encryption {
                None
            } else if let Some(ref provided) = cli_password {
                Some(provided.clone())
            } else {
                Some(get_password("Enter password for new repository: ")?)
            };

            let _repository = Repository::init(backend.clone(), password.as_deref()).await?;
            println!("Repository initialized successfully");
        }
        RepoCommands::Check { read_data } => {
            let password = resolve_password(cli_password.clone())?;
            let repository = Repository::open(backend.clone(), password.as_deref()).await?;
            let result = repository.check_integrity(read_data).await?;

            if result.is_healthy() {
                println!("Repository is healthy");
                println!("  Config: OK");
                println!("  Keys: OK");
                println!("  Index: OK");
                println!(
                    "  Snapshots: {}/{} OK",
                    result.snapshots_ok, result.snapshots_checked
                );

                if read_data {
                    println!(
                        "  Packfiles: {}/{} OK",
                        result.packfiles_ok, result.packfiles_checked
                    );
                    println!(
                        "  Objects: {}/{} OK",
                        result.objects_ok, result.objects_checked
                    );
                }
            } else {
                println!("Repository has issues:");
                for error in &result.errors {
                    println!("  ERROR: {}", error);
                }
                return Err(Error::repository("Repository integrity check failed"));
            }
        }
        RepoCommands::Prune {
            keep_daily,
            keep_weekly,
            keep_monthly,
            keep_yearly,
            keep_last,
            keep_tags,
            dry_run,
        } => {
            let password = resolve_password(cli_password.clone())?;
            let repository = Repository::open(backend.clone(), password.as_deref()).await?;
            let snapshot_manager = SnapshotManager::new(repository);

            let policy = PrunePolicy {
                keep_daily: Some(keep_daily),
                keep_weekly: Some(keep_weekly),
                keep_monthly: Some(keep_monthly),
                keep_yearly: Some(keep_yearly),
                keep_last: Some(keep_last),
                keep_tags,
                ..Default::default()
            };

            if dry_run {
                println!("Dry run - showing what would be pruned");
                println!("No snapshots were deleted during this preview run.");
            } else {
                let result = snapshot_manager.prune_snapshots(&policy).await?;
                println!("Pruning completed:");
                println!("  Total snapshots: {}", result.total_snapshots);
                println!("  Kept snapshots: {}", result.kept_snapshots);
                println!("  Deleted snapshots: {}", result.deleted_snapshots);

                if !result.errors.is_empty() {
                    println!("Errors:");
                    for error in &result.errors {
                        println!("  {}", error);
                    }
                }
            }
        }
        RepoCommands::Stats => {
            let password = resolve_password(cli_password)?;
            let repository = Repository::open(backend, password.as_deref()).await?;
            let config = repository.config();

            println!("Repository Statistics:");
            println!("  Version: {}", config.version);
            println!("  ID: {}", config.id);
            println!(
                "  Created: {}",
                config.created_at.format("%Y-%m-%d %H:%M:%S UTC")
            );
            println!(
                "  Encryption: {}",
                if config.encryption_enabled {
                    "Enabled"
                } else {
                    "Disabled"
                }
            );
            println!("  Compression Level: {}", config.compression_level);

            // Additional statistics can be displayed when more telemetry is collected.
        }
    }
    Ok(())
}

async fn handle_backup_command(
    command: BackupCommands,
    backend: Arc<dyn dj::backend::Backend>,
    password: Option<String>,
) -> Result<()> {
    match command {
        BackupCommands::Create {
            paths,
            tags,
            exclude,
            parent,
            dry_run,
        } => {
            let password = resolve_password(password)?;
            let repository = Repository::open(backend, password.as_deref()).await?;
            let backup_pipeline = BackupPipeline::new(repository);

            let parent_snapshot = if let Some(parent_id) = parent {
                match HashId::from_hex(&parent_id) {
                    Ok(hash) => Some(hash),
                    Err(_) => {
                        return Err(Error::validation(format!(
                            "Invalid parent snapshot identifier: {}",
                            parent_id
                        )));
                    }
                }
            } else {
                None
            };

            let options = BackupOptions {
                paths,
                tags,
                exclude_patterns: exclude,
                parent_snapshot,
                dry_run,
                verbose: false,
            };

            // Start progress monitoring
            let progress_handle = if !dry_run {
                let pipeline_clone = backup_pipeline.clone();
                Some(tokio::spawn(async move {
                    show_backup_progress(&pipeline_clone).await;
                }))
            } else {
                None
            };

            let snapshot = backup_pipeline.backup(options).await?;

            if let Some(handle) = progress_handle {
                handle.abort();
            }

            if dry_run {
                println!("Dry run completed");
                println!("  Files: {}", snapshot.summary.total_files_processed);
                println!(
                    "  Size: {}",
                    format_bytes(snapshot.summary.total_bytes_processed)
                );
            } else {
                println!("Backup completed successfully");
                println!("  Snapshot ID: {}", snapshot.id);
                println!(
                    "  Files processed: {}",
                    snapshot.summary.total_files_processed
                );
                println!(
                    "  Bytes processed: {}",
                    format_bytes(snapshot.summary.total_bytes_processed)
                );
                println!("  New files: {}", snapshot.summary.files_new);
                println!("  Changed files: {}", snapshot.summary.files_changed);
                println!("  Unmodified files: {}", snapshot.summary.files_unmodified);
            }
        }
    }
    Ok(())
}

async fn handle_snapshot_command(
    command: SnapshotCommands,
    backend: Arc<dyn dj::backend::Backend>,
    password: Option<String>,
) -> Result<()> {
    let password = resolve_password(password)?;
    let repository = Repository::open(backend, password.as_deref()).await?;
    let snapshot_manager = SnapshotManager::new(repository);
    match command {
        SnapshotCommands::List {
            tags,
            host,
            path,
            before,
            after,
        } => {
            let filter = SnapshotFilter {
                tags,
                hosts: host,
                paths: path,
                before: before.and_then(|s| {
                    chrono::DateTime::parse_from_rfc3339(&s)
                        .ok()
                        .map(|dt| dt.with_timezone(&chrono::Utc))
                }),
                after: after.and_then(|s| {
                    chrono::DateTime::parse_from_rfc3339(&s)
                        .ok()
                        .map(|dt| dt.with_timezone(&chrono::Utc))
                }),
            };

            let snapshots = snapshot_manager.list_snapshots(Some(filter)).await?;

            if snapshots.is_empty() {
                println!("No snapshots found");
            } else {
                println!(
                    "{:<36} {:<20} {:<15} {:<20} Paths",
                    "ID", "Time", "Host", "Size"
                );
                println!("{}", "-".repeat(100));

                for snapshot in snapshots {
                    let size = format_bytes(snapshot.summary.total_bytes_processed);
                    let paths = snapshot.paths.join(", ");
                    let paths_display = if paths.len() > 40 {
                        format!("{}...", &paths[..37])
                    } else {
                        paths
                    };

                    println!(
                        "{} {} {:<15} {:<20} {}",
                        snapshot.id,
                        snapshot.time.format("%Y-%m-%d %H:%M:%S"),
                        snapshot.hostname,
                        size,
                        paths_display
                    );
                }
            }
        }
        SnapshotCommands::Show { snapshot_id } => {
            let snapshot = snapshot_manager.get_snapshot(&snapshot_id).await?;

            println!("Snapshot Details:");
            println!("  ID: {}", snapshot.id);
            println!("  Time: {}", snapshot.time.format("%Y-%m-%d %H:%M:%S UTC"));
            println!("  Hostname: {}", snapshot.hostname);
            println!("  Username: {}", snapshot.username);
            println!("  Tags: {}", snapshot.tags.join(", "));
            println!("  Paths:");
            for path in &snapshot.paths {
                println!("    {}", path);
            }
            println!("  Summary:");
            println!(
                "    Files processed: {}",
                snapshot.summary.total_files_processed
            );
            println!(
                "    Bytes processed: {}",
                format_bytes(snapshot.summary.total_bytes_processed)
            );
            println!("    New files: {}", snapshot.summary.files_new);
            println!("    Changed files: {}", snapshot.summary.files_changed);
            println!(
                "    Unmodified files: {}",
                snapshot.summary.files_unmodified
            );
        }
        SnapshotCommands::Delete { snapshot_id, force } => {
            if !force {
                print!(
                    "Are you sure you want to delete snapshot {}? [y/N]: ",
                    snapshot_id
                );
                io::stdout().flush().unwrap();

                let mut input = String::new();
                io::stdin().read_line(&mut input).unwrap();

                if !input.trim().to_lowercase().starts_with('y') {
                    println!("Deletion cancelled");
                    return Ok(());
                }
            }

            snapshot_manager.delete_snapshot(&snapshot_id).await?;
            println!("Snapshot {} deleted successfully", snapshot_id);
        }
        SnapshotCommands::Diff {
            snapshot1,
            snapshot2,
        } => {
            let diff = snapshot_manager
                .get_snapshot_diff(&snapshot1, &snapshot2)
                .await?;

            println!("Snapshot Difference ({} -> {}):", snapshot1, snapshot2);
            println!("  Added files: {}", diff.added_files.len());
            println!("  Modified files: {}", diff.modified_files.len());
            println!("  Deleted files: {}", diff.deleted_files.len());
            println!(
                "  Size change: {}",
                format_bytes(diff.size_change.unsigned_abs())
            );
            if let Some(example) = diff.added_files.first() {
                println!("  e.g. added: {}", example);
            }
            if let Some(example) = diff.modified_files.first() {
                println!("  e.g. modified: {}", example);
            }
            if let Some(example) = diff.deleted_files.first() {
                println!("  e.g. deleted: {}", example);
            }
        }
    }
    Ok(())
}

async fn handle_mount_command(
    mount_point: PathBuf,
    _allow_other: bool,
    backend: Arc<dyn dj::backend::Backend>,
    password: Option<String>,
) -> Result<()> {
    let password = resolve_password(password)?;
    let repository = Arc::new(Repository::open(backend.clone(), password.as_deref()).await?);

    #[cfg(feature = "mount")]
    {
        dj::fuse_mount::mount_repository(repository, &mount_point)
            .await
            .map_err(Error::from)
    }

    #[cfg(not(feature = "mount"))]
    {
        let _ = (mount_point, repository);
        Err(Error::Generic(anyhow::anyhow!(
            "FUSE mounting is not supported in this build. Enable the 'mount' feature.",
        )))
    }
}

#[cfg(feature = "server")]
async fn handle_server_command(
    command: ServerCommands,
    backend: Arc<dyn dj::backend::Backend>,
    password: Option<String>,
) -> Result<()> {
    match command {
        ServerCommands::Start {
            listen,
            enable_write,
            auth_token,
            workers,
        } => {
            let password = resolve_password(password)?;
            let repository =
                Arc::new(Repository::open(backend.clone(), password.as_deref()).await?);
            let storage_manager = Arc::new(StorageManager::new(repository.clone()));
            let snapshot_manager = Arc::new(SnapshotManager::new((*repository).clone()));

            let config = dj::server::ServerConfig {
                listen_addr: listen.parse().map_err(|e| {
                    Error::Generic(anyhow::anyhow!("Invalid listen address: {}", e))
                })?,
                enable_write,
                auth_token,
                max_concurrent_operations: workers.unwrap_or(100),
            };

            // Write server info to repository for discovery
            let server_info = serde_json::json!({
                "endpoint": format!("http://{}", listen),
                "capabilities": ["check_hashes", "get_index", "run_prune", "verify", "optimize"],
            });

            repository
                .backend()
                .write(
                    dj::backend::FileType::Config,
                    ".dj_server_info",
                    serde_json::to_vec(&server_info)?,
                )
                .await?;

            println!("Starting server on {}", listen);
            if let Some(workers) = workers {
                println!("Using {} concurrent operations", workers);
            }
            if enable_write {
                println!("Write operations enabled");
            }

            dj::server::start_server(repository, storage_manager, snapshot_manager, config)
                .await
                .map_err(Error::Generic)
        }
    }
}

#[cfg(not(feature = "server"))]
async fn handle_server_command(
    _command: ServerCommands,
    _backend: Arc<dyn dj::backend::Backend>,
    _password: Option<String>,
) -> Result<()> {
    Err(Error::Generic(anyhow::anyhow!(
        "Server mode is not supported in this build. Enable the 'server' feature.",
    )))
}

async fn show_backup_progress(pipeline: &BackupPipeline) {
    let mut interval = interval(Duration::from_millis(100));
    let progress_bar = ProgressBar::new(100);

    progress_bar.set_style(
        ProgressStyle::with_template(
            "{msg} [{elapsed_precise}] [{bar:40.cyan/blue}] {percent}% ({eta})",
        )
        .unwrap()
        .progress_chars("##-"),
    );

    loop {
        interval.tick().await;

        let progress = pipeline.get_progress();
        let percent = (progress.progress_ratio() * 100.0) as u64;

        progress_bar.set_position(percent);

        if let Some(current_file) = &progress.current_file {
            let truncated = dj::utils::truncate_string(current_file, 50);
            progress_bar.set_message(format!(
                "Processing: {} | {} | {}",
                truncated,
                format_bytes(progress.processed_bytes),
                dj::utils::format_transfer_rate(progress.transfer_rate())
            ));
        }

        if progress.processed_files >= progress.total_files {
            break;
        }
    }

    progress_bar.finish_with_message("Backup completed");
}

fn get_password(prompt: &str) -> Result<String> {
    print!("{}", prompt);
    io::stdout().flush().unwrap();

    let password = rpassword::read_password()?;
    if password.is_empty() {
        return Err(Error::validation("Password cannot be empty"));
    }

    // Verify password strength
    dj::crypto::verify_password_strength(&password)?;

    Ok(password)
}

fn default_repo_url() -> Result<String> {
    let data_root = default_data_root()?;
    fs::create_dir_all(&data_root)?;

    let repo_dir = data_root.join("repository");
    fs::create_dir_all(&repo_dir)?;

    let url = Url::from_directory_path(&repo_dir).map_err(|_| {
        Error::configuration(format!("Invalid repository path: {}", repo_dir.display()))
    })?;

    Ok(url.into())
}

fn resolve_password(password: Option<String>) -> Result<Option<String>> {
    if let Some(password) = password {
        return Ok(Some(password));
    }

    if let Ok(password_file) = env::var("DJ_PASSWORD_FILE") {
        let contents = fs::read_to_string(&password_file)?;
        let trimmed = contents.trim_end_matches(['\n', '\r']).to_string();
        if trimmed.is_empty() {
            return Err(Error::validation(format!(
                "Password file {} is empty",
                password_file
            )));
        }
        return Ok(Some(trimmed));
    }

    if let Ok(data_root) = default_data_root() {
        let candidate = data_root.join("password.txt");
        if candidate.exists() {
            let contents = fs::read_to_string(&candidate)?;
            let trimmed = contents.trim_end_matches(['\n', '\r']).to_string();
            if trimmed.is_empty() {
                return Err(Error::validation(format!(
                    "Password file {} is empty",
                    candidate.display()
                )));
            }
            return Ok(Some(trimmed));
        }
    }

    Ok(None)
}

fn default_data_root() -> Result<PathBuf> {
    if let Ok(custom) = env::var("DJ_DATA_DIR") {
        if !custom.is_empty() {
            return Ok(PathBuf::from(custom));
        }
    }

    let cwd = env::current_dir()?;
    Ok(cwd.join(".dj"))
}
