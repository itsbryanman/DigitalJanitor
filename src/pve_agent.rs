use clap::Parser;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, info, warn};

#[derive(Parser)]
#[command(name = "dj-pve-agent")]
#[command(about = "Digital Janitor Proxmox VE Agent")]
#[command(version = env!("CARGO_PKG_VERSION"))]
struct Cli {
    /// Listen address
    #[arg(long, default_value = "0.0.0.0:8081")]
    listen: String,

    /// Proxmox VE API endpoint
    #[arg(long, env = "PVE_API_URL")]
    pve_api: String,

    /// Proxmox VE username
    #[arg(long, env = "PVE_USERNAME")]
    pve_username: String,

    /// Proxmox VE password
    #[arg(long, env = "PVE_PASSWORD")]
    pve_password: String,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VmInfo {
    vmid: u32,
    name: String,
    status: String,
    node: String,
    vm_type: String, // qemu or lxc
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BackupRequest {
    vmid: u32,
    compression: Option<String>,
    mode: Option<String>, // stop, suspend, snapshot
    storage: Option<String>,
}

impl BackupRequest {
    fn validate(&self) -> Result<(), String> {
        if self.vmid == 0 {
            return Err("vmid must be greater than 0".to_string());
        }

        if let Some(mode) = &self.mode {
            if !["stop", "suspend", "snapshot"].contains(&mode.as_str()) {
                return Err(format!("Invalid backup mode: {}", mode));
            }
        }

        if let Some(compression) = &self.compression {
            if !["zstd", "gzip", "lzo"].contains(&compression.as_str()) {
                return Err(format!("Invalid compression type: {}", compression));
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BackupResponse {
    task_id: String,
    status: String,
    backup_file: Option<String>,
}

struct ProxmoxAgent {
    api_url: String,
    username: String,
    password: String,
    client: reqwest::Client,
}

impl ProxmoxAgent {
    fn new(api_url: String, username: String, password: String) -> Self {
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true) // For self-signed certificates
            .build()
            .expect("Failed to create HTTP client");

        Self {
            api_url,
            username,
            password,
            client,
        }
    }

    async fn authenticate(&self) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let auth_url = format!("{}/api2/json/access/ticket", self.api_url);

        let params = HashMap::from([
            ("username", self.username.as_str()),
            ("password", self.password.as_str()),
        ]);

        let response = self.client.post(&auth_url).form(&params).send().await?;

        if !response.status().is_success() {
            return Err(format!("Authentication failed: {}", response.status()).into());
        }

        let auth_data: serde_json::Value = response.json().await?;
        let ticket = auth_data["data"]["ticket"]
            .as_str()
            .ok_or("No ticket in response")?;

        Ok(ticket.to_string())
    }

    async fn list_vms(
        &self,
        ticket: &str,
    ) -> Result<Vec<VmInfo>, Box<dyn std::error::Error + Send + Sync>> {
        let mut vms = Vec::new();

        // Get QEMU VMs
        let qemu_url = format!("{}/api2/json/cluster/resources?type=vm", self.api_url);
        let response = self
            .client
            .get(&qemu_url)
            .header("Cookie", format!("PVEAuthCookie={}", ticket))
            .send()
            .await?;

        if response.status().is_success() {
            let data: serde_json::Value = response.json().await?;
            if let Some(vm_list) = data["data"].as_array() {
                for vm in vm_list {
                    if let (Some(vmid), Some(name), Some(status), Some(node)) = (
                        vm["vmid"].as_u64(),
                        vm["name"].as_str(),
                        vm["status"].as_str(),
                        vm["node"].as_str(),
                    ) {
                        vms.push(VmInfo {
                            vmid: vmid as u32,
                            name: name.to_string(),
                            status: status.to_string(),
                            node: node.to_string(),
                            vm_type: vm["type"].as_str().unwrap_or("qemu").to_string(),
                        });
                    }
                }
            }
        }

        Ok(vms)
    }

    async fn create_vm_backup(
        &self,
        ticket: &str,
        node: &str,
        request: &BackupRequest,
    ) -> Result<BackupResponse, Box<dyn std::error::Error + Send + Sync>> {
        let backup_url = format!("{}/api2/json/nodes/{}/vzdump", self.api_url, node);

        let mut params = HashMap::new();
        params.insert("vmid", request.vmid.to_string());
        params.insert(
            "mode",
            request.mode.as_deref().unwrap_or("snapshot").to_string(),
        );
        params.insert(
            "compress",
            request.compression.as_deref().unwrap_or("zstd").to_string(),
        );

        if let Some(storage) = &request.storage {
            params.insert("storage", storage.clone());
        }

        let response = self
            .client
            .post(&backup_url)
            .header("Cookie", format!("PVEAuthCookie={}", ticket))
            .form(&params)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(format!("Backup failed: {}", response.status()).into());
        }

        let backup_data: serde_json::Value = response.json().await?;
        let task_id = backup_data["data"]
            .as_str()
            .ok_or("No task ID in response")?;

        Ok(BackupResponse {
            task_id: task_id.to_string(),
            status: "started".to_string(),
            backup_file: None,
        })
    }

    async fn get_task_status(
        &self,
        ticket: &str,
        node: &str,
        task_id: &str,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
        let task_url = format!(
            "{}/api2/json/nodes/{}/tasks/{}/status",
            self.api_url, node, task_id
        );

        let response = self
            .client
            .get(&task_url)
            .header("Cookie", format!("PVEAuthCookie={}", ticket))
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(format!("Failed to get task status: {}", response.status()).into());
        }

        let status_data: serde_json::Value = response.json().await?;
        Ok(status_data)
    }

    #[allow(dead_code)]
    async fn stream_vm_data(
        &self,
        _ticket: &str,
        _vmid: u32,
        _backup_file: &str,
    ) -> Result<tokio::fs::File, Box<dyn std::error::Error + Send + Sync>> {
        // Streaming actual VM data can be integrated here when the feature lands.
        // This would involve:
        // 1. Using qemu-img to read the VM disk
        // 2. Streaming the data over the network
        // 3. Handling incremental backups with dirty bitmaps
        Err("VM data streaming not yet implemented".into())
    }
}

async fn handle_api_request(
    agent: &ProxmoxAgent,
    path: &str,
    body: Vec<u8>,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let ticket = agent.authenticate().await?;

    match path {
        "/vms" => {
            let vms = agent.list_vms(&ticket).await?;
            let response = serde_json::to_vec(&vms)?;
            Ok(response)
        }
        "/backup" => {
            let request: BackupRequest = serde_json::from_slice(&body)?;
            request.validate()?;

            // Find the VM to determine the node
            let vms = agent.list_vms(&ticket).await?;
            let vm = vms
                .iter()
                .find(|v| v.vmid == request.vmid)
                .ok_or("VM not found")?;

            let response = agent.create_vm_backup(&ticket, &vm.node, &request).await?;
            let response_data = serde_json::to_vec(&response)?;
            Ok(response_data)
        }
        path if path.starts_with("/task/") => {
            let parts: Vec<&str> = path.split('/').collect();
            if parts.len() >= 4 {
                let node = parts[2];
                let task_id = parts[3];

                let status = agent.get_task_status(&ticket, node, task_id).await?;
                let response = serde_json::to_vec(&status)?;
                Ok(response)
            } else {
                Err("Invalid task path".into())
            }
        }
        _ => Err("Unknown endpoint".into()),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cli = Cli::parse();

    // Setup logging
    let log_level = if cli.verbose {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };

    tracing_subscriber::fmt().with_max_level(log_level).init();

    info!("Starting Proxmox VE agent on {}", cli.listen);

    let agent = Arc::new(ProxmoxAgent::new(
        cli.pve_api,
        cli.pve_username,
        cli.pve_password,
    ));

    // Test authentication
    match agent.authenticate().await {
        Ok(_) => info!("Successfully authenticated with Proxmox VE"),
        Err(e) => {
            error!("Failed to authenticate with Proxmox VE: {}", e);
            return Err(e);
        }
    }

    let listener = TcpListener::bind(&cli.listen).await?;
    info!("Agent listening on {}", cli.listen);

    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                info!("New connection from {}", addr);
                let agent_clone = agent.clone();

                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, agent_clone).await {
                        error!("Error handling connection from {}: {}", addr, e);
                    }
                });
            }
            Err(e) => {
                error!("Failed to accept connection: {}", e);
            }
        }
    }
}

async fn handle_connection(
    mut stream: tokio::net::TcpStream,
    agent: Arc<ProxmoxAgent>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut buffer = vec![0; 4096];
    let bytes_read = stream.read(&mut buffer).await?;

    if bytes_read == 0 {
        return Ok(());
    }

    // Parse simple HTTP-like request
    let request = String::from_utf8_lossy(&buffer[..bytes_read]);
    let lines: Vec<&str> = request.lines().collect();

    if lines.is_empty() {
        return Err("Empty request".into());
    }

    let request_line = lines[0];
    let parts: Vec<&str> = request_line.split_whitespace().collect();

    if parts.len() < 2 {
        return Err("Invalid request format".into());
    }

    let method = parts[0];
    let path = parts[1];

    // Find content length and body
    let mut content_length = 0;
    let mut body_start = 0;

    for (i, line) in lines.iter().enumerate() {
        if line.to_lowercase().starts_with("content-length:") {
            if let Some(len_str) = line.split(':').nth(1) {
                content_length = len_str.trim().parse().unwrap_or(0);
            }
        }
        if line.is_empty() {
            body_start = i + 1;
            break;
        }
    }

    let body = if content_length > 0 && body_start < lines.len() {
        let body_text = lines[body_start..].join("\n");
        body_text.as_bytes().to_vec()
    } else {
        Vec::new()
    };

    match method {
        "GET" | "POST" => match handle_api_request(agent.as_ref(), path, body).await {
            Ok(response_data) => {
                let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                        response_data.len()
                    );

                stream.write_all(response.as_bytes()).await?;
                stream.write_all(&response_data).await?;
            }
            Err(e) => {
                warn!("API request failed: {}", e);
                let error_response = format!(
                        "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
                        e.to_string().len(),
                        e
                    );
                stream.write_all(error_response.as_bytes()).await?;
            }
        },
        _ => {
            let error_response = "HTTP/1.1 405 Method Not Allowed\r\n\r\n";
            stream.write_all(error_response.as_bytes()).await?;
        }
    }

    stream.flush().await?;
    Ok(())
}

impl Clone for ProxmoxAgent {
    fn clone(&self) -> Self {
        Self {
            api_url: self.api_url.clone(),
            username: self.username.clone(),
            password: self.password.clone(),
            client: self.client.clone(),
        }
    }
}
