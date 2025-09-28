use crate::{data::HashId, Result, CHUNK_MAX_SIZE, CHUNK_MIN_SIZE, CHUNK_NORMAL_SIZE};
use fastcdc::v2020::FastCDC;
use std::io::Read;
use tokio::io::{AsyncRead, AsyncReadExt};

#[derive(Debug, Clone)]
pub struct Chunker {
    min_size: usize,
    max_size: usize,
    normal_size: usize,
}

impl Chunker {
    pub fn new() -> Self {
        Self {
            min_size: CHUNK_MIN_SIZE,
            max_size: CHUNK_MAX_SIZE,
            normal_size: CHUNK_NORMAL_SIZE,
        }
    }

    pub fn with_sizes(min_size: usize, normal_size: usize, max_size: usize) -> Self {
        Self {
            min_size,
            max_size,
            normal_size,
        }
    }

    pub fn chunk_data(&self, data: &[u8]) -> Vec<(HashId, Vec<u8>)> {
        if data.is_empty() {
            return Vec::new();
        }

        let mut chunks = Vec::new();
        let chunker = FastCDC::new(
            data,
            self.min_size as u32,
            self.normal_size as u32,
            self.max_size as u32,
        );

        for chunk in chunker {
            let chunk_data = data[chunk.offset..chunk.offset + chunk.length].to_vec();
            let hash = HashId::new(&chunk_data);
            chunks.push((hash, chunk_data));
        }

        chunks
    }

    pub async fn chunk_async_reader<R>(&self, mut reader: R) -> Result<Vec<(HashId, Vec<u8>)>>
    where
        R: AsyncRead + Unpin,
    {
        let mut buffer = Vec::new();
        reader.read_to_end(&mut buffer).await?;
        Ok(self.chunk_data(&buffer))
    }

    pub fn chunk_reader<R>(&self, mut reader: R) -> Result<Vec<(HashId, Vec<u8>)>>
    where
        R: Read,
    {
        let mut buffer = Vec::new();
        reader.read_to_end(&mut buffer)?;
        Ok(self.chunk_data(&buffer))
    }
}

impl Default for Chunker {
    fn default() -> Self {
        Self::new()
    }
}

pub fn calculate_hash(data: &[u8]) -> HashId {
    HashId::new(data)
}

pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB", "PB"];
    let mut size = bytes as f64;
    let mut unit_index = 0;

    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }

    if unit_index == 0 {
        format!("{} {}", bytes, UNITS[unit_index])
    } else {
        format!("{:.2} {}", size, UNITS[unit_index])
    }
}

pub fn format_duration(duration: std::time::Duration) -> String {
    let total_seconds = duration.as_secs();

    if total_seconds < 60 {
        format!("{}s", total_seconds)
    } else if total_seconds < 3600 {
        let minutes = total_seconds / 60;
        let seconds = total_seconds % 60;
        format!("{}m{}s", minutes, seconds)
    } else {
        let hours = total_seconds / 3600;
        let minutes = (total_seconds % 3600) / 60;
        let seconds = total_seconds % 60;
        format!("{}h{}m{}s", hours, minutes, seconds)
    }
}

pub fn estimate_eta(
    processed: u64,
    total: u64,
    elapsed: std::time::Duration,
) -> Option<std::time::Duration> {
    if processed == 0 || elapsed.is_zero() {
        return None;
    }

    let rate = processed as f64 / elapsed.as_secs_f64();
    if rate <= 0.0 {
        return None;
    }

    let remaining = total.saturating_sub(processed);
    let eta_seconds = (remaining as f64 / rate) as u64;
    Some(std::time::Duration::from_secs(eta_seconds))
}

pub fn calculate_transfer_rate(bytes: u64, duration: std::time::Duration) -> f64 {
    if duration.is_zero() {
        return 0.0;
    }
    bytes as f64 / duration.as_secs_f64()
}

pub fn format_transfer_rate(rate: f64) -> String {
    format_bytes(rate as u64) + "/s"
}

pub fn sanitize_filename(filename: &str) -> String {
    filename
        .chars()
        .map(|c| match c {
            '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            c if c.is_control() => '_',
            c => c,
        })
        .collect()
}

pub fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}

#[derive(Debug, Clone)]
pub struct ProgressTracker {
    pub processed_files: u64,
    pub total_files: u64,
    pub processed_bytes: u64,
    pub total_bytes: u64,
    pub current_file: Option<String>,
    pub start_time: std::time::Instant,
}

impl ProgressTracker {
    pub fn new(total_files: u64, total_bytes: u64) -> Self {
        Self {
            processed_files: 0,
            total_files,
            processed_bytes: 0,
            total_bytes,
            current_file: None,
            start_time: std::time::Instant::now(),
        }
    }

    pub fn update_file(&mut self, filename: String, file_size: u64) {
        self.current_file = Some(filename);
        self.processed_files += 1;
        self.processed_bytes += file_size;
    }

    pub fn update_bytes(&mut self, bytes: u64) {
        self.processed_bytes += bytes;
    }

    pub fn elapsed(&self) -> std::time::Duration {
        self.start_time.elapsed()
    }

    pub fn eta(&self) -> Option<std::time::Duration> {
        estimate_eta(self.processed_bytes, self.total_bytes, self.elapsed())
    }

    pub fn transfer_rate(&self) -> f64 {
        calculate_transfer_rate(self.processed_bytes, self.elapsed())
    }

    pub fn progress_ratio(&self) -> f64 {
        if self.total_bytes == 0 {
            0.0
        } else {
            self.processed_bytes as f64 / self.total_bytes as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunker() {
        let data = vec![0u8; 2 * 1024 * 1024]; // 2MB of zeros
        let chunker = Chunker::new();
        let chunks = chunker.chunk_data(&data);

        assert!(!chunks.is_empty());

        // Verify all chunk data combined equals original
        let combined: Vec<u8> = chunks.iter().flat_map(|(_, data)| data).cloned().collect();
        assert_eq!(combined, data);

        // Verify hash consistency
        for (hash, chunk_data) in &chunks {
            assert_eq!(*hash, HashId::new(chunk_data));
        }
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1536), "1.50 KB");
        assert_eq!(format_bytes(1024 * 1024), "1.00 MB");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.00 GB");
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(std::time::Duration::from_secs(30)), "30s");
        assert_eq!(format_duration(std::time::Duration::from_secs(90)), "1m30s");
        assert_eq!(
            format_duration(std::time::Duration::from_secs(3661)),
            "1h1m1s"
        );
    }

    #[test]
    fn test_sanitize_filename() {
        assert_eq!(sanitize_filename("normal_file.txt"), "normal_file.txt");
        assert_eq!(
            sanitize_filename("file/with\\bad:chars"),
            "file_with_bad_chars"
        );
        assert_eq!(sanitize_filename("file<>|?*.txt"), "file_____.txt");
    }

    #[test]
    fn test_progress_tracker() {
        let mut tracker = ProgressTracker::new(10, 1000);

        assert_eq!(tracker.processed_files, 0);
        assert_eq!(tracker.processed_bytes, 0);
        assert_eq!(tracker.progress_ratio(), 0.0);

        tracker.update_file("test.txt".to_string(), 100);
        assert_eq!(tracker.processed_files, 1);
        assert_eq!(tracker.processed_bytes, 100);
        assert_eq!(tracker.progress_ratio(), 0.1);

        tracker.update_bytes(400);
        assert_eq!(tracker.processed_bytes, 500);
        assert_eq!(tracker.progress_ratio(), 0.5);
    }
}
