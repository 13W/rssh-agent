//! Optimized socket server with improved async performance (simplified version)
//!
//! This module provides performance improvements for the SSH agent socket server:
//! - Optimized I/O buffering
//! - Better async task management
//! - Connection tracking

use crate::agent::Agent;
use rssh_core::{Error, Result};
// use std::collections::HashMap; // Unused import
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use std::os::unix::fs::PermissionsExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::{UnixListener, UnixStream};
// use tokio::sync::RwLock; // Unused import

const OPTIMIZED_MESSAGE_LIMIT: usize = 2 * 1024 * 1024; // 2 MiB
const BUFFER_SIZE: usize = 8192; // Optimized buffer size

/// Performance statistics for monitoring
pub struct ConnectionStats {
    pub total_connections: AtomicU64,
    pub active_connections: AtomicU64,
    pub total_requests: AtomicU64,
    pub average_response_time_ms: AtomicU64,
}

/// Optimized client handler with buffered I/O
pub async fn handle_client_optimized(
    stream: UnixStream,
    agent: Arc<Agent>,
    stats: Arc<ConnectionStats>,
) -> Result<()> {
    stats.total_connections.fetch_add(1, Ordering::Relaxed);
    stats.active_connections.fetch_add(1, Ordering::Relaxed);
    
    // Use buffered I/O for better performance
    let (read_half, write_half) = stream.into_split();
    let mut reader = BufReader::with_capacity(BUFFER_SIZE, read_half);
    let mut writer = BufWriter::with_capacity(BUFFER_SIZE, write_half);

    // Message processing buffer - reuse to avoid allocations
    let mut message_buffer = Vec::with_capacity(4096);
    let mut response_times = Vec::with_capacity(16); // For average calculation

    loop {
        // Read message length (4 bytes, big-endian)
        let mut length_bytes = [0u8; 4];
        match reader.read_exact(&mut length_bytes).await {
            Ok(_) => {}
            Err(e) if e.kind() == tokio::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(Error::Io(e)),
        }

        let message_length = u32::from_be_bytes(length_bytes) as usize;
        if message_length == 0 || message_length > OPTIMIZED_MESSAGE_LIMIT {
            tracing::warn!("Invalid message length: {}", message_length);
            break;
        }

        // Reuse buffer, expanding if necessary
        message_buffer.clear();
        message_buffer.reserve(message_length);
        message_buffer.resize(message_length, 0);

        // Read message data
        if let Err(e) = reader.read_exact(&mut message_buffer).await {
            tracing::error!("Failed to read message: {}", e);
            break;
        }

        // Process message with timing
        let request_start = Instant::now();
        let response = match agent.handle_message(&message_buffer).await {
            Ok(resp) => resp,
            Err(e) => {
                tracing::error!("Message handling error: {}", e);
                break;
            }
        };
        let request_duration = request_start.elapsed();
        response_times.push(request_duration.as_millis() as u64);

        // Write response
        let response_length = response.len() as u32;
        if let Err(e) = writer.write_all(&response_length.to_be_bytes()).await {
            tracing::error!("Failed to write response length: {}", e);
            break;
        }

        if let Err(e) = writer.write_all(&response).await {
            tracing::error!("Failed to write response: {}", e);
            break;
        }

        if let Err(e) = writer.flush().await {
            tracing::error!("Failed to flush response: {}", e);
            break;
        }

        stats.total_requests.fetch_add(1, Ordering::Relaxed);
    }

    // Update average response time before connection closes
    if !response_times.is_empty() {
        let avg_time = response_times.iter().sum::<u64>() / response_times.len() as u64;
        stats.average_response_time_ms.store(avg_time, Ordering::Relaxed);
    }

    stats.active_connections.fetch_sub(1, Ordering::Relaxed);
    Ok(())
}

/// Optimized socket server with performance improvements
pub struct OptimizedSocketServer {
    socket_path: std::path::PathBuf,
    agent: Arc<Agent>,
    stats: Arc<ConnectionStats>,
}

impl OptimizedSocketServer {
    pub fn new(socket_path: std::path::PathBuf, agent: Arc<Agent>) -> Self {
        Self {
            socket_path,
            agent,
            stats: Arc::new(ConnectionStats {
                total_connections: AtomicU64::new(0),
                active_connections: AtomicU64::new(0),
                total_requests: AtomicU64::new(0),
                average_response_time_ms: AtomicU64::new(0),
            }),
        }
    }

    pub async fn run(&self) -> Result<()> {
        // Remove existing socket if it exists
        if self.socket_path.exists() {
            std::fs::remove_file(&self.socket_path)?;
        }

        // Create Unix socket listener
        let listener = UnixListener::bind(&self.socket_path)?;
        
        // Set socket permissions
        std::fs::set_permissions(&self.socket_path, std::fs::Permissions::from_mode(0o600))?;
        
        tracing::info!("Optimized agent socket listening at: {}", self.socket_path.display());

        // Start stats logging task
        let stats_clone = self.stats.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                
                // Log stats periodically
                tracing::debug!(
                    "Connection stats: active={}, total={}, requests={}, avg_response_ms={}",
                    stats_clone.active_connections.load(Ordering::Relaxed),
                    stats_clone.total_connections.load(Ordering::Relaxed),
                    stats_clone.total_requests.load(Ordering::Relaxed),
                    stats_clone.average_response_time_ms.load(Ordering::Relaxed)
                );
            }
        });

        // Accept connections
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let agent = self.agent.clone();
                    let stats = self.stats.clone();
                    
                    tokio::spawn(async move {
                        if let Err(e) = handle_client_optimized(stream, agent, stats).await {
                            tracing::error!("Optimized client handler error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    tracing::error!("Failed to accept connection: {}", e);
                    break;
                }
            }
        }

        Ok(())
    }

    pub fn get_performance_stats(&self) -> &ConnectionStats {
        &self.stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_stats() {
        let stats = ConnectionStats {
            total_connections: AtomicU64::new(0),
            active_connections: AtomicU64::new(0),
            total_requests: AtomicU64::new(0),
            average_response_time_ms: AtomicU64::new(0),
        };
        
        stats.total_connections.fetch_add(1, Ordering::Relaxed);
        assert_eq!(stats.total_connections.load(Ordering::Relaxed), 1);
    }
}
