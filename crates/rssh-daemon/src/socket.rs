use crate::agent::Agent;
use nix::sys::socket::{getsockopt, sockopt};
use nix::unistd::{Gid, Uid};
use rssh_core::{Error, Result};

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{self, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

const DEFAULT_MESSAGE_LIMIT: usize = 1024 * 1024; // 1 MiB
const MAX_CONCURRENT_CLIENTS: usize = 64;
#[allow(dead_code)]
const SOCKET_BACKLOG: u32 = 128;

/// Socket server for the SSH agent
pub struct SocketServer {
    socket_path: Option<PathBuf>,
    agent: Arc<Agent>,
    owner_uid: Uid,
    shutdown_signal: Arc<tokio::sync::Notify>,
}

impl SocketServer {
    /// Create a new socket server with a path-based socket
    pub fn new(
        socket_path: PathBuf,
        agent: Arc<Agent>,
        shutdown_signal: Arc<tokio::sync::Notify>,
    ) -> Self {
        SocketServer {
            socket_path: Some(socket_path),
            agent,
            owner_uid: nix::unistd::getuid(),
            shutdown_signal,
        }
    }

    /// Create a socket server using a pre-created listener (e.g., from systemd)
    pub fn from_listener(agent: Arc<Agent>, shutdown_signal: Arc<tokio::sync::Notify>) -> Self {
        SocketServer {
            socket_path: None,
            agent,
            owner_uid: nix::unistd::getuid(),
            shutdown_signal,
        }
    }

    /// Create socket in /tmp/ssh-XXXXXX/agent.<pid> format
    pub fn create_temp_socket(
        agent: Arc<Agent>,
        shutdown_signal: Arc<tokio::sync::Notify>,
    ) -> Result<Self> {
        let pid = std::process::id();

        // Generate random directory name
        let rand_suffix: String = (0..6)
            .map(|_| {
                let n = rand::random::<u32>() % 62;
                match n {
                    0..=9 => (b'0' + n as u8) as char,
                    10..=35 => (b'A' + (n - 10) as u8) as char,
                    _ => (b'a' + (n - 36) as u8) as char,
                }
            })
            .collect();

        let dir_name = format!("ssh-{}", rand_suffix);
        let socket_dir = Path::new("/tmp").join(dir_name);

        // Create directory with 0700 permissions
        fs::create_dir(&socket_dir)?;
        fs::set_permissions(&socket_dir, fs::Permissions::from_mode(0o700))?;

        let socket_path = socket_dir.join(format!("agent.{}", pid));

        Ok(SocketServer::new(socket_path, agent, shutdown_signal))
    }

    /// Start the socket server with a path-based socket
    pub async fn run(&self) -> Result<()> {
        let socket_path = self.socket_path.as_ref().ok_or_else(|| {
            Error::Internal("Cannot run path-based server without socket path".into())
        })?;

        // Remove existing socket if it exists
        if socket_path.exists() {
            fs::remove_file(socket_path)?;
        }

        // Ensure parent directory exists
        if let Some(parent) = socket_path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)?;
                fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
            }
        }

        // Create the Unix socket
        let listener = UnixListener::bind(socket_path)?;

        // Set socket permissions to 0600
        fs::set_permissions(socket_path, fs::Permissions::from_mode(0o600))?;

        tracing::info!("Agent socket created at: {}", socket_path.display());

        self.serve(listener).await
    }

    /// Start the socket server with a pre-created listener
    pub async fn run_with_listener(&self, listener: UnixListener) -> Result<()> {
        tracing::info!("Using pre-created socket listener (systemd activation)");
        self.serve(listener).await
    }

    /// Common server logic for both path-based and pre-created listeners
    async fn serve(&self, listener: UnixListener) -> Result<()> {
        // Accept connections with atomic counter for proper connection tracking
        let client_count = Arc::new(atomic::AtomicUsize::new(0));

        tracing::info!("Socket server started, listening for connections");

        loop {
            tokio::select! {
                // Listen for incoming connections
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok((stream, _)) => {
                            // Check ACL
                            if !self.check_peer_access(&stream)? {
                                tracing::warn!("Rejected connection from unauthorized peer");
                                continue;
                            }

                            let current_count = client_count.load(Ordering::Relaxed);
                            if current_count >= MAX_CONCURRENT_CLIENTS {
                                tracing::warn!("Max concurrent clients reached ({})", current_count);
                                continue;
                            }

                            client_count.fetch_add(1, Ordering::Relaxed);
                            let agent = self.agent.clone();
                            let counter = client_count.clone();

                            tracing::debug!("Accepting new client connection (active: {})", current_count + 1);

                            // Handle client in a separate task
                            tokio::spawn(async move {
                                if let Err(e) = handle_client(stream, agent).await {
                                    tracing::error!("Client handler error: {}", e);
                                }
                                // Properly decrement the counter when client disconnects
                                counter.fetch_sub(1, Ordering::Relaxed);
                                tracing::debug!("Client disconnected");
                            });
                        }
                        Err(e) => {
                            tracing::error!("Failed to accept connection: {}", e);
                            return Err(e.into());
                        }
                    }
                }
                // Listen for shutdown signal
                _ = self.shutdown_signal.notified() => {
                    tracing::info!("Received shutdown signal, stopping socket server");
                    break;
                }
            }
        }

        // Wait a moment for active client connections to finish
        let active_clients = client_count.load(Ordering::Relaxed);
        if active_clients > 0 {
            tracing::info!(
                "Waiting for {} active client connections to finish",
                active_clients
            );
            // Give clients a brief moment to finish ongoing requests
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }

        tracing::info!("Socket server stopped gracefully");
        Ok(())
    }

    /// Check if the peer has access (same UID)
    fn check_peer_access(&self, stream: &UnixStream) -> Result<bool> {
        // Get peer credentials using SO_PEERCRED
        let cred = get_peer_credentials(stream)?;

        // Only allow same UID
        if cred.uid != self.owner_uid {
            tracing::warn!(
                "Access denied for UID {} (owner is {})",
                cred.uid,
                self.owner_uid
            );
            return Ok(false);
        }

        Ok(true)
    }

    /// Get the socket path (if available)
    pub fn socket_path(&self) -> Option<&Path> {
        self.socket_path.as_deref()
    }

    /// Clean up the socket (only for path-based sockets)
    pub fn cleanup(&self) -> Result<()> {
        if let Some(socket_path) = &self.socket_path {
            if socket_path.exists() {
                fs::remove_file(socket_path)?;
            }

            // Also try to remove the parent directory if it's empty
            if let Some(parent) = socket_path.parent() {
                let _ = fs::remove_dir(parent);
            }
        }
        // For systemd-activated sockets, cleanup is not our responsibility

        Ok(())
    }
}

impl Drop for SocketServer {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

/// Handle a client connection
async fn handle_client(mut stream: UnixStream, agent: Arc<Agent>) -> Result<()> {
    let mut buffer = vec![0u8; DEFAULT_MESSAGE_LIMIT + 4];

    loop {
        // Read message length
        match stream.read_exact(&mut buffer[..4]).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                // Client disconnected
                break;
            }
            Err(e) => return Err(e.into()),
        }

        let len = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;

        if len > DEFAULT_MESSAGE_LIMIT {
            tracing::warn!("Message too large: {} bytes", len);
            return Err(Error::Internal("Message too large".into()));
        }

        // Read message body
        stream.read_exact(&mut buffer[..len]).await?;

        // Process message
        let response = agent.handle_message(&buffer[..len]).await?;

        // Send response
        let response_len = response.len() as u32;
        stream.write_all(&response_len.to_be_bytes()).await?;
        stream.write_all(&response).await?;
        stream.flush().await?;
    }

    Ok(())
}

/// Peer credentials
#[derive(Debug)]
struct PeerCredentials {
    uid: Uid,
    #[allow(dead_code)]
    gid: Gid,
    #[allow(dead_code)]
    pid: i32,
}

/// Get peer credentials from a Unix socket
fn get_peer_credentials(stream: &UnixStream) -> Result<PeerCredentials> {
    // On Linux, use SO_PEERCRED
    #[cfg(target_os = "linux")]
    {
        let ucred = getsockopt(&stream, sockopt::PeerCredentials)
            .map_err(|e| Error::Io(std::io::Error::from(e)))?;

        Ok(PeerCredentials {
            uid: Uid::from_raw(ucred.uid()),
            gid: Gid::from_raw(ucred.gid()),
            pid: ucred.pid(),
        })
    }

    // On other Unix systems, we might need different approaches
    #[cfg(not(target_os = "linux"))]
    {
        // Fallback: just use current UID
        Ok(PeerCredentials {
            uid: nix::unistd::getuid(),
            gid: nix::unistd::getgid(),
            pid: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_socket_creation() {
        use rssh_core::config::Config;

        let temp_dir = TempDir::new().unwrap();
        let config = Config::new_with_sentinel(temp_dir.path(), "test_password_12345").unwrap();
        let agent = Arc::new(Agent::new(config).await);
        let socket_path = temp_dir.path().join("test.sock");
        let shutdown_signal = Arc::new(tokio::sync::Notify::new());

        let server = SocketServer::new(socket_path.clone(), agent, shutdown_signal);
        assert_eq!(server.socket_path(), Some(socket_path.as_path()));

        // Cleanup should work even if socket doesn't exist
        assert!(server.cleanup().is_ok());
    }

    #[tokio::test]
    async fn test_temp_socket_creation() {
        use rssh_core::config::Config;

        let temp_dir = TempDir::new().unwrap();
        let config = Config::new_with_sentinel(temp_dir.path(), "test_password_12345").unwrap();
        let agent = Arc::new(Agent::new(config).await);
        let shutdown_signal = Arc::new(tokio::sync::Notify::new());
        let server = SocketServer::create_temp_socket(agent, shutdown_signal).unwrap();

        let path = server
            .socket_path()
            .expect("Temp socket should have a path");
        assert!(path.to_str().unwrap().contains("/tmp/ssh-"));
        assert!(path.to_str().unwrap().contains("/agent."));

        // Parent directory should exist with correct permissions
        let parent = path.parent().unwrap();
        assert!(parent.exists());
        let metadata = fs::metadata(parent).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);

        // Cleanup
        server.cleanup().unwrap();
        assert!(!parent.exists());
    }

    #[tokio::test]
    async fn test_socket_with_missing_parent_directory() {
        use rssh_core::config::Config;

        let temp_dir = TempDir::new().unwrap();
        let config = Config::new_with_sentinel(temp_dir.path(), "test_password_12345").unwrap();
        let agent = Arc::new(Agent::new(config).await);
        let shutdown_signal = Arc::new(tokio::sync::Notify::new());

        // Create a socket path with a non-existent parent directory
        let socket_path = temp_dir.path().join("nonexistent_dir").join("test.sock");
        assert!(!socket_path.parent().unwrap().exists());

        let server = SocketServer::new(socket_path.clone(), agent, shutdown_signal);

        // This should succeed now (previously would fail)
        // Start server in background task since run() blocks
        let server_handle = tokio::spawn(async move { server.run().await });

        // Give it a moment to start up
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        // Verify parent directory was created with correct permissions
        let parent = socket_path.parent().unwrap();
        assert!(parent.exists());
        let metadata = fs::metadata(parent).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);

        // Verify socket was created
        assert!(socket_path.exists());
        let socket_metadata = fs::metadata(&socket_path).unwrap();
        assert_eq!(socket_metadata.permissions().mode() & 0o777, 0o600);

        // Clean up
        server_handle.abort();
        let _ = fs::remove_file(&socket_path);
        let _ = fs::remove_dir(parent);
    }
}
