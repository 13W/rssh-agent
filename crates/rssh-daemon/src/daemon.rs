use crate::{agent::Agent, socket::SocketServer, systemd};

use rssh_core::{Error, Result};
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::signal::unix::{SignalKind, signal};

static RUNNING: AtomicBool = AtomicBool::new(true);

/// Daemon configuration
pub struct DaemonConfig {
    pub socket_path: Option<String>,
    pub foreground: bool,
    pub storage_dir: String,
    pub config: rssh_core::config::Config,
    pub require_mlock: bool,
}

/// Shell output style
#[derive(Debug, Clone, Copy)]
pub enum ShellStyle {
    Sh,   // sh/bash/zsh
    Csh,  // csh/tcsh
    Fish, // fish
}

impl ShellStyle {
    /// Detect shell style from SHELL environment variable
    pub fn detect() -> Self {
        if let Ok(shell) = std::env::var("SHELL") {
            if shell.contains("fish") {
                return ShellStyle::Fish;
            } else if shell.contains("csh") || shell.contains("tcsh") {
                return ShellStyle::Csh;
            }
        }
        ShellStyle::Sh
    }

    /// Format the environment variable export
    pub fn format_export(&self, socket_path: &str) -> String {
        match self {
            ShellStyle::Sh => {
                format!("SSH_AUTH_SOCK=\"{}\"; export SSH_AUTH_SOCK;", socket_path)
            }
            ShellStyle::Csh => {
                format!("setenv SSH_AUTH_SOCK \"{}\";", socket_path)
            }
            ShellStyle::Fish => {
                format!("set -gx SSH_AUTH_SOCK \"{}\";", socket_path)
            }
        }
    }
}

/// Run the daemon
pub async fn run_daemon(config: DaemonConfig, shell_style: Option<ShellStyle>) -> Result<()> {
    // Create shutdown signal that will be shared between agent and signal handlers
    let shutdown_signal = Arc::new(tokio::sync::Notify::new());

    // Create the agent with storage directory and shutdown signal
    let agent = Arc::new(
        Agent::with_storage_dir_and_shutdown(
            config.storage_dir.clone(),
            config.config.clone(),
            shutdown_signal.clone(),
        )
        .await,
    );

    // Create socket server
    tracing::info!(
        "Creating socket server with config: socket_path={:?}, foreground={}",
        config.socket_path,
        config.foreground
    );
    let (server, socket_path, systemd_listener) = if systemd::is_systemd_activated() {
        tracing::info!("Detected systemd socket activation");
        let listener = systemd::take_systemd_socket()?;
        let server = SocketServer::from_listener(agent.clone(), shutdown_signal.clone());
        (
            server,
            String::from("systemd-activated-socket"),
            Some(listener),
        )
    } else if let Some(socket_path) = config.socket_path {
        // For socket paths, ensure the directory exists
        let socket_path_buf = std::path::PathBuf::from(&socket_path);
        tracing::info!("Processing socket path: {}", socket_path);
        if let Some(parent_dir) = socket_path_buf.parent() {
            tracing::info!("Parent directory: {}", parent_dir.display());
            if !parent_dir.exists() {
                tracing::info!("Parent directory does not exist, creating it");
                // Check if this looks like a temp socket directory (ssh-XXXXXX pattern)
                if let Some(dir_name) = parent_dir.file_name() {
                    if let Some(dir_str) = dir_name.to_str() {
                        tracing::info!("Directory name: '{}', length: {}", dir_str, dir_str.len());
                        if dir_str.starts_with("ssh-") && dir_str.len() == 10 {
                            // This is a temp directory - create it with proper permissions
                            tracing::info!(
                                "Creating temp socket directory: {}",
                                parent_dir.display()
                            );
                            std::fs::create_dir_all(parent_dir)?;
                            std::fs::set_permissions(
                                parent_dir,
                                std::fs::Permissions::from_mode(0o700),
                            )?;
                            tracing::info!(
                                "Successfully created temp socket directory: {}",
                                parent_dir.display()
                            );
                        } else {
                            // Regular directory path
                            tracing::info!("Creating regular directory: {}", parent_dir.display());
                            std::fs::create_dir_all(parent_dir)?;
                            std::fs::set_permissions(
                                parent_dir,
                                std::fs::Permissions::from_mode(0o700),
                            )?;
                        }
                    } else {
                        tracing::warn!("Could not convert directory name to string");
                    }
                } else {
                    tracing::info!("No directory name found, creating regular directory");
                    // Regular directory path
                    std::fs::create_dir_all(parent_dir)?;
                    std::fs::set_permissions(parent_dir, std::fs::Permissions::from_mode(0o700))?;
                }
            } else {
                tracing::info!("Parent directory already exists: {}", parent_dir.display());
            }
        } else {
            tracing::warn!("No parent directory found for socket path: {}", socket_path);
        }
        let server = SocketServer::new(
            socket_path.clone().into(),
            agent.clone(),
            shutdown_signal.clone(),
        );
        (server, socket_path, None)
    } else {
        // No socket path provided, create temp socket
        let server = SocketServer::create_temp_socket(agent.clone(), shutdown_signal.clone())?;
        let path = server
            .socket_path()
            .expect("Temp socket should have path")
            .to_string_lossy()
            .to_string();
        (server, path, None)
    };

    // Print socket info if in foreground mode and not systemd activated
    if config.foreground && systemd_listener.is_none() {
        let style = shell_style.unwrap_or_else(ShellStyle::detect);
        println!("{}", style.format_export(&socket_path));
        io::stdout().flush()?;
    }

    // Apply security hardening
    apply_hardening(config.require_mlock)?;

    // Set up signal handlers
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sighup = signal(SignalKind::hangup())?;

    let agent_for_signals = agent.clone();
    let server_for_cleanup: Arc<SocketServer> = Arc::new(server);
    let server_for_run = server_for_cleanup.clone();

    // Spawn signal handler task
    let shutdown_signal_clone = shutdown_signal.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = sigterm.recv() => {
                    tracing::info!("Received SIGTERM, initiating graceful shutdown");
                    if let Err(e) = agent_for_signals.shutdown().await {
                        tracing::error!("Failed to shutdown agent cleanly: {}", e);
                    }
                    RUNNING.store(false, Ordering::Relaxed);
                    shutdown_signal_clone.notify_one();
                    break;
                }
                _ = sigint.recv() => {
                    tracing::info!("Received SIGINT (Ctrl+C), initiating graceful shutdown");
                    if let Err(e) = agent_for_signals.shutdown().await {
                        tracing::error!("Failed to shutdown agent cleanly: {}", e);
                    }
                    RUNNING.store(false, Ordering::Relaxed);
                    shutdown_signal_clone.notify_one();
                    break;
                }
                _ = sighup.recv() => {
                    tracing::info!("Received SIGHUP, locking agent");
                    agent_for_signals.lock_directly().await;
                    tracing::info!("Agent locked due to SIGHUP");
                }
            }
        }
    });

    // Run the server
    let server_task = if let Some(listener) = systemd_listener {
        tokio::spawn(async move { server_for_run.run_with_listener(listener).await })
    } else {
        tokio::spawn(async move { server_for_run.run().await })
    };

    // Wait for shutdown signal or server completion
    tokio::select! {
        _ = shutdown_signal.notified() => {
            tracing::info!("Shutdown signal received, stopping server");
        }
        result = server_task => {
            match result {
                Ok(Ok(())) => {
                    tracing::info!("Server task completed successfully");
                }
                Ok(Err(e)) => {
                    tracing::error!("Server task failed: {}", e);
                }
                Err(e) => {
                    tracing::error!("Server task panicked: {}", e);
                }
            }
        }
    }

    // Graceful shutdown sequence
    tracing::info!("Starting graceful shutdown sequence");
    RUNNING.store(false, Ordering::Relaxed);
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    if let Err(e) = server_for_cleanup.cleanup() {
        tracing::warn!("Failed to cleanup socket: {}", e);
    } else {
        tracing::debug!("Socket cleaned up successfully");
    }

    tracing::info!("Daemon shutdown completed");
    Ok(())
}

/// Apply security hardening
pub fn apply_hardening(require_mlock: bool) -> Result<()> {
    use nix::sys::mman::{MlockAllFlags, mlockall};
    use nix::sys::resource::{Resource, setrlimit};

    // Disable core dumps
    setrlimit(Resource::RLIMIT_CORE, 0, 0).map_err(|e| Error::Io(e.into()))?;

    // Try to lock all current and future memory pages
    // Note: This requires sufficient memlock limits (check with `ulimit -l`)
    // Typical Rust binaries have large virtual memory due to thread stacks (1GB+)
    if let Err(e) = mlockall(MlockAllFlags::MCL_CURRENT | MlockAllFlags::MCL_FUTURE) {
        if require_mlock {
            // User explicitly requested strict memory locking
            tracing::error!(
                "Failed to lock memory: {}. \n\
                To fix this, increase your memory lock limit:\n\
                  Temporary: ulimit -l unlimited\n\
                  Permanent: Add to /etc/security/limits.conf:\n\
                    * soft memlock unlimited\n\
                    * hard memlock unlimited\n\
                Or run without --require-mlock flag",
                e
            );
            return Err(Error::Io(e.into()));
        } else {
            // Default behavior: warn but continue
            tracing::warn!(
                "Memory locking failed ({}), continuing without it. \
                Keys are still encrypted in RAM. \
                Use --require-mlock to enforce memory locking.",
                e
            );
        }
    } else {
        tracing::info!("Memory locked successfully");
    }

    // Set process as non-dumpable
    #[cfg(target_os = "linux")]
    {
        unsafe {
            if libc::prctl(libc::PR_SET_DUMPABLE, 0) != 0 {
                let err = std::io::Error::last_os_error();
                // PR_SET_DUMPABLE may fail in some environments
                // Allow continuing with a warning as it's not critical for testing
                tracing::warn!("Failed to set PR_SET_DUMPABLE (continuing): {}", err);
            }
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1) != 0 {
                let err = std::io::Error::last_os_error();
                // PR_SET_NO_NEW_PRIVS may fail in containers or restricted environments
                // Allow continuing with a warning as it's not critical for testing
                tracing::warn!("Failed to set PR_SET_NO_NEW_PRIVS (continuing): {}", err);
            }
        }
    }

    tracing::info!("Security hardening applied");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shell_style_format() {
        let socket = "/tmp/test.sock";

        assert_eq!(
            ShellStyle::Sh.format_export(socket),
            "SSH_AUTH_SOCK=\"/tmp/test.sock\"; export SSH_AUTH_SOCK;"
        );

        assert_eq!(
            ShellStyle::Csh.format_export(socket),
            "setenv SSH_AUTH_SOCK \"/tmp/test.sock\";"
        );

        assert_eq!(
            ShellStyle::Fish.format_export(socket),
            "set -gx SSH_AUTH_SOCK \"/tmp/test.sock\";"
        );
    }

    #[test]
    fn test_shell_detection() {
        unsafe {
            std::env::set_var("SHELL", "/bin/bash");
        }
        assert!(matches!(ShellStyle::detect(), ShellStyle::Sh));

        unsafe {
            std::env::set_var("SHELL", "/usr/bin/fish");
        }
        assert!(matches!(ShellStyle::detect(), ShellStyle::Fish));

        unsafe {
            std::env::set_var("SHELL", "/bin/tcsh");
        }
        assert!(matches!(ShellStyle::detect(), ShellStyle::Csh));
    }
}
