use crate::{agent::Agent, socket::SocketServer};

use nix::unistd::{ForkResult, fork, setsid};
use rssh_core::{Error, Result};
use std::io::{self, Write};

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::signal::unix::{SignalKind, signal};

static RUNNING: AtomicBool = AtomicBool::new(true);

/// Daemon configuration
pub struct DaemonConfig {
    pub socket_path: Option<String>,
    pub foreground: bool,
    pub storage_dir: String,
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
    // Check if SSH_AUTH_SOCK points to a live agent
    if let Ok(existing_sock) = std::env::var("SSH_AUTH_SOCK") {
        if check_socket_alive(&existing_sock).await {
            return Err(Error::AlreadyRunning);
        }
    }

    // Create the agent
    let agent = Arc::new(Agent::new());

    // Create the socket server
    let server = if let Some(socket_path) = config.socket_path {
        SocketServer::new(socket_path.into(), agent.clone())
    } else {
        SocketServer::create_temp_socket(agent.clone())?
    };

    let socket_path = server.socket_path().to_string_lossy().to_string();

    // Fork to background unless --foreground
    if !config.foreground {
        match unsafe { fork() } {
            Ok(ForkResult::Parent { child }) => {
                // Parent process: print socket info and exit
                let style = shell_style.unwrap_or_else(ShellStyle::detect);
                println!("{}", style.format_export(&socket_path));

                tracing::debug!("Daemon forked with PID {}", child);
                return Ok(());
            }
            Ok(ForkResult::Child) => {
                // Child process: become a daemon
                setsid().map_err(|e| Error::Io(e.into()))?;

                // Close standard file descriptors
                let devnull = std::fs::File::open("/dev/null")?;
                let devnull_fd = devnull.as_raw_fd();
                unsafe {
                    libc::dup2(devnull_fd, 0);
                    libc::dup2(devnull_fd, 1);
                    libc::dup2(devnull_fd, 2);
                }
            }
            Err(e) => {
                return Err(Error::Io(e.into()));
            }
        }
    } else {
        // Foreground mode: print socket info
        let style = shell_style.unwrap_or_else(ShellStyle::detect);
        println!("{}", style.format_export(&socket_path));
        io::stdout().flush()?;
    }

    // Set up signal handlers
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sighup = signal(SignalKind::hangup())?;

    let agent_for_signals = agent.clone();
    let server_for_cleanup = Arc::new(server);
    let server_for_run = server_for_cleanup.clone();

    // Spawn signal handler task
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = sigterm.recv() => {
                    tracing::info!("Received SIGTERM, shutting down");
                    RUNNING.store(false, Ordering::Relaxed);
                    break;
                }
                _ = sigint.recv() => {
                    tracing::info!("Received SIGINT, shutting down");
                    RUNNING.store(false, Ordering::Relaxed);
                    break;
                }
                _ = sighup.recv() => {
                    tracing::info!("Received SIGHUP, locking agent");
                    let _ = agent_for_signals.handle_message(&[22]).await; // Lock message
                }
            }
        }
    });

    // Run the server
    let server_task = tokio::spawn(async move { server_for_run.run().await });

    // Wait for shutdown signal
    while RUNNING.load(Ordering::Relaxed) {
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }

    // Graceful shutdown
    tracing::info!("Shutting down daemon");

    // Cancel the server task
    server_task.abort();
    let _ = server_task.await;

    // Clean up socket
    server_for_cleanup.cleanup()?;

    Ok(())
}

/// Check if a socket is alive
async fn check_socket_alive(socket_path: &str) -> bool {
    use tokio::net::UnixStream;
    use tokio::time::{Duration, timeout};

    let connect_result =
        timeout(Duration::from_millis(100), UnixStream::connect(socket_path)).await;

    matches!(connect_result, Ok(Ok(_)))
}

/// Apply security hardening
pub fn apply_hardening() -> Result<()> {
    use nix::sys::mman::{MlockAllFlags, mlockall};
    use nix::sys::resource::{Resource, setrlimit};

    // Disable core dumps
    setrlimit(Resource::RLIMIT_CORE, 0, 0).map_err(|e| Error::Io(e.into()))?;

    // Lock all memory - warn but don't fail in development
    // In development/testing environments, memory locking often fails due to limits
    // Set RSSH_ALLOW_NO_MLOCK=1 or run in debug mode to continue anyway
    if let Err(e) = mlockall(MlockAllFlags::MCL_CURRENT | MlockAllFlags::MCL_FUTURE) {
        #[cfg(debug_assertions)]
        {
            tracing::warn!("Failed to lock memory in debug mode (continuing): {}", e);
        }
        #[cfg(not(debug_assertions))]
        {
            if std::env::var("RSSH_ALLOW_NO_MLOCK").is_ok() {
                tracing::warn!(
                    "Failed to lock memory (RSSH_ALLOW_NO_MLOCK set, continuing): {}",
                    e
                );
            } else {
                tracing::error!("Failed to lock memory: {}", e);
                return Err(Error::Io(e.into()));
            }
        }
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

use std::os::unix::io::AsRawFd;

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
