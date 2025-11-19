use rand;
use rssh_core::{Result, config::Config};
use rssh_daemon::daemon::{DaemonConfig, ShellStyle, run_daemon};
use std::path::PathBuf;

pub struct DaemonCommand;

impl DaemonCommand {
    pub async fn execute(
        sh: bool,
        csh: bool,
        fish: bool,
        socket: Option<String>,
        foreground: bool,
        require_mlock: bool,
        storage_dir: Option<String>,
    ) -> Result<()> {
        // Determine storage directory
        let storage_dir = resolve_storage_dir(storage_dir)?;

        // Check that agent is initialized
        let config_path = storage_dir.join("config.json");
        if !config_path.exists() {
            return Err(rssh_core::Error::NotInitialized);
        }

        // Load config to verify it's valid
        let config_json = std::fs::read_to_string(&config_path)?;
        let config: Config = serde_json::from_str(&config_json)?;

        // Determine shell style
        let shell_style = if sh {
            Some(ShellStyle::Sh)
        } else if csh {
            Some(ShellStyle::Csh)
        } else if fish {
            Some(ShellStyle::Fish)
        } else {
            None // Auto-detect
        };

        // Handle forking at CLI level if not in foreground mode
        if !foreground {
            return Self::handle_daemon_fork(
                socket,
                storage_dir,
                config,
                shell_style,
                require_mlock,
            )
            .await;
        }

        // Foreground mode: create daemon config and run normally
        let daemon_config = DaemonConfig {
            socket_path: socket,
            foreground: true,
            storage_dir: storage_dir.to_string_lossy().to_string(),
            config,
            require_mlock,
        };

        run_daemon(daemon_config, shell_style).await
    }

    async fn handle_daemon_fork(
        socket: Option<String>,
        storage_dir: std::path::PathBuf,
        config: Config,
        shell_style: Option<ShellStyle>,
        require_mlock: bool,
    ) -> Result<()> {
        use nix::unistd::{ForkResult, fork, setsid};
        use std::os::unix::io::AsRawFd;

        // For background mode, we need to generate the socket path but NOT create the directory yet
        // The child process will handle directory creation to avoid race conditions
        let socket_path = if let Some(socket_path) = socket {
            socket_path
        } else {
            // Generate temp socket path (directory creation will happen in child process)
            let pid = std::process::id();
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
            let socket_dir = std::path::Path::new("/tmp").join(dir_name);
            let socket_path = socket_dir.join(format!("agent.{}", pid));
            socket_path.to_string_lossy().to_string()
        };

        // Fork before entering async context
        match unsafe { fork() } {
            Ok(ForkResult::Parent { child }) => {
                // Parent process: print socket info and exit
                let style = shell_style.unwrap_or_else(ShellStyle::detect);
                println!("{}", style.format_export(&socket_path));
                tracing::debug!("Daemon forked with PID {}", child);
                Ok(())
            }
            Ok(ForkResult::Child) => {
                // Child process: become daemon and run in new runtime

                // Become session leader
                setsid().map_err(|e| rssh_core::Error::Io(e.into()))?;

                // Redirect stdout/stderr to a temporary log file for debugging
                let log_file = std::fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open("/tmp/rssh-daemon-debug.log")?;
                let log_fd = log_file.as_raw_fd();

                let devnull = std::fs::File::open("/dev/null")?;
                let devnull_fd = devnull.as_raw_fd();
                unsafe {
                    libc::dup2(devnull_fd, 0); // Close stdin
                    libc::dup2(log_fd, 1); // Redirect stdout to log file
                    libc::dup2(log_fd, 2); // Redirect stderr to log file
                }

                // Create fresh Tokio runtime for child process
                let rt = tokio::runtime::Runtime::new().map_err(|e| {
                    rssh_core::Error::Internal(format!("Failed to create runtime: {}", e))
                })?;

                rt.block_on(async {
                    let daemon_config = DaemonConfig {
                        socket_path: Some(socket_path),
                        foreground: false, // Child runs in background
                        storage_dir: storage_dir.to_string_lossy().to_string(),
                        config,
                        require_mlock,
                    };

                    run_daemon(daemon_config, None).await
                })
            }
            Err(e) => Err(rssh_core::Error::Io(e.into())),
        }
    }
}

fn resolve_storage_dir(dir: Option<String>) -> Result<PathBuf> {
    if let Some(d) = dir {
        Ok(expand_path(&d)?)
    } else if let Ok(env_dir) = std::env::var("RSSH_STORAGE_DIR") {
        Ok(expand_path(&env_dir)?)
    } else {
        // Try to find existing config
        let default_path = default_storage_dir()?;
        if default_path.join("config.json").exists() {
            Ok(default_path)
        } else {
            // Look for any initialized directory
            Ok(default_path)
        }
    }
}

fn default_storage_dir() -> Result<PathBuf> {
    let home = std::env::var("HOME")
        .map_err(|_| rssh_core::Error::Config("HOME environment variable not set".into()))?;
    Ok(PathBuf::from(home).join(".ssh").join("rssh-agent"))
}

fn expand_path(path: &str) -> Result<PathBuf> {
    let expanded = if let Some(stripped) = path.strip_prefix("~/") {
        let home = std::env::var("HOME")
            .map_err(|_| rssh_core::Error::Config("HOME environment variable not set".into()))?;
        PathBuf::from(home).join(stripped)
    } else {
        PathBuf::from(path)
    };

    if expanded.exists() {
        Ok(expanded.canonicalize()?)
    } else {
        Ok(expanded)
    }
}
