use rssh_core::{Result, config::Config};
use rssh_daemon::daemon::{DaemonConfig, ShellStyle, apply_hardening, run_daemon};
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
        // Apply security hardening
        apply_hardening(require_mlock)?;

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

        // Create daemon config
        let daemon_config = DaemonConfig {
            socket_path: socket,
            foreground,
            storage_dir: storage_dir.to_string_lossy().to_string(),
            config,
        };

        // Run the daemon
        run_daemon(daemon_config, shell_style).await
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
