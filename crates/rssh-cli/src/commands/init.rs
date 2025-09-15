use rssh_core::{Error, Result, config::Config, fs_policy};
use rssh_daemon::prompt::{PrompterDecision, SecureString};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::info;

pub struct InitCommand;

impl InitCommand {
    pub fn execute(dir: Option<String>) -> Result<()> {
        // Determine storage directory
        let storage_dir = resolve_storage_dir(dir)?;
        info!("Initializing rssh-agent in: {}", storage_dir.display());

        // Check if already initialized
        check_not_initialized(&storage_dir)?;

        // Create directory with secure permissions
        fs_policy::ensure_dir_secure(&storage_dir)?;

        // Prompt for master password
        let master_password = prompt_master_password()?;

        // Create config with sentinel
        let config = Config::new_with_sentinel(&storage_dir, master_password.as_str())?;

        // Write config atomically
        let config_path = storage_dir.join("config.json");
        let json = serde_json::to_string_pretty(&config)?;
        fs_policy::atomic_write(&config_path, json.as_bytes())?;

        println!(
            "Successfully initialized rssh-agent in {}",
            storage_dir.display()
        );
        Ok(())
    }
}

fn resolve_storage_dir(dir: Option<String>) -> Result<PathBuf> {
    let path = if let Some(d) = dir {
        expand_path(&d)?
    } else if let Ok(env_dir) = std::env::var("RSSH_STORAGE_DIR") {
        expand_path(&env_dir)?
    } else {
        // Default to ~/.ssh/rssh-agent
        let home = std::env::var("HOME")
            .map_err(|_| Error::Config("HOME environment variable not set".into()))?;
        PathBuf::from(home).join(".ssh").join("rssh-agent")
    };

    // Canonicalize if it exists, otherwise just return the path
    if path.exists() {
        Ok(path.canonicalize()?)
    } else {
        Ok(path)
    }
}

fn expand_path(path: &str) -> Result<PathBuf> {
    let expanded = if let Some(stripped) = path.strip_prefix("~/") {
        let home = std::env::var("HOME")
            .map_err(|_| Error::Config("HOME environment variable not set".into()))?;
        PathBuf::from(home).join(stripped)
    } else {
        PathBuf::from(path)
    };

    Ok(expanded)
}

fn check_not_initialized(dir: &Path) -> Result<()> {
    if !dir.exists() {
        return Ok(());
    }

    // Check for config.json
    if dir.join("config.json").exists() {
        return Err(Error::AlreadyInitialized);
    }

    // Check for any sha256-*.json files
    let entries = fs::read_dir(dir)?;
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str.starts_with("sha256-") && name_str.ends_with(".json") {
            return Err(Error::AlreadyInitialized);
        }
    }

    Ok(())
}

fn prompt_master_password() -> Result<SecureString> {
    let prompter = PrompterDecision::choose().ok_or_else(|| {
        Error::Config("No prompt method available (no TTY and no ASKPASS)".into())
    })?;

    loop {
        let password = prompter.prompt("Enter master password")?;

        // Validate password
        let pw_str = password.as_str();
        if pw_str.len() < 8 || pw_str.len() > 1024 {
            eprintln!("Password must be between 8 and 1024 characters");
            continue;
        }

        if pw_str.trim().is_empty() {
            eprintln!("Password cannot be empty or whitespace only");
            continue;
        }

        // Validate UTF-8 (already guaranteed by String)

        // Confirm password
        let confirm = prompter.prompt("Confirm master password")?;
        if password.as_str() != confirm.as_str() {
            eprintln!("Passwords do not match");
            continue;
        }

        return Ok(password);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_expand_path_home() {
        unsafe {
            std::env::set_var("HOME", "/home/testuser");
        }
        let expanded = expand_path("~/test").unwrap();
        assert_eq!(expanded, PathBuf::from("/home/testuser/test"));
    }

    #[test]
    fn test_expand_path_absolute() {
        let expanded = expand_path("/absolute/path").unwrap();
        assert_eq!(expanded, PathBuf::from("/absolute/path"));
    }

    #[test]
    fn test_check_not_initialized_empty() {
        let temp = TempDir::new().unwrap();
        check_not_initialized(temp.path()).unwrap();
    }

    #[test]
    fn test_check_not_initialized_with_config() {
        let temp = TempDir::new().unwrap();
        fs::write(temp.path().join("config.json"), "{}").unwrap();

        let result = check_not_initialized(temp.path());
        assert!(matches!(result, Err(Error::AlreadyInitialized)));
    }

    #[test]
    fn test_check_not_initialized_with_keyfile() {
        let temp = TempDir::new().unwrap();
        fs::write(temp.path().join("sha256-abcd.json"), "{}").unwrap();

        let result = check_not_initialized(temp.path());
        assert!(matches!(result, Err(Error::AlreadyInitialized)));
    }
}
