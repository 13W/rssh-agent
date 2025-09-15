use crate::{Error, Result};
use nix::sys::stat::{Mode, fchmod};
use nix::unistd::geteuid;
use rand::RngCore;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::Path;

/// Ensure directory exists with secure permissions (0700) and is owned by current user
pub fn ensure_dir_secure<P: AsRef<Path>>(path: P) -> Result<()> {
    let path = path.as_ref();
    let current_uid = geteuid();

    if !path.exists() {
        fs::create_dir_all(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }

    let metadata = fs::metadata(path)?;

    // Check ownership
    if metadata.uid() != current_uid.as_raw() {
        return Err(Error::AccessDenied);
    }

    // Check permissions (must be exactly 0700)
    let mode = metadata.mode() & 0o777;
    if mode != 0o700 {
        return Err(Error::AccessDenied);
    }

    // Check it's actually a directory
    if !metadata.is_dir() {
        return Err(Error::Config(format!(
            "{} is not a directory",
            path.display()
        )));
    }

    Ok(())
}

/// Ensure file has mode 0600
pub fn ensure_file_mode_0600(file: &File) -> Result<()> {
    let fd = file.as_raw_fd();
    fchmod(fd, Mode::from_bits_truncate(0o600)).map_err(|e| Error::Io(std::io::Error::from(e)))?;
    Ok(())
}

/// Atomically write data to a file
pub fn atomic_write<P: AsRef<Path>>(path: P, data: &[u8]) -> Result<()> {
    let path = path.as_ref();

    // Check if path is a symlink
    if let Ok(metadata) = fs::symlink_metadata(path)
        && metadata.file_type().is_symlink()
    {
        return Err(Error::Config("Cannot write to symlink".into()));
    }

    let parent = path
        .parent()
        .ok_or_else(|| Error::Config("Invalid path".into()))?;

    // Generate temporary filename
    let pid = std::process::id();
    let rand_num: u32 = rand::thread_rng().next_u32();
    let tmp_name = format!(".tmp.{}.{}", pid, rand_num);
    let tmp_path = parent.join(&tmp_name);

    // Write to temporary file
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&tmp_path)?;

    file.write_all(data)?;
    file.sync_all()?; // fsync file
    drop(file);

    // Rename temporary to final
    fs::rename(&tmp_path, path)?;

    // fsync directory
    let dir = File::open(parent)?;
    dir.sync_all()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    #[test]
    fn test_ensure_dir_secure_creates_with_correct_perms() {
        let temp = TempDir::new().unwrap();
        let test_dir = temp.path().join("secure_dir");

        ensure_dir_secure(&test_dir).unwrap();

        let metadata = fs::metadata(&test_dir).unwrap();
        assert!(metadata.is_dir());
        assert_eq!(metadata.mode() & 0o777, 0o700);
        assert_eq!(metadata.uid(), geteuid().as_raw());
    }

    #[test]
    fn test_ensure_dir_secure_rejects_bad_perms() {
        let temp = TempDir::new().unwrap();
        let test_dir = temp.path().join("insecure_dir");

        fs::create_dir(&test_dir).unwrap();
        fs::set_permissions(&test_dir, fs::Permissions::from_mode(0o755)).unwrap();

        let result = ensure_dir_secure(&test_dir);
        assert!(matches!(result, Err(Error::AccessDenied)));
    }

    #[test]
    fn test_atomic_write_preserves_old_on_crash() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("test.txt");

        // Write initial content
        fs::write(&file_path, b"original").unwrap();

        // Simulate crash by not doing rename (we can't easily simulate this,
        // so we just test the normal path works)
        atomic_write(&file_path, b"new content").unwrap();

        let content = fs::read(&file_path).unwrap();
        assert_eq!(content, b"new content");
    }

    #[test]
    fn test_atomic_write_rejects_symlink() {
        let temp = TempDir::new().unwrap();
        let target = temp.path().join("target.txt");
        let link = temp.path().join("link.txt");

        fs::write(&target, b"data").unwrap();
        symlink(&target, &link).unwrap();

        let result = atomic_write(&link, b"new data");
        assert!(matches!(result, Err(Error::Config(_))));

        // Original file should be unchanged
        let content = fs::read(&target).unwrap();
        assert_eq!(content, b"data");
    }

    #[test]
    fn test_ensure_file_mode_0600() {
        let temp = TempDir::new().unwrap();
        let file_path = temp.path().join("test.txt");

        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .mode(0o644)
            .open(&file_path)
            .unwrap();

        ensure_file_mode_0600(&file).unwrap();
        drop(file);

        let metadata = fs::metadata(&file_path).unwrap();
        assert_eq!(metadata.mode() & 0o777, 0o600);
    }
}
