//! Systemd socket activation support
//!
//! This module provides functionality to detect and use systemd socket activation
//! according to the systemd socket activation protocol.

use rssh_core::{Error, Result};
use std::os::unix::io::FromRawFd;
use tokio::net::UnixListener;

/// Check if the daemon is being run under systemd socket activation
///
/// Returns `true` if LISTEN_FDS environment variable is set to "1" and
/// LISTEN_PID matches the current process ID.
pub fn is_systemd_activated() -> bool {
    // Check LISTEN_FDS environment variable
    let listen_fds = match std::env::var("LISTEN_FDS") {
        Ok(fds) => {
            tracing::debug!("LISTEN_FDS environment variable: '{}'", fds);
            fds
        }
        Err(_) => {
            tracing::debug!("LISTEN_FDS environment variable not found");
            return false;
        }
    };

    // Should be exactly "1" for single socket activation
    if listen_fds != "1" {
        tracing::debug!("LISTEN_FDS is not '1', got: '{}'", listen_fds);
        return false;
    }

    // Check LISTEN_PID matches current process
    let listen_pid = match std::env::var("LISTEN_PID") {
        Ok(pid_str) => {
            tracing::debug!("LISTEN_PID environment variable: '{}'", pid_str);
            match pid_str.parse::<u32>() {
                Ok(pid) => pid,
                Err(e) => {
                    tracing::debug!("Failed to parse LISTEN_PID '{}': {}", pid_str, e);
                    return false;
                }
            }
        }
        Err(_) => {
            tracing::debug!("LISTEN_PID environment variable not found");
            return false;
        }
    };

    let current_pid = std::process::id();
    let is_activated = listen_pid == current_pid;

    tracing::debug!(
        "Systemd activation check: LISTEN_PID={}, current_pid={}, activated={}",
        listen_pid,
        current_pid,
        is_activated
    );

    is_activated
}

/// Create a UnixListener from the systemd-activated socket file descriptor
///
/// This function assumes that systemd activation has been detected via
/// `is_systemd_activated()` and retrieves the socket from file descriptor 3
/// (SD_LISTEN_FDS_START).
///
/// # Safety
///
/// This function uses `FromRawFd::from_raw_fd()` which is unsafe because it
/// assumes the file descriptor is valid and represents a Unix domain socket.
/// It should only be called when systemd activation is confirmed.
pub fn take_systemd_socket() -> Result<UnixListener> {
    // According to systemd protocol, activated sockets start at FD 3
    const SD_LISTEN_FDS_START: i32 = 3;

    tracing::debug!("Taking systemd socket from FD {}", SD_LISTEN_FDS_START);

    // SAFETY: We've verified systemd activation via is_systemd_activated(),
    // so FD 3 should be a valid Unix domain socket created by systemd.
    let std_listener =
        unsafe { std::os::unix::net::UnixListener::from_raw_fd(SD_LISTEN_FDS_START) };

    // Ensure the socket is in non-blocking mode before converting to tokio
    std_listener
        .set_nonblocking(true)
        .map_err(|e| Error::Io(e))?;

    tracing::debug!("Socket set to non-blocking mode");

    // Convert to tokio UnixListener
    let tokio_listener = UnixListener::from_std(std_listener).map_err(|e| Error::Io(e))?;

    tracing::debug!("Successfully converted to tokio UnixListener");

    // Clean up environment variables as per systemd protocol
    unsafe {
        std::env::remove_var("LISTEN_FDS");
        std::env::remove_var("LISTEN_PID");
    }

    tracing::info!(
        "Using systemd-activated socket (FD {})",
        SD_LISTEN_FDS_START
    );

    Ok(tokio_listener)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_not_systemd_activated_no_env() {
        // Remove env vars if they exist
        unsafe {
            env::remove_var("LISTEN_FDS");
            env::remove_var("LISTEN_PID");
        }

        assert!(!is_systemd_activated());
    }

    #[test]
    fn test_not_systemd_activated_wrong_fds() {
        unsafe {
            env::set_var("LISTEN_FDS", "2");
            env::set_var("LISTEN_PID", &std::process::id().to_string());
        }

        assert!(!is_systemd_activated());

        // Cleanup
        unsafe {
            env::remove_var("LISTEN_FDS");
            env::remove_var("LISTEN_PID");
        }
    }

    #[test]
    fn test_not_systemd_activated_wrong_pid() {
        unsafe {
            env::set_var("LISTEN_FDS", "1");
            env::set_var("LISTEN_PID", "99999"); // Wrong PID
        }

        assert!(!is_systemd_activated());

        // Cleanup
        unsafe {
            env::remove_var("LISTEN_FDS");
            env::remove_var("LISTEN_PID");
        }
    }

    #[test]
    fn test_systemd_activated_correct_env() {
        unsafe {
            env::set_var("LISTEN_FDS", "1");
            env::set_var("LISTEN_PID", &std::process::id().to_string());
        }

        assert!(is_systemd_activated());

        // Cleanup
        unsafe {
            env::remove_var("LISTEN_FDS");
            env::remove_var("LISTEN_PID");
        }
    }

    #[test]
    fn test_not_systemd_activated_invalid_pid_format() {
        unsafe {
            env::set_var("LISTEN_FDS", "1");
            env::set_var("LISTEN_PID", "not_a_number");
        }

        assert!(!is_systemd_activated());

        // Cleanup
        unsafe {
            env::remove_var("LISTEN_FDS");
            env::remove_var("LISTEN_PID");
        }
    }
}
