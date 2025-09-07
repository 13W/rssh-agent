use rssh_core::{Error, Result};
use rssh_daemon::prompt::{PrompterDecision, SecureString};
use rssh_proto::{messages, wire};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

/// Lock command implementation
pub struct LockCommand;

impl LockCommand {
    pub fn execute(socket_path: Option<String>) -> Result<()> {
        let socket = resolve_socket_path(socket_path)?;

        // Build lock message (empty passphrase as per OpenSSH)
        let mut msg = vec![wire::MessageType::Lock as u8];
        wire::write_string(&mut msg, b"");

        let response = send_agent_message(&socket, &msg)?;

        if response.len() == 1 && response[0] == wire::MessageType::Success as u8 {
            println!("Agent locked");
            Ok(())
        } else {
            Err(Error::Internal("Failed to lock agent".into()))
        }
    }
}

/// Unlock command implementation
pub struct UnlockCommand;

impl UnlockCommand {
    pub fn execute(socket_path: Option<String>, pass_fd: Option<i32>) -> Result<()> {
        let socket = resolve_socket_path(socket_path)?;

        // Get master password
        let password = if let Some(fd) = pass_fd {
            // Read from file descriptor
            read_password_from_fd(fd)?
        } else {
            // Prompt for password
            let prompter = PrompterDecision::choose()
                .ok_or_else(|| Error::Config("No prompt method available".into()))?;
            prompter.prompt("Enter master password")?
        };

        // Build unlock message
        let mut msg = vec![wire::MessageType::Unlock as u8];
        wire::write_string(&mut msg, password.as_str().as_bytes());

        let response = send_agent_message(&socket, &msg)?;

        if response.len() == 1 && response[0] == wire::MessageType::Success as u8 {
            println!("Agent unlocked");
            Ok(())
        } else {
            Err(Error::WrongPassword)
        }
    }
}

/// Stop command implementation
pub struct StopCommand;

impl StopCommand {
    pub fn execute(socket_path: Option<String>) -> Result<()> {
        let socket = resolve_socket_path(socket_path)?;

        // Build extension message for shutdown
        let mut msg = vec![wire::MessageType::Extension as u8];
        wire::write_string(&mut msg, b"rssh-agent@local");

        // CBOR payload for control.shutdown
        let payload = ciborium::Value::Map(vec![(
            ciborium::Value::Text("op".to_string()),
            ciborium::Value::Text("control.shutdown".to_string()),
        )]);

        let mut cbor_bytes = Vec::new();
        ciborium::into_writer(&payload, &mut cbor_bytes)
            .map_err(|e| Error::Internal(e.to_string()))?;

        wire::write_string(&mut msg, &cbor_bytes);

        // Send with timeout
        match send_agent_message_timeout(&socket, &msg, Duration::from_secs(5)) {
            Ok(_) => {
                println!("Agent shutdown initiated");
                Ok(())
            }
            Err(_) => {
                // Agent might have already shut down
                println!("Agent stopped");
                Ok(())
            }
        }
    }
}

/// Resolve socket path from options or environment
fn resolve_socket_path(socket_path: Option<String>) -> Result<String> {
    if let Some(path) = socket_path {
        Ok(path)
    } else if let Ok(path) = std::env::var("SSH_AUTH_SOCK") {
        Ok(path)
    } else {
        Err(Error::NoSocket)
    }
}

/// Send a message to the agent and get response
fn send_agent_message(socket_path: &str, message: &[u8]) -> Result<Vec<u8>> {
    let mut stream = UnixStream::connect(socket_path).map_err(|_| Error::NoSocket)?;

    // Set timeout
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;

    // Send message
    let len = message.len() as u32;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(message)?;
    stream.flush()?;

    // Read response
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let response_len = u32::from_be_bytes(len_buf) as usize;

    if response_len > 1024 * 1024 {
        return Err(Error::Internal("Response too large".into()));
    }

    let mut response = vec![0u8; response_len];
    stream.read_exact(&mut response)?;

    Ok(response)
}

/// Send a message with custom timeout
fn send_agent_message_timeout(
    socket_path: &str,
    message: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>> {
    let mut stream = UnixStream::connect(socket_path).map_err(|_| Error::NoSocket)?;

    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    // Send message
    let len = message.len() as u32;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(message)?;
    stream.flush()?;

    // Read response
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf)?;
    let response_len = u32::from_be_bytes(len_buf) as usize;

    if response_len > 1024 * 1024 {
        return Err(Error::Internal("Response too large".into()));
    }

    let mut response = vec![0u8; response_len];
    stream.read_exact(&mut response)?;

    Ok(response)
}

/// Read password from file descriptor
fn read_password_from_fd(fd: i32) -> Result<SecureString> {
    use std::os::unix::io::FromRawFd;

    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut password = String::new();
    file.read_to_string(&mut password)?;

    // Trim trailing newline
    if password.ends_with('\n') {
        password.pop();
    }
    if password.ends_with('\r') {
        password.pop();
    }

    if password.is_empty() {
        return Err(Error::BadArgs);
    }

    Ok(SecureString::new(password))
}
