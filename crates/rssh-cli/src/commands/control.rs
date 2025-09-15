use rssh_core::{Error, Result};
use rssh_daemon::prompt::{PrompterDecision, SecureString};
use rssh_proto::{cbor::ExtensionRequest, wire};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

/// Lock command implementation
pub struct LockCommand;

impl LockCommand {
    pub fn execute(socket_path: Option<String>) -> Result<()> {
        let socket = resolve_socket_path(socket_path)?;

        // Build lock message (no passphrase needed per rssh-agent spec)
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

        // Get master password for unlock
        let password = if let Some(fd) = pass_fd {
            // Read from file descriptor
            read_password_from_fd(fd)?
        } else {
            // Prompt for master password
            let prompter = PrompterDecision::choose()
                .ok_or_else(|| Error::Config("No prompt method available".into()))?;
            prompter.prompt("Enter master password")?
        };

        // Build unlock message with master password
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
        let request = ExtensionRequest {
            extension: "control.shutdown".to_string(),
            data: vec![], // No additional data needed for shutdown
        };

        let mut cbor_data = Vec::new();
        ciborium::into_writer(&request, &mut cbor_data)
            .map_err(|e| Error::Internal(e.to_string()))?;

        // Build SSH protocol message with extension namespace
        let mut message = Vec::new();
        message.push(rssh_proto::messages::SSH_AGENTC_EXTENSION);

        // Add extension namespace
        let ext_namespace = b"rssh-agent@local";
        message.extend_from_slice(&(ext_namespace.len() as u32).to_be_bytes());
        message.extend_from_slice(ext_namespace);

        // Add CBOR data
        message.extend_from_slice(&cbor_data);

        // Send with timeout
        match send_agent_message_timeout(&socket, &message, Duration::from_secs(5)) {
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
