use rssh_core::{Error, Result};
use rssh_daemon::prompt::PrompterDecision;
use std::fs;
use std::path::Path;

/// Import command implementation
pub struct ImportCommand;

impl ImportCommand {
    pub fn execute(
        path: String,
        description: Option<String>,
        protect: bool,
        socket_path: Option<String>,
    ) -> Result<()> {
        // Validate that the file exists
        let key_path = Path::new(&path);
        if !key_path.exists() {
            return Err(Error::Config(format!("Key file does not exist: {}", path)));
        }

        // Read the SSH key file
        let key_content = fs::read_to_string(key_path).map_err(Error::Io)?;

        // Parse the SSH key to validate it and check if it's encrypted
        let ssh_key = ssh_key::PrivateKey::from_openssh(&key_content)
            .map_err(|e| Error::Config(format!("Invalid SSH key file: {}", e)))?;

        // Determine if the original key is password-protected
        let original_was_encrypted = ssh_key.is_encrypted();

        // Extract comment from SSH key
        let key_comment = ssh_key.comment();
        let key_comment_str = if key_comment.is_empty() {
            None
        } else {
            Some(key_comment.to_string())
        };

        // Generate description based on priority:
        // 1. User-provided --description flag (highest priority)
        // 2. Comment/description from the SSH key file itself
        // 3. Filename-based description (fallback)
        let final_description = description
            .clone()
            .or_else(|| key_comment_str.clone())
            .unwrap_or_else(|| {
                key_path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .map(|name| format!("Imported from {}", name))
                    .unwrap_or_else(|| "Imported SSH key".to_string())
            });

        // For disk storage, preserve the original key format without prompting for password
        // We'll pass the original key content and let the daemon handle password protection
        let import_result = if protect {
            // User explicitly wants password protection - prompt for new password
            let prompter = PrompterDecision::choose()
                .ok_or_else(|| Error::Config("No prompt method available".into()))?;

            let new_password = prompter.prompt("Enter password to protect the imported key")?;

            import_key_direct_with_password(
                socket_path.as_ref(),
                &key_content,
                &final_description,
                new_password.as_str(),
            )
        } else {
            // Preserve original protection state without prompting
            import_key_direct_preserving_protection(
                socket_path.as_ref(),
                &key_content,
                &final_description,
                original_was_encrypted,
            )
        };

        match import_result {
            Ok(import_response) => {
                println!("Successfully imported SSH key:");
                println!("  Fingerprint: SHA256:{}", import_response.fingerprint);
                println!("  Description: {}", import_response.description);
                
                // Show how the description was determined
                if description.is_some() {
                    println!("  Description source: User-provided");
                } else if key_comment_str.is_some() {
                    println!("  Description source: SSH key comment");
                } else {
                    println!("  Description source: Filename");
                }
                
                if original_was_encrypted {
                    if protect {
                        println!("  Original key was encrypted, now protected with new password");
                    } else {
                        println!("  Original key was encrypted, password protection preserved");
                    }
                } else if protect {
                    println!("  Key is now protected with password in rssh-agent storage");
                } else {
                    println!("  Key is stored without password protection");
                }

                // Ask if user wants to load the key into memory
                let load_to_memory = ask_user_to_load_key()?;
                if load_to_memory {
                    let load_result = if protect || original_was_encrypted {
                        // Need password to load password-protected key
                        let prompter = PrompterDecision::choose()
                            .ok_or_else(|| Error::Config("No prompt method available".into()))?;
                        let key_password = if protect {
                            prompter.prompt("Enter key password to load into memory")?
                        } else {
                            prompter.prompt("Enter original key passphrase to load into memory")?
                        };
                        load_key_into_memory(
                            socket_path.as_ref(),
                            &import_response.fingerprint,
                            Some(key_password.as_str()),
                        )
                    } else {
                        load_key_into_memory(
                            socket_path.as_ref(),
                            &import_response.fingerprint,
                            None,
                        )
                    };

                    match load_result {
                        Ok(()) => println!("  Key loaded into memory"),
                        Err(e) => println!("  Warning: Failed to load key into memory: {}", e),
                    }
                }

                Ok(())
            }
            Err(e) => Err(e),
        }
    }
}

#[derive(Debug)]
struct ImportDirectResponse {
    fingerprint: String,
    description: String,
}

// Helper function to ask user if they want to load the key into memory
fn ask_user_to_load_key() -> Result<bool> {
    use std::io::{self, Write};

    print!("Load key into memory? (y/n): ");
    io::stdout().flush().map_err(Error::Io)?;

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(Error::Io)?;

    let input = input.trim().to_lowercase();
    Ok(input == "y" || input == "yes")
}

// Import key directly preserving original password protection state
fn import_key_direct_preserving_protection(
    socket_path: Option<&String>,
    key_content: &str,
    description: &str,
    _was_encrypted: bool,
) -> Result<ImportDirectResponse> {
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    use rssh_proto::cbor::ExtensionRequest;
    use std::os::unix::net::UnixStream;

    let socket = resolve_socket_path(socket_path.cloned())?;
    let mut stream = UnixStream::connect(&socket).map_err(Error::Io)?;

    // Build CBOR request for manage.import_direct
    let import_data = {
        #[derive(serde::Serialize)]
        struct ImportDirectRequest {
            key_data_openssh_b64: String,
            description: Option<String>,
            preserve_original_protection: bool,
        }

        let req = ImportDirectRequest {
            key_data_openssh_b64: BASE64.encode(key_content.as_bytes()),
            description: Some(description.to_string()),
            preserve_original_protection: true,
        };

        let mut data = Vec::new();
        ciborium::into_writer(&req, &mut data)
            .map_err(|e| Error::Internal(format!("CBOR encoding error: {}", e)))?;
        data
    };

    let request = ExtensionRequest {
        extension: "manage.import_direct".to_string(),
        data: import_data,
    };

    send_extension_request(&mut stream, &request)?;
    let response = read_extension_response_with_data(&mut stream)?;

    Ok(response)
}

// Import key directly with password protection
fn import_key_direct_with_password(
    socket_path: Option<&String>,
    key_content: &str,
    description: &str,
    new_password: &str,
) -> Result<ImportDirectResponse> {
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    use rssh_proto::cbor::ExtensionRequest;
    use std::os::unix::net::UnixStream;

    let socket = resolve_socket_path(socket_path.cloned())?;
    let mut stream = UnixStream::connect(&socket).map_err(Error::Io)?;

    // Build CBOR request for manage.import_direct
    let import_data = {
        #[derive(serde::Serialize)]
        struct ImportDirectRequest {
            key_data_openssh_b64: String,
            description: Option<String>,
            set_key_password: bool,
            new_key_pass_b64: Option<String>,
        }

        let req = ImportDirectRequest {
            key_data_openssh_b64: BASE64.encode(key_content.as_bytes()),
            description: Some(description.to_string()),
            set_key_password: true,
            new_key_pass_b64: Some(BASE64.encode(new_password.as_bytes())),
        };

        let mut data = Vec::new();
        ciborium::into_writer(&req, &mut data)
            .map_err(|e| Error::Internal(format!("CBOR encoding error: {}", e)))?;
        data
    };

    let request = ExtensionRequest {
        extension: "manage.import_direct".to_string(),
        data: import_data,
    };

    send_extension_request(&mut stream, &request)?;
    let response = read_extension_response_with_data(&mut stream)?;

    Ok(response)
}

// Helper function to send extension request
fn send_extension_request(
    stream: &mut std::os::unix::net::UnixStream,
    request: &rssh_proto::cbor::ExtensionRequest,
) -> Result<()> {
    use std::io::Write;

    // Serialize request to CBOR
    let mut cbor_data = Vec::new();
    ciborium::into_writer(request, &mut cbor_data)
        .map_err(|e| Error::Internal(format!("CBOR encoding error: {}", e)))?;

    // Build SSH protocol message with extension namespace
    let mut message = Vec::new();
    message.push(rssh_proto::wire::MessageType::Extension as u8);

    // Add extension namespace
    let ext_namespace = b"rssh-agent@local";
    rssh_proto::wire::write_string(&mut message, ext_namespace);

    // Add CBOR data
    message.extend_from_slice(&cbor_data);

    // Add length prefix for the whole message
    let mut full_message = Vec::new();
    full_message.extend_from_slice(&(message.len() as u32).to_be_bytes());
    full_message.extend_from_slice(&message);

    stream.write_all(&full_message).map_err(Error::Io)?;

    Ok(())
}

// Helper function to read extension response with data parsing
fn read_extension_response_with_data(
    stream: &mut std::os::unix::net::UnixStream,
) -> Result<ImportDirectResponse> {
    use std::io::Read;

    // Read response length
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).map_err(Error::Io)?;
    let len = u32::from_be_bytes(len_buf) as usize;

    // Read response
    let mut response = vec![0u8; len];
    stream.read_exact(&mut response).map_err(Error::Io)?;

    // Check response type
    if response.is_empty() || response[0] != rssh_proto::wire::MessageType::Success as u8 {
        return Err(Error::Internal("Import operation failed".into()));
    }

    // For extension responses, we should parse the CBOR data to check for errors
    if response.len() > 1 {
        // Skip the success byte and parse CBOR response
        let mut offset = 1;
        if response.len() >= offset + 4 {
            let data_len = u32::from_be_bytes([
                response[offset],
                response[offset + 1],
                response[offset + 2],
                response[offset + 3],
            ]) as usize;
            offset += 4;

            if response.len() >= offset + data_len {
                let cbor_data = &response[offset..offset + data_len];
                if let Ok(cbor_response) =
                    ciborium::from_reader::<rssh_proto::cbor::ExtensionResponse, _>(cbor_data)
                {
                    if !cbor_response.success {
                        // Try to extract error message
                        if let Ok(response_data) =
                            ciborium::from_reader::<serde_json::Value, _>(&cbor_response.data[..])
                            && let Some(error) = response_data.get("error").and_then(|e| e.as_str())
                        {
                            return Err(Error::Internal(format!("Import failed: {}", error)));
                        }
                        return Err(Error::Internal("Import operation failed".into()));
                    }

                    // Parse the success response data
                    if let Ok(response_data) =
                        ciborium::from_reader::<serde_json::Value, _>(&cbor_response.data[..])
                    {
                        let fingerprint = response_data
                            .get("fp_sha256_hex")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown")
                            .to_string();

                        let description = response_data
                            .get("description")
                            .and_then(|v| v.as_str())
                            .unwrap_or("Imported SSH key")
                            .to_string();

                        return Ok(ImportDirectResponse {
                            fingerprint,
                            description,
                        });
                    }
                }
            }
        }
    }

    Err(Error::Internal("Failed to parse import response".into()))
}

// Load key into memory after successful disk import
fn load_key_into_memory(
    socket_path: Option<&String>,
    fingerprint_hex: &str,
    key_password: Option<&str>,
) -> Result<()> {
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    use rssh_proto::cbor::ExtensionRequest;
    use std::os::unix::net::UnixStream;

    let socket = resolve_socket_path(socket_path.cloned())?;
    let mut stream = UnixStream::connect(&socket).map_err(Error::Io)?;

    // Build CBOR request for manage.load
    let load_data = {
        #[derive(serde::Serialize)]
        struct LoadRequest {
            fp_sha256_hex: String,
            key_pass_b64: Option<String>,
        }

        let req = LoadRequest {
            fp_sha256_hex: fingerprint_hex.to_string(),
            key_pass_b64: key_password.map(|p| BASE64.encode(p.as_bytes())),
        };

        let mut data = Vec::new();
        ciborium::into_writer(&req, &mut data)
            .map_err(|e| Error::Internal(format!("CBOR encoding error: {}", e)))?;
        data
    };

    let request = ExtensionRequest {
        extension: "manage.load".to_string(),
        data: load_data,
    };

    send_extension_request(&mut stream, &request)?;
    read_extension_response_simple(&mut stream)?;

    Ok(())
}

// Helper function to read simple extension response (just success/failure)
fn read_extension_response_simple(stream: &mut std::os::unix::net::UnixStream) -> Result<()> {
    use std::io::Read;

    // Read response length
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).map_err(Error::Io)?;
    let len = u32::from_be_bytes(len_buf) as usize;

    // Read response
    let mut response = vec![0u8; len];
    stream.read_exact(&mut response).map_err(Error::Io)?;

    // Check response type
    if response.is_empty() || response[0] != rssh_proto::wire::MessageType::Success as u8 {
        return Err(Error::Internal("Load operation failed".into()));
    }

    Ok(())
}

// Helper function to resolve socket path (copied from control.rs pattern)
fn resolve_socket_path(socket_path: Option<String>) -> Result<String> {
    if let Some(path) = socket_path {
        Ok(path)
    } else if let Ok(path) = std::env::var("SSH_AUTH_SOCK") {
        Ok(path)
    } else {
        Err(Error::NoSocket)
    }
}
