use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::time::sleep;

#[derive(Debug)]
struct MockExchange {
    request: Vec<u8>,
    response: Vec<u8>,
    description: String,
}

fn describe_message(msg: &[u8]) -> String {
    if msg.is_empty() {
        return "empty".to_string();
    }

    match msg[0] {
        11 => "request_identities",
        12 => "identities_answer",
        13 => "sign_request",
        14 => "sign_response",
        17 => "add_identity",
        18 => "remove_identity",
        19 => "remove_all_identities",
        22 => "lock",
        23 => "unlock",
        25 => "add_id_constrained",
        27 => "extension",
        5 => "failure",
        6 => "success",
        _ => "unknown",
    }
    .to_string()
}

async fn proxy_connection(
    mut client: UnixStream,
    backend_path: &Path,
) -> Result<Vec<MockExchange>, Box<dyn std::error::Error>> {
    let mut backend = UnixStream::connect(backend_path).await?;
    let mut exchanges = Vec::new();

    loop {
        // Read request from client
        let mut len_buf = [0u8; 4];
        if client.read_exact(&mut len_buf).await.is_err() {
            break;
        }

        let msg_len = u32::from_be_bytes(len_buf) as usize;
        if msg_len == 0 || msg_len > 256 * 1024 {
            break;
        }

        let mut request = vec![0u8; msg_len];
        client.read_exact(&mut request).await?;

        // Forward to backend
        backend.write_all(&len_buf).await?;
        backend.write_all(&request).await?;

        // Read response from backend
        let mut resp_len_buf = [0u8; 4];
        backend.read_exact(&mut resp_len_buf).await?;

        let resp_len = u32::from_be_bytes(resp_len_buf) as usize;
        if resp_len == 0 || resp_len > 256 * 1024 {
            break;
        }

        let mut response = vec![0u8; resp_len];
        backend.read_exact(&mut response).await?;

        // Forward response to client
        client.write_all(&resp_len_buf).await?;
        client.write_all(&response).await?;

        // Record the exchange
        let description = describe_message(&request);
        println!(
            "Recorded: {} ({} bytes -> {} bytes)",
            description,
            request.len(),
            response.len()
        );

        exchanges.push(MockExchange {
            request,
            response,
            description,
        });
    }

    Ok(exchanges)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <command> [args...]", args[0]);
        eprintln!("Example: {} ssh-add -l", args[0]);
        return Ok(());
    }

    // Start the real daemon
    println!("Starting rssh-agent daemon...");
    let daemon_socket = "/tmp/rssh-daemon-real.sock";
    let mut daemon = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "rssh-agent",
            "--",
            "daemon",
            "--socket",
            daemon_socket,
        ])
        .spawn()?;

    sleep(Duration::from_secs(5)).await;

    // Set up proxy socket
    let proxy_socket = "/tmp/rssh-proxy.sock";
    if Path::new(proxy_socket).exists() {
        fs::remove_file(proxy_socket)?;
    }

    let listener = UnixListener::bind(proxy_socket)?;

    // Run the command with our proxy socket
    let proxy_handle = tokio::spawn(async move {
        let mut all_exchanges = Vec::new();

        while let Ok((stream, _)) = listener.accept().await {
            match proxy_connection(stream, Path::new(daemon_socket)).await {
                Ok(exchanges) => all_exchanges.extend(exchanges),
                Err(e) => eprintln!("Proxy error: {}", e),
            }
        }

        all_exchanges
    });

    // Give proxy time to start
    sleep(Duration::from_millis(500)).await;

    // Run the actual command
    println!("Running command: {:?}", &args[1..]);
    let output = Command::new(&args[1])
        .args(&args[2..])
        .env("SSH_AUTH_SOCK", proxy_socket)
        .output()?;

    println!(
        "Command output: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    if !output.stderr.is_empty() {
        eprintln!(
            "Command stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // Give time for messages to complete
    sleep(Duration::from_millis(500)).await;

    // Stop the proxy
    proxy_handle.abort();

    // Get exchanges if any were recorded
    let exchanges: Vec<MockExchange> = (proxy_handle.await).unwrap_or_default();

    // Save the mocks
    if !exchanges.is_empty() {
        let mock_dir = "tests/mocks";
        fs::create_dir_all(mock_dir)?;

        let command_name = args[1..].join("_").replace(['/', '-'], "_");

        for (i, exchange) in exchanges.iter().enumerate() {
            let base_name = format!("{:02}_{}_{}", i, command_name, exchange.description);

            let request_path = format!("{}/{}.request.bin", mock_dir, base_name);
            fs::write(&request_path, &exchange.request)?;
            println!("Saved request: {}", request_path);

            let response_path = format!("{}/{}.response.bin", mock_dir, base_name);
            fs::write(&response_path, &exchange.response)?;
            println!("Saved response: {}", response_path);
        }
    }

    // Clean up
    daemon.kill()?;
    fs::remove_file(proxy_socket).ok();
    fs::remove_file(daemon_socket).ok();

    Ok(())
}
