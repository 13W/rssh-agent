use rssh_proto::cbor::ExtensionRequest;
use rssh_proto::wire;

fn main() {
    // Simulate what the stop command sends
    let mut msg = vec![wire::MessageType::Extension as u8];
    wire::write_string(&mut msg, b"rssh-agent@local");

    let ext_request = ExtensionRequest {
        extension: "control.shutdown".to_string(),
        data: vec![], // No additional data needed for shutdown
    };

    let mut cbor_bytes = Vec::new();
    ciborium::into_writer(&ext_request, &mut cbor_bytes).unwrap();
    wire::write_string(&mut msg, &cbor_bytes);

    println!("Full message length: {}", msg.len());
    println!("Full message: {:02x?}", msg);

    // Test parsing the way the agent does it
    let result = rssh_daemon::extensions::parse_extension_request(&msg);
    match result {
        Ok(req) => println!("Parsed successfully: {:?}", req),
        Err(e) => println!("Parse error: {}", e),
    }

    // Test parsing without the message type byte
    let result2 = rssh_daemon::extensions::parse_extension_request(&msg[1..]);
    match result2 {
        Ok(req) => println!("Parsed without msg type: {:?}", req),
        Err(e) => println!("Parse error without msg type: {}", e),
    }
}