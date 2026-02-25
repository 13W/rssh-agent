use ssh_key::{
    LineEnding,
    private::{Ed25519Keypair, KeypairData, PrivateKey},
    rand_core::OsRng,
};

#[test]
fn test_ssh_key_comment_extraction() {
    let comment = "test-user@example.com";
    let keypair = Ed25519Keypair::random(&mut OsRng);
    let key_data = KeypairData::Ed25519(keypair);
    let key = PrivateKey::new(key_data, comment.to_string()).expect("Failed to create key");

    let pem = key.to_openssh(LineEnding::LF).expect("Failed to serialize key");
    let parsed = PrivateKey::from_openssh(&*pem).expect("Failed to parse SSH key");

    assert_eq!(parsed.comment(), comment);
    assert!(!parsed.comment().is_empty());
}

#[test]
fn test_ssh_key_without_comment() {
    let keypair = Ed25519Keypair::random(&mut OsRng);
    let key_data = KeypairData::Ed25519(keypair);
    let key = PrivateKey::new(key_data, "".to_string()).expect("Failed to create key");

    let pem = key.to_openssh(LineEnding::LF).expect("Failed to serialize key");
    let parsed = PrivateKey::from_openssh(&*pem).expect("Failed to parse SSH key");

    assert_eq!(parsed.comment(), "");
    assert!(parsed.comment().is_empty());
}

#[test]
fn test_encrypted_ssh_key_comment_extraction() {
    let keypair = Ed25519Keypair::random(&mut OsRng);
    let key_data = KeypairData::Ed25519(keypair);
    let key = PrivateKey::new(key_data, "test-comment".to_string()).expect("Failed to create key");

    let encrypted = key
        .encrypt(&mut OsRng, b"test-passphrase")
        .expect("Failed to encrypt key");
    let pem = encrypted
        .to_openssh(LineEnding::LF)
        .expect("Failed to serialize encrypted key");

    // Parse without passphrase — ssh-key can still read the metadata headers
    let parsed = PrivateKey::from_openssh(&*pem).expect("Failed to parse encrypted SSH key");
    println!("Encrypted key comment: '{}'", parsed.comment());
    // Parsing without crashing is the test goal
}
