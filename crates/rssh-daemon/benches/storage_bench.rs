use base64::{Engine as _, engine::general_purpose};
use chrono::Utc;
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use std::hint::black_box;
use rssh_core::keyfile::{KeyFile, KeyPayload, KeyType};
use rssh_daemon::extensions;
use std::fs;
use tempfile::TempDir;

fn benchmark_keyfile_operations(c: &mut Criterion) {
    c.bench_function("keyfile_write_ed25519", |b| {
        b.iter_batched(
            || {
                let temp_dir = TempDir::new().unwrap();
                let fingerprint = hex::encode([42u8; 32]);
                let payload = KeyPayload {
                    key_type: KeyType::Ed25519,
                    description: "Benchmark Ed25519 key".to_string(),
                    secret_openssh_b64: general_purpose::STANDARD.encode(&[0u8; 64]),
                    cert_openssh_b64: None,
                    password_protected: false,
                    default_confirm: false,
                    default_notification: false,
                    default_lifetime_seconds: None,
                    pub_key_fingerprint_sha256: String::new(),
                    created: Utc::now(),
                    updated: Utc::now(),
                };
                (temp_dir, fingerprint, payload)
            },
            |(temp_dir, fingerprint, payload)| {
                KeyFile::write(temp_dir.path(), &fingerprint, &payload, "test_password_123")
                    .unwrap();
                black_box(())
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("keyfile_read_ed25519", |b| {
        b.iter_batched(
            || {
                let temp_dir = TempDir::new().unwrap();
                let fingerprint = hex::encode([42u8; 32]);
                let payload = KeyPayload {
                    key_type: KeyType::Ed25519,
                    description: "Benchmark Ed25519 key".to_string(),
                    secret_openssh_b64: general_purpose::STANDARD.encode(&[0u8; 64]),
                    cert_openssh_b64: None,
                    password_protected: false,
                    default_confirm: false,
                    default_notification: false,
                    default_lifetime_seconds: None,
                    pub_key_fingerprint_sha256: String::new(),
                    created: Utc::now(),
                    updated: Utc::now(),
                };
                KeyFile::write(temp_dir.path(), &fingerprint, &payload, "test_password_123")
                    .unwrap();
                (temp_dir, fingerprint)
            },
            |(temp_dir, fingerprint)| {
                let payload =
                    KeyFile::read(temp_dir.path(), &fingerprint, "test_password_123").unwrap();
                black_box(payload)
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("keyfile_write_rsa_2048", |b| {
        b.iter_batched(
            || {
                let temp_dir = TempDir::new().unwrap();
                let fingerprint = hex::encode([42u8; 32]);
                let payload = KeyPayload {
                    key_type: KeyType::Rsa,
                    description: "Benchmark RSA 2048 key".to_string(),
                    secret_openssh_b64: general_purpose::STANDARD.encode(&[0u8; 512]), // Larger RSA key
                    cert_openssh_b64: None,
                    password_protected: false,
                    default_confirm: false,
                    default_notification: false,
                    default_lifetime_seconds: None,
                    pub_key_fingerprint_sha256: String::new(),
                    created: Utc::now(),
                    updated: Utc::now(),
                };

                (temp_dir, fingerprint, payload)
            },
            |(temp_dir, fingerprint, payload)| {
                KeyFile::write(temp_dir.path(), &fingerprint, &payload, "test_password_123")
                    .unwrap();
                black_box(())
            },
            BatchSize::SmallInput,
        )
    });
}

fn benchmark_extension_operations(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("extension_manage_list_empty", |b| {
        let temp_dir = TempDir::new().unwrap();

        b.iter(|| {
            rt.block_on(async {
                let result = extensions::handle_manage_list(
                    Vec::new(),
                    Some(temp_dir.path().to_str().unwrap()),
                    Some("test_password_123"),
                )
                .unwrap();
                black_box(result)
            })
        })
    });

    c.bench_function("extension_manage_list_100_keys", |b| {
        let temp_dir = TempDir::new().unwrap();

        // Create 100 keyfiles on disk
        for i in 0..100 {
            let fingerprint = format!("{:064x}", i);
            let payload = KeyPayload {
                key_type: KeyType::Ed25519,
                description: format!("Benchmark key {}", i),
                secret_openssh_b64: general_purpose::STANDARD.encode(&[i as u8; 64]),
                cert_openssh_b64: None,
                password_protected: false,
                default_confirm: false,
                default_notification: false,
                default_lifetime_seconds: None,
                pub_key_fingerprint_sha256: String::new(),
                created: Utc::now(),
                updated: Utc::now(),
            };

            KeyFile::write(temp_dir.path(), &fingerprint, &payload, "test_password_123").unwrap();
        }

        b.iter(|| {
            rt.block_on(async {
                let result = extensions::handle_manage_list(
                    Vec::new(),
                    Some(temp_dir.path().to_str().unwrap()),
                    Some("test_password_123"),
                )
                .unwrap();
                black_box(result)
            })
        })
    });
}

fn benchmark_file_io_operations(c: &mut Criterion) {
    c.bench_function("filesystem_create_1kb_file", |b| {
        b.iter_batched(
            || {
                let temp_dir = TempDir::new().unwrap();
                let data = vec![42u8; 1024];
                (temp_dir, data)
            },
            |(temp_dir, data)| {
                let file_path = temp_dir.path().join("test_file.json");
                fs::write(&file_path, &data).unwrap();
                black_box(())
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("filesystem_read_1kb_file", |b| {
        b.iter_batched(
            || {
                let temp_dir = TempDir::new().unwrap();
                let data = vec![42u8; 1024];
                let file_path = temp_dir.path().join("test_file.json");
                fs::write(&file_path, &data).unwrap();
                (temp_dir, file_path)
            },
            |(_temp_dir, file_path)| {
                let data = fs::read(&file_path).unwrap();
                black_box(data)
            },
            BatchSize::SmallInput,
        )
    });

    c.bench_function("json_serialize_keyfile", |b| {
        let payload = KeyPayload {
            key_type: KeyType::Ed25519,
            description: "Benchmark Ed25519 key".to_string(),
            secret_openssh_b64: general_purpose::STANDARD.encode(&[0u8; 64]),
            cert_openssh_b64: None,
            password_protected: false,
            default_confirm: false,
            default_notification: false,
            default_lifetime_seconds: None,
            pub_key_fingerprint_sha256: String::new(),
            created: Utc::now(),
            updated: Utc::now(),
        };


        b.iter(|| {
            let json = serde_json::to_string_pretty(&payload).unwrap();
            black_box(json)
        })
    });

    c.bench_function("json_deserialize_keyfile", |b| {
        let payload = KeyPayload {
            key_type: KeyType::Ed25519,
            description: "Benchmark Ed25519 key".to_string(),
            secret_openssh_b64: general_purpose::STANDARD.encode(&[0u8; 64]),
            cert_openssh_b64: None,
            password_protected: false,
            default_confirm: false,
            default_notification: false,
            default_lifetime_seconds: None,
            pub_key_fingerprint_sha256: String::new(),
            created: Utc::now(),
            updated: Utc::now(),
        };

        let json = serde_json::to_string_pretty(&payload).unwrap();

        b.iter(|| {
            let parsed: KeyPayload = serde_json::from_str(&json).unwrap();
            black_box(parsed)
        })
    });
}

criterion_group!(
    benches,
    benchmark_keyfile_operations,
    benchmark_extension_operations,
    benchmark_file_io_operations
);
criterion_main!(benches);
