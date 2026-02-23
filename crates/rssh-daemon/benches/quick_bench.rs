use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use ed25519_dalek::{Signer, SigningKey};
use rssh_core::config::Config;
use rssh_core::ram_store::RamStore;
use rssh_proto::wire;
use std::hint::black_box;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

fn quick_crypto_benchmarks(c: &mut Criterion) {
    // Ed25519 signing benchmark
    let secret_key_bytes = [42u8; 32]; // Use fixed bytes for benchmarking
    let signing_key = SigningKey::from_bytes(&secret_key_bytes);
    let data_to_sign = b"test message to sign for performance benchmarking";

    c.bench_function("ed25519_sign_direct", |b| {
        b.iter(|| {
            let signature = signing_key.sign(black_box(data_to_sign));
            black_box(signature)
        })
    });

    // SHA256 fingerprint calculation
    let test_public_key = vec![0u8; 32]; // Ed25519 public key size

    c.bench_function("fingerprint_sha256", |b| {
        b.iter(|| {
            let mut hasher = Sha256::new();
            hasher.update(&test_public_key);
            let result = hasher.finalize();
            black_box(hex::encode(result))
        })
    });

    // Memory zeroization benchmark
    c.bench_function("zeroize_4kb", |b| {
        use zeroize::Zeroize;
        b.iter(|| {
            let mut data = vec![42u8; 4096];
            data.zeroize();
            black_box(data)
        })
    });

    // Wire format operations
    c.bench_function("wire_write_string_small", |b| {
        let data = b"ssh-ed25519";
        b.iter(|| {
            let mut buf = Vec::new();
            wire::write_string(&mut buf, data);
            black_box(buf)
        })
    });

    c.bench_function("wire_read_string", |b| {
        let mut data = Vec::new();
        wire::write_string(&mut data, b"test_string_data");

        b.iter(|| {
            let mut offset = 0;
            let result = wire::read_string(&data, &mut offset);
            black_box(result)
        })
    });
}

fn quick_ram_store_benchmarks(c: &mut Criterion) {
    let temp_dir = TempDir::new().unwrap();
    let config = Config::new_with_sentinel(temp_dir.path(), "test_password_123").unwrap();
    let store = RamStore::new();
    store.unlock("test_password_123", &config).unwrap();

    let test_key_data = b"test_key_data_123456789012345678901234567890";

    c.bench_function("ram_store_encrypt_decrypt", |b| {
        b.iter(|| {
            let fp = format!("fp{}", rand::random::<u32>());
            store
                .load_key(
                    &fp,
                    test_key_data,
                    "test".to_string(),
                    "ed25519".to_string(),
                    false,
                )
                .unwrap();
            let result = store
                .with_key(&fp, |data| Ok(black_box(data.len())))
                .unwrap();
            store.unload_key(&fp).unwrap();
            black_box(result)
        })
    });

    // Load some keys for list performance test
    for i in 0..10 {
        let fp = format!("bench_key_{:04}", i);
        store
            .load_key(
                &fp,
                test_key_data,
                "test".to_string(),
                "ed25519".to_string(),
                false,
            )
            .unwrap();
    }

    c.bench_function("ram_store_list_keys_10", |b| {
        b.iter(|| {
            let keys = store.list_keys().unwrap();
            black_box(keys.len())
        })
    });
}

fn sizing_benchmarks(c: &mut Criterion) {
    let mut group = c.benchmark_group("data_sizes");

    // Test different data sizes for encryption/decryption performance
    for size in [64, 256, 1024, 4096].iter() {
        group.bench_with_input(BenchmarkId::new("zeroize", size), size, |b, &size| {
            use zeroize::Zeroize;
            b.iter(|| {
                let mut data = vec![42u8; size];
                data.zeroize();
                black_box(data)
            })
        });
    }

    group.finish();
}

// Quick Argon2 test with lower memory settings
fn quick_argon2_benchmark(c: &mut Criterion) {
    c.bench_function("argon2_kdf_16mb", |b| {
        b.iter(|| {
            // Direct argon2 call with lower memory for comparison
            use argon2::{Argon2, Params, Version};
            let params = Params::new(16 * 1024, 3, 1, Some(32)).unwrap();
            let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);
            let salt = b"test_salt_12345678901234567890";
            let mut key = vec![0u8; 32];
            argon2
                .hash_password_into(b"test_password_123", salt, &mut key)
                .unwrap();
            black_box(key)
        })
    });
}

criterion_group!(
    quick_benches,
    quick_crypto_benchmarks,
    quick_ram_store_benchmarks,
    sizing_benchmarks,
    quick_argon2_benchmark
);
criterion_main!(quick_benches);
