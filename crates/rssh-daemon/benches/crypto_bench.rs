use criterion::{Criterion, criterion_group, criterion_main};
use ed25519_dalek::{Signer, SigningKey};
use ssh_key::rand_core::OsRng as RandOsRng;
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use rsa::{RsaPrivateKey, RsaPublicKey};
use rssh_core::config::Config;
use rssh_core::ram_store::RamStore;
use rssh_daemon::signing;
use rssh_proto::wire;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use std::hint::black_box;

fn benchmark_argon2_kdf(c: &mut Criterion) {
    let temp_dir = TempDir::new().unwrap();

    c.bench_function("argon2_kdf_256mb", |b| {
        b.iter(|| {
            let config = Config::new_with_sentinel(temp_dir.path(), "test_password_123").unwrap();
            black_box(config.verify_sentinel("test_password_123"))
        })
    });

    // Benchmark different memory settings for optimization
    c.bench_function("argon2_kdf_64mb", |b| {
        b.iter(|| {
            // Direct argon2 call with lower memory for comparison
            use argon2::{Argon2, Params, Version};
            let params = Params::new(64 * 1024, 3, 1, Some(32)).unwrap();
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

fn benchmark_ram_store_operations(c: &mut Criterion) {
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

    c.bench_function("ram_store_list_keys_1000", |b| {
        // Load 1000 keys first
        for i in 0..1000 {
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

        b.iter(|| {
            let keys = store.list_keys().unwrap();
            black_box(keys.len())
        });
    });
}

fn benchmark_ed25519_signing(c: &mut Criterion) {
    // Generate test key
    let secret_key_bytes = [42u8; 32]; // Use fixed bytes for benchmarking
    let signing_key = SigningKey::from_bytes(&secret_key_bytes);
    let data_to_sign = b"test message to sign for performance benchmarking";

    c.bench_function("ed25519_sign_direct", |b| {
        b.iter(|| {
            let signature = signing_key.sign(black_box(data_to_sign));
            black_box(signature)
        })
    });

    // Test wire format signing (what the daemon uses)
    let mut wire_key_data = Vec::new();
    wire::write_string(&mut wire_key_data, b"ssh-ed25519");
    wire::write_string(&mut wire_key_data, signing_key.verifying_key().as_bytes());
    wire::write_string(&mut wire_key_data, &signing_key.to_keypair_bytes());

    c.bench_function("ed25519_sign_wire_format", |b| {
        b.iter(|| {
            let signature = signing::sign_data(&wire_key_data, data_to_sign, 0).unwrap();
            black_box(signature)
        })
    });
}

fn benchmark_rsa_signing(c: &mut Criterion) {
    // Generate 2048-bit RSA key
    let mut rng = RandOsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let _public_key = RsaPublicKey::from(&private_key);

    let data_to_sign = b"test message to sign for performance benchmarking";

    // Create wire format key data
    let mut wire_key_data = Vec::new();
    wire::write_string(&mut wire_key_data, b"ssh-rsa");

    // Write n (modulus) and e (public exponent)
    let n_bytes = private_key.n().to_bytes_be();
    let e_bytes = private_key.e().to_bytes_be();
    let d_bytes = private_key.d().to_bytes_be();
    let primes = private_key.primes();
    let p_bytes = primes[0].to_bytes_be();
    let q_bytes = primes[1].to_bytes_be();
    let iqmp_bytes = private_key.crt_coefficient().unwrap().to_bytes_be();

    wire::write_string(&mut wire_key_data, &n_bytes);
    wire::write_string(&mut wire_key_data, &e_bytes);
    wire::write_string(&mut wire_key_data, &d_bytes);
    wire::write_string(&mut wire_key_data, &iqmp_bytes);
    wire::write_string(&mut wire_key_data, &p_bytes);
    wire::write_string(&mut wire_key_data, &q_bytes);

    c.bench_function("rsa_2048_sign_sha256", |b| {
        b.iter(|| {
            let signature = signing::sign_data(&wire_key_data, data_to_sign, 0x02).unwrap();
            black_box(signature)
        })
    });

    c.bench_function("rsa_2048_sign_sha512", |b| {
        b.iter(|| {
            let signature = signing::sign_data(&wire_key_data, data_to_sign, 0x04).unwrap();
            black_box(signature)
        })
    });
}

fn benchmark_fingerprint_calculation(c: &mut Criterion) {
    let test_public_key = vec![0u8; 32]; // Ed25519 public key size

    c.bench_function("fingerprint_sha256", |b| {
        b.iter(|| {
            let mut hasher = Sha256::new();
            hasher.update(&test_public_key);
            let result = hasher.finalize();
            black_box(hex::encode(result))
        })
    });
}

fn benchmark_memory_operations(c: &mut Criterion) {
    use zeroize::Zeroize;

    c.bench_function("zeroize_1kb", |b| {
        b.iter(|| {
            let mut data = vec![42u8; 1024];
            data.zeroize();
            black_box(data)
        })
    });

    c.bench_function("zeroize_64kb", |b| {
        b.iter(|| {
            let mut data = vec![42u8; 65536];
            data.zeroize();
            black_box(data)
        })
    });
}

criterion_group!(
    benches,
    benchmark_argon2_kdf,
    benchmark_ram_store_operations,
    benchmark_ed25519_signing,
    benchmark_rsa_signing,
    benchmark_fingerprint_calculation,
    benchmark_memory_operations
);
criterion_main!(benches);
