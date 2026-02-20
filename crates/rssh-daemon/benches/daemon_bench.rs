use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use rssh_core::config::Config;
use rssh_daemon::agent::Agent;
use rssh_proto::{messages, wire};
use tempfile::TempDir;
use tokio::runtime::Runtime;
use std::hint::black_box;

fn benchmark_agent_operations(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("agent_handle_request_identities", |b| {
        let temp_dir = TempDir::new().unwrap();
        let config = Config::new_with_sentinel(temp_dir.path(), "test_password_123").unwrap();
        let agent = rt.block_on(Agent::new(config));
        let msg = vec![wire::MessageType::RequestIdentities as u8];

        b.iter(|| {
            rt.block_on(async {
                let response = agent.handle_message(&msg).await.unwrap();
                black_box(response)
            })
        })
    });

    c.bench_function("agent_handle_lock_unlock_cycle", |b| {
        let temp_dir = TempDir::new().unwrap();
        let config = Config::new_with_sentinel(temp_dir.path(), "test_password_123").unwrap();
        let agent = rt.block_on(Agent::new(config));

        b.iter_batched(
            || {
                // Setup: create lock and unlock messages
                let mut lock_msg = vec![wire::MessageType::Lock as u8];
                wire::write_string(&mut lock_msg, b"test_lock_password");

                let mut unlock_msg = vec![wire::MessageType::Unlock as u8];
                wire::write_string(&mut unlock_msg, b"test_lock_password");

                (lock_msg, unlock_msg)
            },
            |(lock_msg, unlock_msg)| {
                rt.block_on(async {
                    // Skip accessing private fields for benchmark
                    let lock_response = agent.handle_message(&lock_msg).await.unwrap();
                    let unlock_response = agent.handle_message(&unlock_msg).await.unwrap();
                    black_box((lock_response, unlock_response))
                })
            },
            BatchSize::SmallInput,
        )
    });
}

fn benchmark_message_parsing(c: &mut Criterion) {
    c.bench_function("parse_request_identities", |b| {
        let msg = vec![wire::MessageType::RequestIdentities as u8];
        b.iter(|| {
            let result = messages::parse_request_identities(&msg);
            black_box(result)
        })
    });

    c.bench_function("parse_add_identity", |b| {
        // Create a simple add identity message
        let mut msg = vec![wire::MessageType::AddIdentity as u8];
        // Add fake key data (simplified)
        wire::write_string(&mut msg, b"ssh-ed25519");
        wire::write_string(&mut msg, &[0u8; 32]); // fake public key
        wire::write_string(&mut msg, &[0u8; 64]); // fake private key
        wire::write_string(&mut msg, b"test key"); // comment

        b.iter(|| {
            let result = messages::parse_add_identity(&msg);
            black_box(result)
        })
    });
}

fn benchmark_wire_format_operations(c: &mut Criterion) {
    c.bench_function("wire_write_string_small", |b| {
        let data = b"ssh-ed25519";
        b.iter(|| {
            let mut buf = Vec::new();
            wire::write_string(&mut buf, data);
            black_box(buf)
        })
    });

    c.bench_function("wire_write_string_large", |b| {
        let data = vec![42u8; 4096];
        b.iter(|| {
            let mut buf = Vec::new();
            wire::write_string(&mut buf, &data);
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

fn benchmark_concurrent_operations(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("concurrent_request_identities_10", |b| {
        let temp_dir = TempDir::new().unwrap();
        let config = Config::new_with_sentinel(temp_dir.path(), "test_password_123").unwrap();
        let agent = std::sync::Arc::new(rt.block_on(Agent::new(config)));
        let msg = vec![wire::MessageType::RequestIdentities as u8];

        b.iter(|| {
            let agent = agent.clone();
            let msg = msg.clone();
            rt.block_on(async move {
                let handles: Vec<_> = (0..10)
                    .map(|_| {
                        let agent = agent.clone();
                        let msg = msg.clone();
                        tokio::spawn(async move { agent.handle_message(&msg).await.unwrap() })
                    })
                    .collect();

                let mut results = Vec::new();
                for handle in handles {
                    results.push(handle.await.unwrap());
                }
                black_box(results)
            })
        })
    });
}

criterion_group!(
    benches,
    benchmark_agent_operations,
    benchmark_message_parsing,
    benchmark_wire_format_operations,
    benchmark_concurrent_operations
);
criterion_main!(benches);
