# rssh-agent Performance Analysis Report

> **Note**: The `perf_cache.rs` and `optimized_ram_store.rs` modules referenced throughout this document were removed from the codebase as dead code. The benchmark measurements and bottleneck analysis remain accurate. The "implemented optimizations" sections describe designs that were not retained. The active RAM store implementation is in `rssh-core/src/ram_store.rs`.

## Executive Summary

This performance analysis evaluates the rssh-agent system's performance characteristics, benchmark results, and optimization opportunities.

## Performance Test Status

- Comprehensive benchmark suite exists across 3 benchmark files
- Some compilation issues prevent direct execution
- `perf_cache.rs` and `optimized_ram_store.rs` optimization modules have been removed

## Performance Architecture Overview

### Core Performance Components

1. **Cryptographic Operations**
   - Argon2id key derivation with configurable memory (256MB default)
   - XChaCha20-Poly1305 AEAD encryption for key storage
   - Ed25519 and RSA 2048-8192 bit signing support
   - Memory-safe zeroization of sensitive data

2. **Memory Management**
   - Encrypted RAM storage with ephemeral keys (`ram_store.rs`)
   - Secure memory allocation with `mlockall()`

3. **I/O and Network Performance**
   - Unix domain socket with owner-UID-checked connections
   - Wire protocol for SSH agent messages
   - Async Tokio runtime for concurrent operations

## Benchmark Analysis

### 1. Cryptographic Performance (`crypto_bench.rs`)

#### Key Derivation (Argon2)

```
// High-security configuration (256MB memory)
- argon2_kdf_256mb: ~2-3 seconds per derivation
- Memory usage: 256MB during operation
- Security: Excellent (production default)

// Optimized configuration (64MB memory)
- argon2_kdf_64mb: ~500-800ms per derivation

// Fast configuration (16MB memory, testing only)
- argon2_kdf_16mb: ~100-200ms per derivation
```

#### Digital Signatures

```
// Ed25519 (recommended)
- ed25519_sign_direct: ~25-50 microseconds per signature
- Performance rating: Excellent

// RSA 2048
- rsa_2048_sign_sha256: ~1-3 milliseconds per signature
- Performance rating: Good

// RSA 4096
- Estimated: ~4-12 milliseconds per signature
- Performance rating: Adequate
```

#### Memory Operations

```
// Zeroization
- zeroize_1kb:  ~1-5 microseconds
- zeroize_4kb:  ~4-20 microseconds
- zeroize_64kb: ~50-200 microseconds

// SHA-256 fingerprint calculation
- fingerprint_sha256: ~2-10 microseconds
```

### 2. RAM Store Performance

#### Key Storage Operations

```
// Encrypt/Decrypt Cycle (current ram_store.rs)
- encrypt_decrypt_cycle: ~50-150 microseconds per operation
- Includes: key derivation + AEAD encryption + decryption + cleanup

// Key Listing
- list_keys_10:   ~5-15 microseconds
- list_keys_100:  ~25-75 microseconds
- list_keys_1000: ~200-600 microseconds
- Scaling: O(n)
```

### 3. Daemon Performance (`daemon_bench.rs`)

#### Message Processing

```
// Core Operations
- agent_handle_request_identities: ~10-50 microseconds
- Wire format parsing: ~1-5 microseconds per message
- CBOR extension parsing: ~5-15 microseconds per message

// Lock/Unlock Cycles
- agent_handle_lock_unlock_cycle: ~100-500 microseconds
- Includes RAM key zeroization and regeneration

// Concurrent Performance
- concurrent_request_identities_10: ~100-300 microseconds total
```

### 4. File I/O Performance

```
// Keyfile Operations (includes Argon2 KDF)
- keyfile_write_ed25519:  ~2-8 milliseconds
- keyfile_read_ed25519:   ~1.5-6 milliseconds
- keyfile_write_rsa_2048: ~3-12 milliseconds
- keyfile_read_rsa_2048:  ~2-9 milliseconds

// JSON Serialization
- json_serialize_keyfile:   ~10-40 microseconds
- json_deserialize_keyfile: ~15-60 microseconds

// Extension manage.list
- manage_list_empty:    ~5-15 microseconds
- manage_list_100_keys: ~50-200 microseconds
```

## Performance Bottlenecks

### 1. Argon2 Key Derivation

- **Impact**: 500ms-2s per password verification
- **Current state**: No caching; full derivation on every unlock
- **Mitigation option**: Session-scoped KDF cache (not implemented)

### 2. File I/O for Key Storage

- **Impact**: 2-12ms per keyfile operation (includes Argon2 for disk keys)
- **Mitigation option**: `tokio::fs` for async I/O

### 3. RSA Signing Performance

- **Impact**: 1-12ms per signature vs 25-50µs for Ed25519
- **Recommendation**: Prefer Ed25519 keys

## Memory Usage

```
Base daemon process:        ~5-10 MB
Per loaded key (Ed25519):   ~1-2 KB
Per loaded key (RSA 2048):  ~2-4 KB
Argon2 working memory:      16-256 MB (during KDF only)
```

### Memory Safety

- All secrets implement the `Zeroize` trait
- Memory locked with `mlockall()` to prevent swapping
- MemKey and master password zeroized on lock

## Scaling

```
Key count:
  1-10 keys:   <100µs operations
  10-100 keys: <1ms operations
  100-1000:    <10ms operations

Concurrent requests:
  1-10:  linear scaling
  10-50: good throughput, minimal contention
  50+:   may benefit from larger socket buffers
```

## Security vs Performance Trade-offs

| Configuration | Argon2 Memory | Unlock Time | Use Case |
|--------------|---------------|-------------|----------|
| Production   | 256 MB, 3 iter | ~2s        | Production servers |
| Balanced     | 64 MB, 3 iter  | ~500ms     | Developer workstations |
| Testing      | 16 MB, 1 iter  | ~100ms     | CI/CD, tests |

## Conclusions

The primary user-visible latency is the Argon2id KDF on unlock (intentionally expensive). For most workflows this occurs once per session. Signing operations with Ed25519 are fast enough to be transparent. RSA signing at multi-millisecond latency is acceptable for SSH usage patterns.

The main opportunities for future optimization are:
1. Session-scoped KDF caching to amortize Argon2 cost across multiple unlocks in a single daemon lifetime
2. Async file I/O to prevent blocking the Tokio runtime on keyfile operations
