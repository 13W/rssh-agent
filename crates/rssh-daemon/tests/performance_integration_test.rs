//! Integration tests for performance optimizations
//!
//! These tests validate that the optimizations work correctly and provide
//! measurable performance improvements while maintaining correctness.

use rssh_core::{config::Config, perf_cache::{KeyDerivationCache, ConnectionKeyCache}};
use rssh_daemon::optimized_socket::ConnectionStats;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio;

#[tokio::test]
async fn test_kdf_cache_performance() {
    let cache = KeyDerivationCache::new(10, Duration::from_secs(300));
    
    // First derivation (should be slow)
    let start = Instant::now();
    let result1 = cache.get_or_derive("test_key", || {
        // Simulate expensive KDF
        std::thread::sleep(Duration::from_millis(100));
        Ok([42u8; 32])
    }).unwrap();
    let first_duration = start.elapsed();
    
    // Second derivation (should be fast - cached)
    let start = Instant::now();
    let result2 = cache.get_or_derive("test_key", || {
        // This should not be called
        panic!("Should use cached value");
    }).unwrap();
    let second_duration = start.elapsed();
    
    assert_eq!(result1, result2);
    assert!(first_duration > Duration::from_millis(50)); // First call is slow
    assert!(second_duration < Duration::from_millis(10)); // Second call is fast (cached)
    
    println!("KDF Cache Performance:");
    println!("  First call: {:?}", first_duration);
    println!("  Cached call: {:?}", second_duration);
    println!("  Speedup: {:.1}x", first_duration.as_nanos() as f64 / second_duration.as_nanos() as f64);
}

#[tokio::test]
async fn test_connection_key_cache() {
    let cache = ConnectionKeyCache::new(5);
    let test_key = vec![1, 2, 3, 4, 5];
    
    // Cache a key
    cache.cache_key("conn1", "key1", test_key.clone());
    
    // Retrieve it
    let start = Instant::now();
    let retrieved = cache.get_key("conn1", "key1");
    let cache_duration = start.elapsed();
    
    assert_eq!(retrieved, Some(test_key));
    assert!(cache_duration < Duration::from_millis(1)); // Should be very fast
    
    println!("Connection Key Cache:");
    println!("  Cache retrieval: {:?}", cache_duration);
}

#[tokio::test]
async fn test_connection_stats() {
    let stats = Arc::new(ConnectionStats {
        total_connections: std::sync::atomic::AtomicU64::new(0),
        active_connections: std::sync::atomic::AtomicU64::new(0),
        total_requests: std::sync::atomic::AtomicU64::new(0),
        average_response_time_ms: std::sync::atomic::AtomicU64::new(0),
    });
    
    // Simulate some activity
    stats.total_connections.fetch_add(5, Ordering::Relaxed);
    stats.active_connections.fetch_add(3, Ordering::Relaxed);
    stats.total_requests.fetch_add(100, Ordering::Relaxed);
    stats.average_response_time_ms.store(25, Ordering::Relaxed);
    
    // Verify stats
    assert_eq!(stats.total_connections.load(Ordering::Relaxed), 5);
    assert_eq!(stats.active_connections.load(Ordering::Relaxed), 3);
    assert_eq!(stats.total_requests.load(Ordering::Relaxed), 100);
    assert_eq!(stats.average_response_time_ms.load(Ordering::Relaxed), 25);
    
    println!("Connection Stats Test:");
    println!("  Total connections: {}", stats.total_connections.load(Ordering::Relaxed));
    println!("  Active connections: {}", stats.active_connections.load(Ordering::Relaxed));
    println!("  Total requests: {}", stats.total_requests.load(Ordering::Relaxed));
    println!("  Average response time: {}ms", stats.average_response_time_ms.load(Ordering::Relaxed));
}

#[tokio::test]
async fn test_cache_memory_cleanup() {
    let cache = ConnectionKeyCache::new(2); // Small cache for testing eviction
    
    // Fill cache beyond capacity
    cache.cache_key("conn1", "key1", vec![1, 2, 3]);
    cache.cache_key("conn1", "key2", vec![4, 5, 6]);
    cache.cache_key("conn1", "key3", vec![7, 8, 9]); // Should evict one of the earlier keys
    
    // Check that we don't have all three keys (one should be evicted)
    let keys = [
        cache.get_key("conn1", "key1"),
        cache.get_key("conn1", "key2"), 
        cache.get_key("conn1", "key3"),
    ];
    
    let present_count = keys.iter().filter(|k| k.is_some()).count();
    assert_eq!(present_count, 2, "Cache should limit to 2 keys and evict excess");
    
    println!("Cache Eviction Test:");
    println!("  Keys present after eviction: {}/3", present_count);
}

#[tokio::test]
async fn test_cache_connection_isolation() {
    let cache = ConnectionKeyCache::new(5);
    
    // Cache keys for different connections
    cache.cache_key("conn1", "key1", vec![1, 1, 1]);
    cache.cache_key("conn2", "key1", vec![2, 2, 2]); // Same key ID, different connection
    
    // Verify isolation
    assert_eq!(cache.get_key("conn1", "key1"), Some(vec![1, 1, 1]));
    assert_eq!(cache.get_key("conn2", "key1"), Some(vec![2, 2, 2]));
    
    // Clear one connection
    cache.clear_connection("conn1");
    
    // Verify conn1 is cleared but conn2 remains
    assert_eq!(cache.get_key("conn1", "key1"), None);
    assert_eq!(cache.get_key("conn2", "key1"), Some(vec![2, 2, 2]));
    
    println!("Connection Isolation Test: PASSED");
}

#[test]
fn test_performance_baseline() {
    // This test establishes baseline measurements for comparison
    println!("=== Performance Baseline Test ===");
    
    // Test basic Vec allocation performance
    let start = Instant::now();
    let mut vectors = Vec::new();
    for i in 0..1000 {
        let mut v = Vec::with_capacity(1024);
        v.extend(std::iter::repeat(i as u8).take(1024));
        vectors.push(v);
    }
    let allocation_time = start.elapsed();
    
    println!("Baseline Measurements:");
    println!("  1000 x 1KB Vec allocations: {:?}", allocation_time);
    println!("  Per allocation: {:?}", allocation_time / 1000);
    
    // Basic crypto operations baseline would go here
    // (requires actual crypto library integration)
    
    assert!(allocation_time < Duration::from_millis(100), "Basic allocation should be fast");
}

// Helper function to format duration nicely
fn format_duration(d: Duration) -> String {
    if d.as_secs() > 0 {
        format!("{:.2}s", d.as_secs_f64())
    } else if d.as_millis() > 0 {
        format!("{}ms", d.as_millis())
    } else if d.as_micros() > 0 {
        format!("{}μs", d.as_micros())
    } else {
        format!("{}ns", d.as_nanos())
    }
}
