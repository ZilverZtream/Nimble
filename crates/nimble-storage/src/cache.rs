use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

const DEFAULT_CACHE_CAPACITY: usize = 1024;

#[derive(Hash, Eq, PartialEq, Clone, Copy, Debug)]
struct CacheKey {
    file_index: usize,
    offset: u64,
}

/// A thread-safe, in-memory block cache.
///
/// Designed to sit in front of the DiskWorker:
/// - Reads: Check cache first -> if miss, submit DiskRequest -> on completion, insert.
/// - Writes: Insert to cache -> submit DiskRequest immediately (write-through).
pub struct BlockCache {
    inner: Mutex<LruCache<CacheKey, Arc<Vec<u8>>>>,
}

impl BlockCache {
    pub fn new(capacity_blocks: usize) -> Self {
        let cap = NonZeroUsize::new(capacity_blocks)
            .or_else(|| NonZeroUsize::new(DEFAULT_CACHE_CAPACITY))
            .expect("default cache capacity must be non-zero");
        BlockCache {
            inner: Mutex::new(LruCache::new(cap)),
        }
    }

    /// Retrieves a block from the cache if available.
    pub fn get(&self, file_index: usize, offset: u64) -> Option<Arc<Vec<u8>>> {
        let mut cache = self.inner.lock().unwrap();
        cache.get(&CacheKey { file_index, offset }).cloned()
    }

    /// Inserts a block into the cache.
    pub fn insert(&self, file_index: usize, offset: u64, data: Vec<u8>) {
        let mut cache = self.inner.lock().unwrap();
        cache.put(CacheKey { file_index, offset }, Arc::new(data));
    }

    /// Inserts an existing Arc (e.g. from a write request).
    pub fn insert_arc(&self, file_index: usize, offset: u64, data: Arc<Vec<u8>>) {
        let mut cache = self.inner.lock().unwrap();
        cache.put(CacheKey { file_index, offset }, data);
    }

    /// Invalidates a specific block (e.g. on hash failure).
    pub fn remove(&self, file_index: usize, offset: u64) {
        let mut cache = self.inner.lock().unwrap();
        cache.pop(&CacheKey { file_index, offset });
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_insert_get_remove() {
        let cache = BlockCache::new(4);

        cache.insert(0, 0, vec![1, 2, 3]);
        cache.insert(0, 16, vec![4, 5, 6]);

        let data = cache.get(0, 0).expect("cache hit");
        assert_eq!(data.as_slice(), &[1, 2, 3]);

        cache.remove(0, 0);
        assert!(cache.get(0, 0).is_none());
    }

    #[test]
    fn test_cache_lru_eviction() {
        let cache = BlockCache::new(2);

        cache.insert(0, 0, vec![1]);
        cache.insert(0, 16, vec![2]);
        cache.get(0, 0);
        cache.insert(0, 32, vec![3]);

        assert!(cache.get(0, 16).is_none());
        assert!(cache.get(0, 0).is_some());
        assert!(cache.get(0, 32).is_some());
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn test_insert_arc_shares() {
        let cache = BlockCache::new(1);
        let data = Arc::new(vec![7, 8]);
        cache.insert_arc(1, 0, data.clone());

        let cached = cache.get(1, 0).expect("cache hit");
        assert!(Arc::ptr_eq(&cached, &data));
    }
}
