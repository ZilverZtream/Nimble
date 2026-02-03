use crossbeam_queue::SegQueue;
use std::sync::{Arc, OnceLock};

static GLOBAL_BUFFER_POOL: OnceLock<BufferPool> = OnceLock::new();

/// Gets the global buffer pool instance.
/// Pool is initialized on first access with 16KB buffers.
pub fn global_pool() -> &'static BufferPool {
    GLOBAL_BUFFER_POOL.get_or_init(|| {
        const BLOCK_SIZE: usize = 16384;
        BufferPool::new(BLOCK_SIZE)
    })
}

/// A pool of reusable buffers to reduce allocations for piece data.
///
/// Implements buffer pooling to eliminate excessive memory copying.
/// Instead of allocating new Vec<u8> for every piece block, buffers are reused
/// from a global pool, reducing GC pressure and improving throughput.
#[derive(Clone)]
pub struct BufferPool {
    queue: Arc<SegQueue<Vec<u8>>>,
    buffer_size: usize,
}

/// RAII wrapper for a pooled buffer. Returns buffer to pool on drop.
pub struct PooledBuffer {
    data: Option<Vec<u8>>,
    pool: BufferPool,
}

impl BufferPool {
    /// Creates a new buffer pool.
    ///
    /// # Arguments
    /// * `buffer_size` - Size of each buffer (typically 16KB for blocks)
    pub fn new(buffer_size: usize) -> Self {
        BufferPool {
            queue: Arc::new(SegQueue::new()),
            buffer_size,
        }
    }

    /// Gets a buffer from the pool, or allocates a new one if pool is empty.
    ///
    /// This method is lock-free. Use `try_get()` if you want to avoid
    /// allocating a new buffer when the pool is empty.
    pub fn get(&self) -> PooledBuffer {
        let data = self.queue.pop().unwrap_or_else(|| Vec::with_capacity(self.buffer_size));

        PooledBuffer {
            data: Some(data),
            pool: self.clone(),
        }
    }

    /// Attempts to get a buffer from the pool without allocating.
    ///
    pub fn try_get(&self) -> Option<PooledBuffer> {
        let data = self.queue.pop()?;

        Some(PooledBuffer {
            data: Some(data),
            pool: self.clone(),
        })
    }

    /// Returns the number of buffers currently in the pool (approximate).
    pub fn size(&self) -> usize {
        self.queue.len()
    }
}

impl PooledBuffer {
    /// Takes ownership of the internal buffer, consuming this PooledBuffer.
    /// The buffer will NOT be returned to the pool.
    pub fn take(mut self) -> Vec<u8> {
        self.data.take().unwrap()
    }

    /// Gets a mutable reference to the buffer data.
    pub fn as_mut(&mut self) -> &mut Vec<u8> {
        self.data.as_mut().unwrap()
    }

    /// Gets an immutable reference to the buffer data.
    pub fn as_ref(&self) -> &Vec<u8> {
        self.data.as_ref().unwrap()
    }

    /// Gets the buffer as a slice.
    pub fn as_slice(&self) -> &[u8] {
        self.data.as_ref().unwrap()
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        if let Some(data) = self.data.take() {
            let mut data = data;
            data.clear();
            self.pool.queue.push(data);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer_pool_reuse() {
        let pool = BufferPool::new(1024);

        {
            let mut buf = pool.get();
            buf.as_mut().extend_from_slice(&[1, 2, 3]);
        }

        assert_eq!(pool.size(), 1);

        let buf = pool.get();
        assert_eq!(buf.as_slice().len(), 0);
    }

    #[test]
    fn test_buffer_take() {
        let pool = BufferPool::new(1024);

        let mut buf = pool.get();
        buf.as_mut().extend_from_slice(&[1, 2, 3]);
        let data = buf.take();

        assert_eq!(data.len(), 3);
        assert_eq!(pool.size(), 0);
    }
}
