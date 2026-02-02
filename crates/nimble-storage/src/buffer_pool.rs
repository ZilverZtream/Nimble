use std::sync::{Arc, Mutex, OnceLock};

static GLOBAL_BUFFER_POOL: OnceLock<BufferPool> = OnceLock::new();

/// Gets the global buffer pool instance.
/// Pool is initialized on first access with 16KB buffers and max 256 buffers.
pub fn global_pool() -> &'static BufferPool {
    GLOBAL_BUFFER_POOL.get_or_init(|| {
        const BLOCK_SIZE: usize = 16384;
        const MAX_BUFFERS: usize = 256;
        BufferPool::new(BLOCK_SIZE, MAX_BUFFERS)
    })
}

/// A pool of reusable buffers to reduce allocations for piece data.
///
/// Issue #10 Fix: Implements buffer pooling to eliminate excessive memory copying.
/// Instead of allocating new Vec<u8> for every piece block, buffers are reused
/// from a global pool, reducing GC pressure and improving throughput.
#[derive(Clone)]
pub struct BufferPool {
    inner: Arc<Mutex<BufferPoolInner>>,
}

struct BufferPoolInner {
    buffers: Vec<Vec<u8>>,
    buffer_size: usize,
    max_buffers: usize,
}

/// RAII wrapper for a pooled buffer. Returns buffer to pool on drop.
pub struct PooledBuffer {
    data: Option<Vec<u8>>,
    pool: Arc<Mutex<BufferPoolInner>>,
}

impl BufferPool {
    /// Creates a new buffer pool.
    ///
    /// # Arguments
    /// * `buffer_size` - Size of each buffer (typically 16KB for blocks)
    /// * `max_buffers` - Maximum number of buffers to keep in pool
    pub fn new(buffer_size: usize, max_buffers: usize) -> Self {
        BufferPool {
            inner: Arc::new(Mutex::new(BufferPoolInner {
                buffers: Vec::with_capacity(max_buffers),
                buffer_size,
                max_buffers,
            })),
        }
    }

    /// Gets a buffer from the pool, or allocates a new one if pool is empty.
    pub fn get(&self) -> PooledBuffer {
        let mut inner = self.inner.lock().unwrap();
        let data = inner.buffers.pop().unwrap_or_else(|| Vec::with_capacity(inner.buffer_size));

        PooledBuffer {
            data: Some(data),
            pool: self.inner.clone(),
        }
    }

    /// Returns a buffer to the pool.
    fn return_buffer(&self, mut buffer: Vec<u8>) {
        let mut inner = self.inner.lock().unwrap();
        if inner.buffers.len() < inner.max_buffers {
            buffer.clear();
            inner.buffers.push(buffer);
        }
    }

    /// Returns the number of buffers currently in the pool.
    pub fn size(&self) -> usize {
        self.inner.lock().unwrap().buffers.len()
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
            let pool = self.pool.lock().unwrap();
            if pool.buffers.len() < pool.max_buffers {
                drop(pool);
                BufferPool { inner: self.pool.clone() }.return_buffer(data);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer_pool_reuse() {
        let pool = BufferPool::new(1024, 10);

        {
            let mut buf = pool.get();
            buf.as_mut().extend_from_slice(&[1, 2, 3]);
        }

        assert_eq!(pool.size(), 1);

        let buf = pool.get();
        assert_eq!(buf.as_slice().len(), 0);
    }

    #[test]
    fn test_buffer_pool_max_size() {
        let pool = BufferPool::new(1024, 2);

        {
            let _buf1 = pool.get();
            let _buf2 = pool.get();
            let _buf3 = pool.get();
        }

        assert_eq!(pool.size(), 2);
    }

    #[test]
    fn test_buffer_take() {
        let pool = BufferPool::new(1024, 10);

        let mut buf = pool.get();
        buf.as_mut().extend_from_slice(&[1, 2, 3]);
        let data = buf.take();

        assert_eq!(data.len(), 3);
        assert_eq!(pool.size(), 0);
    }
}
