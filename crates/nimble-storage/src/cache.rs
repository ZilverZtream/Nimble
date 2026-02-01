use anyhow::{Context, Result};
use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::mpsc::{channel, Sender, Receiver, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const DEFAULT_CACHE_SIZE: usize = 32 * 1024 * 1024;
const FLUSH_INTERVAL: Duration = Duration::from_secs(10);
const BLOCK_SIZE: usize = 16384;
const MAX_QUEUED_WRITES: usize = 2048;

#[derive(Debug, Clone)]
struct CachedWrite {
    file_index: usize,
    offset: u64,
    data: Vec<u8>,
    timestamp: Instant,
}

enum CacheCommand {
    Write {
        file_index: usize,
        offset: u64,
        data: Vec<u8>,
    },
    Flush,
    Shutdown,
}

struct CacheWorker {
    receiver: Receiver<CacheCommand>,
    file_handles: HashMap<usize, File>,
    file_paths: HashMap<usize, PathBuf>,
    pending_writes: VecDeque<CachedWrite>,
    cache_size: usize,
    current_cache_bytes: usize,
}

impl CacheWorker {
    fn new(
        receiver: Receiver<CacheCommand>,
        file_paths: HashMap<usize, PathBuf>,
        cache_size: usize,
    ) -> Self {
        CacheWorker {
            receiver,
            file_handles: HashMap::new(),
            file_paths,
            pending_writes: VecDeque::new(),
            cache_size,
            current_cache_bytes: 0,
        }
    }

    fn run(&mut self) {
        let mut last_flush = Instant::now();

        loop {
            let should_flush = last_flush.elapsed() >= FLUSH_INTERVAL
                || self.current_cache_bytes >= self.cache_size;

            if should_flush {
                if let Err(e) = self.flush_all() {
                    eprintln!("Cache flush error: {}", e);
                }
                last_flush = Instant::now();
            }

            match self.receiver.try_recv() {
                Ok(CacheCommand::Write { file_index, offset, data }) => {
                    self.queue_write(file_index, offset, data);
                }
                Ok(CacheCommand::Flush) => {
                    if let Err(e) = self.flush_all() {
                        eprintln!("Explicit flush error: {}", e);
                    }
                    last_flush = Instant::now();
                }
                Ok(CacheCommand::Shutdown) => {
                    let _ = self.flush_all();
                    self.close_all_files();
                    break;
                }
                Err(TryRecvError::Empty) => {
                    thread::sleep(Duration::from_millis(50));
                }
                Err(TryRecvError::Disconnected) => {
                    let _ = self.flush_all();
                    self.close_all_files();
                    break;
                }
            }

            if self.current_cache_bytes >= self.cache_size * 2 {
                if let Err(e) = self.flush_oldest(self.cache_size) {
                    eprintln!("Emergency flush error: {}", e);
                }
            }
        }
    }

    fn queue_write(&mut self, file_index: usize, offset: u64, data: Vec<u8>) {
        let data_len = data.len();

        self.pending_writes.push_back(CachedWrite {
            file_index,
            offset,
            data,
            timestamp: Instant::now(),
        });

        self.current_cache_bytes += data_len;

        if self.pending_writes.len() > MAX_QUEUED_WRITES {
            if let Err(e) = self.flush_oldest(BLOCK_SIZE * 16) {
                eprintln!("Queue overflow flush error: {}", e);
            }
        }
    }

    fn flush_oldest(&mut self, target_bytes: usize) -> Result<()> {
        let mut flushed = 0;
        let mut writes_to_flush = Vec::new();

        while flushed < target_bytes {
            match self.pending_writes.pop_front() {
                Some(write) => {
                    flushed += write.data.len();
                    writes_to_flush.push(write);
                }
                None => break,
            }
        }

        for write in writes_to_flush {
            self.write_to_disk(&write)?;
        }

        Ok(())
    }

    fn flush_all(&mut self) -> Result<()> {
        while let Some(write) = self.pending_writes.pop_front() {
            self.write_to_disk(&write)?;
        }

        for file in self.file_handles.values_mut() {
            file.flush().context("Failed to flush file to disk")?;
        }

        self.current_cache_bytes = 0;
        Ok(())
    }

    fn write_to_disk(&mut self, write: &CachedWrite) -> Result<()> {
        let file = self.get_or_open_file(write.file_index)?;

        file.seek(SeekFrom::Start(write.offset))
            .context("Failed to seek in file")?;

        file.write_all(&write.data)
            .context("Failed to write block to file")?;

        self.current_cache_bytes = self.current_cache_bytes.saturating_sub(write.data.len());

        Ok(())
    }

    fn get_or_open_file(&mut self, file_index: usize) -> Result<&mut File> {
        if !self.file_handles.contains_key(&file_index) {
            let path = self.file_paths.get(&file_index)
                .context("File index not found in paths")?;

            let file = File::options()
                .read(true)
                .write(true)
                .create(true)
                .open(path)
                .with_context(|| format!("Failed to open file: {:?}", path))?;

            self.file_handles.insert(file_index, file);
        }

        self.file_handles.get_mut(&file_index)
            .ok_or_else(|| anyhow::anyhow!("File handle missing after insertion for index {}", file_index))
    }

    fn close_all_files(&mut self) {
        for (_, mut file) in self.file_handles.drain() {
            let _ = file.flush();
        }
    }
}

pub struct DiskCache {
    sender: Sender<CacheCommand>,
    worker_handle: Option<JoinHandle<()>>,
    stats: Arc<Mutex<CacheStats>>,
}

#[derive(Debug, Default, Clone)]
pub struct CacheStats {
    pub writes_queued: u64,
    pub writes_completed: u64,
    pub bytes_cached: u64,
    pub flushes: u64,
}

impl DiskCache {
    pub fn new(file_paths: HashMap<usize, PathBuf>) -> Self {
        Self::with_size(file_paths, DEFAULT_CACHE_SIZE)
    }

    pub fn with_size(file_paths: HashMap<usize, PathBuf>, cache_size: usize) -> Self {
        let (sender, receiver) = channel();
        let stats = Arc::new(Mutex::new(CacheStats::default()));

        let mut worker = CacheWorker::new(receiver, file_paths, cache_size);

        let worker_handle = thread::Builder::new()
            .name("disk-cache-worker".to_string())
            .spawn(move || {
                worker.run();
            })
            .expect("Failed to spawn cache worker thread");

        DiskCache {
            sender,
            worker_handle: Some(worker_handle),
            stats,
        }
    }

    pub fn write_block(&self, file_index: usize, offset: u64, data: Vec<u8>) -> Result<()> {
        if let Ok(mut stats) = self.stats.lock() {
            stats.writes_queued += 1;
            stats.bytes_cached += data.len() as u64;
        }

        self.sender
            .send(CacheCommand::Write {
                file_index,
                offset,
                data,
            })
            .context("Failed to send write command to cache worker")?;

        Ok(())
    }

    pub fn flush(&self) -> Result<()> {
        if let Ok(mut stats) = self.stats.lock() {
            stats.flushes += 1;
        }

        self.sender
            .send(CacheCommand::Flush)
            .context("Failed to send flush command")?;

        Ok(())
    }

    pub fn get_stats(&self) -> CacheStats {
        self.stats.lock()
            .map(|s| s.clone())
            .unwrap_or_default()
    }

    pub fn shutdown(&mut self) {
        let _ = self.sender.send(CacheCommand::Shutdown);

        if let Some(handle) = self.worker_handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for DiskCache {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_cache_creation() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("test.dat");

        let mut file_paths = HashMap::new();
        file_paths.insert(0, path);

        let cache = DiskCache::new(file_paths);
        drop(cache);
    }

    #[test]
    fn test_write_and_flush() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("test.dat");

        let mut file_paths = HashMap::new();
        file_paths.insert(0, path.clone());

        let cache = DiskCache::new(file_paths);

        let data = vec![1u8, 2, 3, 4, 5];
        cache.write_block(0, 0, data.clone()).unwrap();

        cache.flush().unwrap();
        thread::sleep(Duration::from_millis(200));

        let read_data = fs::read(&path).unwrap();
        assert_eq!(&read_data[..5], &data[..]);
    }

    #[test]
    fn test_multiple_writes() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("test.dat");

        let mut file_paths = HashMap::new();
        file_paths.insert(0, path.clone());

        let mut cache = DiskCache::new(file_paths);

        for i in 0..10 {
            let data = vec![i as u8; 1024];
            cache.write_block(0, i * 1024, data).unwrap();
        }

        cache.shutdown();
        thread::sleep(Duration::from_millis(100));

        let metadata = fs::metadata(&path).unwrap();
        assert!(metadata.len() >= 10240);
    }

    #[test]
    fn test_stats_tracking() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("test.dat");

        let mut file_paths = HashMap::new();
        file_paths.insert(0, path);

        let cache = DiskCache::new(file_paths);

        cache.write_block(0, 0, vec![1, 2, 3, 4]).unwrap();
        cache.write_block(0, 4, vec![5, 6, 7, 8]).unwrap();

        thread::sleep(Duration::from_millis(50));

        let stats = cache.get_stats();
        assert_eq!(stats.writes_queued, 2);
        assert!(stats.bytes_cached > 0);
    }
}
