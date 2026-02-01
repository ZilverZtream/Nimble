use anyhow::{Context, Result};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;

const IO_THREAD_COUNT: usize = 4;

#[derive(Debug)]
pub enum IoRequest {
    ReadBlock {
        request_id: u64,
        file_index: usize,
        file_offset: u64,
        length: usize,
    },
    WriteSegment {
        request_id: u64,
        file_index: usize,
        file_offset: u64,
        data: Vec<u8>,
    },
    Shutdown,
}

#[derive(Debug)]
pub enum IoResponse {
    ReadComplete {
        request_id: u64,
        data: Result<Vec<u8>>,
    },
    WriteComplete {
        request_id: u64,
        result: Result<()>,
    },
}

pub struct IoPool {
    request_tx: Sender<IoRequest>,
    response_rx: Receiver<IoResponse>,
    next_request_id: u64,
    pending_reads: HashMap<u64, ()>,
    pending_writes: HashMap<u64, ()>,
}

impl IoPool {
    pub fn new(
        file_paths: Vec<PathBuf>,
        download_dir: PathBuf,
    ) -> Result<Self> {
        let (request_tx, request_rx) = channel::<IoRequest>();
        let (response_tx, response_rx) = channel::<IoResponse>();

        let request_rx = std::sync::Arc::new(std::sync::Mutex::new(request_rx));

        for thread_id in 0..IO_THREAD_COUNT {
            let rx = request_rx.clone();
            let tx = response_tx.clone();
            let paths = file_paths.clone();
            let base_dir = download_dir.clone();

            thread::Builder::new()
                .name(format!("io-worker-{}", thread_id))
                .spawn(move || {
                    io_worker_thread(rx, tx, paths, base_dir);
                })
                .context("failed to spawn I/O worker thread")?;
        }

        Ok(IoPool {
            request_tx,
            response_rx,
            next_request_id: 0,
            pending_reads: HashMap::new(),
            pending_writes: HashMap::new(),
        })
    }

    pub fn submit_read(
        &mut self,
        file_index: usize,
        file_offset: u64,
        length: usize,
    ) -> u64 {
        let request_id = self.next_request_id;
        self.next_request_id += 1;

        self.pending_reads.insert(request_id, ());

        let _ = self.request_tx.send(IoRequest::ReadBlock {
            request_id,
            file_index,
            file_offset,
            length,
        });

        request_id
    }

    pub fn submit_write(
        &mut self,
        file_index: usize,
        file_offset: u64,
        data: Vec<u8>,
    ) -> u64 {
        let request_id = self.next_request_id;
        self.next_request_id += 1;

        self.pending_writes.insert(request_id, ());

        let _ = self.request_tx.send(IoRequest::WriteSegment {
            request_id,
            file_index,
            file_offset,
            data,
        });

        request_id
    }

    pub fn poll_completions(&mut self) -> Vec<IoResponse> {
        let mut completions = Vec::new();

        while let Ok(response) = self.response_rx.try_recv() {
            match &response {
                IoResponse::ReadComplete { request_id, .. } => {
                    self.pending_reads.remove(request_id);
                }
                IoResponse::WriteComplete { request_id, .. } => {
                    self.pending_writes.remove(request_id);
                }
            }
            completions.push(response);
        }

        completions
    }

    pub fn has_pending_operations(&self) -> bool {
        !self.pending_reads.is_empty() || !self.pending_writes.is_empty()
    }

    pub fn shutdown(&self) {
        for _ in 0..IO_THREAD_COUNT {
            let _ = self.request_tx.send(IoRequest::Shutdown);
        }
    }
}

impl Drop for IoPool {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn io_worker_thread(
    request_rx: std::sync::Arc<std::sync::Mutex<Receiver<IoRequest>>>,
    response_tx: Sender<IoResponse>,
    file_paths: Vec<PathBuf>,
    download_dir: PathBuf,
) {
    let mut file_cache: HashMap<usize, File> = HashMap::new();

    loop {
        let request = {
            let rx = match request_rx.lock() {
                Ok(guard) => guard,
                Err(_) => break,
            };

            match rx.recv() {
                Ok(req) => req,
                Err(_) => break,
            }
        };

        match request {
            IoRequest::Shutdown => break,

            IoRequest::ReadBlock {
                request_id,
                file_index,
                file_offset,
                length,
            } => {
                let result = read_block_sync(
                    &mut file_cache,
                    &file_paths,
                    &download_dir,
                    file_index,
                    file_offset,
                    length,
                );

                let _ = response_tx.send(IoResponse::ReadComplete {
                    request_id,
                    data: result,
                });
            }

            IoRequest::WriteSegment {
                request_id,
                file_index,
                file_offset,
                data,
            } => {
                let result = write_segment_sync(
                    &mut file_cache,
                    &file_paths,
                    &download_dir,
                    file_index,
                    file_offset,
                    &data,
                );

                let _ = response_tx.send(IoResponse::WriteComplete {
                    request_id,
                    result,
                });
            }
        }
    }

    for (_, mut file) in file_cache.drain() {
        let _ = file.flush();
    }
}

fn get_or_open_file<'a>(
    cache: &'a mut HashMap<usize, File>,
    paths: &[PathBuf],
    base_dir: &PathBuf,
    file_index: usize,
) -> Result<&'a mut File> {
    if !cache.contains_key(&file_index) {
        let path = paths.get(file_index)
            .context("invalid file index")?;

        let full_path = base_dir.join(path);

        if let Some(parent) = full_path.parent() {
            std::fs::create_dir_all(parent)
                .context("failed to create parent directories")?;
        }

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&full_path)
            .context("failed to open file")?;

        cache.insert(file_index, file);
    }

    cache.get_mut(&file_index)
        .ok_or_else(|| anyhow::anyhow!("File handle missing after insertion for index {}", file_index))
}

fn read_block_sync(
    cache: &mut HashMap<usize, File>,
    paths: &[PathBuf],
    base_dir: &PathBuf,
    file_index: usize,
    file_offset: u64,
    length: usize,
) -> Result<Vec<u8>> {
    let file = get_or_open_file(cache, paths, base_dir, file_index)?;

    file.seek(SeekFrom::Start(file_offset))
        .context("seek failed")?;

    let mut buffer = vec![0u8; length];
    file.read_exact(&mut buffer)
        .context("read failed")?;

    Ok(buffer)
}

fn write_segment_sync(
    cache: &mut HashMap<usize, File>,
    paths: &[PathBuf],
    base_dir: &PathBuf,
    file_index: usize,
    file_offset: u64,
    data: &[u8],
) -> Result<()> {
    let file = get_or_open_file(cache, paths, base_dir, file_index)?;

    file.seek(SeekFrom::Start(file_offset))
        .context("seek failed")?;

    file.write_all(data)
        .context("write failed")?;

    Ok(())
}
