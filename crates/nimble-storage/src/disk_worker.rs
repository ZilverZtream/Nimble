use anyhow::Result;
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError};
use std::thread::{self, JoinHandle};

use crate::layout::FileLayout;

const DISK_WORKER_THREADS: usize = 2;
const DISK_QUEUE_DEPTH: usize = 256;
const MAX_OPEN_FILE_HANDLES: usize = 128;

use std::net::SocketAddrV4;

pub enum DiskRequest {
    WritePiece {
        piece_index: u64,
        data: Vec<u8>,
        request_id: u64,
    },
    ReadBlock {
        piece_index: u64,
        block_offset: u32,
        length: u32,
        request_id: u64,
        peer_addr: Option<SocketAddrV4>,
    },
}

pub enum DiskResult {
    WritePieceComplete {
        piece_index: u64,
        request_id: u64,
        result: Result<(), String>,
    },
    ReadBlockComplete {
        piece_index: u64,
        block_offset: u32,
        request_id: u64,
        peer_addr: Option<SocketAddrV4>,
        result: Result<Vec<u8>, String>,
    },
}

struct DiskWorkerState {
    layout: FileLayout,
    piece_length: u64,
    total_length: u64,
    file_handles: HashMap<usize, File>,
    file_lru: Vec<usize>,
}

impl DiskWorkerState {
    fn new(layout: FileLayout, piece_length: u64, total_length: u64) -> Self {
        DiskWorkerState {
            layout,
            piece_length,
            total_length,
            file_handles: HashMap::new(),
            file_lru: Vec::new(),
        }
    }

    fn get_or_create_file(&mut self, file_index: usize) -> Result<&mut File> {
        if self.file_handles.contains_key(&file_index) {
            self.file_lru.retain(|&idx| idx != file_index);
            self.file_lru.push(file_index);
        } else {
            if self.file_handles.len() >= MAX_OPEN_FILE_HANDLES {
                if let Some(&lru_index) = self.file_lru.first() {
                    self.file_lru.remove(0);
                    if let Some(mut file) = self.file_handles.remove(&lru_index) {
                        let _ = file.flush();
                    }
                }
            }

            let path = self.layout.file_path(file_index)
                .ok_or_else(|| anyhow::anyhow!("invalid file index"))?;

            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;

                #[cfg(target_os = "windows")]
                {
                    use std::os::windows::fs::MetadataExt;
                    if let Ok(metadata) = fs::symlink_metadata(parent) {
                        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x00000400;
                        if (metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
                            anyhow::bail!("refusing to write through reparse point: {:?}", parent);
                        }
                    }
                }
                #[cfg(not(target_os = "windows"))]
                {
                    if let Ok(metadata) = fs::symlink_metadata(parent) {
                        if metadata.file_type().is_symlink() {
                            anyhow::bail!("refusing to write through symlink: {:?}", parent);
                        }
                    }
                }
            }

            #[cfg(target_os = "windows")]
            {
                use std::os::windows::fs::MetadataExt;
                if path.exists() {
                    if let Ok(metadata) = fs::symlink_metadata(&path) {
                        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x00000400;
                        if (metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
                            anyhow::bail!("refusing to write to reparse point: {:?}", path);
                        }
                    }
                }
            }
            #[cfg(not(target_os = "windows"))]
            {
                if path.exists() {
                    if let Ok(metadata) = fs::symlink_metadata(&path) {
                        if metadata.file_type().is_symlink() {
                            anyhow::bail!("refusing to write to symlink: {:?}", path);
                        }
                    }
                }
            }

            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .open(path)?;

            self.file_handles.insert(file_index, file);
            self.file_lru.push(file_index);
        }

        self.file_handles.get_mut(&file_index)
            .ok_or_else(|| anyhow::anyhow!("file handle missing"))
    }

    fn write_piece(&mut self, piece_index: u64, data: &[u8]) -> Result<()> {
        let segments = self.layout.map_piece(piece_index);
        let mut offset = 0;

        for segment in segments {
            let file_handle = self.get_or_create_file(segment.file_index)?;

            file_handle.seek(SeekFrom::Start(segment.file_offset))?;

            let end = offset + segment.length as usize;
            file_handle.write_all(&data[offset..end])?;

            offset = end;
        }

        Ok(())
    }

    fn read_block(&mut self, piece_index: u64, block_offset: u32, length: u32) -> Result<Vec<u8>> {
        let global_start = piece_index * self.piece_length + block_offset as u64;
        let global_end = global_start + length as u64;

        let segments = self.layout.map_range(global_start, global_end);
        // Use buffer pool for disk reads to reduce allocations.
        let mut pooled_buf = crate::buffer_pool::global_pool().get();
        pooled_buf.as_mut().resize(length as usize, 0);
        let data_slice = pooled_buf.as_mut().as_mut_slice();
        let mut data_offset = 0;

        for segment in segments {
            let file_handle = self.get_or_create_file(segment.file_index)?;
            file_handle.seek(SeekFrom::Start(segment.file_offset))?;

            let read_length = segment.length as usize;
            file_handle.read_exact(&mut data_slice[data_offset..data_offset + read_length])?;

            data_offset += read_length;
        }

        if data_offset != length as usize {
            anyhow::bail!("incomplete read: expected {} bytes, got {}", length, data_offset);
        }

        Ok(pooled_buf.take())
    }

    fn flush_all(&mut self) -> Result<()> {
        for (_, mut file) in self.file_handles.drain() {
            file.flush()?;
        }
        Ok(())
    }
}

pub struct DiskWorker {
    request_tx: SyncSender<DiskRequest>,
    result_rx: Receiver<DiskResult>,
    _workers: Vec<JoinHandle<()>>,
}

impl DiskWorker {
    pub fn new(layout: FileLayout, piece_length: u64, total_length: u64) -> Self {
        let (request_tx, request_rx) = mpsc::sync_channel::<DiskRequest>(DISK_QUEUE_DEPTH);
        let (result_tx, result_rx) = mpsc::sync_channel::<DiskResult>(DISK_QUEUE_DEPTH);

        let request_rx = std::sync::Arc::new(std::sync::Mutex::new(request_rx));
        let layout = std::sync::Arc::new(std::sync::Mutex::new(layout));
        let mut workers = Vec::with_capacity(DISK_WORKER_THREADS);

        for _ in 0..DISK_WORKER_THREADS {
            let rx = request_rx.clone();
            let tx = result_tx.clone();
            let layout_clone = layout.clone();

            let handle = thread::spawn(move || {
                let mut state = {
                    let layout_guard = match layout_clone.lock() {
                        Ok(g) => g,
                        Err(_) => return,
                    };
                    DiskWorkerState::new(layout_guard.clone(), piece_length, total_length)
                };

                loop {
                    let request = {
                        let guard = match rx.lock() {
                            Ok(g) => g,
                            Err(_) => break,
                        };
                        match guard.recv() {
                            Ok(req) => req,
                            Err(_) => break,
                        }
                    };

                    match request {
                        DiskRequest::WritePiece { piece_index, data, request_id } => {
                            let result = state.write_piece(piece_index, &data)
                                .map_err(|e| e.to_string());
                            let disk_result = DiskResult::WritePieceComplete {
                                piece_index,
                                request_id,
                                result,
                            };
                            if tx.send(disk_result).is_err() {
                                break;
                            }
                        }
                        DiskRequest::ReadBlock { piece_index, block_offset, length, request_id, peer_addr } => {
                            let result = state.read_block(piece_index, block_offset, length)
                                .map_err(|e| e.to_string());
                            let disk_result = DiskResult::ReadBlockComplete {
                                piece_index,
                                block_offset,
                                request_id,
                                peer_addr,
                                result,
                            };
                            if tx.send(disk_result).is_err() {
                                break;
                            }
                        }
                    }
                }

                let _ = state.flush_all();
            });

            workers.push(handle);
        }

        DiskWorker {
            request_tx,
            result_rx,
            _workers: workers,
        }
    }

    pub fn submit(&self, request: DiskRequest) -> bool {
        self.request_tx.try_send(request).is_ok()
    }

    pub fn try_recv(&self) -> Option<DiskResult> {
        match self.result_rx.try_recv() {
            Ok(result) => Some(result),
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => None,
        }
    }
}
