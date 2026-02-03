use anyhow::Result;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::net::SocketAddrV4;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::{self, JoinHandle};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Storage::FileSystem::*;
use windows_sys::Win32::System::IO::*;

use crate::layout::FileLayout;

const IOCP_WORKER_THREADS: usize = 4;
const DISK_QUEUE_DEPTH: usize = 512;
const MAX_OPEN_FILE_HANDLES: usize = 128;

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
    Shutdown,
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

#[repr(C)]
struct OperationContext {
    overlapped: OVERLAPPED,
    operation: OperationKind,
    buffer_offset: usize,
    length: u32,
}

enum OperationKind {
    Write(Arc<WriteRequest>),
    Read(Arc<ReadRequest>),
}

struct WriteRequest {
    piece_index: u64,
    request_id: u64,
    remaining: AtomicUsize,
    done: AtomicBool,
    result_tx: mpsc::SyncSender<DiskResult>,
    data: Arc<Vec<u8>>,
}

impl WriteRequest {
    fn fail(&self, message: String) {
        if self.done.swap(true, Ordering::AcqRel) {
            return;
        }
        let _ = self.result_tx.send(DiskResult::WritePieceComplete {
            piece_index: self.piece_index,
            request_id: self.request_id,
            result: Err(message),
        });
    }

    fn complete_segment(&self) {
        if self.done.load(Ordering::Acquire) {
            return;
        }
        if self.remaining.fetch_sub(1, Ordering::AcqRel) == 1 {
            if self.done.swap(true, Ordering::AcqRel) {
                return;
            }
            let _ = self.result_tx.send(DiskResult::WritePieceComplete {
                piece_index: self.piece_index,
                request_id: self.request_id,
                result: Ok(()),
            });
        }
    }
}

struct ReadRequest {
    piece_index: u64,
    block_offset: u32,
    request_id: u64,
    peer_addr: Option<SocketAddrV4>,
    remaining: AtomicUsize,
    done: AtomicBool,
    result_tx: mpsc::SyncSender<DiskResult>,
    buffer: std::cell::UnsafeCell<Box<[u8]>>,
}

unsafe impl Send for ReadRequest {}
unsafe impl Sync for ReadRequest {}

impl ReadRequest {
    fn buffer_ptr(&self, offset: usize) -> *mut u8 {
        unsafe { (*self.buffer.get()).as_mut_ptr().add(offset) }
    }

    fn fail(&self, message: String) {
        if self.done.swap(true, Ordering::AcqRel) {
            return;
        }
        let _ = self.result_tx.send(DiskResult::ReadBlockComplete {
            piece_index: self.piece_index,
            block_offset: self.block_offset,
            request_id: self.request_id,
            peer_addr: self.peer_addr,
            result: Err(message),
        });
    }

    fn complete_segment(&self) {
        if self.done.load(Ordering::Acquire) {
            return;
        }
        if self.remaining.fetch_sub(1, Ordering::AcqRel) == 1 {
            if self.done.swap(true, Ordering::AcqRel) {
                return;
            }
            let data = unsafe {
                std::mem::replace(&mut *self.buffer.get(), Vec::new().into_boxed_slice())
            };
            let _ = self.result_tx.send(DiskResult::ReadBlockComplete {
                piece_index: self.piece_index,
                block_offset: self.block_offset,
                request_id: self.request_id,
                peer_addr: self.peer_addr,
                result: Ok(Vec::from(data)),
            });
        }
    }
}

struct IocpFileHandle {
    handle: HANDLE,
    _path: PathBuf,
}

impl IocpFileHandle {
    fn new(path: PathBuf) -> Result<Self> {
        ensure_safe_path(&path)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
            ensure_safe_path(parent)?;
        }
        let wide_path: Vec<u16> = OsStr::new(&path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        unsafe {
            let handle = CreateFileW(
                wide_path.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ,
                ptr::null(),
                OPEN_ALWAYS,
                FILE_FLAG_OVERLAPPED,
                0,
            );
            if handle == INVALID_HANDLE_VALUE {
                return Err(anyhow::anyhow!("CreateFileW failed: {}", GetLastError()));
            }
            Ok(IocpFileHandle { handle, _path: path })
        }
    }

    fn raw_handle(&self) -> HANDLE {
        self.handle
    }
}

impl Drop for IocpFileHandle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle);
        }
    }
}

fn ensure_safe_path(path: &Path) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::fs::MetadataExt;
        if let Ok(metadata) = std::fs::symlink_metadata(path) {
            const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x00000400;
            if (metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
                anyhow::bail!("refusing to write through reparse point: {:?}", path);
            }
        }
    }
    Ok(())
}

struct IocpPort(HANDLE);
impl Drop for IocpPort {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0); }
    }
}

struct SubmissionState {
    iocp_handle: HANDLE,
    layout: FileLayout,
    piece_length: u64,
    total_length: u64,
    file_handles: HashMap<usize, Arc<IocpFileHandle>>,
    file_lru: Vec<usize>,
    result_tx: mpsc::SyncSender<DiskResult>,
}

struct CompletionState {
    iocp_handle: HANDLE,
    shutdown: Arc<AtomicBool>,
}

impl SubmissionState {
    fn get_or_open_file(&mut self, file_index: usize) -> Result<Arc<IocpFileHandle>> {
        if let Some(handle) = self.file_handles.get(&file_index) {
            self.file_lru.retain(|&idx| idx != file_index);
            self.file_lru.push(file_index);
            return Ok(handle.clone());
        }

        if self.file_handles.len() >= MAX_OPEN_FILE_HANDLES {
            if let Some(&lru_index) = self.file_lru.first() {
                self.file_lru.remove(0);
                self.file_handles.remove(&lru_index);
            }
        }

        let path = self.layout.file_path(file_index)
            .ok_or_else(|| anyhow::anyhow!("invalid file index"))?
            .clone();

        let handle = Arc::new(IocpFileHandle::new(path)?);

        unsafe {
            let result = CreateIoCompletionPort(
                handle.raw_handle(),
                self.iocp_handle,
                file_index as usize,
                0,
            );
            if result == 0 {
                return Err(anyhow::anyhow!("CreateIoCompletionPort failed: {}", GetLastError()));
            }
        }

        self.file_handles.insert(file_index, handle.clone());
        self.file_lru.push(file_index);
        Ok(handle)
    }

    fn submit_write(&mut self, piece_index: u64, data: Vec<u8>, request_id: u64) -> Result<()> {
        let segments = self.layout.map_piece(piece_index);
        if segments.is_empty() {
            anyhow::bail!("no segments for piece {}", piece_index);
        }

        let shared_data = Arc::new(data);
        let request = Arc::new(WriteRequest {
            piece_index,
            request_id,
            remaining: AtomicUsize::new(segments.len()),
            done: AtomicBool::new(false),
            result_tx: self.result_tx.clone(),
            data: shared_data.clone(),
        });

        let mut offset = 0usize;
        for segment in segments {
            let file_handle = match self.get_or_open_file(segment.file_index) {
                Ok(handle) => handle,
                Err(err) => {
                    request.fail(err.to_string());
                    return Err(err);
                }
            };
            let length = segment.length as usize;
            if offset + length > shared_data.len() {
                let message = format!(
                    "write segment out of bounds: offset {} length {} data_len {}",
                    offset,
                    length,
                    shared_data.len()
                );
                request.fail(message.clone());
                anyhow::bail!(message);
            }

            let ctx = Box::new(OperationContext {
                overlapped: unsafe { std::mem::zeroed() },
                operation: OperationKind::Write(request.clone()),
                buffer_offset: offset,
                length: length as u32,
            });

            let ctx_ptr = Box::into_raw(ctx);

            unsafe {
                (*ctx_ptr).overlapped.Anonymous.Anonymous.Offset = (segment.file_offset & 0xFFFFFFFF) as u32;
                (*ctx_ptr).overlapped.Anonymous.Anonymous.OffsetHigh = (segment.file_offset >> 32) as u32;

                let buffer_ptr = request.data.as_ptr().add(offset);

                let result = WriteFile(
                    file_handle.raw_handle(),
                    buffer_ptr,
                    length as u32,
                    ptr::null_mut(),
                    &mut (*ctx_ptr).overlapped,
                );

                if result == 0 {
                    let error = GetLastError();
                    if error != ERROR_IO_PENDING {
                        let _ = Box::from_raw(ctx_ptr);
                        let message = format!("WriteFile failed: {}", error);
                        request.fail(message.clone());
                        return Err(anyhow::anyhow!(message));
                    }
                }
            }
            offset += length;
        }
        Ok(())
    }

    fn submit_read(
        &mut self,
        piece_index: u64,
        block_offset: u32,
        length: u32,
        request_id: u64,
        peer_addr: Option<SocketAddrV4>,
    ) -> Result<()> {
        let global_start = piece_index * self.piece_length + block_offset as u64;
        let global_end = global_start + length as u64;
        if global_end > self.total_length {
            anyhow::bail!("read beyond total length: {} > {}", global_end, self.total_length);
        }
        let segments = self.layout.map_range(global_start, global_end);
        if segments.is_empty() {
            anyhow::bail!("no segments for read piece {}", piece_index);
        }

        let request = Arc::new(ReadRequest {
            piece_index,
            block_offset,
            request_id,
            peer_addr,
            remaining: AtomicUsize::new(segments.len()),
            done: AtomicBool::new(false),
            result_tx: self.result_tx.clone(),
            buffer: std::cell::UnsafeCell::new(vec![0u8; length as usize].into_boxed_slice()),
        });

        let mut buffer_offset = 0usize;
        for segment in segments {
            let file_handle = match self.get_or_open_file(segment.file_index) {
                Ok(handle) => handle,
                Err(err) => {
                    request.fail(err.to_string());
                    return Err(err);
                }
            };
            let read_length = segment.length as usize;
            if buffer_offset + read_length > length as usize {
                let message = format!(
                    "read segment out of bounds: offset {} length {} buffer_len {}",
                    buffer_offset,
                    read_length,
                    length
                );
                request.fail(message.clone());
                anyhow::bail!(message);
            }

            let ctx = Box::new(OperationContext {
                overlapped: unsafe { std::mem::zeroed() },
                operation: OperationKind::Read(request.clone()),
                buffer_offset,
                length: read_length as u32,
            });

            let ctx_ptr = Box::into_raw(ctx);

            unsafe {
                (*ctx_ptr).overlapped.Anonymous.Anonymous.Offset = (segment.file_offset & 0xFFFFFFFF) as u32;
                (*ctx_ptr).overlapped.Anonymous.Anonymous.OffsetHigh = (segment.file_offset >> 32) as u32;

                let result = ReadFile(
                    file_handle.raw_handle(),
                    request.buffer_ptr(buffer_offset),
                    read_length as u32,
                    ptr::null_mut(),
                    &mut (*ctx_ptr).overlapped,
                );

                if result == 0 {
                    let error = GetLastError();
                    if error != ERROR_IO_PENDING {
                        let _ = Box::from_raw(ctx_ptr);
                        let message = format!("ReadFile failed: {}", error);
                        request.fail(message.clone());
                        return Err(anyhow::anyhow!(message));
                    }
                }
            }
            buffer_offset += read_length;
        }
        Ok(())
    }
}

impl CompletionState {
    fn process_completions(&mut self) {
        let mut _bytes_transferred: u32 = 0;
        let mut _completion_key: usize = 0;
        let mut overlapped_ptr: *mut OVERLAPPED = ptr::null_mut();

        loop {
            if self.shutdown.load(Ordering::Relaxed) {
                break;
            }

            unsafe {
                let result = GetQueuedCompletionStatus(
                    self.iocp_handle,
                    &mut _bytes_transferred,
                    &mut _completion_key,
                    &mut overlapped_ptr,
                    100,
                );

                if result == 0 && overlapped_ptr.is_null() {
                    continue;
                }

                if overlapped_ptr.is_null() {
                    continue;
                }

                let ctx_ptr = overlapped_ptr as *mut OperationContext;
                let ctx = Box::from_raw(ctx_ptr);

                if result == 0 {
                    let err_msg = format!("Async IO failed: {}", GetLastError());
                    match ctx.operation {
                        OperationKind::Write(request) => request.fail(err_msg),
                        OperationKind::Read(request) => request.fail(err_msg),
                    }
                    continue;
                }

                match ctx.operation {
                    OperationKind::Write(request) => request.complete_segment(),
                    OperationKind::Read(request) => request.complete_segment(),
                }
            }
        }
    }
}

pub struct DiskWorker {
    request_tx: mpsc::SyncSender<DiskRequest>,
    result_rx: mpsc::Receiver<DiskResult>,
    shutdown: Arc<AtomicBool>,
    _workers: Vec<JoinHandle<()>>,
    _iocp_port: Arc<IocpPort>,
}

impl DiskWorker {
    pub fn new(layout: FileLayout, piece_length: u64, total_length: u64) -> Self {
        let (request_tx, request_rx) = mpsc::sync_channel::<DiskRequest>(DISK_QUEUE_DEPTH);
        let (result_tx, result_rx) = mpsc::sync_channel::<DiskResult>(DISK_QUEUE_DEPTH);
        let shutdown = Arc::new(AtomicBool::new(false));
        let request_rx = Arc::new(Mutex::new(request_rx));
        let mut workers = Vec::with_capacity(IOCP_WORKER_THREADS);

        let iocp_handle = unsafe {
            let h = CreateIoCompletionPort(INVALID_HANDLE_VALUE, 0, 0, IOCP_WORKER_THREADS as u32);
            if h == 0 {
                panic!("Failed to create IOCP handle");
            }
            h
        };
        let iocp_port = Arc::new(IocpPort(iocp_handle));

        for _ in 0..IOCP_WORKER_THREADS {
            let rx = request_rx.clone();
            let tx = result_tx.clone();
            let layout_clone = layout.clone();
            let shutdown_clone = shutdown.clone();
            let iocp = iocp_handle;

            let handle = thread::spawn(move || {
                let mut submission_state = SubmissionState {
                    iocp_handle: iocp,
                    layout: layout_clone,
                    piece_length,
                    total_length,
                    file_handles: HashMap::new(),
                    file_lru: Vec::new(),
                    result_tx: tx.clone(),
                };

                let mut completion_state = CompletionState {
                    iocp_handle: iocp,
                    shutdown: shutdown_clone.clone(),
                };

                thread::spawn(move || {
                    completion_state.process_completions();
                });

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
                        DiskRequest::Shutdown => {
                            shutdown_clone.store(true, Ordering::Relaxed);
                            break;
                        }
                        DiskRequest::WritePiece { piece_index, data, request_id } => {
                            if let Err(err) = submission_state.submit_write(piece_index, data, request_id) {
                                let _ = submission_state.result_tx.send(DiskResult::WritePieceComplete {
                                    piece_index,
                                    request_id,
                                    result: Err(err.to_string()),
                                });
                            }
                        }
                        DiskRequest::ReadBlock { piece_index, block_offset, length, request_id, peer_addr } => {
                            if let Err(err) = submission_state.submit_read(
                                piece_index,
                                block_offset,
                                length,
                                request_id,
                                peer_addr,
                            ) {
                                let _ = submission_state.result_tx.send(DiskResult::ReadBlockComplete {
                                    piece_index,
                                    block_offset,
                                    request_id,
                                    peer_addr,
                                    result: Err(err.to_string()),
                                });
                            }
                        }
                    }
                }
            });
            workers.push(handle);
        }

        DiskWorker {
            request_tx,
            result_rx,
            shutdown,
            _workers: workers,
            _iocp_port: iocp_port,
        }
    }

    pub fn submit(&self, request: DiskRequest) -> bool {
        self.request_tx.try_send(request).is_ok()
    }

    pub fn try_recv(&self) -> Option<DiskResult> {
        self.result_rx.try_recv().ok()
    }
}

impl Drop for DiskWorker {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        let _ = self.request_tx.send(DiskRequest::Shutdown);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nimble_bencode::torrent::{InfoHash, TorrentInfo, TorrentMode};

    #[cfg(target_os = "windows")]
    #[test]
    fn iocp_disk_worker_round_trip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let info = TorrentInfo {
            announce: None,
            announce_list: vec![],
            piece_length: 16,
            pieces: vec![],
            mode: TorrentMode::SingleFile {
                name: "test.bin".to_string(),
                length: 16,
            },
            infohash: InfoHash([0u8; 20]),
            total_length: 16,
            private: false,
        };
        let layout = FileLayout::new(&info, dir.path().to_path_buf()).expect("layout");
        let worker = DiskWorker::new(layout, info.piece_length, info.total_length);

        let payload = vec![42u8; 16];
        assert!(worker.submit(DiskRequest::WritePiece {
            piece_index: 0,
            data: payload.clone(),
            request_id: 1,
        }));

        let mut wrote = false;
        let start = std::time::Instant::now();
        while start.elapsed() < std::time::Duration::from_secs(2) {
            if let Some(DiskResult::WritePieceComplete { result, .. }) = worker.try_recv() {
                assert!(result.is_ok());
                wrote = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(wrote, "write completion timed out");

        assert!(worker.submit(DiskRequest::ReadBlock {
            piece_index: 0,
            block_offset: 0,
            length: 16,
            request_id: 2,
            peer_addr: None,
        }));

        let mut read = None;
        let start = std::time::Instant::now();
        while start.elapsed() < std::time::Duration::from_secs(2) {
            if let Some(DiskResult::ReadBlockComplete { result, .. }) = worker.try_recv() {
                read = Some(result.expect("read ok"));
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(read, Some(payload));
    }
}
