use anyhow::{Context, Result};
use nimble_bencode::torrent::TorrentInfo;
use nimble_util::bitfield::Bitfield;
use std::collections::{HashMap, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

use crate::hasher::{HashVerifier, VerifyRequest};
use crate::layout::FileLayout;
use crate::resume::ResumeData;
use crate::checkpoint::CheckpointManager;

const BLOCK_SIZE: u32 = 16384;
const RESUME_SAVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);
const STALE_PIECE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);
const MAX_OPEN_FILE_HANDLES: usize = 128;

pub struct DiskStorage {
    layout: FileLayout,
    piece_length: u64,
    total_length: u64,
    pieces: Vec<[u8; 20]>,
    bitfield: Bitfield,
    file_handles: HashMap<usize, File>,
    file_lru: VecDeque<usize>,
    pending_pieces: HashMap<u64, PendingPiece>,
    verifying_pieces: HashMap<u64, ()>,
    failed_pieces: Vec<u64>,
    info_hash: [u8; 20],
    download_dir: PathBuf,
    hasher: HashVerifier,
    last_resume_save: std::time::Instant,
    resume_dirty: bool,
    checkpoint_manager: CheckpointManager,
}

struct PendingPiece {
    data: Vec<u8>,
    received_blocks: Bitfield,
    last_updated: std::time::Instant,
}

impl DiskStorage {
    pub fn new(info: &TorrentInfo, download_dir: PathBuf) -> Result<Self> {
        let layout = FileLayout::new(info, download_dir.clone());
        let piece_count = info.pieces.len();
        let info_hash = *info.infohash.as_bytes();

        let resume_path = ResumeData::resume_file_path(&download_dir, info_hash);
        let bitfield = if resume_path.exists() {
            match ResumeData::load(&resume_path, piece_count) {
                Ok(resume_data) => {
                    if resume_data.info_hash == info_hash {
                        resume_data.bitfield
                    } else {
                        Bitfield::new(piece_count)
                    }
                }
                Err(_) => Bitfield::new(piece_count),
            }
        } else {
            Bitfield::new(piece_count)
        };

        let mut checkpoint_manager = CheckpointManager::new(
            &download_dir,
            info_hash,
            info.piece_length,
            BLOCK_SIZE,
        )?;

        let mut pending_pieces = HashMap::new();

        if let Ok(Some(checkpoint)) = checkpoint_manager.load_checkpoint() {
            let piece_len = if checkpoint.piece_index == piece_count as u64 - 1 {
                let remainder = info.total_length % info.piece_length;
                if remainder > 0 {
                    remainder
                } else {
                    info.piece_length
                }
            } else {
                info.piece_length
            };

            if let Ok(data) = checkpoint_manager.read_checkpoint_data(
                checkpoint.data_offset,
                piece_len as usize,
            ) {
                pending_pieces.insert(checkpoint.piece_index, PendingPiece {
                    data,
                    received_blocks: checkpoint.received_blocks,
                    last_updated: std::time::Instant::now(),
                });
            }
        }

        Ok(DiskStorage {
            layout,
            piece_length: info.piece_length,
            total_length: info.total_length,
            pieces: info.pieces.clone(),
            bitfield,
            file_handles: HashMap::new(),
            file_lru: VecDeque::new(),
            pending_pieces,
            verifying_pieces: HashMap::new(),
            failed_pieces: Vec::new(),
            info_hash,
            download_dir,
            hasher: HashVerifier::new(),
            last_resume_save: std::time::Instant::now(),
            resume_dirty: false,
            checkpoint_manager,
        })
    }

    pub fn piece_count(&self) -> usize {
        self.pieces.len()
    }

    pub fn has_piece(&self, index: u64) -> bool {
        self.bitfield.get(index as usize)
    }

    pub fn bitfield(&self) -> &Bitfield {
        &self.bitfield
    }

    pub fn write_block(&mut self, piece_index: u64, block_offset: u32, data: &[u8]) -> Result<bool> {
        if piece_index >= self.pieces.len() as u64 {
            anyhow::bail!("invalid piece index: {}", piece_index);
        }

        if self.has_piece(piece_index) {
            return Ok(false);
        }

        if self.verifying_pieces.contains_key(&piece_index) {
            return Ok(false);
        }

        let piece_len = self.get_piece_length(piece_index);

        if block_offset % BLOCK_SIZE != 0 {
            anyhow::bail!("block offset {} is not aligned to BLOCK_SIZE", block_offset);
        }

        if block_offset as u64 >= piece_len {
            anyhow::bail!(
                "block offset {} exceeds piece length {}",
                block_offset,
                piece_len
            );
        }

        let expected_block_len = if block_offset as u64 + BLOCK_SIZE as u64 > piece_len {
            (piece_len - block_offset as u64) as usize
        } else {
            BLOCK_SIZE as usize
        };

        if data.len() != expected_block_len {
            anyhow::bail!(
                "block data length {} does not match expected {}",
                data.len(),
                expected_block_len
            );
        }

        let block_count = ((piece_len + BLOCK_SIZE as u64 - 1) / BLOCK_SIZE as u64) as u32;
        let block_index = block_offset / BLOCK_SIZE;

        let pending = self.pending_pieces.entry(piece_index).or_insert_with(|| {
            PendingPiece {
                data: vec![0u8; piece_len as usize],
                received_blocks: Bitfield::new(block_count as usize),
                last_updated: std::time::Instant::now(),
            }
        });

        if pending.received_blocks.get(block_index as usize) {
            return Ok(false);
        }

        let start = block_offset as usize;
        let end = start + data.len();
        pending.data[start..end].copy_from_slice(data);
        pending.received_blocks.set(block_index as usize, true);
        pending.last_updated = std::time::Instant::now();

        if pending.received_blocks.count_ones() == block_count as usize {
            self.submit_piece_for_verification(piece_index);
            let _ = self.checkpoint_manager.clear();
            Ok(false)
        } else {
            let _ = self.checkpoint_manager.write_partial_piece(
                piece_index,
                &pending.received_blocks,
                &pending.data,
            );
            Ok(false)
        }
    }

    pub fn read_block(&mut self, piece_index: u64, block_offset: u32, length: u32) -> Result<Vec<u8>> {
        if piece_index >= self.pieces.len() as u64 {
            anyhow::bail!("invalid piece index: {}", piece_index);
        }

        if !self.has_piece(piece_index) {
            anyhow::bail!("piece {} not available", piece_index);
        }

        let piece_len = self.get_piece_length(piece_index);

        if block_offset as u64 >= piece_len {
            anyhow::bail!(
                "block offset {} exceeds piece length {}",
                block_offset,
                piece_len
            );
        }

        let max_length = (piece_len - block_offset as u64) as u32;
        if length > max_length {
            anyhow::bail!(
                "requested length {} exceeds available {} bytes",
                length,
                max_length
            );
        }

        if length > BLOCK_SIZE {
            anyhow::bail!("requested length {} exceeds max block size", length);
        }

        let global_start = piece_index * self.piece_length + block_offset as u64;
        let global_end = global_start + length as u64;

        let segments = self.layout.map_range(global_start, global_end);
        let mut data = vec![0u8; length as usize];
        let mut data_offset = 0;

        for segment in segments {
            let file_handle = self.get_or_create_file(segment.file_index)?;
            file_handle.seek(SeekFrom::Start(segment.file_offset))
                .context("seek failed")?;

            let read_length = segment.length as usize;
            file_handle.read_exact(&mut data[data_offset..data_offset + read_length])
                .context("read failed")?;

            data_offset += read_length;
        }

        if data_offset != length as usize {
            anyhow::bail!(
                "incomplete read: expected {} bytes, got {}",
                length,
                data_offset
            );
        }

        Ok(data)
    }

    fn submit_piece_for_verification(&mut self, piece_index: u64) {
        if let Some(pending) = self.pending_pieces.remove(&piece_index) {
            let expected_hash = self.pieces[piece_index as usize];
            let request = VerifyRequest {
                piece_index,
                data: pending.data,
                expected_hash,
            };
            if self.hasher.submit(request) {
                self.verifying_pieces.insert(piece_index, ());
            }
        }
    }

    pub fn poll_verifications(&mut self) -> Vec<u64> {
        let mut completed = Vec::new();

        while let Some(result) = self.hasher.try_recv() {
            self.verifying_pieces.remove(&result.piece_index);

            if result.hash_matches {
                if let Err(e) = self.finalize_verified_piece(result.piece_index, &result.data) {
                    eprintln!("Failed to finalize piece {}: {}", result.piece_index, e);
                    self.failed_pieces.push(result.piece_index);
                    continue;
                }
                completed.push(result.piece_index);
            } else {
                self.failed_pieces.push(result.piece_index);
            }
        }

        completed
    }

    pub fn take_failed_pieces(&mut self) -> Vec<u64> {
        std::mem::take(&mut self.failed_pieces)
    }

    fn finalize_verified_piece(&mut self, piece_index: u64, data: &[u8]) -> Result<()> {
        self.write_piece_to_disk(piece_index, data)?;
        self.bitfield.set(piece_index as usize, true);
        self.resume_dirty = true;
        Ok(())
    }

    pub fn tick(&mut self) -> Result<()> {
        if self.resume_dirty && self.last_resume_save.elapsed() >= RESUME_SAVE_INTERVAL {
            self.save_resume_data()?;
            self.last_resume_save = std::time::Instant::now();
            self.resume_dirty = false;
        }

        let now = std::time::Instant::now();
        self.pending_pieces.retain(|_, piece| {
            now.duration_since(piece.last_updated) < STALE_PIECE_TIMEOUT
        });

        Ok(())
    }

    fn write_piece_to_disk(&mut self, piece_index: u64, data: &[u8]) -> Result<()> {
        let segments = self.layout.map_piece(piece_index);
        let mut offset = 0;

        for segment in segments {
            let file_handle = self.get_or_create_file(segment.file_index)?;

            file_handle.seek(SeekFrom::Start(segment.file_offset))
                .context("seek failed")?;

            let end = offset + segment.length as usize;
            file_handle.write_all(&data[offset..end])
                .context("write failed")?;

            offset = end;
        }

        Ok(())
    }

    fn get_or_create_file(&mut self, file_index: usize) -> Result<&mut File> {
        if self.file_handles.contains_key(&file_index) {
            self.file_lru.retain(|&idx| idx != file_index);
            self.file_lru.push_back(file_index);
        } else {
            if self.file_handles.len() >= MAX_OPEN_FILE_HANDLES {
                if let Some(lru_index) = self.file_lru.pop_front() {
                    if let Some(mut file) = self.file_handles.remove(&lru_index) {
                        let _ = file.flush();
                    }
                }
            }

            let path = self.layout.file_path(file_index)
                .context("invalid file index")?;

            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)
                    .context("failed to create parent directories")?;
            }

            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .open(path)
                .context("failed to open file")?;

            self.file_handles.insert(file_index, file);
            self.file_lru.push_back(file_index);
        }

        Ok(self.file_handles.get_mut(&file_index).unwrap())
    }

    fn get_piece_length(&self, piece_index: u64) -> u64 {
        let total_pieces = self.pieces.len() as u64;
        if total_pieces == 0 {
            return 0;
        }
        if piece_index < total_pieces - 1 {
            self.piece_length
        } else {
            let remainder = self.total_length % self.piece_length;
            if remainder == 0 {
                self.piece_length
            } else {
                remainder
            }
        }
    }

    pub fn close(&mut self) -> Result<()> {
        if self.resume_dirty {
            self.save_resume_data()?;
            self.resume_dirty = false;
        }

        for (_, mut file) in self.file_handles.drain() {
            file.flush().context("failed to flush file")?;
        }
        Ok(())
    }

    fn save_resume_data(&self) -> Result<()> {
        let resume_data = ResumeData {
            info_hash: self.info_hash,
            bitfield: self.bitfield.clone(),
        };
        let resume_path = ResumeData::resume_file_path(&self.download_dir, self.info_hash);
        resume_data.save(&resume_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nimble_bencode::torrent::{InfoHash, TorrentMode};
    use sha1::{Digest, Sha1};
    use tempfile::TempDir;

    fn make_test_info() -> TorrentInfo {
        let piece_data = vec![0u8; 16384];
        let mut hasher = Sha1::new();
        hasher.update(&piece_data);
        let hash: [u8; 20] = hasher.finalize().into();

        TorrentInfo {
            announce: None,
            announce_list: vec![],
            piece_length: 16384,
            pieces: vec![hash],
            mode: TorrentMode::SingleFile {
                name: "test.dat".to_string(),
                length: 16384,
            },
            infohash: InfoHash([0u8; 20]),
            total_length: 16384,
        }
    }

    #[test]
    fn test_write_block_and_complete() {
        let temp_dir = TempDir::new().unwrap();
        let info = make_test_info();
        let mut storage = DiskStorage::new(&info, temp_dir.path().to_path_buf()).unwrap();

        let data = vec![0u8; 16384];
        storage.write_block(0, 0, &data).unwrap();

        std::thread::sleep(std::time::Duration::from_millis(100));
        let completed = storage.poll_verifications();

        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0], 0);
        assert!(storage.has_piece(0));
    }

    #[test]
    fn test_write_multiple_blocks() {
        let temp_dir = TempDir::new().unwrap();
        let mut info = make_test_info();
        info.piece_length = 32768;
        info.total_length = 32768;

        let piece_data = vec![0u8; 32768];
        let mut hasher = Sha1::new();
        hasher.update(&piece_data);
        let hash: [u8; 20] = hasher.finalize().into();
        info.pieces = vec![hash];

        let mut storage = DiskStorage::new(&info, temp_dir.path().to_path_buf()).unwrap();

        let block1 = vec![0u8; 16384];
        let block2 = vec![0u8; 16384];

        storage.write_block(0, 0, &block1).unwrap();
        let completed = storage.poll_verifications();
        assert!(completed.is_empty());

        storage.write_block(0, 16384, &block2).unwrap();

        std::thread::sleep(std::time::Duration::from_millis(100));
        let completed = storage.poll_verifications();

        assert_eq!(completed.len(), 1);
        assert!(storage.has_piece(0));
    }
}
