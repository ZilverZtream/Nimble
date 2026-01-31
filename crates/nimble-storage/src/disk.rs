use anyhow::{Context, Result};
use nimble_bencode::torrent::TorrentInfo;
use nimble_util::bitfield::Bitfield;
use sha1::{Digest, Sha1};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::PathBuf;

use crate::layout::FileLayout;
use crate::resume::ResumeData;

const BLOCK_SIZE: u32 = 16384;

pub struct DiskStorage {
    layout: FileLayout,
    piece_length: u64,
    pieces: Vec<[u8; 20]>,
    bitfield: Bitfield,
    file_handles: HashMap<usize, File>,
    pending_pieces: HashMap<u64, PendingPiece>,
    info_hash: [u8; 20],
    download_dir: PathBuf,
}

struct PendingPiece {
    data: Vec<u8>,
    received_blocks: Bitfield,
    block_count: u32,
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

        Ok(DiskStorage {
            layout,
            piece_length: info.piece_length,
            pieces: info.pieces.clone(),
            bitfield,
            file_handles: HashMap::new(),
            pending_pieces: HashMap::new(),
            info_hash,
            download_dir,
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

        let piece_len = self.get_piece_length(piece_index);
        let block_count = ((piece_len + BLOCK_SIZE as u64 - 1) / BLOCK_SIZE as u64) as u32;
        let block_index = block_offset / BLOCK_SIZE;

        if block_index >= block_count {
            anyhow::bail!("invalid block offset: {}", block_offset);
        }

        let pending = self.pending_pieces.entry(piece_index).or_insert_with(|| {
            PendingPiece {
                data: vec![0u8; piece_len as usize],
                received_blocks: Bitfield::new(block_count as usize),
                block_count,
            }
        });

        if pending.received_blocks.get(block_index as usize) {
            return Ok(false);
        }

        let start = block_offset as usize;
        let end = (start + data.len()).min(pending.data.len());
        pending.data[start..end].copy_from_slice(&data[..end - start]);
        pending.received_blocks.set(block_index as usize, true);

        if pending.received_blocks.count_ones() == block_count as usize {
            self.complete_piece(piece_index)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn complete_piece(&mut self, piece_index: u64) -> Result<()> {
        let pending = self.pending_pieces.remove(&piece_index)
            .context("pending piece not found")?;

        let expected_hash = &self.pieces[piece_index as usize];
        let mut hasher = Sha1::new();
        hasher.update(&pending.data);
        let computed_hash: [u8; 20] = hasher.finalize().into();

        if &computed_hash != expected_hash {
            anyhow::bail!(
                "piece {} hash mismatch: expected {:?}, got {:?}",
                piece_index,
                expected_hash,
                computed_hash
            );
        }

        self.write_piece_to_disk(piece_index, &pending.data)?;
        self.bitfield.set(piece_index as usize, true);

        self.save_resume_data()?;

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
        if !self.file_handles.contains_key(&file_index) {
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
        }

        Ok(self.file_handles.get_mut(&file_index).unwrap())
    }

    fn get_piece_length(&self, piece_index: u64) -> u64 {
        let total_pieces = self.pieces.len() as u64;
        if piece_index < total_pieces - 1 {
            self.piece_length
        } else {
            let total_length = (total_pieces - 1) * self.piece_length + self.piece_length;
            let last_piece_length = total_length - (piece_index * self.piece_length);
            last_piece_length.min(self.piece_length)
        }
    }

    pub fn close(&mut self) -> Result<()> {
        self.save_resume_data()?;

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
        let completed = storage.write_block(0, 0, &data).unwrap();

        assert!(completed);
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

        let completed = storage.write_block(0, 0, &block1).unwrap();
        assert!(!completed);

        let completed = storage.write_block(0, 16384, &block2).unwrap();
        assert!(completed);
        assert!(storage.has_piece(0));
    }
}
