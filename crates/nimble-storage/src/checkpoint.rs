use anyhow::{Context, Result};
use nimble_util::bitfield::Bitfield;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const CHECKPOINT_VERSION: u8 = 1;
const CHECKPOINT_HEADER: &[u8] = b"NIMBLE_CP";
const CHECKPOINT_WRITE_THRESHOLD: usize = 4;

#[derive(Debug)]
pub struct PieceCheckpoint {
    pub piece_index: u64,
    pub received_blocks: Bitfield,
    pub data_offset: u64,
}

pub struct CheckpointManager {
    checkpoint_file: File,
    checkpoint_path: PathBuf,
    piece_length: u64,
    block_size: u32,
}

impl CheckpointManager {
    pub fn new(
        download_dir: &Path,
        info_hash: [u8; 20],
        piece_length: u64,
        block_size: u32,
    ) -> Result<Self> {
        let hex = hex_encode(&info_hash);
        let checkpoint_path = download_dir.join(format!("{}.checkpoint", hex));

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&checkpoint_path)
            .context("failed to open checkpoint file")?;

        Ok(Self {
            checkpoint_file: file,
            checkpoint_path,
            piece_length,
            block_size,
        })
    }

    pub fn write_partial_piece(
        &mut self,
        piece_index: u64,
        received_blocks: &Bitfield,
        piece_data: &[u8],
    ) -> Result<()> {
        if received_blocks.count_ones() < CHECKPOINT_WRITE_THRESHOLD {
            return Ok(());
        }

        self.checkpoint_file.seek(SeekFrom::Start(0))
            .context("seek failed")?;

        self.checkpoint_file.write_all(CHECKPOINT_HEADER)
            .context("failed to write header")?;
        self.checkpoint_file.write_all(&[CHECKPOINT_VERSION])
            .context("failed to write version")?;

        let piece_index_bytes = piece_index.to_le_bytes();
        self.checkpoint_file.write_all(&piece_index_bytes)
            .context("failed to write piece index")?;

        let bitfield_bytes = received_blocks.as_bytes();
        let bitfield_len = (bitfield_bytes.len() as u32).to_le_bytes();
        self.checkpoint_file.write_all(&bitfield_len)
            .context("failed to write bitfield length")?;
        self.checkpoint_file.write_all(bitfield_bytes)
            .context("failed to write bitfield")?;

        let data_len = (piece_data.len() as u64).to_le_bytes();
        self.checkpoint_file.write_all(&data_len)
            .context("failed to write data length")?;
        self.checkpoint_file.write_all(piece_data)
            .context("failed to write piece data")?;

        self.checkpoint_file.sync_data()
            .context("failed to sync checkpoint")?;

        Ok(())
    }

    pub fn load_checkpoint(&mut self) -> Result<Option<PieceCheckpoint>> {
        self.checkpoint_file.seek(SeekFrom::Start(0))
            .context("seek failed")?;

        let file_len = self.checkpoint_file.metadata()?.len();
        if file_len < CHECKPOINT_HEADER.len() as u64 + 1 {
            return Ok(None);
        }

        let mut header = vec![0u8; CHECKPOINT_HEADER.len()];
        if self.checkpoint_file.read_exact(&mut header).is_err() {
            return Ok(None);
        }

        if header != CHECKPOINT_HEADER {
            return Ok(None);
        }

        let mut version = [0u8; 1];
        self.checkpoint_file.read_exact(&mut version)
            .context("failed to read version")?;

        if version[0] != CHECKPOINT_VERSION {
            return Ok(None);
        }

        let mut piece_index_bytes = [0u8; 8];
        self.checkpoint_file.read_exact(&mut piece_index_bytes)
            .context("failed to read piece index")?;
        let piece_index = u64::from_le_bytes(piece_index_bytes);

        let mut bitfield_len_bytes = [0u8; 4];
        self.checkpoint_file.read_exact(&mut bitfield_len_bytes)
            .context("failed to read bitfield length")?;
        let bitfield_len = u32::from_le_bytes(bitfield_len_bytes) as usize;

        if bitfield_len > 1024 {
            return Ok(None);
        }

        let mut bitfield_bytes = vec![0u8; bitfield_len];
        self.checkpoint_file.read_exact(&mut bitfield_bytes)
            .context("failed to read bitfield")?;

        let block_count = ((self.piece_length + self.block_size as u64 - 1) / self.block_size as u64) as usize;
        let received_blocks = Bitfield::from_bytes(&bitfield_bytes, block_count);

        let mut data_len_bytes = [0u8; 8];
        self.checkpoint_file.read_exact(&mut data_len_bytes)
            .context("failed to read data length")?;
        let _data_len = u64::from_le_bytes(data_len_bytes);

        let data_offset = self.checkpoint_file.stream_position()
            .context("failed to get stream position")?;

        Ok(Some(PieceCheckpoint {
            piece_index,
            received_blocks,
            data_offset,
        }))
    }

    pub fn read_checkpoint_data(&mut self, offset: u64, length: usize) -> Result<Vec<u8>> {
        self.checkpoint_file.seek(SeekFrom::Start(offset))
            .context("seek failed")?;

        let mut buffer = vec![0u8; length];
        self.checkpoint_file.read_exact(&mut buffer)
            .context("read failed")?;

        Ok(buffer)
    }

    pub fn clear(&mut self) -> Result<()> {
        self.checkpoint_file.set_len(0)
            .context("failed to truncate checkpoint file")?;
        self.checkpoint_file.sync_data()
            .context("failed to sync")?;
        Ok(())
    }

    pub fn delete(self) -> Result<()> {
        drop(self.checkpoint_file);
        std::fs::remove_file(&self.checkpoint_path)
            .context("failed to delete checkpoint file")?;
        Ok(())
    }
}

fn hex_encode(data: &[u8]) -> String {
    data.iter()
        .map(|byte| format!("{:02x}", byte))
        .collect::<String>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_checkpoint_write_and_load() {
        let temp_dir = TempDir::new().unwrap();
        let info_hash = [0x42u8; 20];
        let piece_length = 262144;
        let block_size = 16384;

        let mut manager = CheckpointManager::new(
            temp_dir.path(),
            info_hash,
            piece_length,
            block_size,
        ).unwrap();

        let piece_index = 5;
        let block_count = 16;
        let mut received_blocks = Bitfield::new(block_count);
        received_blocks.set(0, true);
        received_blocks.set(1, true);
        received_blocks.set(5, true);
        received_blocks.set(10, true);
        received_blocks.set(15, true);

        let test_data = vec![0x42u8; piece_length as usize];

        manager.write_partial_piece(piece_index, &received_blocks, &test_data).unwrap();

        let loaded = manager.load_checkpoint().unwrap();
        assert!(loaded.is_some());

        let checkpoint = loaded.unwrap();
        assert_eq!(checkpoint.piece_index, piece_index);
        assert_eq!(checkpoint.received_blocks.count_ones(), 5);
        assert!(checkpoint.received_blocks.get(0));
        assert!(checkpoint.received_blocks.get(1));
        assert!(checkpoint.received_blocks.get(5));
    }

    #[test]
    fn test_checkpoint_clear() {
        let temp_dir = TempDir::new().unwrap();
        let info_hash = [0x42u8; 20];

        let mut manager = CheckpointManager::new(
            temp_dir.path(),
            info_hash,
            262144,
            16384,
        ).unwrap();

        let mut received_blocks = Bitfield::new(16);
        received_blocks.set(0, true);
        received_blocks.set(3, true);
        received_blocks.set(7, true);
        received_blocks.set(12, true);
        received_blocks.set(15, true);

        let test_data = vec![0x42u8; 262144];
        manager.write_partial_piece(0, &received_blocks, &test_data).unwrap();

        manager.clear().unwrap();

        let loaded = manager.load_checkpoint().unwrap();
        assert!(loaded.is_none());
    }
}
