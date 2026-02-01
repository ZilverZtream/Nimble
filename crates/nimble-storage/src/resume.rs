use anyhow::{Context, Result};
use nimble_util::bitfield::Bitfield;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const RESUME_VERSION: u8 = 1;
const RESUME_FILE_HEADER: &[u8] = b"NIMBLE_RESUME";

#[derive(Debug)]
pub struct ResumeData {
    pub info_hash: [u8; 20],
    pub bitfield: Bitfield,
}

impl ResumeData {
    pub fn new(info_hash: [u8; 20], piece_count: usize) -> Self {
        Self {
            info_hash,
            bitfield: Bitfield::new(piece_count),
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let mut temp_path = path.to_path_buf();
        temp_path.set_extension("tmp");

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temp_path)
            .context("failed to create resume temp file")?;

        file.write_all(RESUME_FILE_HEADER)
            .context("failed to write header")?;
        file.write_all(&[RESUME_VERSION])
            .context("failed to write version")?;
        file.write_all(&self.info_hash)
            .context("failed to write info_hash")?;

        let bitfield_bytes = self.bitfield.as_bytes();
        let len = (bitfield_bytes.len() as u32).to_le_bytes();
        file.write_all(&len)
            .context("failed to write bitfield length")?;
        file.write_all(bitfield_bytes)
            .context("failed to write bitfield")?;

        file.sync_all().context("failed to sync temp file")?;
        drop(file);

        std::fs::rename(&temp_path, path).context("failed to rename temp file to final path")?;

        Ok(())
    }

    pub fn load(path: &Path, expected_piece_count: usize) -> Result<Self> {
        let mut file = File::open(path).context("failed to open resume file")?;

        let mut header = vec![0u8; RESUME_FILE_HEADER.len()];
        file.read_exact(&mut header)
            .context("failed to read header")?;
        if header != RESUME_FILE_HEADER {
            anyhow::bail!("invalid resume file header");
        }

        let mut version = [0u8; 1];
        file.read_exact(&mut version)
            .context("failed to read version")?;
        if version[0] != RESUME_VERSION {
            anyhow::bail!(
                "unsupported resume file version: {} (expected {})",
                version[0],
                RESUME_VERSION
            );
        }

        let mut info_hash = [0u8; 20];
        file.read_exact(&mut info_hash)
            .context("failed to read info_hash")?;

        let mut len_bytes = [0u8; 4];
        file.read_exact(&mut len_bytes)
            .context("failed to read bitfield length")?;
        let len = u32::from_le_bytes(len_bytes) as usize;

        if len > 1_000_000 {
            anyhow::bail!("bitfield length too large: {}", len);
        }

        let expected_bytes = (expected_piece_count + 7) / 8;
        if len != expected_bytes {
            anyhow::bail!(
                "bitfield length mismatch: expected {} bytes for {} pieces, got {} bytes",
                expected_bytes,
                expected_piece_count,
                len
            );
        }

        let mut bitfield_bytes = vec![0u8; len];
        file.read_exact(&mut bitfield_bytes)
            .context("failed to read bitfield")?;

        let bitfield = Bitfield::from_bytes(&bitfield_bytes, expected_piece_count);

        Ok(Self {
            info_hash,
            bitfield,
        })
    }

    pub fn resume_file_path(download_dir: &Path, info_hash: [u8; 20]) -> PathBuf {
        let hex = hex_encode(&info_hash);
        download_dir.join(format!("{}.resume", hex))
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
    fn test_save_and_load() {
        let temp_dir = TempDir::new().unwrap();
        let info_hash = [0x42u8; 20];
        let path = temp_dir.path().join("test.resume");

        let mut resume = ResumeData::new(info_hash, 100);
        resume.bitfield.set(0, true);
        resume.bitfield.set(50, true);
        resume.bitfield.set(99, true);

        resume.save(&path).unwrap();

        let loaded = ResumeData::load(&path, 100).unwrap();
        assert_eq!(loaded.info_hash, info_hash);
        assert!(loaded.bitfield.get(0));
        assert!(loaded.bitfield.get(50));
        assert!(loaded.bitfield.get(99));
        assert!(!loaded.bitfield.get(1));
    }

    #[test]
    fn test_version_mismatch() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("bad.resume");

        let mut file = File::create(&path).unwrap();
        file.write_all(RESUME_FILE_HEADER).unwrap();
        file.write_all(&[99u8]).unwrap();
        drop(file);

        let result = ResumeData::load(&path, 100);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("unsupported resume file version"));
    }
}
