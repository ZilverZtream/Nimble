use nimble_bencode::torrent::{TorrentInfo, TorrentMode};
use std::path::{Path, PathBuf};
use anyhow::{Context, Result};

#[derive(Clone)]
pub struct FileLayout {
    files: Vec<FileEntry>,
    piece_length: u64,
    total_length: u64,
    root_dir: PathBuf,
}

#[derive(Clone)]
struct FileEntry {
    path: PathBuf,
    offset: u64,
    length: u64,
}

#[derive(Clone)]
pub struct FileInfo {
    pub path: PathBuf,
    pub length: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct FileSegment {
    pub file_index: usize,
    pub file_offset: u64,
    pub length: u64,
}

/// Sanitizes a path component to prevent directory traversal attacks.
/// Rejects absolute paths, "..", ".", and other dangerous patterns.
/// Returns None if the component is invalid.
fn sanitize_path_component(component: &str) -> Option<&str> {
    // Reject empty components
    if component.is_empty() {
        return None;
    }

    // Reject "." and ".." to prevent traversal
    if component == "." || component == ".." {
        return None;
    }

    // Reject absolute paths (starting with / or \)
    if component.starts_with('/') || component.starts_with('\\') {
        return None;
    }

    // Reject drive letters on Windows (e.g., "C:", "D:")
    #[cfg(target_os = "windows")]
    {
        if component.len() >= 2 && component.chars().nth(1) == Some(':') {
            let first_char = component.chars().next().unwrap();
            if first_char.is_ascii_alphabetic() {
                return None;
            }
        }
    }

    // Reject components containing null bytes
    if component.contains('\0') {
        return None;
    }

    // Reject components with path separators in the middle
    if component.contains('/') || component.contains('\\') {
        return None;
    }

    Some(component)
}

/// Safely joins path components, sanitizing each one to prevent traversal.
/// Returns None if any component is invalid.
fn safe_join(base: &Path, components: &[String]) -> Option<PathBuf> {
    let mut path = base.to_path_buf();
    for component in components {
        let sanitized = sanitize_path_component(component)?;
        path = path.join(sanitized);
    }
    Some(path)
}

impl FileLayout {
    pub fn new(info: &TorrentInfo, download_dir: PathBuf) -> Result<Self> {
        let mut files = Vec::new();
        let mut offset = 0u64;
        let root = download_dir.clone();

        match &info.mode {
            TorrentMode::SingleFile { name, length } => {
                let sanitized_name = sanitize_path_component(name)
                    .ok_or_else(|| anyhow::anyhow!("invalid file name in torrent: {:?}", name))?;
                files.push(FileEntry {
                    path: download_dir.join(sanitized_name),
                    offset: 0,
                    length: *length,
                });
            }
            TorrentMode::MultiFile { name, files: file_list } => {
                let sanitized_dir = sanitize_path_component(name)
                    .ok_or_else(|| anyhow::anyhow!("invalid directory name in torrent: {:?}", name))?;
                let base = download_dir.join(sanitized_dir);

                for file_info in file_list {
                    let path = safe_join(&base, &file_info.path)
                        .ok_or_else(|| anyhow::anyhow!("invalid file path in torrent: {:?}", file_info.path))?;

                    files.push(FileEntry {
                        path,
                        offset,
                        length: file_info.length,
                    });

                    offset += file_info.length;
                }
            }
        }

        Ok(FileLayout {
            files,
            piece_length: info.piece_length,
            total_length: info.total_length,
            root_dir: root,
        })
    }

    pub fn files(&self) -> Vec<FileInfo> {
        self.files.iter().map(|f| FileInfo {
            path: f.path.clone(),
            length: f.length,
        }).collect()
    }

    pub fn root_dir(&self) -> PathBuf {
        self.root_dir.clone()
    }

    pub fn file_count(&self) -> usize {
        self.files.len()
    }

    pub fn file_path(&self, index: usize) -> Option<&PathBuf> {
        self.files.get(index).map(|f| &f.path)
    }

    pub fn map_piece(&self, piece_index: u64) -> Vec<FileSegment> {
        let start = piece_index * self.piece_length;
        let end = ((piece_index + 1) * self.piece_length).min(self.total_length);
        self.map_range(start, end)
    }

    pub fn map_range(&self, start: u64, end: u64) -> Vec<FileSegment> {
        let mut segments = Vec::new();
        let length = end - start;

        if length == 0 {
            return segments;
        }

        for (file_index, file) in self.files.iter().enumerate() {
            let file_end = file.offset + file.length;

            if start >= file_end || end <= file.offset {
                continue;
            }

            let seg_start = start.max(file.offset);
            let seg_end = end.min(file_end);
            let seg_length = seg_end - seg_start;

            if seg_length > 0 {
                segments.push(FileSegment {
                    file_index,
                    file_offset: seg_start - file.offset,
                    length: seg_length,
                });
            }
        }

        segments
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nimble_bencode::torrent::{FileInfo, InfoHash, TorrentMode};

    fn make_test_info_single() -> TorrentInfo {
        TorrentInfo {
            announce: None,
            announce_list: vec![],
            piece_length: 16384,
            pieces: vec![],
            mode: TorrentMode::SingleFile {
                name: "test.dat".to_string(),
                length: 32768,
            },
            infohash: InfoHash([0u8; 20]),
            total_length: 32768,
            private: false,
        }
    }

    fn make_test_info_multi() -> TorrentInfo {
        TorrentInfo {
            announce: None,
            announce_list: vec![],
            piece_length: 16384,
            pieces: vec![],
            mode: TorrentMode::MultiFile {
                name: "test_dir".to_string(),
                files: vec![
                    FileInfo {
                        path: vec!["file1.dat".to_string()],
                        length: 10000,
                    },
                    FileInfo {
                        path: vec!["file2.dat".to_string()],
                        length: 20000,
                    },
                    FileInfo {
                        path: vec!["file3.dat".to_string()],
                        length: 5000,
                    },
                ],
            },
            infohash: InfoHash([0u8; 20]),
            total_length: 35000,
            private: false,
        }
    }

    #[test]
    fn test_single_file_layout() {
        let info = make_test_info_single();
        let layout = FileLayout::new(&info, PathBuf::from("/downloads")).unwrap();

        assert_eq!(layout.file_count(), 1);
        assert_eq!(
            layout.file_path(0).unwrap(),
            &PathBuf::from("/downloads/test.dat")
        );
    }

    #[test]
    fn test_multi_file_layout() {
        let info = make_test_info_multi();
        let layout = FileLayout::new(&info, PathBuf::from("/downloads")).unwrap();

        assert_eq!(layout.file_count(), 3);
        assert_eq!(
            layout.file_path(0).unwrap(),
            &PathBuf::from("/downloads/test_dir/file1.dat")
        );
    }

    #[test]
    fn test_map_piece_single_file() {
        let info = make_test_info_single();
        let layout = FileLayout::new(&info, PathBuf::from("/downloads")).unwrap();

        let segments = layout.map_piece(0);
        assert_eq!(segments.len(), 1);
        assert_eq!(segments[0].file_index, 0);
        assert_eq!(segments[0].file_offset, 0);
        assert_eq!(segments[0].length, 16384);
    }

    #[test]
    fn test_map_piece_multi_file() {
        let info = make_test_info_multi();
        let layout = FileLayout::new(&info, PathBuf::from("/downloads")).unwrap();

        let segments = layout.map_piece(0);
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[0].file_index, 0);
        assert_eq!(segments[0].file_offset, 0);
        assert_eq!(segments[0].length, 10000);
        assert_eq!(segments[1].file_index, 1);
        assert_eq!(segments[1].file_offset, 0);
        assert_eq!(segments[1].length, 6384);
    }

    #[test]
    fn test_path_traversal_rejection() {
        let mut info = make_test_info_multi();
        if let TorrentMode::MultiFile { files, .. } = &mut info.mode {
            // Try to inject path traversal
            files[0].path = vec!["..".to_string(), "etc".to_string(), "passwd".to_string()];
        }

        let result = FileLayout::new(&info, PathBuf::from("/downloads"));
        assert!(result.is_err(), "Should reject .. in path");
    }

    #[test]
    fn test_absolute_path_rejection() {
        let mut info = make_test_info_single();
        if let TorrentMode::SingleFile { name, .. } = &mut info.mode {
            *name = "/etc/passwd".to_string();
        }

        let result = FileLayout::new(&info, PathBuf::from("/downloads"));
        assert!(result.is_err(), "Should reject absolute path");
    }
}
