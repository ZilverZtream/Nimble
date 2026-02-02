use nimble_bencode::torrent::{TorrentInfo, TorrentMode};
use std::path::PathBuf;

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

impl FileLayout {
    pub fn new(info: &TorrentInfo, download_dir: PathBuf) -> Self {
        let mut files = Vec::new();
        let mut offset = 0u64;
        let root = download_dir.clone();

        match &info.mode {
            TorrentMode::SingleFile { name, length } => {
                files.push(FileEntry {
                    path: download_dir.join(name),
                    offset: 0,
                    length: *length,
                });
            }
            TorrentMode::MultiFile { name, files: file_list } => {
                let base = download_dir.join(name);
                for file_info in file_list {
                    let mut path = base.clone();
                    for component in &file_info.path {
                        path = path.join(component);
                    }

                    files.push(FileEntry {
                        path,
                        offset,
                        length: file_info.length,
                    });

                    offset += file_info.length;
                }
            }
        }

        FileLayout {
            files,
            piece_length: info.piece_length,
            total_length: info.total_length,
            root_dir: root,
        }
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
        }
    }

    #[test]
    fn test_single_file_layout() {
        let info = make_test_info_single();
        let layout = FileLayout::new(&info, PathBuf::from("/downloads"));

        assert_eq!(layout.file_count(), 1);
        assert_eq!(
            layout.file_path(0).unwrap(),
            &PathBuf::from("/downloads/test.dat")
        );
    }

    #[test]
    fn test_multi_file_layout() {
        let info = make_test_info_multi();
        let layout = FileLayout::new(&info, PathBuf::from("/downloads"));

        assert_eq!(layout.file_count(), 3);
        assert_eq!(
            layout.file_path(0).unwrap(),
            &PathBuf::from("/downloads/test_dir/file1.dat")
        );
    }

    #[test]
    fn test_map_piece_single_file() {
        let info = make_test_info_single();
        let layout = FileLayout::new(&info, PathBuf::from("/downloads"));

        let segments = layout.map_piece(0);
        assert_eq!(segments.len(), 1);
        assert_eq!(segments[0].file_index, 0);
        assert_eq!(segments[0].file_offset, 0);
        assert_eq!(segments[0].length, 16384);
    }

    #[test]
    fn test_map_piece_multi_file() {
        let info = make_test_info_multi();
        let layout = FileLayout::new(&info, PathBuf::from("/downloads"));

        let segments = layout.map_piece(0);
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[0].file_index, 0);
        assert_eq!(segments[0].file_offset, 0);
        assert_eq!(segments[0].length, 10000);
        assert_eq!(segments[1].file_index, 1);
        assert_eq!(segments[1].file_offset, 0);
        assert_eq!(segments[1].length, 6384);
    }
}
