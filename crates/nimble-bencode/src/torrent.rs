use crate::decode::{decode, DecodeError, Value};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TorrentError {
    #[error("bencode decode error: {0}")]
    Decode(#[from] DecodeError),
    #[error("missing required field: {0}")]
    MissingField(&'static str),
    #[error("invalid field type: {0}")]
    InvalidFieldType(&'static str),
    #[error("unsafe file path: {0}")]
    UnsafePath(String),
    #[error("invalid pieces hash length (must be multiple of 20)")]
    InvalidPiecesLength,
    #[error("invalid announce URL")]
    InvalidAnnounce,
}

pub type Result<T> = std::result::Result<T, TorrentError>;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InfoHash(pub [u8; 20]);

impl InfoHash {
    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[derive(Debug, Clone)]
pub struct FileInfo {
    pub path: Vec<String>,
    pub length: u64,
}

#[derive(Debug, Clone)]
pub enum TorrentMode {
    SingleFile { name: String, length: u64 },
    MultiFile { name: String, files: Vec<FileInfo> },
}

#[derive(Debug, Clone)]
pub struct TorrentInfo {
    pub announce: Option<String>,
    pub announce_list: Vec<Vec<String>>,
    pub piece_length: u64,
    pub pieces: Vec<[u8; 20]>,
    pub mode: TorrentMode,
    pub infohash: InfoHash,
    pub total_length: u64,
}

fn sanitize_path_component(component: &str) -> Result<String> {
    if component.is_empty() {
        return Err(TorrentError::UnsafePath("empty path component".to_string()));
    }

    if component == "." || component == ".." {
        return Err(TorrentError::UnsafePath(format!(
            "path traversal not allowed: {}",
            component
        )));
    }

    if component.contains('/') || component.contains('\\') {
        return Err(TorrentError::UnsafePath(format!(
            "path component contains separator: {}",
            component
        )));
    }

    if component.starts_with('/') || component.starts_with('\\') {
        return Err(TorrentError::UnsafePath(format!(
            "absolute path not allowed: {}",
            component
        )));
    }

    #[cfg(windows)]
    {
        if component.len() >= 2 && component.chars().nth(1) == Some(':') {
            return Err(TorrentError::UnsafePath(format!(
                "drive letter not allowed: {}",
                component
            )));
        }
    }

    Ok(component.to_string())
}

fn extract_file_path(path_value: &Value) -> Result<Vec<String>> {
    let path_list = path_value
        .as_list()
        .ok_or(TorrentError::InvalidFieldType("file path must be list"))?;

    if path_list.is_empty() {
        return Err(TorrentError::UnsafePath("empty file path".to_string()));
    }

    let mut sanitized = Vec::new();
    for component_val in path_list {
        let component_str = component_val
            .as_str()
            .ok_or(TorrentError::InvalidFieldType(
                "path component must be string",
            ))?;

        let sanitized_component = sanitize_path_component(component_str)?;
        sanitized.push(sanitized_component);
    }

    Ok(sanitized)
}

pub fn parse_info_dict(info_bencoded: &[u8]) -> Result<TorrentInfo> {
    let value = decode(info_bencoded)?;
    let info_dict = value
        .as_dict()
        .ok_or(TorrentError::InvalidFieldType("info must be dict"))?;

    parse_info_dict_fields(info_dict, info_bencoded, None, Vec::new())
}

pub fn parse_torrent(data: &[u8]) -> Result<TorrentInfo> {
    let root = decode(data)?;
    let root_dict = root
        .as_dict()
        .ok_or(TorrentError::InvalidFieldType("root must be dict"))?;

    let announce = root_dict
        .get(b"announce".as_ref())
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let mut announce_list = Vec::new();
    if let Some(announce_list_val) = root_dict.get(b"announce-list".as_ref()) {
        if let Some(tiers) = announce_list_val.as_list() {
            for tier_val in tiers {
                if let Some(tier) = tier_val.as_list() {
                    let mut tier_urls = Vec::new();
                    for url_val in tier {
                        if let Some(url) = url_val.as_str() {
                            tier_urls.push(url.to_string());
                        }
                    }
                    if !tier_urls.is_empty() {
                        announce_list.push(tier_urls);
                    }
                }
            }
        }
    }

    let info_value = root_dict
        .get(b"info".as_ref())
        .ok_or(TorrentError::MissingField("info"))?;

    let info_dict = info_value
        .as_dict()
        .ok_or(TorrentError::InvalidFieldType("info must be dict"))?;

    let info_range =
        find_info_dict_range(data).ok_or(TorrentError::MissingField("info dict not found"))?;
    let info_bencoded = &data[info_range.0..info_range.1];

    parse_info_dict_fields(info_dict, info_bencoded, announce, announce_list)
}

fn parse_info_dict_fields(
    info_dict: &std::collections::BTreeMap<&[u8], Value>,
    info_bencoded: &[u8],
    announce: Option<String>,
    announce_list: Vec<Vec<String>>,
) -> Result<TorrentInfo> {
    let piece_length = info_dict
        .get(b"piece length".as_ref())
        .and_then(|v| v.as_integer())
        .ok_or(TorrentError::MissingField("piece length"))?;

    if piece_length <= 0 {
        return Err(TorrentError::InvalidFieldType(
            "piece length must be positive",
        ));
    }

    let pieces_bytes = info_dict
        .get(b"pieces".as_ref())
        .and_then(|v| v.as_bytes())
        .ok_or(TorrentError::MissingField("pieces"))?;

    if pieces_bytes.len() % 20 != 0 {
        return Err(TorrentError::InvalidPiecesLength);
    }

    let mut pieces = Vec::new();
    for chunk in pieces_bytes.chunks_exact(20) {
        let mut hash = [0u8; 20];
        hash.copy_from_slice(chunk);
        pieces.push(hash);
    }

    let name = info_dict
        .get(b"name".as_ref())
        .and_then(|v| v.as_str())
        .ok_or(TorrentError::MissingField("name"))?
        .to_string();

    let name = sanitize_path_component(&name)?;

    let (mode, total_length) = if let Some(length_val) = info_dict.get(b"length".as_ref()) {
        let length = length_val
            .as_integer()
            .ok_or(TorrentError::InvalidFieldType("length must be integer"))?;

        if length < 0 {
            return Err(TorrentError::InvalidFieldType(
                "length must be non-negative",
            ));
        }

        (
            TorrentMode::SingleFile {
                name: name.clone(),
                length: length as u64,
            },
            length as u64,
        )
    } else if let Some(files_val) = info_dict.get(b"files".as_ref()) {
        let files_list = files_val
            .as_list()
            .ok_or(TorrentError::InvalidFieldType("files must be list"))?;

        let mut files = Vec::new();
        let mut total = 0u64;

        for file_val in files_list {
            let file_dict = file_val
                .as_dict()
                .ok_or(TorrentError::InvalidFieldType("file entry must be dict"))?;

            let length = file_dict
                .get(b"length".as_ref())
                .and_then(|v| v.as_integer())
                .ok_or(TorrentError::MissingField("file length"))?;

            if length < 0 {
                return Err(TorrentError::InvalidFieldType(
                    "file length must be non-negative",
                ));
            }

            let path_val = file_dict
                .get(b"path".as_ref())
                .ok_or(TorrentError::MissingField("file path"))?;

            let path = extract_file_path(path_val)?;

            total = total.saturating_add(length as u64);

            files.push(FileInfo {
                path,
                length: length as u64,
            });
        }

        (TorrentMode::MultiFile { name, files }, total)
    } else {
        return Err(TorrentError::MissingField("length or files"));
    };

    let infohash = compute_infohash(info_bencoded);

    Ok(TorrentInfo {
        announce,
        announce_list,
        piece_length: piece_length as u64,
        pieces,
        mode,
        infohash,
        total_length,
    })
}

fn compute_infohash(info_bencoded: &[u8]) -> InfoHash {
    let hash = nimble_util::hash::sha1(info_bencoded);

    InfoHash(hash)
}

fn find_info_dict_range(data: &[u8]) -> Option<(usize, usize)> {
    let needle = b"4:info";
    let mut pos = 0;

    while pos + needle.len() <= data.len() {
        if &data[pos..pos + needle.len()] == needle {
            let value_start = pos + needle.len();
            if let Some(value_end) = find_bencode_value_end(data, value_start) {
                return Some((value_start, value_end));
            }
        }
        pos += 1;
    }

    None
}

fn find_bencode_value_end(data: &[u8], start: usize) -> Option<usize> {
    if start >= data.len() {
        return None;
    }

    let mut pos = start;
    let first = data[pos];

    match first {
        b'i' => {
            pos += 1;
            while pos < data.len() && data[pos] != b'e' {
                pos += 1;
            }
            if pos < data.len() {
                Some(pos + 1)
            } else {
                None
            }
        }
        b'l' | b'd' => {
            pos += 1;
            let mut depth = 1;

            while pos < data.len() && depth > 0 {
                match data[pos] {
                    b'l' | b'd' => depth += 1,
                    b'e' => depth -= 1,
                    b'i' => {
                        pos += 1;
                        while pos < data.len() && data[pos] != b'e' {
                            pos += 1;
                        }
                    }
                    b'0'..=b'9' => {
                        let len_start = pos;
                        while pos < data.len() && data[pos].is_ascii_digit() {
                            pos += 1;
                        }
                        if pos < data.len() && data[pos] == b':' {
                            let len_bytes = &data[len_start..pos];
                            if let Ok(len_str) = std::str::from_utf8(len_bytes) {
                                if let Ok(len) = len_str.parse::<usize>() {
                                    pos += 1;
                                    pos += len;
                                    continue;
                                }
                            }
                            return None;
                        }
                    }
                    _ => {}
                }
                pos += 1;
            }

            if depth == 0 {
                Some(pos)
            } else {
                None
            }
        }
        b'0'..=b'9' => {
            let len_start = pos;
            while pos < data.len() && data[pos].is_ascii_digit() {
                pos += 1;
            }
            if pos < data.len() && data[pos] == b':' {
                let len_bytes = &data[len_start..pos];
                if let Ok(len_str) = std::str::from_utf8(len_bytes) {
                    if let Ok(len) = len_str.parse::<usize>() {
                        pos += 1;
                        pos += len;
                        return Some(pos);
                    }
                }
            }
            None
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_path_reject_traversal() {
        assert!(sanitize_path_component("..").is_err());
        assert!(sanitize_path_component(".").is_err());
    }

    #[test]
    fn test_sanitize_path_reject_separators() {
        assert!(sanitize_path_component("foo/bar").is_err());
        assert!(sanitize_path_component("foo\\bar").is_err());
    }

    #[test]
    fn test_sanitize_path_accept_normal() {
        assert_eq!(sanitize_path_component("hello.txt").unwrap(), "hello.txt");
        assert_eq!(sanitize_path_component("subdir").unwrap(), "subdir");
    }

    #[test]
    fn test_parse_single_file_torrent() {
        let torrent = b"d8:announce21:http://example.com:804:infod6:lengthi1024e4:name8:test.txt12:piece lengthi262144e6:pieces20:\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13ee";

        let info = parse_torrent(torrent).unwrap();

        assert_eq!(info.announce, Some("http://example.com:80".to_string()));
        assert_eq!(info.piece_length, 262144);
        assert_eq!(info.pieces.len(), 1);
        assert_eq!(info.total_length, 1024);

        match info.mode {
            TorrentMode::SingleFile { name, length } => {
                assert_eq!(name, "test.txt");
                assert_eq!(length, 1024);
            }
            _ => panic!("expected single file mode"),
        }
    }

    #[test]
    fn test_parse_info_dict() {
        let info = b"d6:lengthi1024e4:name8:test.txt12:piece lengthi262144e6:pieces20:\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13e";
        let parsed = parse_info_dict(info).unwrap();

        assert_eq!(parsed.announce, None);
        assert_eq!(parsed.piece_length, 262144);
        assert_eq!(parsed.pieces.len(), 1);
        assert_eq!(parsed.total_length, 1024);

        let expected_hash = nimble_util::hash::sha1(info);
        assert_eq!(*parsed.infohash.as_bytes(), expected_hash);
    }
}
