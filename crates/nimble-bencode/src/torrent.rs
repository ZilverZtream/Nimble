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
    #[error("piece count mismatch: expected {expected}, got {actual}")]
    PieceCountMismatch { expected: usize, actual: usize },
    #[error("piece length too large: {0} bytes (max {1})")]
    PieceLengthTooLarge(u64, u64),
    #[error("total length overflow")]
    TotalLengthOverflow,
    #[error("too many files: {0} (max {1})")]
    TooManyFiles(usize, usize),
    #[error("path depth too deep: {0} components (max {1})")]
    PathTooDeep(usize, usize),
    #[error("total path length too long: {0} bytes (max {1})")]
    TotalPathTooLong(usize, usize),
    #[error("too many trackers: {0} (max {1})")]
    TooManyTrackers(usize, usize),
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
    pub private: bool,
}

const MAX_PATH_COMPONENT_LENGTH: usize = 255;
const MAX_FILES_IN_TORRENT: usize = 50_000;
const MAX_PATH_DEPTH: usize = 32;
const MAX_TOTAL_PATH_LENGTH: usize = 4096;
const MAX_TRACKERS: usize = 200;
const MAX_BITFIELD_BYTES: usize = 262144;
const MAX_PIECES: usize = MAX_BITFIELD_BYTES * 8;
const MAX_TRACKER_URL_LENGTH: usize = 2048;
const WINDOWS_RESERVED_NAMES: &[&str] = &[
    "CON", "PRN", "AUX", "NUL",
    "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
    "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];
const WINDOWS_FORBIDDEN_CHARS: &[char] = &['<', '>', ':', '"', '|', '?', '*'];

fn validate_tracker_url(url: &str) -> Result<()> {
    if url.len() > MAX_TRACKER_URL_LENGTH {
        return Err(TorrentError::InvalidAnnounce);
    }

    if url.is_empty() {
        return Err(TorrentError::InvalidAnnounce);
    }

    let lower = url.to_lowercase();
    if !lower.starts_with("http://")
        && !lower.starts_with("https://")
        && !lower.starts_with("udp://")
        && !lower.starts_with("wss://")
        && !lower.starts_with("ws://")
    {
        return Err(TorrentError::InvalidAnnounce);
    }

    Ok(())
}

fn sanitize_path_component(component: &str) -> Result<String> {
    if component.is_empty() {
        return Err(TorrentError::UnsafePath("empty path component".to_string()));
    }

    if component.len() > MAX_PATH_COMPONENT_LENGTH {
        return Err(TorrentError::UnsafePath(format!(
            "path component too long: {} bytes (max {})",
            component.len(),
            MAX_PATH_COMPONENT_LENGTH
        )));
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

    for &forbidden_char in WINDOWS_FORBIDDEN_CHARS {
        if component.contains(forbidden_char) {
            return Err(TorrentError::UnsafePath(format!(
                "forbidden character '{}' in path component: {}",
                forbidden_char, component
            )));
        }
    }

    let trimmed = component.trim_end_matches(&['.', ' '][..]);
    if trimmed.is_empty() {
        return Err(TorrentError::UnsafePath(format!(
            "path component is only dots/spaces: {}",
            component
        )));
    }
    if trimmed != component {
        return Err(TorrentError::UnsafePath(format!(
            "path component has trailing dots/spaces: {}",
            component
        )));
    }

    let upper = component.to_uppercase();
    let base_name = upper.split('.').next().unwrap_or("");
    if WINDOWS_RESERVED_NAMES.contains(&base_name) {
        return Err(TorrentError::UnsafePath(format!(
            "Windows reserved device name: {}",
            component
        )));
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

    if path_list.len() > MAX_PATH_DEPTH {
        return Err(TorrentError::PathTooDeep(path_list.len(), MAX_PATH_DEPTH));
    }

    let mut sanitized = Vec::new();
    let mut total_path_len = 0;
    for component_val in path_list {
        let component_str = component_val
            .as_str()
            .ok_or(TorrentError::InvalidFieldType(
                "path component must be string",
            ))?;

        let sanitized_component = sanitize_path_component(component_str)?;
        total_path_len += sanitized_component.len() + 1;
        if total_path_len > MAX_TOTAL_PATH_LENGTH {
            return Err(TorrentError::TotalPathTooLong(
                total_path_len,
                MAX_TOTAL_PATH_LENGTH,
            ));
        }
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
        .map(|s| {
            validate_tracker_url(s)?;
            Ok::<String, TorrentError>(s.to_string())
        })
        .transpose()?;

    let mut announce_list = Vec::new();
    let mut total_tracker_count = if announce.is_some() { 1 } else { 0 };
    if let Some(announce_list_val) = root_dict.get(b"announce-list".as_ref()) {
        if let Some(tiers) = announce_list_val.as_list() {
            for tier_val in tiers {
                if let Some(tier) = tier_val.as_list() {
                    let mut tier_urls = Vec::new();
                    for url_val in tier {
                        if let Some(url) = url_val.as_str() {
                            total_tracker_count += 1;
                            if total_tracker_count > MAX_TRACKERS {
                                return Err(TorrentError::TooManyTrackers(
                                    total_tracker_count,
                                    MAX_TRACKERS,
                                ));
                            }
                            validate_tracker_url(url)?;
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

const MAX_PIECE_LENGTH: u64 = 64 * 1024 * 1024;

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

    let piece_length = piece_length as u64;
    if piece_length > MAX_PIECE_LENGTH {
        return Err(TorrentError::PieceLengthTooLarge(
            piece_length,
            MAX_PIECE_LENGTH,
        ));
    }

    let pieces_bytes = info_dict
        .get(b"pieces".as_ref())
        .and_then(|v| v.as_bytes())
        .ok_or(TorrentError::MissingField("pieces"))?;

    if pieces_bytes.len() % 20 != 0 {
        return Err(TorrentError::InvalidPiecesLength);
    }

    let piece_count = pieces_bytes.len() / 20;
    if piece_count > MAX_PIECES {
        return Err(TorrentError::InvalidFieldType(
            "piece count exceeds protocol bitfield limit",
        ));
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

    let private = info_dict
        .get(b"private".as_ref())
        .and_then(|v| v.as_integer())
        .map(|i| i == 1)
        .unwrap_or(false);

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

        if files_list.len() > MAX_FILES_IN_TORRENT {
            return Err(TorrentError::TooManyFiles(
                files_list.len(),
                MAX_FILES_IN_TORRENT,
            ));
        }

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

            total = total
                .checked_add(length as u64)
                .ok_or(TorrentError::TotalLengthOverflow)?;

            files.push(FileInfo {
                path,
                length: length as u64,
            });
        }

        (TorrentMode::MultiFile { name, files }, total)
    } else {
        return Err(TorrentError::MissingField("length or files"));
    };

    let expected_pieces = if total_length == 0 {
        0
    } else {
        ((total_length + piece_length - 1) / piece_length) as usize
    };

    if pieces.len() != expected_pieces {
        return Err(TorrentError::PieceCountMismatch {
            expected: expected_pieces,
            actual: pieces.len(),
        });
    }

    let infohash = compute_infohash(info_bencoded);

    Ok(TorrentInfo {
        announce,
        announce_list,
        piece_length,
        pieces,
        mode,
        infohash,
        total_length,
        private,
    })
}

fn compute_infohash(info_bencoded: &[u8]) -> InfoHash {
    let hash = nimble_util::hash::sha1(info_bencoded);

    InfoHash(hash)
}

fn find_info_dict_range(data: &[u8]) -> Option<(usize, usize)> {
    if data.is_empty() || data[0] != b'd' {
        return None;
    }

    let mut pos = 1;

    while pos < data.len() && data[pos] != b'e' {
        let key_start = pos;
        let key_end = skip_bencode_string(data, key_start)?;
        let key_bytes = extract_bencode_string(data, key_start)?;

        let value_start = key_end;
        let value_end = find_bencode_value_end(data, value_start)?;

        if key_bytes == b"info" {
            return Some((value_start, value_end));
        }

        pos = value_end;
    }

    None
}

fn skip_bencode_string(data: &[u8], start: usize) -> Option<usize> {
    if start >= data.len() || !data[start].is_ascii_digit() {
        return None;
    }

    let mut pos = start;
    while pos < data.len() && data[pos].is_ascii_digit() {
        pos += 1;
    }

    if pos >= data.len() || data[pos] != b':' {
        return None;
    }

    let len_bytes = &data[start..pos];
    let len_str = std::str::from_utf8(len_bytes).ok()?;
    let len: usize = len_str.parse().ok()?;

    pos += 1;
    let end = pos.checked_add(len)?;
    if end > data.len() {
        return None;
    }

    Some(end)
}

fn extract_bencode_string(data: &[u8], start: usize) -> Option<&[u8]> {
    if start >= data.len() || !data[start].is_ascii_digit() {
        return None;
    }

    let mut pos = start;
    while pos < data.len() && data[pos].is_ascii_digit() {
        pos += 1;
    }

    if pos >= data.len() || data[pos] != b':' {
        return None;
    }

    let len_bytes = &data[start..pos];
    let len_str = std::str::from_utf8(len_bytes).ok()?;
    let len: usize = len_str.parse().ok()?;

    pos += 1;
    let end = pos.checked_add(len)?;
    if end > data.len() {
        return None;
    }

    Some(&data[pos..end])
}

fn find_bencode_value_end(data: &[u8], start: usize) -> Option<usize> {
    if start >= data.len() {
        return None;
    }

    let mut pos = start;
    let first = data[pos];
    let mut depth = 0usize;

    match first {
        b'i' => {
            pos = pos.checked_add(1)?;
            while pos < data.len() && data[pos] != b'e' {
                pos = pos.checked_add(1)?;
            }
            if pos < data.len() {
                pos.checked_add(1)
            } else {
                None
            }
        }
        b'l' | b'd' => {
            pos = pos.checked_add(1)?;
            depth = 1;

            while pos < data.len() && depth > 0 {
                match data[pos] {
                    b'l' | b'd' => depth = depth.checked_add(1)?,
                    b'e' => depth = depth.saturating_sub(1),
                    b'i' => {
                        pos = pos.checked_add(1)?;
                        while pos < data.len() && data[pos] != b'e' {
                            pos = pos.checked_add(1)?;
                        }
                    }
                    b'0'..=b'9' => {
                        let len_start = pos;
                        while pos < data.len() && data[pos].is_ascii_digit() {
                            pos = pos.checked_add(1)?;
                        }
                        if pos < data.len() && data[pos] == b':' {
                            let len_bytes = &data[len_start..pos];
                            if let Ok(len_str) = std::str::from_utf8(len_bytes) {
                                if let Ok(len) = len_str.parse::<usize>() {
                                    pos = pos.checked_add(1)?;
                                    pos = pos.checked_add(len)?;
                                    if pos > data.len() {
                                        return None;
                                    }
                                    continue;
                                }
                            }
                            return None;
                        }
                    }
                    _ => {}
                }
                pos = pos.checked_add(1)?;
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
                pos = pos.checked_add(1)?;
            }
            if pos < data.len() && data[pos] == b':' {
                let len_bytes = &data[len_start..pos];
                if let Ok(len_str) = std::str::from_utf8(len_bytes) {
                    if let Ok(len) = len_str.parse::<usize>() {
                        pos = pos.checked_add(1)?;
                        pos = pos.checked_add(len)?;
                        if pos > data.len() {
                            return None;
                        }
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

    #[test]
    fn test_parse_info_dict_accepts_large_pieces_field() {
        let piece_count = 419_431usize;
        let pieces_len = piece_count * 20;
        let piece_length = 4u64;
        let total_length = piece_length * piece_count as u64;

        let mut info = Vec::new();
        info.extend_from_slice(b"d6:lengthi");
        info.extend_from_slice(total_length.to_string().as_bytes());
        info.extend_from_slice(b"e4:name8:test.txt12:piece lengthi");
        info.extend_from_slice(piece_length.to_string().as_bytes());
        info.extend_from_slice(b"e6:pieces");
        info.extend_from_slice(pieces_len.to_string().as_bytes());
        info.push(b':');
        info.extend(std::iter::repeat(0u8).take(pieces_len));
        info.push(b'e');

        let parsed = parse_info_dict(&info).unwrap();
        assert_eq!(parsed.piece_length, piece_length);
        assert_eq!(parsed.pieces.len(), piece_count);
        assert_eq!(parsed.total_length, total_length);
    }

    #[test]
    fn test_parse_torrent_accepts_large_pieces_field() {
        let piece_count = 419_431usize;
        let pieces_len = piece_count * 20;
        let piece_length = 4u64;
        let total_length = piece_length * piece_count as u64;
        let announce = b"http://tracker";

        let mut info = Vec::new();
        info.extend_from_slice(b"d6:lengthi");
        info.extend_from_slice(total_length.to_string().as_bytes());
        info.extend_from_slice(b"e4:name8:test.txt12:piece lengthi");
        info.extend_from_slice(piece_length.to_string().as_bytes());
        info.extend_from_slice(b"e6:pieces");
        info.extend_from_slice(pieces_len.to_string().as_bytes());
        info.push(b':');
        info.extend(std::iter::repeat(0u8).take(pieces_len));
        info.push(b'e');

        let mut torrent = Vec::new();
        torrent.extend_from_slice(b"d8:announce");
        torrent.extend_from_slice(announce.len().to_string().as_bytes());
        torrent.push(b':');
        torrent.extend_from_slice(announce);
        torrent.extend_from_slice(b"4:info");
        torrent.extend_from_slice(&info);
        torrent.push(b'e');

        let parsed = parse_torrent(&torrent).unwrap();
        assert_eq!(parsed.announce, Some(String::from_utf8_lossy(announce).to_string()));
        assert_eq!(parsed.piece_length, piece_length);
        assert_eq!(parsed.pieces.len(), piece_count);
        assert_eq!(parsed.total_length, total_length);
    }
}
