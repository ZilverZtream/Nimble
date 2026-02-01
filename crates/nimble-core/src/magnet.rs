use thiserror::Error;

#[derive(Debug, Error)]
pub enum MagnetError {
    #[error("invalid magnet URI")]
    InvalidUri,
    #[error("missing btih infohash")]
    MissingInfoHash,
    #[error("invalid infohash length")]
    InvalidInfoHashLength,
    #[error("invalid infohash encoding")]
    InvalidInfoHashEncoding,
    #[error("invalid percent encoding")]
    InvalidPercentEncoding,
    #[error("invalid utf-8 in magnet parameter")]
    InvalidUtf8,
    #[error("too many trackers: {0} (max {1})")]
    TooManyTrackers(usize, usize),
    #[error("unsupported tracker scheme: {0}")]
    UnsupportedTrackerScheme(String),
}

pub type Result<T> = std::result::Result<T, MagnetError>;

#[derive(Debug, Clone)]
pub struct MagnetLink {
    pub info_hash: [u8; 20],
    pub trackers: Vec<String>,
}

const MAX_TRACKERS: usize = 200;

fn is_supported_tracker_scheme(url: &str) -> bool {
    url.starts_with("http://") || url.starts_with("https://") || url.starts_with("udp://")
}

pub fn parse_magnet(uri: &str) -> Result<MagnetLink> {
    let query = uri
        .strip_prefix("magnet:?")
        .ok_or(MagnetError::InvalidUri)?;
    let mut info_hash = None;
    let mut trackers = Vec::new();

    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let mut iter = pair.splitn(2, '=');
        let key = iter.next().unwrap_or("");
        let value = iter.next().unwrap_or("");
        if value.is_empty() {
            continue;
        }

        if key == "xt" {
            let decoded = percent_decode(value)?;
            if let Some(hash) = parse_btih(&decoded)? {
                info_hash = Some(hash);
            }
        } else if key == "tr" {
            let decoded = percent_decode(value)?;
            if !decoded.is_empty() {
                if !is_supported_tracker_scheme(&decoded) {
                    return Err(MagnetError::UnsupportedTrackerScheme(decoded));
                }
                if trackers.len() >= MAX_TRACKERS {
                    return Err(MagnetError::TooManyTrackers(
                        trackers.len() + 1,
                        MAX_TRACKERS,
                    ));
                }
                trackers.push(decoded);
            }
        }
    }

    let info_hash = info_hash.ok_or(MagnetError::MissingInfoHash)?;

    Ok(MagnetLink {
        info_hash,
        trackers,
    })
}

fn parse_btih(value: &str) -> Result<Option<[u8; 20]>> {
    let prefix = "urn:btih:";
    if !value.starts_with(prefix) {
        return Ok(None);
    }
    let hash = &value[prefix.len()..];
    if hash.len() == 40 {
        let bytes = decode_hex(hash)?;
        return bytes
            .try_into()
            .map(Some)
            .map_err(|_| MagnetError::InvalidInfoHashLength);
    }
    if hash.len() == 32 {
        let bytes = decode_base32(hash)?;
        if bytes.len() != 20 {
            return Err(MagnetError::InvalidInfoHashLength);
        }
        return bytes
            .try_into()
            .map(Some)
            .map_err(|_| MagnetError::InvalidInfoHashLength);
    }
    Err(MagnetError::InvalidInfoHashLength)
}

fn decode_hex(input: &str) -> Result<Vec<u8>> {
    if input.len() % 2 != 0 {
        return Err(MagnetError::InvalidInfoHashLength);
    }
    let mut out = Vec::with_capacity(input.len() / 2);
    let mut chars = input.as_bytes().iter().copied();
    while let Some(high) = chars.next() {
        let low = chars.next().ok_or(MagnetError::InvalidInfoHashLength)?;
        let hi = hex_value(high)?;
        let lo = hex_value(low)?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_value(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(MagnetError::InvalidInfoHashEncoding),
    }
}

fn decode_base32(input: &str) -> Result<Vec<u8>> {
    let mut buffer: u32 = 0;
    let mut bits: u8 = 0;
    let mut out = Vec::new();

    for ch in input.chars() {
        if ch == '=' {
            break;
        }
        let val = match ch.to_ascii_uppercase() {
            'A'..='Z' => (ch.to_ascii_uppercase() as u8 - b'A') as u32,
            '2'..='7' => (ch as u8 - b'2' + 26) as u32,
            _ => return Err(MagnetError::InvalidInfoHashEncoding),
        };
        buffer = (buffer << 5) | val;
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }

    Ok(out)
}

fn percent_decode(input: &str) -> Result<String> {
    let mut out = Vec::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut idx = 0;

    while idx < bytes.len() {
        match bytes[idx] {
            b'%' => {
                if idx + 2 >= bytes.len() {
                    return Err(MagnetError::InvalidPercentEncoding);
                }
                let hi = hex_value(bytes[idx + 1])?;
                let lo = hex_value(bytes[idx + 2])?;
                out.push((hi << 4) | lo);
                idx += 3;
            }
            b'+' => {
                out.push(b' ');
                idx += 1;
            }
            byte => {
                out.push(byte);
                idx += 1;
            }
        }
    }

    String::from_utf8(out).map_err(|_| MagnetError::InvalidUtf8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_magnet_hex_infohash() {
        let uri = "magnet:?xt=urn:btih:000102030405060708090a0b0c0d0e0f10111213&tr=http%3A%2F%2Ftracker.example.com%2Fannounce";
        let link = parse_magnet(uri).unwrap();
        assert_eq!(
            link.info_hash,
            [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
            ]
        );
        assert_eq!(link.trackers.len(), 1);
    }

    #[test]
    fn parse_magnet_base32_infohash() {
        let uri = "magnet:?xt=urn:btih:AAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQT";
        let link = parse_magnet(uri).unwrap();
        assert_eq!(
            link.info_hash,
            [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
            ]
        );
    }
}
