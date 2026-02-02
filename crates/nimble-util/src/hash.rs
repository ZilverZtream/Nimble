// SHA-1 helpers.
// For minimal footprint on Windows, consider using Windows CNG (bcrypt) instead of a Rust crypto crate.

pub fn sha1(data: &[u8]) -> [u8; 20] {
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    h.update(data);
    let out = h.finalize();
    let mut r = [0u8; 20];
    r.copy_from_slice(&out[..]);
    r
}

pub fn percent_encode(data: &[u8]) -> String {
    let mut result = String::with_capacity(data.len() * 3);

    for &byte in data {
        if byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' || byte == b'.' || byte == b'~' {
            result.push(byte as char);
        } else {
            result.push('%');
            result.push_str(&format!("{:02X}", byte));
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::sha1;

    #[test]
    fn sha1_matches_known_vector() {
        let expected = [
            0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78,
            0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
        ];
        assert_eq!(sha1(b"abc"), expected);
    }
}
