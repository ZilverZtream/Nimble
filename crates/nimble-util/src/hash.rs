// SHA-1 helpers.
// For minimal footprint on Windows, consider using Windows CNG (bcrypt) instead of a Rust crypto crate.

#[cfg(feature = "sha1_crate")]
pub fn sha1(data: &[u8]) -> [u8; 20] {
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    h.update(data);
    let out = h.finalize();
    let mut r = [0u8; 20];
    r.copy_from_slice(&out[..]);
    r
}

#[cfg(not(feature = "sha1_crate"))]
pub fn sha1(_data: &[u8]) -> [u8; 20] {
    // Placeholder: switch to Windows CNG or a tiny internal implementation.
    [0u8; 20]
}
