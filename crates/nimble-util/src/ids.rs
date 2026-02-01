const PEER_ID_PREFIX: &[u8; 8] = b"-NM0001-";

pub fn peer_id_20() -> [u8; 20] {
    let mut id = [0u8; 20];
    id[..8].copy_from_slice(PEER_ID_PREFIX);

    let random_bytes = generate_random_bytes::<12>();
    id[8..20].copy_from_slice(&random_bytes);

    id
}

pub fn dht_node_id_20() -> [u8; 20] {
    generate_random_bytes::<20>()
}

pub fn generate_random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];

    #[cfg(target_os = "windows")]
    {
        use windows_sys::Win32::Security::Cryptography::{
            BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        };

        let result = unsafe {
            BCryptGenRandom(
                std::ptr::null_mut(),
                bytes.as_mut_ptr(),
                N as u32,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };

        if result != 0 {
            panic!(
                "BCryptGenRandom failed with status 0x{:08X} - this should never happen on Windows",
                result
            );
        }
    }

    #[cfg(all(unix, not(target_os = "windows")))]
    {
        use std::io::Read;
        let mut file = std::fs::File::open("/dev/urandom")
            .expect("Failed to open /dev/urandom");
        file.read_exact(&mut bytes)
            .expect("Failed to read from /dev/urandom");
    }

    #[cfg(not(any(target_os = "windows", unix)))]
    {
        compile_error!("No secure random number generator available for this platform");
    }

    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_id_prefix() {
        let id = peer_id_20();
        assert_eq!(&id[..8], PEER_ID_PREFIX);
    }

    #[test]
    fn test_peer_id_length() {
        let id = peer_id_20();
        assert_eq!(id.len(), 20);
    }

    #[test]
    fn test_peer_ids_differ() {
        let id1 = peer_id_20();
        let id2 = peer_id_20();
        assert_ne!(id1[8..], id2[8..]);
    }

    #[test]
    fn test_dht_node_id_length() {
        let id = dht_node_id_20();
        assert_eq!(id.len(), 20);
    }
}
