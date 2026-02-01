const PEER_ID_PREFIX: &[u8; 8] = b"-NM0001-";

pub fn peer_id_20() -> Result<[u8; 20], String> {
    let mut id = [0u8; 20];
    id[..8].copy_from_slice(PEER_ID_PREFIX);

    let random_bytes = generate_random_bytes::<12>()?;
    id[8..20].copy_from_slice(&random_bytes);

    Ok(id)
}

pub fn dht_node_id_20() -> Result<[u8; 20], String> {
    generate_random_bytes::<20>()
}

pub fn generate_random_bytes<const N: usize>() -> Result<[u8; N], String> {
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
            return Err(format!(
                "BCryptGenRandom failed with status 0x{:08X}",
                result
            ));
        }
    }

    #[cfg(all(unix, not(target_os = "windows")))]
    {
        use std::io::Read;
        let mut file = std::fs::File::open("/dev/urandom")
            .map_err(|e| format!("Failed to open /dev/urandom: {}", e))?;
        file.read_exact(&mut bytes)
            .map_err(|e| format!("Failed to read from /dev/urandom: {}", e))?;
    }

    #[cfg(not(any(target_os = "windows", unix)))]
    {
        compile_error!("No secure random number generator available for this platform");
    }

    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_id_prefix() {
        let id = peer_id_20().unwrap();
        assert_eq!(&id[..8], PEER_ID_PREFIX);
    }

    #[test]
    fn test_peer_id_length() {
        let id = peer_id_20().unwrap();
        assert_eq!(id.len(), 20);
    }

    #[test]
    fn test_peer_ids_differ() {
        let id1 = peer_id_20().unwrap();
        let id2 = peer_id_20().unwrap();
        assert_ne!(id1[8..], id2[8..]);
    }

    #[test]
    fn test_dht_node_id_length() {
        let id = dht_node_id_20().unwrap();
        assert_eq!(id.len(), 20);
    }
}
