use std::time::{SystemTime, UNIX_EPOCH};

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
            fallback_random(&mut bytes);
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        fallback_random(&mut bytes);
    }

    bytes
}

fn fallback_random(bytes: &mut [u8]) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);

    let pid = std::process::id() as u128;
    let addr = bytes.as_ptr() as usize as u128;

    let mut state = now ^ (pid << 32) ^ (addr << 64);

    for byte in bytes.iter_mut() {
        state = state.wrapping_mul(0x5851F42D4C957F2D);
        state = state.wrapping_add(0x14057B7EF767814F);
        *byte = (state >> 64) as u8;
    }
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
