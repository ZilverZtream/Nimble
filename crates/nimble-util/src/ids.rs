// Placeholder: peer id generation, node id generation, random ids.

pub fn peer_id_20() -> [u8; 20] {
    // TODO: stable-per-install with optional rotation
    *b"-NM0001-000000000000"
}

pub fn dht_node_id_20() -> [u8; 20] {
    // TODO: random 20 bytes with good entropy
    [0u8; 20]
}
