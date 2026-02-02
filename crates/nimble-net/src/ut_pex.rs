use anyhow::{anyhow, Result};
use nimble_bencode::decode::Value;
use nimble_bencode::decode::decode;
use std::net::{Ipv4Addr, SocketAddrV4};

use crate::peer_ip::is_valid_peer_ip_v4;

const COMPACT_PEER_LEN: usize = 6;
const MAX_PEX_PEERS: usize = 200;
const MAX_PEX_BYTES: usize = COMPACT_PEER_LEN * MAX_PEX_PEERS;

#[derive(Debug, Default)]
pub struct PexMessage {
    pub added: Vec<SocketAddrV4>,
    pub dropped: Vec<SocketAddrV4>,
}

pub fn parse_pex(payload: &[u8]) -> Result<PexMessage> {
    let value = decode(payload)
        .map_err(|e| anyhow!("ut_pex payload decode failed: {e}"))?;
    let dict = value
        .as_dict()
        .ok_or_else(|| anyhow!("ut_pex payload must be dict"))?;

    let added = dict
        .get(b"added".as_ref())
        .and_then(Value::as_bytes)
        .map(parse_compact_peers)
        .transpose()?
        .unwrap_or_default();

    let dropped = dict
        .get(b"dropped".as_ref())
        .and_then(Value::as_bytes)
        .map(parse_compact_peers)
        .transpose()?
        .unwrap_or_default();

    Ok(PexMessage { added, dropped })
}

fn parse_compact_peers(bytes: &[u8]) -> Result<Vec<SocketAddrV4>> {
    if bytes.len() > MAX_PEX_BYTES {
        return Err(anyhow!("ut_pex compact peer list too large"));
    }
    if bytes.len() % COMPACT_PEER_LEN != 0 {
        return Err(anyhow!("ut_pex compact peer list invalid length"));
    }

    let mut peers = Vec::with_capacity(bytes.len() / COMPACT_PEER_LEN);
    for chunk in bytes.chunks_exact(COMPACT_PEER_LEN) {
        let ip = Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]);
        let port = u16::from_be_bytes([chunk[4], chunk[5]]);
        if port == 0 {
            continue;
        }
        if !is_valid_peer_ip_v4(&ip) {
            continue;
        }
        peers.push(SocketAddrV4::new(ip, port));
    }

    Ok(peers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_added_and_dropped_peers() {
        let mut payload = Vec::new();
        payload.extend_from_slice(b"d5:added6:");
        payload.extend_from_slice(&[1, 1, 1, 1, 0x1a, 0xe1]);
        payload.extend_from_slice(b"7:dropped6:");
        payload.extend_from_slice(&[8, 8, 8, 8, 0x1a, 0xe2]);
        payload.extend_from_slice(b"e");

        let msg = parse_pex(&payload).unwrap();
        assert_eq!(msg.added.len(), 1);
        assert_eq!(msg.dropped.len(), 1);
        assert_eq!(
            msg.added[0],
            SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 6881)
        );
        assert_eq!(
            msg.dropped[0],
            SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 6882)
        );
    }

    #[test]
    fn reject_invalid_length() {
        let mut payload = Vec::new();
        payload.extend_from_slice(b"d5:added5:");
        payload.extend_from_slice(&[1, 2, 3, 4, 5]);
        payload.extend_from_slice(b"e");

        assert!(parse_pex(&payload).is_err());
    }

    #[test]
    fn reject_too_many_peers() {
        let mut payload = Vec::new();
        let bytes = vec![0u8; (MAX_PEX_PEERS + 1) * COMPACT_PEER_LEN];
        payload.extend_from_slice(b"d5:added");
        payload.extend_from_slice(format!("{}:", bytes.len()).as_bytes());
        payload.extend_from_slice(&bytes);
        payload.extend_from_slice(b"e");

        assert!(parse_pex(&payload).is_err());
    }
}
