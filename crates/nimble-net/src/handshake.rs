use anyhow::Result;

use crate::extension::set_extension_bit;

const PROTOCOL_STRING: &[u8] = b"BitTorrent protocol";
const PROTOCOL_STRING_LENGTH: u8 = 19;
const HANDSHAKE_LENGTH: usize = 68;

pub enum HandshakeStep {
    /// Wait for more data. `min_bytes` indicates how much total data we need
    /// in the buffer to proceed to the next step.
    Read { min_bytes: usize },
    /// Write data to the socket.
    Write { data: Vec<u8> },
    /// Handshake finished.
    Complete {
        peer_id: [u8; 20],
        info_hash: [u8; 20],
        reserved_bytes: [u8; 8],
    },
}

pub trait HandshakeProtocol {
    /// process buffer data and return the next action
    fn step(&mut self, input_buffer: &[u8]) -> Result<HandshakeStep>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BitTorrentHandshakeState {
    Init,
    AwaitingResponse,
    Complete,
}

pub struct BitTorrentHandshake {
    state: BitTorrentHandshakeState,
    info_hash: [u8; 20],
    peer_id: [u8; 20],
    reserved_bytes: [u8; 8],
}

impl BitTorrentHandshake {
    pub fn new(info_hash: [u8; 20], peer_id: [u8; 20]) -> Self {
        let mut reserved_bytes = [0u8; 8];
        set_extension_bit(&mut reserved_bytes);
        Self {
            state: BitTorrentHandshakeState::Init,
            info_hash,
            peer_id,
            reserved_bytes,
        }
    }
}

impl HandshakeProtocol for BitTorrentHandshake {
    fn step(&mut self, input_buffer: &[u8]) -> Result<HandshakeStep> {
        match self.state {
            BitTorrentHandshakeState::Init => {
                let mut handshake = Vec::with_capacity(HANDSHAKE_LENGTH);
                handshake.push(PROTOCOL_STRING_LENGTH);
                handshake.extend_from_slice(PROTOCOL_STRING);
                handshake.extend_from_slice(&self.reserved_bytes);
                handshake.extend_from_slice(&self.info_hash);
                handshake.extend_from_slice(&self.peer_id);
                self.state = BitTorrentHandshakeState::AwaitingResponse;
                Ok(HandshakeStep::Write { data: handshake })
            }
            BitTorrentHandshakeState::AwaitingResponse => {
                if input_buffer.len() < HANDSHAKE_LENGTH {
                    return Ok(HandshakeStep::Read {
                        min_bytes: HANDSHAKE_LENGTH,
                    });
                }

                if input_buffer[0] != PROTOCOL_STRING_LENGTH {
                    anyhow::bail!("invalid protocol string length: {}", input_buffer[0]);
                }

                if &input_buffer[1..20] != PROTOCOL_STRING {
                    anyhow::bail!("invalid protocol string");
                }

                let reserved_bytes: [u8; 8] = input_buffer[20..28]
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("invalid reserved bytes length"))?;
                let info_hash: [u8; 20] = input_buffer[28..48]
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("invalid info hash length"))?;
                if info_hash != self.info_hash {
                    anyhow::bail!("info hash mismatch");
                }
                let peer_id: [u8; 20] = input_buffer[48..68]
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("invalid peer id length"))?;

                self.state = BitTorrentHandshakeState::Complete;
                Ok(HandshakeStep::Complete {
                    peer_id,
                    info_hash,
                    reserved_bytes,
                })
            }
            BitTorrentHandshakeState::Complete => {
                anyhow::bail!("handshake already completed");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bittorrent_handshake_steps() {
        let info_hash = [1u8; 20];
        let our_peer_id = [2u8; 20];
        let mut handshake = BitTorrentHandshake::new(info_hash, our_peer_id);

        match handshake.step(&[]).expect("write step") {
            HandshakeStep::Write { data } => {
                assert_eq!(data.len(), HANDSHAKE_LENGTH);
                assert_eq!(data[0], PROTOCOL_STRING_LENGTH);
                assert_eq!(&data[1..20], PROTOCOL_STRING);
                assert_eq!(&data[28..48], &info_hash);
                assert_eq!(&data[48..68], &our_peer_id);
            }
            other => panic!("unexpected step: {:?}", std::mem::discriminant(&other)),
        }

        match handshake.step(&[]).expect("read step") {
            HandshakeStep::Read { min_bytes } => {
                assert_eq!(min_bytes, HANDSHAKE_LENGTH);
            }
            other => panic!("unexpected step: {:?}", std::mem::discriminant(&other)),
        }

        let their_peer_id = [9u8; 20];
        let mut response = Vec::with_capacity(HANDSHAKE_LENGTH);
        response.push(PROTOCOL_STRING_LENGTH);
        response.extend_from_slice(PROTOCOL_STRING);
        let mut reserved = [0u8; 8];
        set_extension_bit(&mut reserved);
        response.extend_from_slice(&reserved);
        response.extend_from_slice(&info_hash);
        response.extend_from_slice(&their_peer_id);

        match handshake.step(&response).expect("complete step") {
            HandshakeStep::Complete {
                peer_id,
                info_hash: confirmed_hash,
                reserved_bytes,
            } => {
                assert_eq!(peer_id, their_peer_id);
                assert_eq!(confirmed_hash, info_hash);
                assert_eq!(reserved_bytes, reserved);
            }
            other => panic!("unexpected step: {:?}", std::mem::discriminant(&other)),
        }
    }
}
