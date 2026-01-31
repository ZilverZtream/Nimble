use anyhow::{anyhow, Result};
use nimble_bencode::{decode_prefix, Value};
use nimble_util::hash::sha1;

const METADATA_PIECE_SIZE: usize = 16 * 1024;
const MAX_METADATA_SIZE: u32 = 2 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UtMetadataMessageType {
    Request = 0,
    Data = 1,
    Reject = 2,
}

#[derive(Debug, Clone)]
pub struct UtMetadataMessage {
    pub msg_type: UtMetadataMessageType,
    pub piece: u32,
    pub total_size: Option<u32>,
    pub data: Vec<u8>,
}

impl UtMetadataMessage {
    pub fn parse(payload: &[u8]) -> Result<Self> {
        let (value, consumed) = decode_prefix(payload)
            .map_err(|e| anyhow!("failed to decode ut_metadata dict: {e}"))?;
        let dict = value
            .as_dict()
            .ok_or_else(|| anyhow!("ut_metadata payload must be dict"))?;

        let msg_type = dict
            .get(b"msg_type".as_ref())
            .and_then(Value::as_integer)
            .ok_or_else(|| anyhow!("ut_metadata missing msg_type"))?;

        let msg_type = match msg_type {
            0 => UtMetadataMessageType::Request,
            1 => UtMetadataMessageType::Data,
            2 => UtMetadataMessageType::Reject,
            _ => return Err(anyhow!("ut_metadata invalid msg_type: {msg_type}")),
        };

        let piece = dict
            .get(b"piece".as_ref())
            .and_then(Value::as_integer)
            .ok_or_else(|| anyhow!("ut_metadata missing piece"))?;
        if piece < 0 {
            return Err(anyhow!("ut_metadata negative piece"));
        }

        let total_size = dict
            .get(b"total_size".as_ref())
            .and_then(Value::as_integer)
            .and_then(|v| if v >= 0 { Some(v as u32) } else { None });

        let data = match msg_type {
            UtMetadataMessageType::Data => payload[consumed..].to_vec(),
            _ => {
                if consumed != payload.len() {
                    return Err(anyhow!("ut_metadata unexpected trailing data"));
                }
                Vec::new()
            }
        };

        Ok(UtMetadataMessage {
            msg_type,
            piece: piece as u32,
            total_size,
            data,
        })
    }

    pub fn build_request(piece: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"d8:msg_typei0e5:piecei");
        buf.extend_from_slice(piece.to_string().as_bytes());
        buf.extend_from_slice(b"ee");
        buf
    }
}

#[derive(Debug, Clone)]
pub struct UtMetadataState {
    total_size: u32,
    piece_count: usize,
    pieces: Vec<Option<Vec<u8>>>,
    received: usize,
    complete: bool,
}

pub fn verify_metadata_infohash(metadata: &[u8], expected: [u8; 20]) -> bool {
    sha1(metadata) == expected
}

impl UtMetadataState {
    pub fn new(total_size: u32) -> Result<Self> {
        if total_size == 0 {
            return Err(anyhow!("ut_metadata size cannot be zero"));
        }
        if total_size > MAX_METADATA_SIZE {
            return Err(anyhow!("ut_metadata size cap exceeded: {total_size}"));
        }

        let piece_count = ((total_size as usize + METADATA_PIECE_SIZE - 1) / METADATA_PIECE_SIZE)
            .max(1);

        Ok(UtMetadataState {
            total_size,
            piece_count,
            pieces: vec![None; piece_count],
            received: 0,
            complete: false,
        })
    }

    pub fn insert_piece(&mut self, piece: u32, data: &[u8]) -> Result<Option<Vec<u8>>> {
        if self.complete {
            return Ok(None);
        }

        let piece_index = piece as usize;
        if piece_index >= self.piece_count {
            return Err(anyhow!("ut_metadata piece out of range"));
        }

        if data.is_empty() {
            return Err(anyhow!("ut_metadata empty piece data"));
        }

        let expected_len = if piece_index + 1 == self.piece_count {
            let remaining = self.total_size as usize - piece_index * METADATA_PIECE_SIZE;
            remaining
        } else {
            METADATA_PIECE_SIZE
        };

        if piece_index + 1 == self.piece_count {
            if data.len() > expected_len {
                return Err(anyhow!("ut_metadata final piece too large"));
            }
        } else if data.len() != expected_len {
            return Err(anyhow!("ut_metadata piece size mismatch"));
        }

        if self.pieces[piece_index].is_none() {
            self.pieces[piece_index] = Some(data.to_vec());
            self.received += 1;
        }

        if self.received == self.piece_count {
            let mut combined = Vec::with_capacity(self.total_size as usize);
            for piece in self.pieces.iter() {
                let data = piece.as_ref().ok_or_else(|| {
                    anyhow!("ut_metadata missing piece during assembly")
                })?;
                combined.extend_from_slice(data);
            }
            combined.truncate(self.total_size as usize);
            self.complete = true;
            return Ok(Some(combined));
        }

        Ok(None)
    }

    pub fn piece_count(&self) -> usize {
        self.piece_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_request_is_sorted() {
        let request = UtMetadataMessage::build_request(2);
        let (value, consumed) = decode_prefix(&request).unwrap();
        assert_eq!(consumed, request.len());
        let dict = value.as_dict().unwrap();
        assert_eq!(
            dict.get(b"msg_type".as_ref()).unwrap().as_integer(),
            Some(0)
        );
        assert_eq!(
            dict.get(b"piece".as_ref()).unwrap().as_integer(),
            Some(2)
        );
    }

    #[test]
    fn assemble_metadata_from_pieces() {
        let total_size = METADATA_PIECE_SIZE as u32 + 4;
        let mut state = UtMetadataState::new(total_size).unwrap();
        let part1 = vec![1u8; METADATA_PIECE_SIZE];
        let part2 = vec![2u8; 4];

        assert!(state.insert_piece(0, &part1).unwrap().is_none());
        let done = state.insert_piece(1, &part2).unwrap().unwrap();

        assert_eq!(done.len(), total_size as usize);
        assert_eq!(&done[..16], &[1u8; 16]);
        assert_eq!(&done[METADATA_PIECE_SIZE..], &[2u8; 4]);
    }
}
