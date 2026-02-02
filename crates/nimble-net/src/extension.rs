use anyhow::{anyhow, Context, Result};
use std::collections::BTreeMap;

const EXTENDED_MESSAGE_ID: u8 = 20;
const EXTENDED_HANDSHAKE_ID: u8 = 0;

const MAX_HANDSHAKE_SIZE: usize = 4096;
const MAX_EXTENSION_PAYLOAD_SIZE: usize = 32 * 1024;
const MAX_CLIENT_NAME_LEN: usize = 128;
const MAX_EXTENSION_NAME_LEN: usize = 32;
const MAX_EXTENSIONS: usize = 16;

pub const EXTENSION_UT_METADATA: &str = "ut_metadata";
pub const EXTENSION_UT_PEX: &str = "ut_pex";

#[derive(Debug, Clone, Default)]
pub struct ExtensionHandshake {
    pub extensions: BTreeMap<String, u8>,
    pub listen_port: Option<u16>,
    pub client: Option<String>,
    pub yourip: Option<Vec<u8>>,
    pub ipv6: Option<Vec<u8>>,
    pub ipv4: Option<Vec<u8>>,
    pub reqq: Option<u32>,
    pub metadata_size: Option<u32>,
}

impl ExtensionHandshake {
    pub fn new() -> Self {
        ExtensionHandshake::default()
    }

    pub fn with_extensions(extensions: &[(&str, u8)]) -> Self {
        let mut hs = ExtensionHandshake::new();
        for &(name, id) in extensions {
            hs.extensions.insert(name.to_string(), id);
        }
        hs
    }

    pub fn get_extension_id(&self, name: &str) -> Option<u8> {
        self.extensions.get(name).copied()
    }

    pub fn supports(&self, name: &str) -> bool {
        self.extensions.contains_key(name)
    }

    pub fn encode(&self) -> Vec<u8> {
        use std::collections::BTreeMap;

        let mut entries: BTreeMap<&[u8], Vec<u8>> = BTreeMap::new();

        if !self.extensions.is_empty() {
            let mut m_dict = Vec::new();
            m_dict.push(b'd');
            for (name, &id) in &self.extensions {
                let name_len = name.len();
                m_dict.extend_from_slice(format!("{}:", name_len).as_bytes());
                m_dict.extend_from_slice(name.as_bytes());
                m_dict.extend_from_slice(format!("i{}e", id).as_bytes());
            }
            m_dict.push(b'e');
            entries.insert(b"m", m_dict);
        }

        if let Some(size) = self.metadata_size {
            let mut val = Vec::new();
            val.extend_from_slice(format!("i{}e", size).as_bytes());
            entries.insert(b"metadata_size", val);
        }

        if let Some(port) = self.listen_port {
            let mut val = Vec::new();
            val.extend_from_slice(format!("i{}e", port).as_bytes());
            entries.insert(b"p", val);
        }

        if let Some(ref reqq) = self.reqq {
            let mut val = Vec::new();
            val.extend_from_slice(format!("i{}e", reqq).as_bytes());
            entries.insert(b"reqq", val);
        }

        if let Some(ref client) = self.client {
            let client_len = client.len().min(MAX_CLIENT_NAME_LEN);
            let mut val = Vec::new();
            val.extend_from_slice(format!("{}:", client_len).as_bytes());
            val.extend_from_slice(&client.as_bytes()[..client_len]);
            entries.insert(b"v", val);
        }

        let mut dict = Vec::new();
        dict.push(b'd');
        for (key, value) in entries {
            dict.extend_from_slice(format!("{}:", key.len()).as_bytes());
            dict.extend_from_slice(key);
            dict.extend_from_slice(&value);
        }
        dict.push(b'e');
        dict
    }

    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() > MAX_HANDSHAKE_SIZE {
            anyhow::bail!("extension handshake too large: {} bytes", data.len());
        }

        use nimble_bencode::decode::{decode, Value};

        let value = decode(data).context("failed to decode extension handshake")?;
        let dict = value
            .as_dict()
            .ok_or_else(|| anyhow!("extension handshake must be dict"))?;

        let mut hs = ExtensionHandshake::new();

        if let Some(m_val) = dict.get(b"m".as_ref()) {
            if let Some(m_dict) = m_val.as_dict() {
                let mut count = 0;
                for (name_bytes, id_val) in m_dict {
                    if count >= MAX_EXTENSIONS {
                        break;
                    }

                    if name_bytes.len() > MAX_EXTENSION_NAME_LEN {
                        continue;
                    }

                    if let (Ok(name), Some(id)) = (
                        std::str::from_utf8(name_bytes),
                        id_val.as_integer(),
                    ) {
                        if id >= 0 && id <= 255 {
                            hs.extensions.insert(name.to_string(), id as u8);
                            count += 1;
                        }
                    }
                }
            }
        }

        if let Some(p_val) = dict.get(b"p".as_ref()) {
            if let Some(port) = p_val.as_integer() {
                if port > 0 && port <= 65535 {
                    hs.listen_port = Some(port as u16);
                }
            }
        }

        if let Some(v_val) = dict.get(b"v".as_ref()) {
            if let Some(client) = v_val.as_str() {
                let truncated = if client.len() > MAX_CLIENT_NAME_LEN {
                    &client[..MAX_CLIENT_NAME_LEN]
                } else {
                    client
                };
                hs.client = Some(truncated.to_string());
            }
        }

        if let Some(yourip_val) = dict.get(b"yourip".as_ref()) {
            if let Some(bytes) = yourip_val.as_bytes() {
                if bytes.len() == 4 || bytes.len() == 16 {
                    hs.yourip = Some(bytes.to_vec());
                }
            }
        }

        if let Some(ipv4_val) = dict.get(b"ipv4".as_ref()) {
            if let Some(bytes) = ipv4_val.as_bytes() {
                if bytes.len() == 4 {
                    hs.ipv4 = Some(bytes.to_vec());
                }
            }
        }

        if let Some(ipv6_val) = dict.get(b"ipv6".as_ref()) {
            if let Some(bytes) = ipv6_val.as_bytes() {
                if bytes.len() == 16 {
                    hs.ipv6 = Some(bytes.to_vec());
                }
            }
        }

        if let Some(reqq_val) = dict.get(b"reqq".as_ref()) {
            if let Some(reqq) = reqq_val.as_integer() {
                if reqq >= 0 {
                    hs.reqq = Some(reqq as u32);
                }
            }
        }

        if let Some(size_val) = dict.get(b"metadata_size".as_ref()) {
            if let Some(size) = size_val.as_integer() {
                if size >= 0 {
                    hs.metadata_size = Some(size as u32);
                }
            }
        }

        Ok(hs)
    }
}

#[derive(Debug, Clone)]
pub enum ExtendedMessage {
    Handshake(ExtensionHandshake),
    Extension { id: u8, payload: Vec<u8> },
}

impl ExtendedMessage {
    pub fn serialize(&self) -> Vec<u8> {
        match self {
            ExtendedMessage::Handshake(hs) => {
                let payload = hs.encode();
                let msg_len = 2 + payload.len();
                let mut buf = Vec::with_capacity(4 + msg_len);
                buf.extend_from_slice(&(msg_len as u32).to_be_bytes());
                buf.push(EXTENDED_MESSAGE_ID);
                buf.push(EXTENDED_HANDSHAKE_ID);
                buf.extend_from_slice(&payload);
                buf
            }
            ExtendedMessage::Extension { id, payload } => {
                let msg_len = 2 + payload.len();
                let mut buf = Vec::with_capacity(4 + msg_len);
                buf.extend_from_slice(&(msg_len as u32).to_be_bytes());
                buf.push(EXTENDED_MESSAGE_ID);
                buf.push(*id);
                buf.extend_from_slice(payload);
                buf
            }
        }
    }

    pub fn parse(ext_type: u8, payload: &[u8]) -> Result<Self> {
        if ext_type == EXTENDED_HANDSHAKE_ID {
            let hs = ExtensionHandshake::parse(payload)?;
            Ok(ExtendedMessage::Handshake(hs))
        } else {
            if payload.len() > MAX_EXTENSION_PAYLOAD_SIZE {
                anyhow::bail!("extension payload too large: {} bytes", payload.len());
            }
            Ok(ExtendedMessage::Extension {
                id: ext_type,
                payload: payload.to_vec(),
            })
        }
    }
}

pub const RESERVED_BIT_EXTENSION: u8 = 0x10;

pub fn set_extension_bit(reserved: &mut [u8; 8]) {
    reserved[5] |= RESERVED_BIT_EXTENSION;
}

pub fn has_extension_bit(reserved: &[u8; 8]) -> bool {
    (reserved[5] & RESERVED_BIT_EXTENSION) != 0
}

pub fn message_id() -> u8 {
    EXTENDED_MESSAGE_ID
}

#[derive(Debug, Clone)]
pub struct ExtensionState {
    pub our_handshake: ExtensionHandshake,
    pub their_handshake: Option<ExtensionHandshake>,
    pub handshake_sent: bool,
    pub handshake_received: bool,
}

impl ExtensionState {
    pub fn new(our_handshake: ExtensionHandshake) -> Self {
        ExtensionState {
            our_handshake,
            their_handshake: None,
            handshake_sent: false,
            handshake_received: false,
        }
    }

    pub fn our_id_for(&self, name: &str) -> Option<u8> {
        self.our_handshake.get_extension_id(name)
    }

    pub fn their_id_for(&self, name: &str) -> Option<u8> {
        self.their_handshake
            .as_ref()
            .and_then(|hs| hs.get_extension_id(name))
    }

    pub fn peer_supports(&self, name: &str) -> bool {
        self.their_handshake
            .as_ref()
            .map(|hs| hs.supports(name))
            .unwrap_or(false)
    }

    pub fn metadata_size(&self) -> Option<u32> {
        self.their_handshake
            .as_ref()
            .and_then(|hs| hs.metadata_size)
    }
}

pub fn create_nimble_handshake(listen_port: u16, metadata_size: Option<u32>) -> ExtensionHandshake {
    let mut hs = ExtensionHandshake::with_extensions(&[
        (EXTENSION_UT_METADATA, 1),
        (EXTENSION_UT_PEX, 2),
    ]);
    hs.listen_port = Some(listen_port);
    hs.client = Some("Nimble/0.1".to_string());
    hs.reqq = Some(250);
    hs.metadata_size = metadata_size;
    hs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extension_handshake_encode_decode() {
        let mut hs = ExtensionHandshake::new();
        hs.extensions.insert("ut_metadata".to_string(), 1);
        hs.extensions.insert("ut_pex".to_string(), 2);
        hs.listen_port = Some(6881);
        hs.client = Some("TestClient/1.0".to_string());

        let encoded = hs.encode();
        let decoded = ExtensionHandshake::parse(&encoded).unwrap();

        assert_eq!(decoded.extensions.get("ut_metadata"), Some(&1));
        assert_eq!(decoded.extensions.get("ut_pex"), Some(&2));
        assert_eq!(decoded.listen_port, Some(6881));
        assert_eq!(decoded.client, Some("TestClient/1.0".to_string()));
    }

    #[test]
    fn test_extension_handshake_empty() {
        let hs = ExtensionHandshake::new();
        let encoded = hs.encode();
        let decoded = ExtensionHandshake::parse(&encoded).unwrap();
        assert!(decoded.extensions.is_empty());
    }

    #[test]
    fn test_extension_bit() {
        let mut reserved = [0u8; 8];
        assert!(!has_extension_bit(&reserved));
        set_extension_bit(&mut reserved);
        assert!(has_extension_bit(&reserved));
        assert_eq!(reserved[5], 0x10);
    }

    #[test]
    fn test_extended_message_serialize() {
        let hs = ExtensionHandshake::with_extensions(&[("ut_metadata", 1)]);
        let msg = ExtendedMessage::Handshake(hs);
        let data = msg.serialize();

        assert_eq!(data[4], EXTENDED_MESSAGE_ID);
        assert_eq!(data[5], EXTENDED_HANDSHAKE_ID);
    }

    #[test]
    fn test_nimble_handshake() {
        let hs = create_nimble_handshake(6881, Some(12345));
        assert!(hs.supports(EXTENSION_UT_METADATA));
        assert!(hs.supports(EXTENSION_UT_PEX));
        assert_eq!(hs.listen_port, Some(6881));
        assert_eq!(hs.metadata_size, Some(12345));
    }

    #[test]
    fn test_extension_state() {
        let our_hs = create_nimble_handshake(6881, None);
        let mut state = ExtensionState::new(our_hs);

        assert!(!state.peer_supports(EXTENSION_UT_METADATA));

        let their_hs = ExtensionHandshake::with_extensions(&[(EXTENSION_UT_METADATA, 3)]);
        state.their_handshake = Some(their_hs);
        state.handshake_received = true;

        assert!(state.peer_supports(EXTENSION_UT_METADATA));
        assert_eq!(state.their_id_for(EXTENSION_UT_METADATA), Some(3));
        assert_eq!(state.our_id_for(EXTENSION_UT_METADATA), Some(1));
    }

    #[test]
    fn test_handshake_size_cap() {
        let large_data = vec![b'd'; MAX_HANDSHAKE_SIZE + 1];
        let result = ExtensionHandshake::parse(&large_data);
        assert!(result.is_err());
    }
}
