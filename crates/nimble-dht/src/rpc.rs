use std::net::{Ipv4Addr, SocketAddrV4};
#[cfg(feature = "ipv6")]
use std::net::{Ipv6Addr, SocketAddrV6};

use nimble_bencode::{decode, DecodeError, Value};
use thiserror::Error;

const NODE_ID_LEN: usize = 20;
const MAX_MESSAGE_SIZE: usize = 4096;
const MAX_TRANSACTION_ID_LEN: usize = 32;
const MAX_TOKEN_LEN: usize = 64;
const MAX_NODES: usize = 64;
const MAX_PEERS: usize = 64;

#[derive(Debug, Error)]
pub enum RpcError {
    #[error("message too large")]
    MessageTooLarge,
    #[error("transaction id too large")]
    TransactionIdTooLarge,
    #[error("token too large")]
    TokenTooLarge,
    #[error("bencode decode error: {0}")]
    Decode(#[from] DecodeError),
    #[error("invalid rpc message: {0}")]
    Invalid(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeEntry {
    pub id: [u8; NODE_ID_LEN],
    pub addr: SocketAddrV4,
}

#[cfg(feature = "ipv6")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeEntry6 {
    pub id: [u8; NODE_ID_LEN],
    pub addr: SocketAddrV6,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryKind {
    Ping { id: [u8; NODE_ID_LEN] },
    FindNode {
        id: [u8; NODE_ID_LEN],
        target: [u8; NODE_ID_LEN],
    },
    GetPeers {
        id: [u8; NODE_ID_LEN],
        info_hash: [u8; NODE_ID_LEN],
    },
    AnnouncePeer {
        id: [u8; NODE_ID_LEN],
        info_hash: [u8; NODE_ID_LEN],
        token: Vec<u8>,
        port: u16,
        implied_port: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    pub transaction_id: Vec<u8>,
    pub kind: QueryKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseKind {
    Ping { id: [u8; NODE_ID_LEN] },
    FindNode {
        id: [u8; NODE_ID_LEN],
        nodes: Vec<NodeEntry>,
        #[cfg(feature = "ipv6")]
        nodes6: Vec<NodeEntry6>,
    },
    GetPeers {
        id: [u8; NODE_ID_LEN],
        token: Option<Vec<u8>>,
        nodes: Vec<NodeEntry>,
        values: Vec<SocketAddrV4>,
        #[cfg(feature = "ipv6")]
        nodes6: Vec<NodeEntry6>,
        #[cfg(feature = "ipv6")]
        values6: Vec<SocketAddrV6>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub transaction_id: Vec<u8>,
    pub kind: ResponseKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorMessage {
    pub transaction_id: Vec<u8>,
    pub code: i64,
    pub message: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Query(Query),
    Response(Response),
    Error(ErrorMessage),
}

impl Message {
    pub fn sender_id(&self) -> Option<[u8; NODE_ID_LEN]> {
        match self {
            Message::Query(query) => match &query.kind {
                QueryKind::Ping { id }
                | QueryKind::FindNode { id, .. }
                | QueryKind::GetPeers { id, .. }
                | QueryKind::AnnouncePeer { id, .. } => Some(*id),
            },
            Message::Response(response) => match &response.kind {
                ResponseKind::Ping { id }
                | ResponseKind::FindNode { id, .. }
                | ResponseKind::GetPeers { id, .. } => Some(*id),
            },
            Message::Error(_) => None,
        }
    }
}

pub fn decode_message(input: &[u8]) -> Result<Message, RpcError> {
    if input.len() > MAX_MESSAGE_SIZE {
        return Err(RpcError::MessageTooLarge);
    }

    let value = decode(input)?;
    let dict = value
        .as_dict()
        .ok_or(RpcError::Invalid("top-level is not dict"))?;

    let transaction_id = read_bytes(dict.get(b"t".as_ref()))?;
    if transaction_id.is_empty() {
        return Err(RpcError::Invalid("missing transaction id"));
    }
    if transaction_id.len() > MAX_TRANSACTION_ID_LEN {
        return Err(RpcError::TransactionIdTooLarge);
    }

    let message_type = read_bytes(dict.get(b"y".as_ref()))?;
    if message_type == b"q" {
        let query_name = read_bytes(dict.get(b"q".as_ref()))?;
        let args = dict
            .get(b"a".as_ref())
            .and_then(Value::as_dict)
            .ok_or(RpcError::Invalid("missing args"))?;
        let id = read_node_id(args.get(b"id".as_ref()))?;

        let kind = match query_name {
            b"ping" => QueryKind::Ping { id },
            b"find_node" => {
                let target = read_node_id(args.get(b"target".as_ref()))?;
                QueryKind::FindNode { id, target }
            }
            b"get_peers" => {
                let info_hash = read_node_id(args.get(b"info_hash".as_ref()))?;
                QueryKind::GetPeers { id, info_hash }
            }
            b"announce_peer" => {
                let info_hash = read_node_id(args.get(b"info_hash".as_ref()))?;
                let token = read_bytes(args.get(b"token".as_ref()))?.to_vec();
                if token.len() > MAX_TOKEN_LEN {
                    return Err(RpcError::TokenTooLarge);
                }
                let implied_port =
                    matches!(read_optional_int(args.get(b"implied_port".as_ref()))?, Some(1));
                let port = match read_optional_int(args.get(b"port".as_ref()))? {
                    Some(port) => u16::try_from(port)
                        .map_err(|_| RpcError::Invalid("port out of range"))?,
                    None => {
                        if implied_port {
                            0
                        } else {
                            return Err(RpcError::Invalid("missing port"));
                        }
                    }
                };
                if port == 0 && !implied_port {
                    return Err(RpcError::Invalid("invalid port"));
                }
                QueryKind::AnnouncePeer {
                    id,
                    info_hash,
                    token,
                    port,
                    implied_port,
                }
            }
            _ => return Err(RpcError::Invalid("unsupported query")),
        };

        Ok(Message::Query(Query {
            transaction_id: transaction_id.to_vec(),
            kind,
        }))
    } else if message_type == b"r" {
        let response = dict
            .get(b"r".as_ref())
            .and_then(Value::as_dict)
            .ok_or(RpcError::Invalid("missing response"))?;
        let id = read_node_id(response.get(b"id".as_ref()))?;

        let nodes = parse_nodes(response.get(b"nodes".as_ref()))?;
        let values = parse_peers(response.get(b"values".as_ref()))?;
        #[cfg(feature = "ipv6")]
        let nodes6 = parse_nodes6(response.get(b"nodes6".as_ref()))?;
        #[cfg(feature = "ipv6")]
        let values6 = parse_peers6(response.get(b"values6".as_ref()))?;
        let token = match response.get(b"token".as_ref()) {
            Some(value) => {
                let token = read_bytes(Some(value))?.to_vec();
                if token.len() > MAX_TOKEN_LEN {
                    return Err(RpcError::TokenTooLarge);
                }
                Some(token)
            }
            None => None,
        };

        #[cfg(feature = "ipv6")]
        let has_values = !values.is_empty() || !values6.is_empty();
        #[cfg(not(feature = "ipv6"))]
        let has_values = !values.is_empty();

        #[cfg(feature = "ipv6")]
        let has_nodes = !nodes.is_empty() || !nodes6.is_empty();
        #[cfg(not(feature = "ipv6"))]
        let has_nodes = !nodes.is_empty();

        let kind = if has_values || token.is_some() {
            ResponseKind::GetPeers {
                id,
                token,
                nodes,
                values,
                #[cfg(feature = "ipv6")]
                nodes6,
                #[cfg(feature = "ipv6")]
                values6,
            }
        } else if has_nodes {
            ResponseKind::FindNode {
                id,
                nodes,
                #[cfg(feature = "ipv6")]
                nodes6,
            }
        } else {
            ResponseKind::Ping { id }
        };

        Ok(Message::Response(Response {
            transaction_id: transaction_id.to_vec(),
            kind,
        }))
    } else if message_type == b"e" {
        let error_list = dict
            .get(b"e".as_ref())
            .and_then(Value::as_list)
            .ok_or(RpcError::Invalid("missing error list"))?;
        if error_list.len() != 2 {
            return Err(RpcError::Invalid("invalid error list"));
        }

        let code = error_list[0]
            .as_integer()
            .ok_or(RpcError::Invalid("invalid error code"))?;
        let message = error_list[1]
            .as_bytes()
            .ok_or(RpcError::Invalid("invalid error message"))?
            .to_vec();

        Ok(Message::Error(ErrorMessage {
            transaction_id: transaction_id.to_vec(),
            code,
            message,
        }))
    } else {
        Err(RpcError::Invalid("unknown message type"))
    }
}

pub fn encode_message(message: &Message) -> Vec<u8> {
    let mut encoder = Encoder::new();
    match message {
        Message::Query(query) => encoder.encode_query(query),
        Message::Response(response) => encoder.encode_response(response),
        Message::Error(error) => encoder.encode_error(error),
    }
    encoder.finish()
}

fn read_bytes<'a>(value: Option<&'a Value<'a>>) -> Result<&'a [u8], RpcError> {
    value
        .and_then(Value::as_bytes)
        .ok_or(RpcError::Invalid("missing byte string"))
}

fn read_node_id(value: Option<&Value<'_>>) -> Result<[u8; NODE_ID_LEN], RpcError> {
    let bytes = read_bytes(value)?;
    if bytes.len() != NODE_ID_LEN {
        return Err(RpcError::Invalid("invalid node id length"));
    }
    let mut id = [0u8; NODE_ID_LEN];
    id.copy_from_slice(bytes);
    Ok(id)
}

fn read_optional_int(value: Option<&Value<'_>>) -> Result<Option<i64>, RpcError> {
    Ok(match value {
        Some(value) => Some(
            value
                .as_integer()
                .ok_or(RpcError::Invalid("expected integer"))?,
        ),
        None => None,
    })
}

fn parse_nodes(value: Option<&Value<'_>>) -> Result<Vec<NodeEntry>, RpcError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let bytes = value
        .as_bytes()
        .ok_or(RpcError::Invalid("nodes is not bytes"))?;
    if bytes.len() % 26 != 0 {
        return Err(RpcError::Invalid("nodes length invalid"));
    }
    let count = bytes.len() / 26;
    if count > MAX_NODES {
        return Err(RpcError::Invalid("too many nodes"));
    }

    let mut nodes = Vec::with_capacity(count);
    for chunk in bytes.chunks_exact(26) {
        let mut id = [0u8; NODE_ID_LEN];
        id.copy_from_slice(&chunk[..NODE_ID_LEN]);
        let ip = Ipv4Addr::new(chunk[20], chunk[21], chunk[22], chunk[23]);
        let port = u16::from_be_bytes([chunk[24], chunk[25]]);
        nodes.push(NodeEntry {
            id,
            addr: SocketAddrV4::new(ip, port),
        });
    }

    Ok(nodes)
}

fn parse_peers(value: Option<&Value<'_>>) -> Result<Vec<SocketAddrV4>, RpcError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let list = value
        .as_list()
        .ok_or(RpcError::Invalid("values is not list"))?;
    if list.len() > MAX_PEERS {
        return Err(RpcError::Invalid("too many peers"));
    }

    let mut peers = Vec::with_capacity(list.len());
    for entry in list {
        let bytes = entry
            .as_bytes()
            .ok_or(RpcError::Invalid("peer value not bytes"))?;
        if bytes.len() != 6 {
            return Err(RpcError::Invalid("peer value length invalid"));
        }
        let ip = Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
        let port = u16::from_be_bytes([bytes[4], bytes[5]]);
        peers.push(SocketAddrV4::new(ip, port));
    }

    Ok(peers)
}

#[cfg(feature = "ipv6")]
fn parse_nodes6(value: Option<&Value<'_>>) -> Result<Vec<NodeEntry6>, RpcError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let bytes = value
        .as_bytes()
        .ok_or(RpcError::Invalid("nodes6 is not bytes"))?;
    if bytes.len() % 38 != 0 {
        return Err(RpcError::Invalid("nodes6 length invalid"));
    }
    let count = bytes.len() / 38;
    if count > MAX_NODES {
        return Err(RpcError::Invalid("too many nodes6"));
    }

    let mut nodes = Vec::with_capacity(count);
    for chunk in bytes.chunks_exact(38) {
        let mut id = [0u8; NODE_ID_LEN];
        id.copy_from_slice(&chunk[..NODE_ID_LEN]);
        let mut ip_bytes = [0u8; 16];
        ip_bytes.copy_from_slice(&chunk[20..36]);
        let ip = Ipv6Addr::from(ip_bytes);
        let port = u16::from_be_bytes([chunk[36], chunk[37]]);
        nodes.push(NodeEntry6 {
            id,
            addr: SocketAddrV6::new(ip, port, 0, 0),
        });
    }

    Ok(nodes)
}

#[cfg(feature = "ipv6")]
fn parse_peers6(value: Option<&Value<'_>>) -> Result<Vec<SocketAddrV6>, RpcError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let list = value
        .as_list()
        .ok_or(RpcError::Invalid("values6 is not list"))?;
    if list.len() > MAX_PEERS {
        return Err(RpcError::Invalid("too many peers6"));
    }

    let mut peers = Vec::with_capacity(list.len());
    for entry in list {
        let bytes = entry
            .as_bytes()
            .ok_or(RpcError::Invalid("peer6 value not bytes"))?;
        if bytes.len() != 18 {
            return Err(RpcError::Invalid("peer6 value length invalid"));
        }
        let mut ip_bytes = [0u8; 16];
        ip_bytes.copy_from_slice(&bytes[0..16]);
        let ip = Ipv6Addr::from(ip_bytes);
        let port = u16::from_be_bytes([bytes[16], bytes[17]]);
        peers.push(SocketAddrV6::new(ip, port, 0, 0));
    }

    Ok(peers)
}

struct Encoder {
    buf: Vec<u8>,
}

impl Encoder {
    fn new() -> Self {
        Self { buf: Vec::new() }
    }

    fn finish(self) -> Vec<u8> {
        self.buf
    }

    fn encode_query(&mut self, query: &Query) {
        self.dict_start();
        self.write_bytes(b"a");
        self.encode_query_args(&query.kind);
        self.write_bytes(b"q");
        self.write_bytes(query_name(&query.kind));
        self.write_bytes(b"t");
        self.write_bytes(&query.transaction_id);
        self.write_bytes(b"y");
        self.write_bytes(b"q");
        self.dict_end();
    }

    fn encode_response(&mut self, response: &Response) {
        self.dict_start();
        self.write_bytes(b"r");
        self.encode_response_args(&response.kind);
        self.write_bytes(b"t");
        self.write_bytes(&response.transaction_id);
        self.write_bytes(b"y");
        self.write_bytes(b"r");
        self.dict_end();
    }

    fn encode_error(&mut self, error: &ErrorMessage) {
        self.dict_start();
        self.write_bytes(b"e");
        self.list_start();
        self.write_int(error.code);
        self.write_bytes(&error.message);
        self.list_end();
        self.write_bytes(b"t");
        self.write_bytes(&error.transaction_id);
        self.write_bytes(b"y");
        self.write_bytes(b"e");
        self.dict_end();
    }

    fn encode_query_args(&mut self, kind: &QueryKind) {
        self.dict_start();
        match kind {
            QueryKind::Ping { id } => {
                self.write_bytes(b"id");
                self.write_bytes(id);
            }
            QueryKind::FindNode { id, target } => {
                self.write_bytes(b"id");
                self.write_bytes(id);
                self.write_bytes(b"target");
                self.write_bytes(target);
            }
            QueryKind::GetPeers { id, info_hash } => {
                self.write_bytes(b"id");
                self.write_bytes(id);
                self.write_bytes(b"info_hash");
                self.write_bytes(info_hash);
            }
            QueryKind::AnnouncePeer {
                id,
                info_hash,
                token,
                port,
                implied_port,
            } => {
                self.write_bytes(b"id");
                self.write_bytes(id);
                self.write_bytes(b"implied_port");
                self.write_int(if *implied_port { 1 } else { 0 });
                self.write_bytes(b"info_hash");
                self.write_bytes(info_hash);
                if !*implied_port {
                    self.write_bytes(b"port");
                    self.write_int(i64::from(*port));
                }
                self.write_bytes(b"token");
                self.write_bytes(token);
            }
        }
        self.dict_end();
    }

    fn encode_response_args(&mut self, kind: &ResponseKind) {
        self.dict_start();
        match kind {
            ResponseKind::Ping { id } => {
                self.write_bytes(b"id");
                self.write_bytes(id);
            }
            ResponseKind::FindNode {
                id,
                nodes,
                #[cfg(feature = "ipv6")]
                nodes6,
            } => {
                self.write_bytes(b"id");
                self.write_bytes(id);
                if !nodes.is_empty() {
                    self.write_bytes(b"nodes");
                    self.write_bytes(&encode_nodes(nodes));
                }
                #[cfg(feature = "ipv6")]
                if !nodes6.is_empty() {
                    self.write_bytes(b"nodes6");
                    self.write_bytes(&encode_nodes6(nodes6));
                }
            }
            ResponseKind::GetPeers {
                id,
                token,
                nodes,
                values,
                #[cfg(feature = "ipv6")]
                nodes6,
                #[cfg(feature = "ipv6")]
                values6,
            } => {
                self.write_bytes(b"id");
                self.write_bytes(id);
                if !nodes.is_empty() {
                    self.write_bytes(b"nodes");
                    self.write_bytes(&encode_nodes(nodes));
                }
                #[cfg(feature = "ipv6")]
                if !nodes6.is_empty() {
                    self.write_bytes(b"nodes6");
                    self.write_bytes(&encode_nodes6(nodes6));
                }
                if let Some(token) = token {
                    self.write_bytes(b"token");
                    self.write_bytes(token);
                }
                if !values.is_empty() {
                    self.write_bytes(b"values");
                    self.list_start();
                    for addr in values {
                        self.write_bytes(&encode_peer(addr));
                    }
                    self.list_end();
                }
                #[cfg(feature = "ipv6")]
                if !values6.is_empty() {
                    self.write_bytes(b"values6");
                    self.list_start();
                    for addr in values6 {
                        self.write_bytes(&encode_peer6(addr));
                    }
                    self.list_end();
                }
            }
        }
        self.dict_end();
    }

    fn write_int(&mut self, value: i64) {
        self.buf.push(b'i');
        write_i64(&mut self.buf, value);
        self.buf.push(b'e');
    }

    fn write_bytes(&mut self, bytes: &[u8]) {
        write_usize(&mut self.buf, bytes.len());
        self.buf.push(b':');
        self.buf.extend_from_slice(bytes);
    }

    fn dict_start(&mut self) {
        self.buf.push(b'd');
    }

    fn dict_end(&mut self) {
        self.buf.push(b'e');
    }

    fn list_start(&mut self) {
        self.buf.push(b'l');
    }

    fn list_end(&mut self) {
        self.buf.push(b'e');
    }
}

fn query_name(kind: &QueryKind) -> &'static [u8] {
    match kind {
        QueryKind::Ping { .. } => b"ping",
        QueryKind::FindNode { .. } => b"find_node",
        QueryKind::GetPeers { .. } => b"get_peers",
        QueryKind::AnnouncePeer { .. } => b"announce_peer",
    }
}

fn encode_nodes(nodes: &[NodeEntry]) -> Vec<u8> {
    let mut out = Vec::with_capacity(nodes.len() * 26);
    for node in nodes {
        out.extend_from_slice(&node.id);
        let octets = node.addr.ip().octets();
        out.extend_from_slice(&octets);
        out.extend_from_slice(&node.addr.port().to_be_bytes());
    }
    out
}

fn encode_peer(addr: &SocketAddrV4) -> [u8; 6] {
    let mut out = [0u8; 6];
    let octets = addr.ip().octets();
    out[0..4].copy_from_slice(&octets);
    out[4..6].copy_from_slice(&addr.port().to_be_bytes());
    out
}

#[cfg(feature = "ipv6")]
fn encode_nodes6(nodes: &[NodeEntry6]) -> Vec<u8> {
    let mut out = Vec::with_capacity(nodes.len() * 38);
    for node in nodes {
        out.extend_from_slice(&node.id);
        out.extend_from_slice(&node.addr.ip().octets());
        out.extend_from_slice(&node.addr.port().to_be_bytes());
    }
    out
}

#[cfg(feature = "ipv6")]
fn encode_peer6(addr: &SocketAddrV6) -> [u8; 18] {
    let mut out = [0u8; 18];
    out[0..16].copy_from_slice(&addr.ip().octets());
    out[16..18].copy_from_slice(&addr.port().to_be_bytes());
    out
}

fn write_usize(buf: &mut Vec<u8>, mut value: usize) {
    let start = buf.len();
    if value == 0 {
        buf.push(b'0');
        return;
    }

    while value > 0 {
        buf.push(b'0' + (value % 10) as u8);
        value /= 10;
    }

    buf[start..].reverse();
}

fn write_i64(buf: &mut Vec<u8>, mut value: i64) {
    if value == 0 {
        buf.push(b'0');
        return;
    }

    if value < 0 {
        buf.push(b'-');
        value = -value;
    }

    write_usize(buf, value as usize);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id_with_last_byte(byte: u8) -> [u8; NODE_ID_LEN] {
        let mut id = [0u8; NODE_ID_LEN];
        id[NODE_ID_LEN - 1] = byte;
        id
    }

    #[test]
    fn encode_decode_ping_query() {
        let query = Query {
            transaction_id: b"aa".to_vec(),
            kind: QueryKind::Ping {
                id: id_with_last_byte(1),
            },
        };
        let encoded = encode_message(&Message::Query(query.clone()));
        let decoded = decode_message(&encoded).unwrap();
        assert_eq!(decoded, Message::Query(query));
    }

    #[test]
    fn decode_get_peers_response_with_values() {
        let response = Response {
            transaction_id: b"t1".to_vec(),
            kind: ResponseKind::GetPeers {
                id: id_with_last_byte(2),
                token: Some(b"tok".to_vec()),
                nodes: Vec::new(),
                values: vec![SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 6881)],
            },
        };
        let encoded = encode_message(&Message::Response(response.clone()));
        let decoded = decode_message(&encoded).unwrap();
        assert_eq!(decoded, Message::Response(response));
    }

    #[test]
    fn decode_rejects_large_nodes() {
        let response = Response {
            transaction_id: b"t1".to_vec(),
            kind: ResponseKind::FindNode {
                id: id_with_last_byte(2),
                nodes: vec![NodeEntry {
                    id: id_with_last_byte(1),
                    addr: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 6881),
                }; MAX_NODES + 1],
            },
        };
        let encoded = encode_message(&Message::Response(response));
        let decoded = decode_message(&encoded);
        assert!(matches!(decoded, Err(RpcError::Invalid("too many nodes"))));
    }

    #[test]
    fn decode_find_node_response() {
        let response = Response {
            transaction_id: b"t1".to_vec(),
            kind: ResponseKind::FindNode {
                id: id_with_last_byte(2),
                nodes: vec![NodeEntry {
                    id: id_with_last_byte(3),
                    addr: SocketAddrV4::new(Ipv4Addr::new(2, 2, 2, 2), 6881),
                }],
            },
        };
        let encoded = encode_message(&Message::Response(response.clone()));
        let decoded = decode_message(&encoded).unwrap();
        assert_eq!(decoded, Message::Response(response));
    }
}
