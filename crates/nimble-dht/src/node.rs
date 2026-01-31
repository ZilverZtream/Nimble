use nimble_util::ids::dht_node_id_20;
use std::collections::HashMap;
use std::net::SocketAddrV4;

use crate::rpc::{
    decode_message, ErrorMessage, Message, NodeEntry, Query, QueryKind, Response, ResponseKind,
    RpcError,
};
use crate::routing::RoutingTable;
use crate::tokens::TokenIssuer;

const MAX_RESPONSE_NODES: usize = 16;
const MAX_PEERS_PER_INFOHASH: usize = 32;
const MAX_INFOHASHES: usize = 128;

pub struct DhtNode {
    node_id: [u8; 20],
    logged_startup: bool,
    routing: RoutingTable,
    tokens: TokenIssuer,
    peers: HashMap<[u8; 20], Vec<SocketAddrV4>>,
}

pub struct PacketOutcome {
    pub message: Message,
    pub response: Option<Message>,
}

impl DhtNode {
    pub fn new() -> Self {
        let node_id = dht_node_id_20();
        let routing = RoutingTable::new(node_id);
        Self {
            node_id,
            logged_startup: false,
            routing,
            tokens: TokenIssuer::new(),
            peers: HashMap::new(),
        }
    }

    pub fn node_id(&self) -> &[u8; 20] {
        &self.node_id
    }

    pub fn known_nodes(&self) -> u32 {
        self.routing.len() as u32
    }

    pub fn tick(&mut self) -> Option<String> {
        if self.logged_startup {
            return None;
        }

        self.logged_startup = true;
        Some("DHT node initialized".to_string())
    }

    pub fn handle_packet(
        &mut self,
        source: SocketAddrV4,
        payload: &[u8],
    ) -> Result<PacketOutcome, RpcError> {
        let message = decode_message(payload)?;
        if let Some(id) = message.sender_id() {
            self.observe_node(id, source);
        }
        let response = match &message {
            Message::Query(query) => self.handle_query(source, query),
            _ => None,
        };
        Ok(PacketOutcome { message, response })
    }

    pub fn observe_node(&mut self, id: [u8; 20], addr: SocketAddrV4) -> bool {
        self.routing.insert(id, addr)
    }

    fn handle_query(&mut self, source: SocketAddrV4, query: &Query) -> Option<Message> {
        match &query.kind {
            QueryKind::Ping { .. } => Some(Message::Response(Response {
                transaction_id: query.transaction_id.clone(),
                kind: ResponseKind::Ping { id: self.node_id },
            })),
            QueryKind::FindNode { target, .. } => {
                let nodes = self.closest_nodes(*target);
                Some(Message::Response(Response {
                    transaction_id: query.transaction_id.clone(),
                    kind: ResponseKind::FindNode {
                        id: self.node_id,
                        nodes,
                    },
                }))
            }
            QueryKind::GetPeers { info_hash, .. } => {
                let token = self.tokens.token_for(*source.ip());
                let peers = self
                    .peers
                    .get(info_hash)
                    .map(|values| limit_peers(values))
                    .unwrap_or_default();
                let nodes = if peers.is_empty() {
                    self.closest_nodes(*info_hash)
                } else {
                    Vec::new()
                };
                Some(Message::Response(Response {
                    transaction_id: query.transaction_id.clone(),
                    kind: ResponseKind::GetPeers {
                        id: self.node_id,
                        token: Some(token),
                        nodes,
                        values: peers,
                    },
                }))
            }
            QueryKind::AnnouncePeer {
                info_hash,
                token,
                port,
                implied_port,
                ..
            } => {
                let peer_port = if *implied_port { source.port() } else { *port };
                if !self.tokens.validate(*source.ip(), token) {
                    return Some(Message::Error(ErrorMessage {
                        transaction_id: query.transaction_id.clone(),
                        code: 203,
                        message: b"invalid token".to_vec(),
                    }));
                }
                self.store_peer(*info_hash, SocketAddrV4::new(*source.ip(), peer_port));
                Some(Message::Response(Response {
                    transaction_id: query.transaction_id.clone(),
                    kind: ResponseKind::Ping { id: self.node_id },
                }))
            }
        }
    }

    fn closest_nodes(&self, target: [u8; 20]) -> Vec<NodeEntry> {
        self.routing
            .find_closest(target, MAX_RESPONSE_NODES)
            .into_iter()
            .map(|node| NodeEntry {
                id: node.id,
                addr: node.addr,
            })
            .collect()
    }

    fn store_peer(&mut self, info_hash: [u8; 20], peer: SocketAddrV4) {
        if self.peers.len() >= MAX_INFOHASHES && !self.peers.contains_key(&info_hash) {
            if let Some(key) = self.peers.keys().next().copied() {
                self.peers.remove(&key);
            }
        }
        let entry = self.peers.entry(info_hash).or_insert_with(Vec::new);
        if entry.iter().any(|existing| *existing == peer) {
            return;
        }
        if entry.len() >= MAX_PEERS_PER_INFOHASH {
            entry.remove(0);
        }
        entry.push(peer);
    }
}

fn limit_peers(peers: &[SocketAddrV4]) -> Vec<SocketAddrV4> {
    let mut out = Vec::with_capacity(peers.len().min(MAX_PEERS_PER_INFOHASH));
    out.extend(peers.iter().take(MAX_PEERS_PER_INFOHASH).copied());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::{encode_message, Message, Query, QueryKind};
    use std::net::{Ipv4Addr, SocketAddrV4};

    #[test]
    fn test_node_id_generated() {
        let node = DhtNode::new();
        assert!(node.node_id().iter().any(|byte| *byte != 0));
    }

    #[test]
    fn test_observe_node_updates_count() {
        let mut node = DhtNode::new();
        let addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 6881);
        let mut other_id = [0u8; 20];
        other_id[19] = 1;
        assert!(node.observe_node(other_id, addr));
        assert_eq!(node.known_nodes(), 1);
    }

    #[test]
    fn handle_packet_tracks_sender() {
        let mut node = DhtNode::new();
        let mut sender_id = [0u8; 20];
        sender_id[19] = 9;
        let message = Message::Query(Query {
            transaction_id: b"aa".to_vec(),
            kind: QueryKind::Ping { id: sender_id },
        });
        let payload = encode_message(&message);
        let addr = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 5), 6881);

        let outcome = node.handle_packet(addr, &payload).unwrap();
        assert_eq!(outcome.message, message);
        assert_eq!(node.known_nodes(), 1);
    }

    #[test]
    fn handle_ping_returns_response() {
        let mut node = DhtNode::new();
        let mut sender_id = [0u8; 20];
        sender_id[19] = 2;
        let message = Message::Query(Query {
            transaction_id: b"aa".to_vec(),
            kind: QueryKind::Ping { id: sender_id },
        });
        let payload = encode_message(&message);
        let addr = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 10), 6881);

        let outcome = node.handle_packet(addr, &payload).unwrap();
        assert!(matches!(
            outcome.response,
            Some(Message::Response(Response {
                transaction_id,
                kind: ResponseKind::Ping { id },
            })) if transaction_id == b"aa".to_vec() && id == *node.node_id()
        ));
    }

    #[test]
    fn handle_find_node_returns_closest_nodes() {
        let mut node = DhtNode::new();
        let addr = SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 6881);
        let mut other_id = [0u8; 20];
        other_id[19] = 5;
        node.observe_node(other_id, addr);

        let mut sender_id = [0u8; 20];
        sender_id[19] = 9;
        let query = Message::Query(Query {
            transaction_id: b"fn".to_vec(),
            kind: QueryKind::FindNode {
                id: sender_id,
                target: other_id,
            },
        });

        let payload = encode_message(&query);
        let outcome = node
            .handle_packet(SocketAddrV4::new(Ipv4Addr::new(2, 2, 2, 2), 6881), &payload)
            .unwrap();

        let response = outcome.response.expect("response");
        match response {
            Message::Response(Response {
                kind: ResponseKind::FindNode { nodes, .. },
                ..
            }) => {
                assert!(nodes.iter().any(|node| node.id == other_id));
            }
            _ => panic!("unexpected response"),
        }
    }

    #[test]
    fn announce_peer_then_get_peers_returns_value() {
        let mut node = DhtNode::new();
        let mut sender_id = [0u8; 20];
        sender_id[19] = 7;
        let info_hash = [0x22u8; 20];
        let source = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 9), 6889);

        let get_query = Message::Query(Query {
            transaction_id: b"gp".to_vec(),
            kind: QueryKind::GetPeers {
                id: sender_id,
                info_hash,
            },
        });
        let get_payload = encode_message(&get_query);
        let get_outcome = node.handle_packet(source, &get_payload).unwrap();
        let token = match get_outcome.response {
            Some(Message::Response(Response {
                kind: ResponseKind::GetPeers { token, .. },
                ..
            })) => token.expect("token"),
            _ => panic!("missing get_peers response"),
        };

        let announce = Message::Query(Query {
            transaction_id: b"ap".to_vec(),
            kind: QueryKind::AnnouncePeer {
                id: sender_id,
                info_hash,
                token,
                port: 6881,
                implied_port: false,
            },
        });
        let announce_payload = encode_message(&announce);
        let announce_outcome = node.handle_packet(source, &announce_payload).unwrap();
        assert!(matches!(
            announce_outcome.response,
            Some(Message::Response(Response {
                kind: ResponseKind::Ping { .. },
                ..
            }))
        ));

        let get_again = Message::Query(Query {
            transaction_id: b"g2".to_vec(),
            kind: QueryKind::GetPeers {
                id: sender_id,
                info_hash,
            },
        });
        let get_again_payload = encode_message(&get_again);
        let get_again_outcome = node.handle_packet(source, &get_again_payload).unwrap();
        match get_again_outcome.response {
            Some(Message::Response(Response {
                kind: ResponseKind::GetPeers { values, .. },
                ..
            })) => {
                assert_eq!(values.len(), 1);
                assert_eq!(values[0], SocketAddrV4::new(*source.ip(), 6881));
            }
            _ => panic!("missing get_peers values"),
        }
    }
}
