use nimble_util::ids::dht_node_id_20;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{Ipv4Addr, SocketAddrV4};
#[cfg(feature = "ipv6")]
use std::net::SocketAddrV6;
use std::time::{Duration, Instant};

use crate::bootstrap::default_bootstrap_nodes;
use crate::peer_ip::{is_valid_peer_ip_v4, is_valid_peer_ip_v6};
use crate::rpc::{
    decode_message, encode_message, ErrorMessage, Message, NodeEntry, Query, QueryKind, Response,
    ResponseKind, RpcError,
};
#[cfg(feature = "ipv6")]
use crate::rpc::NodeEntry6;
use crate::routing::RoutingTable;
#[cfg(feature = "ipv6")]
use crate::routing::{NodeInfo6, RoutingTable6};
use crate::tokens::TokenIssuer;

const MAX_RESPONSE_NODES: usize = 16;
const MAX_PEERS_PER_INFOHASH: usize = 32;
const MAX_INFOHASHES: usize = 128;
const PEER_TTL_MS: u64 = 1_800_000;
const RATE_LIMIT_WINDOW_MS: u64 = 1_000;
const RATE_LIMIT_MAX_QUERIES: u32 = 32;
const RATE_LIMIT_MAX_CLIENTS: usize = 1_024;
const RATE_LIMIT_STALE_MS: u64 = 60_000;
const BOOTSTRAP_RETRY_MS: u64 = 60_000;
const REFRESH_INTERVAL_MS: u64 = 300_000;
const REFRESH_BATCH_SIZE: usize = 8;
const QUERY_TIMEOUT_MS: u64 = 5_000;
const MAX_PENDING_QUERIES: usize = 256;
const MAX_NODE_IDS_PER_IP: usize = 3;
const NODE_ID_PER_IP_TTL_MS: u64 = 900_000;

#[derive(Debug, Clone, Copy)]
struct StoredPeer {
    addr: std::net::SocketAddr,
    stored_at_ms: u64,
}

#[derive(Debug, Clone)]
struct NodeIdEntry {
    node_id: [u8; 20],
    last_seen_ms: u64,
}

fn validate_node_id_for_ipv4v4(node_id: &[u8; 20], ip: &Ipv4Addr) -> bool {
    let ip_bytes = ip.octets();
    let rand = node_id[19];

    let mut v = [0u8; 4];
    v[0] = (ip_bytes[0] & 0x03) | ((rand & 0x07) << 5);
    v[1] = (ip_bytes[1] & 0x0f) | ((rand >> 3) & 0x70);
    v[2] = (ip_bytes[2] & 0x3f) | ((rand >> 5) & 0xc0);
    v[3] = ip_bytes[3];

    let expected_0 = ((v[0] as u32) << 24 | (v[1] as u32) << 16 | (v[2] as u32) << 8 | v[3] as u32)
        .wrapping_mul(0x9E3779B1);
    let expected_0 = ((expected_0 >> 24) & 0xFF) as u8;

    let expected_1 = ((v[0] as u32) << 24 | (v[1] as u32) << 16 | (v[2] as u32) << 8 | v[3] as u32)
        .wrapping_mul(0x9E3779B1)
        .wrapping_add(0x12345678);
    let expected_1 = ((expected_1 >> 24) & 0xFF) as u8;

    let expected_2 = ((v[0] as u32) << 24 | (v[1] as u32) << 16 | (v[2] as u32) << 8 | v[3] as u32)
        .wrapping_mul(0x9E3779B1)
        .wrapping_add(0x23456789);
    let expected_2 = ((expected_2 >> 24) & 0xFF) as u8;

    node_id[0] == expected_0 && node_id[1] == expected_1 && node_id[2] == expected_2
}

#[cfg(feature = "ipv6")]
fn validate_node_id_for_ipv4v6(_node_id: &[u8; 20], _ip: &std::net::Ipv6Addr) -> bool {
    true
}

pub struct DhtNode {
    node_id: [u8; 20],
    logged_startup: bool,
    routing: RoutingTable,
    #[cfg(feature = "ipv6")]
    routing6: RoutingTable6,
    tokens: TokenIssuer,
    peers: HashMap<[u8; 20], Vec<StoredPeer>>,
    peers_lru: VecDeque<[u8; 20]>,
    rate_limiter: RateLimiter,
    #[cfg(feature = "ipv6")]
    rate_limiter6: RateLimiter6,
    pending_outbound: Vec<(SocketAddrV4, Vec<u8>)>,
    #[cfg(feature = "ipv6")]
    pending_outbound6: Vec<(SocketAddrV6, Vec<u8>)>,
    pending_queries: HashMap<TransactionId, PendingQuery>,
    tid_counter: u16,
    bootstrap_done: bool,
    last_bootstrap_ms: Option<u64>,
    next_refresh_ms: u64,
    clock_start: Instant,
    node_ids_per_ip_v4: HashMap<Ipv4Addr, Vec<NodeIdEntry>>,
    #[cfg(feature = "ipv6")]
    node_ids_per_ip_v6: HashMap<std::net::Ipv6Addr, Vec<NodeIdEntry>>,
}

pub struct PacketOutcome {
    pub message: Message,
    pub response: Option<Message>,
    pub discovered_peers: Vec<(std::net::SocketAddr, [u8; 20])>,
}

type TransactionId = [u8; 2];

struct PendingQuery {
    query_type: QueryType,
    sent_at_ms: u64,
    addr: std::net::SocketAddr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QueryType {
    BootstrapPing,
    RefreshPing,
    VerificationPing([u8; 20]),
    GetPeers([u8; 20]),
}

impl DhtNode {
    pub fn new() -> Self {
        let node_id = dht_node_id_20().expect("Failed to generate DHT node ID");
        let routing = RoutingTable::new(node_id);
        #[cfg(feature = "ipv6")]
        let routing6 = RoutingTable6::new(node_id);
        let clock_start = Instant::now();
        Self {
            node_id,
            logged_startup: false,
            routing,
            #[cfg(feature = "ipv6")]
            routing6,
            tokens: TokenIssuer::new(),
            peers: HashMap::new(),
            peers_lru: VecDeque::new(),
            rate_limiter: RateLimiter::new(RATE_LIMIT_WINDOW_MS, RATE_LIMIT_MAX_QUERIES),
            #[cfg(feature = "ipv6")]
            rate_limiter6: RateLimiter6::new(RATE_LIMIT_WINDOW_MS, RATE_LIMIT_MAX_QUERIES),
            pending_outbound: Vec::new(),
            #[cfg(feature = "ipv6")]
            pending_outbound6: Vec::new(),
            pending_queries: HashMap::new(),
            tid_counter: 0,
            bootstrap_done: false,
            last_bootstrap_ms: None,
            next_refresh_ms: REFRESH_INTERVAL_MS,
            clock_start,
            node_ids_per_ip_v4: HashMap::new(),
            #[cfg(feature = "ipv6")]
            node_ids_per_ip_v6: HashMap::new(),
        }
    }

    pub fn node_id(&self) -> &[u8; 20] {
        &self.node_id
    }

    pub fn known_nodes(&self) -> u32 {
        let v4 = self.routing.len() as u32;
        #[cfg(feature = "ipv6")]
        let v6 = self.routing6.len() as u32;
        #[cfg(not(feature = "ipv6"))]
        let v6 = 0;
        v4 + v6
    }

    fn elapsed_ms(&self) -> u64 {
        Instant::now()
            .checked_duration_since(self.clock_start)
            .unwrap_or(Duration::from_millis(0))
            .as_millis() as u64
    }

    pub fn tick(&mut self) -> Vec<String> {
        let now = Instant::now();
        self.tick_at(now)
    }

    pub fn tick_at(&mut self, now: Instant) -> Vec<String> {
        let mut log_lines = Vec::new();

        if !self.logged_startup {
            self.logged_startup = true;
            log_lines.push("DHT node initialized".to_string());
        }

        let now_ms = now
            .checked_duration_since(self.clock_start)
            .unwrap_or(Duration::from_millis(0))
            .as_millis() as u64;

        self.cleanup_stale_queries(now_ms);
        self.prune_expired_peers();
        self.cleanup_stale_node_ids(now_ms);

        if !self.bootstrap_done {
            if self.routing.is_empty() {
                if self
                    .last_bootstrap_ms
                    .map(|last| now_ms.saturating_sub(last) >= BOOTSTRAP_RETRY_MS)
                    .unwrap_or(true)
                {
                    for node in default_bootstrap_nodes() {
                        self.queue_ping(*node, QueryType::BootstrapPing, now_ms);
                    }
                    self.last_bootstrap_ms = Some(now_ms);
                    log_lines.push(format!(
                        "DHT bootstrap queued: {} nodes",
                        default_bootstrap_nodes().len()
                    ));
                }
            } else {
                self.bootstrap_done = true;
            }
        }

        if now_ms >= self.next_refresh_ms {
            let mut refresh_targets = self.routing.oldest_nodes(REFRESH_BATCH_SIZE);
            if refresh_targets.is_empty() {
                refresh_targets = default_bootstrap_nodes().to_vec();
            }
            for addr in refresh_targets.iter().copied() {
                self.queue_ping(addr, QueryType::RefreshPing, now_ms);
            }
            if !refresh_targets.is_empty() {
                log_lines.push(format!(
                    "DHT refresh queued: {} nodes",
                    refresh_targets.len()
                ));
            }
            #[cfg(feature = "ipv6")]
            {
                let refresh_targets6 = self.routing6.oldest_nodes(REFRESH_BATCH_SIZE);
                if !refresh_targets6.is_empty() {
                    for addr in refresh_targets6.iter().copied() {
                        self.queue_ping6(addr, QueryType::RefreshPing, now_ms);
                    }
                    log_lines.push(format!(
                        "DHT v6 refresh queued: {} nodes",
                        refresh_targets6.len()
                    ));
                }
            }
            self.next_refresh_ms = now_ms.saturating_add(REFRESH_INTERVAL_MS);
        }

        log_lines
    }

    pub fn handle_packet(
        &mut self,
        source: SocketAddrV4,
        payload: &[u8],
    ) -> Result<PacketOutcome, RpcError> {
        let message = decode_message(payload)?;
        let mut discovered_peers = Vec::new();

        if let Message::Query(query) = &message {
            if !self.rate_limiter.allow(*source.ip()) {
                let transaction_id = query.transaction_id.clone();
                return Ok(PacketOutcome {
                    message,
                    response: Some(Message::Error(ErrorMessage {
                        transaction_id,
                        code: 202,
                        message: b"rate limited".to_vec(),
                    })),
                    discovered_peers,
                });
            }
        }

        if let Message::Response(response) = &message {
            if response.transaction_id.len() == 2 {
                let mut tid = [0u8; 2];
                tid.copy_from_slice(&response.transaction_id);
                if let Some(pending) = self.pending_queries.remove(&tid) {
                    match &response.kind {
                        ResponseKind::FindNode {
                            nodes,
                            #[cfg(feature = "ipv6")]
                            nodes6,
                            ..
                        } => {
                            for node in nodes {
                                self.observe_node(node.id, node.addr);
                            }
                            #[cfg(feature = "ipv6")]
                            for node in nodes6 {
                                self.observe_node6(node.id, node.addr);
                            }
                        }
                        ResponseKind::GetPeers {
                            nodes,
                            values,
                            #[cfg(feature = "ipv6")]
                            nodes6,
                            #[cfg(feature = "ipv6")]
                            values6,
                            ..
                        } => {
                            for node in nodes {
                                self.observe_node(node.id, node.addr);
                            }
                            #[cfg(feature = "ipv6")]
                            for node in nodes6 {
                                self.observe_node6(node.id, node.addr);
                            }
                            if let QueryType::GetPeers(info_hash) = pending.query_type {
                                for peer_addr in values {
                                    discovered_peers.push((std::net::SocketAddr::V4(*peer_addr), info_hash));
                                }
                                #[cfg(feature = "ipv6")]
                                for peer_addr in values6 {
                                    discovered_peers.push((std::net::SocketAddr::V6(*peer_addr), info_hash));
                                }
                            }
                        }
                        ResponseKind::Ping { id } => {
                            if let QueryType::VerificationPing(expected_id) = pending.query_type {
                                if *id == expected_id {
                                    self.routing.mark_node_good(&expected_id);
                                }
                            }
                        }
                    }
                }
            }
        }

        if let Some(id) = message.sender_id() {
            self.observe_node(id, source);
        }
        let response = match &message {
            Message::Query(query) => self.handle_query(source, query),
            _ => None,
        };
        Ok(PacketOutcome {
            message,
            response,
            discovered_peers,
        })
    }

    #[cfg(feature = "ipv6")]
    pub fn handle_packet6(
        &mut self,
        source: SocketAddrV6,
        payload: &[u8],
    ) -> Result<PacketOutcome, RpcError> {
        let message = decode_message(payload)?;
        let mut discovered_peers = Vec::new();

        if let Message::Query(query) = &message {
            if !self.rate_limiter6.allow(*source.ip()) {
                let transaction_id = query.transaction_id.clone();
                return Ok(PacketOutcome {
                    message,
                    response: Some(Message::Error(ErrorMessage {
                        transaction_id,
                        code: 202,
                        message: b"rate limited".to_vec(),
                    })),
                    discovered_peers,
                });
            }
        }

        if let Message::Response(response) = &message {
            if response.transaction_id.len() == 2 {
                let mut tid = [0u8; 2];
                tid.copy_from_slice(&response.transaction_id);
                if let Some(pending) = self.pending_queries.remove(&tid) {
                    match &response.kind {
                        ResponseKind::FindNode { nodes, nodes6, .. } => {
                            for node in nodes {
                                self.observe_node(node.id, node.addr);
                            }
                            for node in nodes6 {
                                self.observe_node6(node.id, node.addr);
                            }
                        }
                        ResponseKind::GetPeers {
                            nodes,
                            values,
                            nodes6,
                            values6,
                            ..
                        } => {
                            for node in nodes {
                                self.observe_node(node.id, node.addr);
                            }
                            for node in nodes6 {
                                self.observe_node6(node.id, node.addr);
                            }
                            if let QueryType::GetPeers(info_hash) = pending.query_type {
                                for peer_addr in values {
                                    discovered_peers.push((std::net::SocketAddr::V4(*peer_addr), info_hash));
                                }
                                for peer_addr in values6 {
                                    discovered_peers.push((std::net::SocketAddr::V6(*peer_addr), info_hash));
                                }
                            }
                        }
                        ResponseKind::Ping { id } => {
                            if let QueryType::VerificationPing(expected_id) = pending.query_type {
                                if *id == expected_id {
                                    self.routing6.mark_node_good(&expected_id);
                                }
                            }
                        }
                    }
                }
            }
        }

        if let Some(id) = message.sender_id() {
            self.observe_node6(id, source);
        }
        let response = match &message {
            Message::Query(query) => self.handle_query6(source, query),
            _ => None,
        };
        Ok(PacketOutcome {
            message,
            response,
            discovered_peers,
        })
    }

    pub fn observe_node(&mut self, id: [u8; 20], addr: SocketAddrV4) -> bool {
        use crate::routing::InsertResult;

        if !validate_node_id_for_ipv4v4(&id, addr.ip()) {
            return false;
        }

        let now_ms = self.elapsed_ms();
        let ip = *addr.ip();
        let node_ids = self.node_ids_per_ip_v4.entry(ip).or_insert_with(Vec::new);

        if let Some(entry) = node_ids.iter_mut().find(|e| e.node_id == id) {
            entry.last_seen_ms = now_ms;
        } else {
            if node_ids.len() >= MAX_NODE_IDS_PER_IP {
                return false;
            }
            node_ids.push(NodeIdEntry {
                node_id: id,
                last_seen_ms: now_ms,
            });
        }

        let result = self.routing.insert(id, addr);

        if let InsertResult::PingOldest { addr: ping_addr, id: ping_id } = result {
            self.queue_verification_ping(ping_addr, ping_id, now_ms);
        }

        result.was_inserted()
    }

    #[cfg(feature = "ipv6")]
    pub fn observe_node6(&mut self, id: [u8; 20], addr: std::net::SocketAddrV6) -> bool {
        let now_ms = self.elapsed_ms();
        let ip = *addr.ip();
        let node_ids = self.node_ids_per_ip_v6.entry(ip).or_insert_with(Vec::new);

        if let Some(entry) = node_ids.iter_mut().find(|e| e.node_id == id) {
            entry.last_seen_ms = now_ms;
        } else {
            if node_ids.len() >= MAX_NODE_IDS_PER_IP {
                return false;
            }
            node_ids.push(NodeIdEntry {
                node_id: id,
                last_seen_ms: now_ms,
            });
        }

        self.routing6.insert(id, addr);
        true
    }

    pub fn take_pending_packets(&mut self) -> Vec<(SocketAddrV4, Vec<u8>)> {
        std::mem::take(&mut self.pending_outbound)
    }

    #[cfg(feature = "ipv6")]
    pub fn take_pending_packets6(&mut self) -> Vec<(SocketAddrV6, Vec<u8>)> {
        std::mem::take(&mut self.pending_outbound6)
    }

    pub fn announce_peer(&mut self, info_hash: [u8; 20], is_private: bool) {
        if is_private {
            return;
        }

        let now_ms = Instant::now()
            .checked_duration_since(self.clock_start)
            .unwrap_or(Duration::from_millis(0))
            .as_millis() as u64;

        let targets = self.routing.find_closest(info_hash, 8);
        if targets.is_empty() {
            for bootstrap_addr in default_bootstrap_nodes() {
                self.queue_get_peers(*bootstrap_addr, info_hash, now_ms);
            }
        } else {
            for node in targets {
                self.queue_get_peers(node.addr, info_hash, now_ms);
            }
        }
        #[cfg(feature = "ipv6")]
        {
            let targets6 = self.routing6.find_closest(info_hash, 8);
            for node in targets6 {
                self.queue_get_peers6(node.addr, info_hash, now_ms);
            }
        }
    }

    fn generate_tid(&mut self) -> TransactionId {
        let tid = self.tid_counter.to_be_bytes();
        self.tid_counter = self.tid_counter.wrapping_add(1);
        tid
    }

    fn queue_ping(&mut self, addr: SocketAddrV4, query_type: QueryType, now_ms: u64) {
        if self.pending_queries.len() >= MAX_PENDING_QUERIES {
            return;
        }

        let tid = self.generate_tid();
        let message = Message::Query(Query {
            transaction_id: tid.to_vec(),
            kind: QueryKind::Ping { id: self.node_id },
        });
        let payload = encode_message(&message);

        self.pending_queries.insert(
            tid,
            PendingQuery {
                query_type,
                sent_at_ms: now_ms,
                addr: std::net::SocketAddr::V4(addr),
            },
        );

        self.pending_outbound.push((addr, payload));
    }

    #[cfg(feature = "ipv6")]
    fn queue_ping6(&mut self, addr: SocketAddrV6, query_type: QueryType, now_ms: u64) {
        if self.pending_queries.len() >= MAX_PENDING_QUERIES {
            return;
        }

        let tid = self.generate_tid();
        let message = Message::Query(Query {
            transaction_id: tid.to_vec(),
            kind: QueryKind::Ping { id: self.node_id },
        });
        let payload = encode_message(&message);

        self.pending_queries.insert(
            tid,
            PendingQuery {
                query_type,
                sent_at_ms: now_ms,
                addr: std::net::SocketAddr::V6(addr),
            },
        );

        self.pending_outbound6.push((addr, payload));
    }

    fn queue_verification_ping(&mut self, addr: SocketAddrV4, node_id: [u8; 20], now_ms: u64) {
        self.queue_ping(addr, QueryType::VerificationPing(node_id), now_ms);
    }

    fn queue_get_peers(&mut self, addr: SocketAddrV4, info_hash: [u8; 20], now_ms: u64) {
        if self.pending_queries.len() >= MAX_PENDING_QUERIES {
            return;
        }

        let tid = self.generate_tid();
        let message = Message::Query(Query {
            transaction_id: tid.to_vec(),
            kind: QueryKind::GetPeers {
                id: self.node_id,
                info_hash,
            },
        });
        let payload = encode_message(&message);

        self.pending_queries.insert(
            tid,
            PendingQuery {
                query_type: QueryType::GetPeers(info_hash),
                sent_at_ms: now_ms,
                addr: std::net::SocketAddr::V4(addr),
            },
        );

        self.pending_outbound.push((addr, payload));
    }

    #[cfg(feature = "ipv6")]
    fn queue_get_peers6(&mut self, addr: SocketAddrV6, info_hash: [u8; 20], now_ms: u64) {
        if self.pending_queries.len() >= MAX_PENDING_QUERIES {
            return;
        }

        let tid = self.generate_tid();
        let message = Message::Query(Query {
            transaction_id: tid.to_vec(),
            kind: QueryKind::GetPeers {
                id: self.node_id,
                info_hash,
            },
        });
        let payload = encode_message(&message);

        self.pending_queries.insert(
            tid,
            PendingQuery {
                query_type: QueryType::GetPeers(info_hash),
                sent_at_ms: now_ms,
                addr: std::net::SocketAddr::V6(addr),
            },
        );

        self.pending_outbound6.push((addr, payload));
    }

    fn cleanup_stale_queries(&mut self, now_ms: u64) {
        let mut timed_out_verifications = Vec::new();

        self.pending_queries.retain(|_, query| {
            let is_stale = now_ms.saturating_sub(query.sent_at_ms) >= QUERY_TIMEOUT_MS;
            if is_stale {
                if let QueryType::VerificationPing(node_id) = query.query_type {
                    timed_out_verifications.push(node_id);
                }
            }
            !is_stale
        });

        for node_id in timed_out_verifications {
            self.routing.handle_ping_timeout(&node_id);
        }
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
                        #[cfg(feature = "ipv6")]
                        nodes6: Vec::new(),
                    },
                }))
            }
            QueryKind::GetPeers { info_hash, .. } => {
                let token = self.tokens.token_for(*source.ip());
                let all_peers = self
                    .peers
                    .get(info_hash)
                    .map(|values| limit_peers(values))
                    .unwrap_or_default();

                let mut peers_v4 = Vec::new();
                #[cfg(feature = "ipv6")]
                let mut peers_v6 = Vec::new();

                for peer in all_peers {
                    match peer {
                        std::net::SocketAddr::V4(v4) => peers_v4.push(v4),
                        #[cfg(feature = "ipv6")]
                        std::net::SocketAddr::V6(v6) => peers_v6.push(v6),
                        #[cfg(not(feature = "ipv6"))]
                        _ => {}
                    }
                }

                let nodes = if peers_v4.is_empty() {
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
                        values: peers_v4,
                        #[cfg(feature = "ipv6")]
                        nodes6: Vec::new(),
                        #[cfg(feature = "ipv6")]
                        values6: peers_v6,
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
                use crate::peer_ip::is_valid_peer_ip_v4;
                if !is_valid_peer_ip_v4(source.ip()) {
                    return Some(Message::Error(ErrorMessage {
                        transaction_id: query.transaction_id.clone(),
                        code: 203,
                        message: b"invalid peer IP".to_vec(),
                    }));
                }
                let peer_addr = std::net::SocketAddr::V4(SocketAddrV4::new(*source.ip(), peer_port));
                self.store_peer(*info_hash, peer_addr);
                Some(Message::Response(Response {
                    transaction_id: query.transaction_id.clone(),
                    kind: ResponseKind::Ping { id: self.node_id },
                }))
            }
        }
    }

    #[cfg(feature = "ipv6")]
    fn handle_query6(&mut self, source: SocketAddrV6, query: &Query) -> Option<Message> {
        match &query.kind {
            QueryKind::Ping { .. } => Some(Message::Response(Response {
                transaction_id: query.transaction_id.clone(),
                kind: ResponseKind::Ping { id: self.node_id },
            })),
            QueryKind::FindNode { target, .. } => {
                let nodes6 = self.closest_nodes6(*target);
                Some(Message::Response(Response {
                    transaction_id: query.transaction_id.clone(),
                    kind: ResponseKind::FindNode {
                        id: self.node_id,
                        nodes: Vec::new(),
                        nodes6,
                    },
                }))
            }
            QueryKind::GetPeers { info_hash, .. } => {
                let token = self.tokens.token_for_v6(*source.ip());
                let all_peers = self
                    .peers
                    .get(info_hash)
                    .map(|values| limit_peers(values))
                    .unwrap_or_default();

                let mut peers_v4 = Vec::new();
                let mut peers_v6 = Vec::new();

                for peer in all_peers {
                    match peer {
                        std::net::SocketAddr::V4(v4) => peers_v4.push(v4),
                        std::net::SocketAddr::V6(v6) => peers_v6.push(v6),
                    }
                }

                let nodes6 = if peers_v6.is_empty() {
                    self.closest_nodes6(*info_hash)
                } else {
                    Vec::new()
                };
                Some(Message::Response(Response {
                    transaction_id: query.transaction_id.clone(),
                    kind: ResponseKind::GetPeers {
                        id: self.node_id,
                        token: Some(token),
                        nodes: Vec::new(),
                        values: peers_v4,
                        nodes6,
                        values6: peers_v6,
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
                if !self.tokens.validate_v6(*source.ip(), token) {
                    return Some(Message::Error(ErrorMessage {
                        transaction_id: query.transaction_id.clone(),
                        code: 203,
                        message: b"invalid token".to_vec(),
                    }));
                }
                use crate::peer_ip::is_valid_peer_ip_v6;
                if !is_valid_peer_ip_v6(source.ip()) {
                    return Some(Message::Error(ErrorMessage {
                        transaction_id: query.transaction_id.clone(),
                        code: 203,
                        message: b"invalid peer IP".to_vec(),
                    }));
                }
                let peer_addr = std::net::SocketAddr::V6(SocketAddrV6::new(
                    *source.ip(),
                    peer_port,
                    source.flowinfo(),
                    source.scope_id(),
                ));
                self.store_peer(*info_hash, peer_addr);
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

    #[cfg(feature = "ipv6")]
    fn closest_nodes6(&self, target: [u8; 20]) -> Vec<NodeEntry6> {
        self.routing6
            .find_closest(target, MAX_RESPONSE_NODES)
            .into_iter()
            .map(|node| NodeEntry6 {
                id: node.id,
                addr: node.addr,
            })
            .collect()
    }

    fn store_peer(&mut self, info_hash: [u8; 20], peer: std::net::SocketAddr) {
        let now_ms = self.elapsed_ms();

        if self.peers.len() >= MAX_INFOHASHES && !self.peers.contains_key(&info_hash) {
            if let Some(oldest_key) = self.peers_lru.pop_front() {
                self.peers.remove(&oldest_key);
            }
        }

        if self.peers.contains_key(&info_hash) {
            if let Some(pos) = self.peers_lru.iter().position(|k| k == &info_hash) {
                self.peers_lru.remove(pos);
            }
            self.peers_lru.push_back(info_hash);
        } else {
            self.peers_lru.push_back(info_hash);
        }

        let entry = self.peers.entry(info_hash).or_insert_with(Vec::new);
        if let Some(existing) = entry.iter_mut().find(|p| p.addr == peer) {
            existing.stored_at_ms = now_ms;
            return;
        }
        if entry.len() >= MAX_PEERS_PER_INFOHASH {
            entry.remove(0);
        }
        entry.push(StoredPeer {
            addr: peer,
            stored_at_ms: now_ms,
        });
    }

    fn prune_expired_peers(&mut self) {
        let now_ms = self.elapsed_ms();
        for peers in self.peers.values_mut() {
            peers.retain(|p| now_ms.saturating_sub(p.stored_at_ms) < PEER_TTL_MS);
        }

        self.peers.retain(|_, peers| !peers.is_empty());
        self.peers_lru.retain(|key| self.peers.contains_key(key));
    }

    fn cleanup_stale_node_ids(&mut self, now_ms: u64) {
        for (_ip, entries) in self.node_ids_per_ip_v4.iter_mut() {
            entries.retain(|entry| now_ms.saturating_sub(entry.last_seen_ms) < NODE_ID_PER_IP_TTL_MS);
        }
        self.node_ids_per_ip_v4.retain(|_, entries| !entries.is_empty());

        #[cfg(feature = "ipv6")]
        {
            for (_ip, entries) in self.node_ids_per_ip_v6.iter_mut() {
                entries.retain(|entry| now_ms.saturating_sub(entry.last_seen_ms) < NODE_ID_PER_IP_TTL_MS);
            }
            self.node_ids_per_ip_v6.retain(|_, entries| !entries.is_empty());
        }
    }
}

fn limit_peers(peers: &[StoredPeer]) -> Vec<std::net::SocketAddr> {
    let mut out = Vec::with_capacity(peers.len().min(MAX_PEERS_PER_INFOHASH));
    out.extend(peers.iter().take(MAX_PEERS_PER_INFOHASH).map(|p| p.addr));
    out
}

struct RateLimiter {
    window_ms: u64,
    max_hits: u32,
    start: Instant,
    entries: HashMap<Ipv4Addr, RateEntry>,
}

struct RateEntry {
    window_start_ms: u64,
    hits: u32,
    last_seen_ms: u64,
}

impl RateLimiter {
    fn new(window_ms: u64, max_hits: u32) -> Self {
        Self {
            window_ms,
            max_hits,
            start: Instant::now(),
            entries: HashMap::new(),
        }
    }

    fn allow(&mut self, ip: Ipv4Addr) -> bool {
        let now_ms = self.start.elapsed().as_millis() as u64;
        self.allow_at(ip, now_ms)
    }

    fn allow_at(&mut self, ip: Ipv4Addr, now_ms: u64) -> bool {
        self.cleanup(now_ms);
        let entry = self.entries.entry(ip).or_insert(RateEntry {
            window_start_ms: now_ms,
            hits: 0,
            last_seen_ms: now_ms,
        });
        if now_ms.saturating_sub(entry.window_start_ms) >= self.window_ms {
            entry.window_start_ms = now_ms;
            entry.hits = 0;
        }
        entry.last_seen_ms = now_ms;
        if entry.hits >= self.max_hits {
            return false;
        }
        entry.hits += 1;
        true
    }

    fn cleanup(&mut self, now_ms: u64) {
        self.entries
            .retain(|_, entry| now_ms.saturating_sub(entry.last_seen_ms) <= RATE_LIMIT_STALE_MS);

        while self.entries.len() > RATE_LIMIT_MAX_CLIENTS {
            if let Some((oldest_ip, _)) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_seen_ms)
                .map(|(ip, entry)| (*ip, entry.last_seen_ms))
            {
                self.entries.remove(&oldest_ip);
            } else {
                break;
            }
        }
    }
}

#[cfg(feature = "ipv6")]
struct RateLimiter6 {
    window_ms: u64,
    max_hits: u32,
    start: Instant,
    entries: HashMap<std::net::Ipv6Addr, RateEntry>,
}

#[cfg(feature = "ipv6")]
impl RateLimiter6 {
    fn new(window_ms: u64, max_hits: u32) -> Self {
        Self {
            window_ms,
            max_hits,
            start: Instant::now(),
            entries: HashMap::new(),
        }
    }

    fn allow(&mut self, ip: std::net::Ipv6Addr) -> bool {
        let now_ms = self.start.elapsed().as_millis() as u64;
        self.allow_at(ip, now_ms)
    }

    fn allow_at(&mut self, ip: std::net::Ipv6Addr, now_ms: u64) -> bool {
        self.cleanup(now_ms);
        let entry = self.entries.entry(ip).or_insert(RateEntry {
            window_start_ms: now_ms,
            hits: 0,
            last_seen_ms: now_ms,
        });
        if now_ms.saturating_sub(entry.window_start_ms) >= self.window_ms {
            entry.window_start_ms = now_ms;
            entry.hits = 0;
        }
        entry.last_seen_ms = now_ms;
        if entry.hits >= self.max_hits {
            return false;
        }
        entry.hits += 1;
        true
    }

    fn cleanup(&mut self, now_ms: u64) {
        self.entries
            .retain(|_, entry| now_ms.saturating_sub(entry.last_seen_ms) <= RATE_LIMIT_STALE_MS);

        while self.entries.len() > RATE_LIMIT_MAX_CLIENTS {
            if let Some((oldest_ip, _)) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_seen_ms)
                .map(|(ip, entry)| (*ip, entry.last_seen_ms))
            {
                self.entries.remove(&oldest_ip);
            } else {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrap::default_bootstrap_nodes;
    use crate::rpc::{encode_message, Message, Query, QueryKind};
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn node_id_for_ipv4v4(ip: Ipv4Addr, rand: u8) -> [u8; 20] {
        let ip_bytes = ip.octets();
        let mut v = [0u8; 4];
        v[0] = (ip_bytes[0] & 0x03) | ((rand & 0x07) << 5);
        v[1] = (ip_bytes[1] & 0x0f) | ((rand >> 3) & 0x70);
        v[2] = (ip_bytes[2] & 0x3f) | ((rand >> 5) & 0xc0);
        v[3] = ip_bytes[3];

        let hash_base = (v[0] as u32) << 24 | (v[1] as u32) << 16 | (v[2] as u32) << 8 | v[3] as u32;

        let expected_0 = (hash_base.wrapping_mul(0x9E3779B1) >> 24) as u8;
        let expected_1 = (hash_base.wrapping_mul(0x9E3779B1).wrapping_add(0x12345678) >> 24) as u8;
        let expected_2 = (hash_base.wrapping_mul(0x9E3779B1).wrapping_add(0x23456789) >> 24) as u8;

        let mut node_id = [0u8; 20];
        node_id[0] = expected_0;
        node_id[1] = expected_1;
        node_id[2] = expected_2;
        node_id[19] = rand;
        node_id
    }

    #[test]
    fn test_node_id_generated() {
        let node = DhtNode::new();
        assert!(node.node_id().iter().any(|byte| *byte != 0));
    }

    #[test]
    fn test_observe_node_updates_count() {
        let mut node = DhtNode::new();
        let addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 6881);
        let other_id = node_id_for_ipv4(*addr.ip(), 1);
        assert!(node.observe_node(other_id, addr));
        assert_eq!(node.known_nodes(), 1);
    }

    #[test]
    fn handle_packet_tracks_sender() {
        let mut node = DhtNode::new();
        let addr = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 5), 6881);
        let sender_id = node_id_for_ipv4(*addr.ip(), 9);
        let message = Message::Query(Query {
            transaction_id: b"aa".to_vec(),
            kind: QueryKind::Ping { id: sender_id },
        });
        let payload = encode_message(&message);

        let outcome = node.handle_packet(addr, &payload).unwrap();
        assert_eq!(outcome.message, message);
        assert_eq!(node.known_nodes(), 1);
        assert!(outcome.discovered_peers.is_empty());
    }

    #[test]
    fn handle_ping_returns_response() {
        let mut node = DhtNode::new();
        let addr = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 10), 6881);
        let sender_id = node_id_for_ipv4(*addr.ip(), 2);
        let message = Message::Query(Query {
            transaction_id: b"aa".to_vec(),
            kind: QueryKind::Ping { id: sender_id },
        });
        let payload = encode_message(&message);

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
        let other_id = node_id_for_ipv4(*addr.ip(), 5);
        node.observe_node(other_id, addr);

        let sender_addr = SocketAddrV4::new(Ipv4Addr::new(2, 2, 2, 2), 6881);
        let sender_id = node_id_for_ipv4(*sender_addr.ip(), 9);
        let query = Message::Query(Query {
            transaction_id: b"fn".to_vec(),
            kind: QueryKind::FindNode {
                id: sender_id,
                target: other_id,
            },
        });

        let payload = encode_message(&query);
        let outcome = node
            .handle_packet(sender_addr, &payload)
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
        let source = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 9), 6889);
        let sender_id = node_id_for_ipv4(*source.ip(), 7);
        let info_hash = [0x22u8; 20];

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

    #[test]
    fn rate_limited_queries_return_error() {
        let mut node = DhtNode::new();
        let source = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 4), 6881);
        let mut sender_id = [0u8; 20];
        sender_id[0] = 1;

        for index in 0..RATE_LIMIT_MAX_QUERIES {
            let message = Message::Query(Query {
                transaction_id: vec![index as u8],
                kind: QueryKind::Ping { id: sender_id },
            });
            let payload = encode_message(&message);
            let outcome = node.handle_packet(source, &payload).unwrap();
            assert!(matches!(
                outcome.response,
                Some(Message::Response(Response {
                    kind: ResponseKind::Ping { .. },
                    ..
                }))
            ));
        }

        let message = Message::Query(Query {
            transaction_id: b"rl".to_vec(),
            kind: QueryKind::Ping { id: sender_id },
        });
        let payload = encode_message(&message);
        let outcome = node.handle_packet(source, &payload).unwrap();
        assert!(matches!(
            outcome.response,
            Some(Message::Error(ErrorMessage { code, .. })) if code == 202
        ));
    }

    #[test]
    fn tick_queues_bootstrap_queries_on_startup() {
        let mut node = DhtNode::new();
        let now = node.clock_start;
        let logs = node.tick_at(now);
        assert!(logs.iter().any(|line| line.contains("DHT bootstrap queued")));
        let packets = node.take_pending_packets();
        assert!(!packets.is_empty());
        assert_eq!(packets.len(), default_bootstrap_nodes().len());
    }

    #[test]
    fn tick_queues_refresh_queries_after_interval() {
        let mut node = DhtNode::new();
        let addr = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 8), 6881);
        let mut other_id = [0u8; 20];
        other_id[0] = 42;
        node.observe_node(other_id, addr);

        let now = node
            .clock_start
            .checked_add(Duration::from_millis(REFRESH_INTERVAL_MS))
            .unwrap();
        let logs = node.tick_at(now);
        assert!(logs.iter().any(|line| line.contains("DHT refresh queued")));
        let packets = node.take_pending_packets();
        assert!(!packets.is_empty());
    }
}
