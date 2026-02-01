use std::collections::VecDeque;
use std::net::SocketAddrV4;
#[cfg(feature = "ipv6")]
use std::net::SocketAddrV6;
use std::time::{Duration, Instant};

const NODE_ID_LEN: usize = 20;
const K_BUCKET_SIZE: usize = 8;
const BUCKET_COUNT: usize = NODE_ID_LEN * 8;
const REPLACEMENT_CACHE_SIZE: usize = 8;
const NODE_STALE_TIMEOUT: Duration = Duration::from_secs(900);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InsertResult {
    Inserted,
    Updated,
    Cached,
    Rejected,
    PingOldest { addr: SocketAddrV4, id: [u8; NODE_ID_LEN] },
}

impl InsertResult {
    pub fn was_inserted(&self) -> bool {
        matches!(self, InsertResult::Inserted)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeInfo {
    pub id: [u8; NODE_ID_LEN],
    pub addr: SocketAddrV4,
    last_seen: Instant,
    pending_ping: bool,
}

impl NodeInfo {
    fn new(id: [u8; NODE_ID_LEN], addr: SocketAddrV4) -> Self {
        Self {
            id,
            addr,
            last_seen: Instant::now(),
            pending_ping: false,
        }
    }

    fn touch(&mut self, addr: SocketAddrV4) {
        self.addr = addr;
        self.last_seen = Instant::now();
        self.pending_ping = false;
    }

    fn is_questionable(&self) -> bool {
        self.last_seen.elapsed() > NODE_STALE_TIMEOUT
    }
}

struct Bucket {
    nodes: VecDeque<NodeInfo>,
    replacement_cache: VecDeque<NodeInfo>,
}

impl Bucket {
    fn new() -> Self {
        Self {
            nodes: VecDeque::new(),
            replacement_cache: VecDeque::new(),
        }
    }
}

pub struct RoutingTable {
    self_id: [u8; NODE_ID_LEN],
    buckets: Vec<Bucket>,
}

impl RoutingTable {
    pub fn new(self_id: [u8; NODE_ID_LEN]) -> Self {
        let mut buckets = Vec::with_capacity(BUCKET_COUNT);
        for _ in 0..BUCKET_COUNT {
            buckets.push(Bucket::new());
        }
        Self { self_id, buckets }
    }

    pub fn len(&self) -> usize {
        self.buckets.iter().map(|bucket| bucket.nodes.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn insert(&mut self, id: [u8; NODE_ID_LEN], addr: SocketAddrV4) -> InsertResult {
        if id == self.self_id {
            return InsertResult::Rejected;
        }

        let bucket_index = match bucket_index(&self.self_id, &id) {
            Some(index) => index,
            None => return InsertResult::Rejected,
        };

        let bucket = &mut self.buckets[bucket_index];

        if let Some(pos) = bucket.nodes.iter().position(|node| node.id == id) {
            if let Some(mut node) = bucket.nodes.remove(pos) {
                node.touch(addr);
                bucket.nodes.push_back(node);
            }
            bucket.replacement_cache.retain(|node| node.id != id);
            return InsertResult::Updated;
        }

        if let Some(pos) = bucket.replacement_cache.iter().position(|node| node.id == id) {
            if let Some(mut node) = bucket.replacement_cache.remove(pos) {
                node.touch(addr);
                bucket.replacement_cache.push_back(node);
            }
            return InsertResult::Updated;
        }

        if bucket.nodes.len() < K_BUCKET_SIZE {
            bucket.nodes.push_back(NodeInfo::new(id, addr));
            return InsertResult::Inserted;
        }

        if let Some(oldest) = bucket.nodes.front() {
            if oldest.is_questionable() && !oldest.pending_ping {
                let oldest_addr = oldest.addr;
                let oldest_id = oldest.id;

                if bucket.replacement_cache.len() >= REPLACEMENT_CACHE_SIZE {
                    bucket.replacement_cache.pop_front();
                }
                bucket.replacement_cache.push_back(NodeInfo::new(id, addr));

                if let Some(node) = bucket.nodes.front_mut() {
                    node.pending_ping = true;
                }

                return InsertResult::PingOldest { addr: oldest_addr, id: oldest_id };
            }
        }

        if bucket.replacement_cache.len() >= REPLACEMENT_CACHE_SIZE {
            bucket.replacement_cache.pop_front();
        }
        bucket.replacement_cache.push_back(NodeInfo::new(id, addr));

        InsertResult::Cached
    }

    pub fn mark_node_good(&mut self, id: &[u8; NODE_ID_LEN]) {
        let bucket_index = match bucket_index(&self.self_id, id) {
            Some(index) => index,
            None => return,
        };

        let bucket = &mut self.buckets[bucket_index];
        if let Some(pos) = bucket.nodes.iter().position(|node| &node.id == id) {
            if let Some(mut node) = bucket.nodes.remove(pos) {
                node.last_seen = Instant::now();
                node.pending_ping = false;
                bucket.nodes.push_back(node);
            }
        }
    }

    pub fn handle_ping_timeout(&mut self, id: &[u8; NODE_ID_LEN]) {
        let bucket_index = match bucket_index(&self.self_id, id) {
            Some(index) => index,
            None => return,
        };

        let bucket = &mut self.buckets[bucket_index];

        if let Some(pos) = bucket.nodes.iter().position(|node| &node.id == id && node.pending_ping) {
            bucket.nodes.remove(pos);

            if let Some(replacement) = bucket.replacement_cache.pop_front() {
                bucket.nodes.push_back(replacement);
            }
        }
    }

    pub fn get_stale_nodes(&self, limit: usize) -> Vec<(SocketAddrV4, [u8; NODE_ID_LEN])> {
        let mut stale = Vec::new();

        for bucket in &self.buckets {
            for node in &bucket.nodes {
                if node.is_questionable() && !node.pending_ping {
                    stale.push((node.addr, node.id));
                    if stale.len() >= limit {
                        return stale;
                    }
                }
            }
        }

        stale
    }

    pub fn find_closest(&self, target: [u8; NODE_ID_LEN], limit: usize) -> Vec<NodeInfo> {
        if limit == 0 {
            return Vec::new();
        }

        let mut nodes = Vec::new();
        for bucket in &self.buckets {
            for node in &bucket.nodes {
                nodes.push(node.clone());
            }
        }

        nodes.sort_by(|a, b| xor_distance_cmp(&a.id, &b.id, &target));
        if nodes.len() > limit {
            nodes.truncate(limit);
        }
        nodes
    }

    pub fn oldest_nodes(&self, limit: usize) -> Vec<SocketAddrV4> {
        if limit == 0 {
            return Vec::new();
        }

        let mut nodes = Vec::new();
        for bucket in &self.buckets {
            for node in &bucket.nodes {
                nodes.push(node);
            }
        }

        nodes.sort_by_key(|node| node.last_seen);
        let mut out = Vec::with_capacity(limit.min(nodes.len()));
        for node in nodes.into_iter().take(limit) {
            out.push(node.addr);
        }
        out
    }

    pub fn remove_node(&mut self, id: &[u8; NODE_ID_LEN]) -> bool {
        let bucket_index = match bucket_index(&self.self_id, id) {
            Some(index) => index,
            None => return false,
        };

        let bucket = &mut self.buckets[bucket_index];
        if let Some(pos) = bucket.nodes.iter().position(|node| &node.id == id) {
            bucket.nodes.remove(pos);

            if let Some(replacement) = bucket.replacement_cache.pop_front() {
                bucket.nodes.push_back(replacement);
            }
            return true;
        }

        false
    }
}

fn bucket_index(self_id: &[u8; NODE_ID_LEN], node_id: &[u8; NODE_ID_LEN]) -> Option<usize> {
    let mut leading_zero_bits = 0usize;

    for (a, b) in self_id.iter().zip(node_id.iter()) {
        let diff = a ^ b;
        if diff == 0 {
            leading_zero_bits += 8;
        } else {
            leading_zero_bits += diff.leading_zeros() as usize;
            break;
        }
    }

    if leading_zero_bits >= NODE_ID_LEN * 8 {
        return None;
    }

    let distance_bits = NODE_ID_LEN * 8 - leading_zero_bits;
    Some(distance_bits - 1)
}

fn xor_distance_cmp(
    a: &[u8; NODE_ID_LEN],
    b: &[u8; NODE_ID_LEN],
    target: &[u8; NODE_ID_LEN],
) -> std::cmp::Ordering {
    for i in 0..NODE_ID_LEN {
        let ad = a[i] ^ target[i];
        let bd = b[i] ^ target[i];
        if ad != bd {
            return ad.cmp(&bd);
        }
    }
    std::cmp::Ordering::Equal
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn id_with_last_byte(byte: u8) -> [u8; NODE_ID_LEN] {
        let mut id = [0u8; NODE_ID_LEN];
        id[NODE_ID_LEN - 1] = byte;
        id
    }

    #[test]
    fn bucket_index_handles_msb_and_lsb() {
        let self_id = [0u8; NODE_ID_LEN];
        let mut msb = [0u8; NODE_ID_LEN];
        msb[0] = 0x80;
        let lsb = id_with_last_byte(0x01);

        assert_eq!(bucket_index(&self_id, &msb), Some(159));
        assert_eq!(bucket_index(&self_id, &lsb), Some(0));
    }

    #[test]
    fn insert_replacement_cache_fills_on_overflow() {
        let self_id = [0u8; NODE_ID_LEN];
        let mut table = RoutingTable::new(self_id);
        let addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 6881);
        let base = 0x80u8;
        let mut ids = Vec::new();

        for i in 0..=(K_BUCKET_SIZE + 2) {
            let id = id_with_last_byte(base + i as u8);
            ids.push(id);
            table.insert(id, addr);
        }

        let bucket_idx = bucket_index(&self_id, &ids[0]).unwrap();
        let bucket = &table.buckets[bucket_idx];
        assert_eq!(bucket.nodes.len(), K_BUCKET_SIZE);
        assert!(bucket.nodes.iter().any(|node| node.id == ids[0]));
        assert_eq!(bucket.replacement_cache.len(), 3);
    }

    #[test]
    fn find_closest_orders_by_distance() {
        let self_id = [0u8; NODE_ID_LEN];
        let mut table = RoutingTable::new(self_id);
        let addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 6881);

        let target = id_with_last_byte(0x08);
        let far = id_with_last_byte(0x80);
        let near = id_with_last_byte(0x09);
        let mid = id_with_last_byte(0x20);

        table.insert(far, addr);
        table.insert(near, addr);
        table.insert(mid, addr);

        let closest = table.find_closest(target, 3);
        assert_eq!(closest[0].id, near);
        assert_eq!(closest[1].id, mid);
        assert_eq!(closest[2].id, far);
    }

    #[test]
    fn oldest_nodes_returns_addresses() {
        let self_id = [0u8; NODE_ID_LEN];
        let mut table = RoutingTable::new(self_id);
        let addr1 = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 6881);
        let addr2 = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 6881);

        let id1 = id_with_last_byte(0x10);
        let id2 = id_with_last_byte(0x20);

        table.insert(id1, addr1);
        table.insert(id2, addr2);

        let nodes = table.oldest_nodes(1);
        assert_eq!(nodes.len(), 1);
        assert!(nodes[0] == addr1 || nodes[0] == addr2);
    }
}

#[cfg(feature = "ipv6")]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeInfo6 {
    pub id: [u8; NODE_ID_LEN],
    pub addr: SocketAddrV6,
    last_seen: Instant,
    pending_ping: bool,
}

#[cfg(feature = "ipv6")]
impl NodeInfo6 {
    fn new(id: [u8; NODE_ID_LEN], addr: SocketAddrV6) -> Self {
        Self {
            id,
            addr,
            last_seen: Instant::now(),
            pending_ping: false,
        }
    }

    fn touch(&mut self, addr: SocketAddrV6) {
        self.addr = addr;
        self.last_seen = Instant::now();
        self.pending_ping = false;
    }

    fn is_questionable(&self) -> bool {
        self.last_seen.elapsed() > NODE_STALE_TIMEOUT
    }
}

#[cfg(feature = "ipv6")]
struct Bucket6 {
    nodes: VecDeque<NodeInfo6>,
    replacement_cache: VecDeque<NodeInfo6>,
}

#[cfg(feature = "ipv6")]
impl Bucket6 {
    fn new() -> Self {
        Self {
            nodes: VecDeque::new(),
            replacement_cache: VecDeque::new(),
        }
    }
}

#[cfg(feature = "ipv6")]
pub struct RoutingTable6 {
    self_id: [u8; NODE_ID_LEN],
    buckets: Vec<Bucket6>,
}

#[cfg(feature = "ipv6")]
impl RoutingTable6 {
    pub fn new(self_id: [u8; NODE_ID_LEN]) -> Self {
        let mut buckets = Vec::with_capacity(BUCKET_COUNT);
        for _ in 0..BUCKET_COUNT {
            buckets.push(Bucket6::new());
        }
        Self { self_id, buckets }
    }

    pub fn len(&self) -> usize {
        self.buckets.iter().map(|bucket| bucket.nodes.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn insert(&mut self, id: [u8; NODE_ID_LEN], addr: SocketAddrV6) -> InsertResult {
        if id == self.self_id {
            return InsertResult::Rejected;
        }

        let bucket_index = match bucket_index(&self.self_id, &id) {
            Some(index) => index,
            None => return InsertResult::Rejected,
        };

        let bucket = &mut self.buckets[bucket_index];

        if let Some(pos) = bucket.nodes.iter().position(|node| node.id == id) {
            if let Some(mut node) = bucket.nodes.remove(pos) {
                node.touch(addr);
                bucket.nodes.push_back(node);
            }
            bucket.replacement_cache.retain(|node| node.id != id);
            return InsertResult::Updated;
        }

        if let Some(pos) = bucket.replacement_cache.iter().position(|node| node.id == id) {
            if let Some(mut node) = bucket.replacement_cache.remove(pos) {
                node.touch(addr);
                bucket.replacement_cache.push_back(node);
            }
            return InsertResult::Updated;
        }

        if bucket.nodes.len() < K_BUCKET_SIZE {
            bucket.nodes.push_back(NodeInfo6::new(id, addr));
            return InsertResult::Inserted;
        }

        if bucket.replacement_cache.len() >= REPLACEMENT_CACHE_SIZE {
            bucket.replacement_cache.pop_front();
        }
        bucket.replacement_cache.push_back(NodeInfo6::new(id, addr));

        InsertResult::Cached
    }

    pub fn mark_node_good(&mut self, id: &[u8; NODE_ID_LEN]) {
        let bucket_index = match bucket_index(&self.self_id, id) {
            Some(index) => index,
            None => return,
        };

        let bucket = &mut self.buckets[bucket_index];
        if let Some(pos) = bucket.nodes.iter().position(|node| &node.id == id) {
            if let Some(mut node) = bucket.nodes.remove(pos) {
                node.last_seen = Instant::now();
                node.pending_ping = false;
                bucket.nodes.push_back(node);
            }
        }
    }

    pub fn find_closest(&self, target: [u8; NODE_ID_LEN], limit: usize) -> Vec<NodeInfo6> {
        if limit == 0 {
            return Vec::new();
        }

        let mut nodes = Vec::new();
        for bucket in &self.buckets {
            for node in &bucket.nodes {
                nodes.push(node.clone());
            }
        }

        nodes.sort_by(|a, b| xor_distance_cmp(&a.id, &b.id, &target));
        if nodes.len() > limit {
            nodes.truncate(limit);
        }
        nodes
    }

    pub fn oldest_nodes(&self, limit: usize) -> Vec<SocketAddrV6> {
        if limit == 0 {
            return Vec::new();
        }

        let mut nodes = Vec::new();
        for bucket in &self.buckets {
            for node in &bucket.nodes {
                nodes.push(node);
            }
        }

        nodes.sort_by_key(|node| node.last_seen);
        let mut out = Vec::with_capacity(limit.min(nodes.len()));
        for node in nodes.into_iter().take(limit) {
            out.push(node.addr);
        }
        out
    }
}
