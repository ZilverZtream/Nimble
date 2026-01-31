use nimble_util::ids::dht_node_id_20;
use std::net::SocketAddrV4;

use crate::routing::RoutingTable;

pub struct DhtNode {
    node_id: [u8; 20],
    logged_startup: bool,
    routing: RoutingTable,
}

impl DhtNode {
    pub fn new() -> Self {
        let node_id = dht_node_id_20();
        let routing = RoutingTable::new(node_id);
        Self {
            node_id,
            logged_startup: false,
            routing,
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

    pub fn observe_node(&mut self, id: [u8; 20], addr: SocketAddrV4) -> bool {
        self.routing.insert(id, addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
