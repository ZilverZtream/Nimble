use nimble_util::ids::dht_node_id_20;

pub struct DhtNode {
    node_id: [u8; 20],
    logged_startup: bool,
    known_nodes: u32,
}

impl DhtNode {
    pub fn new() -> Self {
        Self {
            node_id: dht_node_id_20(),
            logged_startup: false,
            known_nodes: 1,
        }
    }

    pub fn node_id(&self) -> &[u8; 20] {
        &self.node_id
    }

    pub fn known_nodes(&self) -> u32 {
        self.known_nodes
    }

    pub fn tick(&mut self) -> Option<String> {
        if self.logged_startup {
            return None;
        }

        self.logged_startup = true;
        Some("DHT node initialized".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_id_generated() {
        let node = DhtNode::new();
        assert!(node.node_id().iter().any(|byte| *byte != 0));
    }
}
