use std::net::{Ipv4Addr, SocketAddrV4};

const DEFAULT_BOOTSTRAP_NODES: [SocketAddrV4; 3] = [
    SocketAddrV4::new(Ipv4Addr::new(67, 215, 246, 10), 6881),
    SocketAddrV4::new(Ipv4Addr::new(87, 98, 162, 88), 6881),
    SocketAddrV4::new(Ipv4Addr::new(82, 221, 103, 244), 6881),
];

pub fn default_bootstrap_nodes() -> &'static [SocketAddrV4] {
    &DEFAULT_BOOTSTRAP_NODES
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_bootstrap_nodes_have_mainline_port() {
        for node in default_bootstrap_nodes() {
            assert_eq!(node.port(), 6881);
        }
    }

    #[test]
    fn default_bootstrap_nodes_are_unique() {
        let nodes = default_bootstrap_nodes();
        for (idx, node) in nodes.iter().enumerate() {
            assert!(
                !nodes[..idx].iter().any(|other| other == node),
                "duplicate bootstrap node {node:?}"
            );
        }
    }
}
