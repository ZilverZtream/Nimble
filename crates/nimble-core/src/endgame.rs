use std::collections::{HashMap, HashSet};
use std::net::{SocketAddr, SocketAddrV4};

const ENDGAME_THRESHOLD_PIECES: usize = 5;
const MAX_DUPLICATE_REQUESTS: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlockId {
    pub piece: u32,
    pub offset: u32,
}

impl BlockId {
    pub fn new(piece: u32, offset: u32) -> Self {
        BlockId { piece, offset }
    }
}

pub struct EndgameMode {
    active: bool,
    pending_blocks: HashMap<BlockId, HashSet<SocketAddr>>,
    completed_blocks: HashSet<BlockId>,
}

impl EndgameMode {
    pub fn new() -> Self {
        EndgameMode {
            active: false,
            pending_blocks: HashMap::new(),
            completed_blocks: HashSet::new(),
        }
    }

    pub fn update_state(&mut self, pieces_remaining: usize, blocks_remaining: usize) {
        let should_activate = pieces_remaining <= ENDGAME_THRESHOLD_PIECES && blocks_remaining > 0;

        if should_activate && !self.active {
            self.active = true;
        } else if !should_activate && self.active {
            self.deactivate();
        }
    }

    pub fn is_active(&self) -> bool {
        self.active
    }

    fn deactivate(&mut self) {
        self.active = false;
        self.pending_blocks.clear();
        self.completed_blocks.clear();
    }

    pub fn record_request(&mut self, block: BlockId, peer: SocketAddr) -> bool {
        if !self.active {
            return true;
        }

        if self.completed_blocks.contains(&block) {
            return false;
        }

        let peers = self.pending_blocks.entry(block).or_insert_with(HashSet::new);

        if peers.len() >= MAX_DUPLICATE_REQUESTS {
            return false;
        }

        peers.insert(peer);
        true
    }

    pub fn record_completion(&mut self, block: BlockId) -> Vec<(SocketAddr, BlockId)> {
        if !self.active {
            return Vec::new();
        }

        self.completed_blocks.insert(block);

        let peers = match self.pending_blocks.remove(&block) {
            Some(p) => p,
            None => return Vec::new(),
        };

        let mut cancellations = Vec::new();
        for peer in peers {
            cancellations.push((peer, block));
        }

        cancellations
    }

    pub fn remove_peer(&mut self, peer: &SocketAddr) {
        for peers in self.pending_blocks.values_mut() {
            peers.remove(peer);
        }

        self.pending_blocks.retain(|_, peers| !peers.is_empty());
    }

    pub fn can_request_block(&self, block: BlockId) -> bool {
        if !self.active {
            return true;
        }

        if self.completed_blocks.contains(&block) {
            return false;
        }

        let request_count = self.pending_blocks.get(&block).map(|p| p.len()).unwrap_or(0);

        request_count < MAX_DUPLICATE_REQUESTS
    }

    pub fn get_pending_count(&self, block: BlockId) -> usize {
        self.pending_blocks.get(&block).map(|p| p.len()).unwrap_or(0)
    }

    pub fn pending_blocks_count(&self) -> usize {
        self.pending_blocks.len()
    }

    pub fn reset(&mut self) {
        self.deactivate();
    }
}

impl Default for EndgameMode {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_addr(port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new([127, 0, 0, 1].into(), port))
    }

    #[test]
    fn test_activation() {
        let mut endgame = EndgameMode::new();
        assert!(!endgame.is_active());

        endgame.update_state(3, 10);
        assert!(endgame.is_active());

        endgame.update_state(10, 100);
        assert!(!endgame.is_active());
    }

    #[test]
    fn test_duplicate_requests() {
        let mut endgame = EndgameMode::new();
        endgame.active = true;

        let block = BlockId::new(0, 0);
        let peer1 = make_addr(1000);
        let peer2 = make_addr(1001);
        let peer3 = make_addr(1002);
        let peer4 = make_addr(1003);

        assert!(endgame.record_request(block, peer1));
        assert!(endgame.record_request(block, peer2));
        assert!(endgame.record_request(block, peer3));

        assert!(!endgame.record_request(block, peer4));

        assert_eq!(endgame.get_pending_count(block), 3);
    }

    #[test]
    fn test_completion_cancellation() {
        let mut endgame = EndgameMode::new();
        endgame.active = true;

        let block = BlockId::new(0, 0);
        let peer1 = make_addr(1000);
        let peer2 = make_addr(1001);

        endgame.record_request(block, peer1);
        endgame.record_request(block, peer2);

        let cancellations = endgame.record_completion(block);

        assert_eq!(cancellations.len(), 2);
        assert!(cancellations.iter().any(|(p, _)| p == &peer1));
        assert!(cancellations.iter().any(|(p, _)| p == &peer2));
        assert!(!endgame.can_request_block(block));
    }

    #[test]
    fn test_remove_peer() {
        let mut endgame = EndgameMode::new();
        endgame.active = true;

        let block1 = BlockId::new(0, 0);
        let block2 = BlockId::new(0, 16384);
        let peer1 = make_addr(1000);
        let peer2 = make_addr(1001);

        endgame.record_request(block1, peer1);
        endgame.record_request(block1, peer2);
        endgame.record_request(block2, peer1);

        endgame.remove_peer(&peer1);

        assert_eq!(endgame.get_pending_count(block1), 1);
        assert_eq!(endgame.get_pending_count(block2), 0);
    }

    #[test]
    fn test_can_request_block() {
        let mut endgame = EndgameMode::new();
        endgame.active = true;

        let block = BlockId::new(0, 0);
        let peer1 = make_addr(1000);
        let peer2 = make_addr(1001);
        let peer3 = make_addr(1002);

        assert!(endgame.can_request_block(block));

        endgame.record_request(block, peer1);
        endgame.record_request(block, peer2);
        endgame.record_request(block, peer3);

        assert!(!endgame.can_request_block(block));

        endgame.record_completion(block);
        assert!(!endgame.can_request_block(block));
    }

    #[test]
    fn test_deactivation_clears_state() {
        let mut endgame = EndgameMode::new();
        endgame.active = true;

        let block = BlockId::new(0, 0);
        let peer = make_addr(1000);
        endgame.record_request(block, peer);

        endgame.update_state(10, 100);

        assert!(!endgame.is_active());
        assert_eq!(endgame.pending_blocks_count(), 0);
    }

    #[test]
    fn test_completed_blocks_tracking() {
        let mut endgame = EndgameMode::new();
        endgame.active = true;

        let block = BlockId::new(0, 0);
        let peer = make_addr(1000);

        endgame.record_request(block, peer);
        endgame.record_completion(block);

        assert!(!endgame.record_request(block, make_addr(1001)));
        assert!(!endgame.can_request_block(block));
    }
}
