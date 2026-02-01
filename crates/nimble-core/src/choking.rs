use std::net::SocketAddrV4;
use std::time::{Duration, Instant};

const RECHOKE_INTERVAL: Duration = Duration::from_secs(10);
const OPTIMISTIC_UNCHOKE_INTERVAL: Duration = Duration::from_secs(30);
const REGULAR_UNCHOKE_SLOTS: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChokeReason {
    Regular,
    SlowPeer,
    TooManyConnections,
}

pub struct ChokingManager {
    last_rechoke: Instant,
    last_optimistic: Instant,
    unchoked_peers: Vec<SocketAddrV4>,
    optimistic_peer: Option<SocketAddrV4>,
    is_seeding: bool,
}

impl ChokingManager {
    pub fn new() -> Self {
        ChokingManager {
            last_rechoke: Instant::now(),
            last_optimistic: Instant::now(),
            unchoked_peers: Vec::new(),
            optimistic_peer: None,
            is_seeding: false,
        }
    }

    pub fn set_seeding(&mut self, seeding: bool) {
        self.is_seeding = seeding;
    }

    pub fn should_rechoke(&self) -> bool {
        self.last_rechoke.elapsed() >= RECHOKE_INTERVAL
    }

    pub fn should_optimistic_unchoke(&self) -> bool {
        self.last_optimistic.elapsed() >= OPTIMISTIC_UNCHOKE_INTERVAL
    }

    pub fn is_unchoked(&self, addr: &SocketAddrV4) -> bool {
        self.unchoked_peers.contains(addr) || self.optimistic_peer.as_ref() == Some(addr)
    }

    pub fn is_optimistic(&self, addr: &SocketAddrV4) -> bool {
        self.optimistic_peer.as_ref() == Some(addr)
    }

    pub fn rechoke<F>(&mut self, mut peers: Vec<SocketAddrV4>, score_fn: F) -> Vec<(SocketAddrV4, bool)>
    where
        F: Fn(&SocketAddrV4) -> f64,
    {
        self.last_rechoke = Instant::now();

        if peers.is_empty() {
            self.unchoked_peers.clear();
            return Vec::new();
        }

        peers.sort_by(|a, b| {
            let score_a = score_fn(a);
            let score_b = score_fn(b);
            score_b.partial_cmp(&score_a).unwrap_or(std::cmp::Ordering::Equal)
        });

        let old_unchoked = std::mem::replace(&mut self.unchoked_peers, Vec::new());

        let to_unchoke = REGULAR_UNCHOKE_SLOTS.min(peers.len());
        for peer in peers.iter().take(to_unchoke) {
            self.unchoked_peers.push(*peer);
        }

        let mut changes = Vec::new();

        for peer in &self.unchoked_peers {
            if !old_unchoked.contains(peer) && self.optimistic_peer.as_ref() != Some(peer) {
                changes.push((*peer, false));
            }
        }

        for peer in &old_unchoked {
            if !self.unchoked_peers.contains(peer) && self.optimistic_peer.as_ref() != Some(peer) {
                changes.push((*peer, true));
            }
        }

        changes
    }

    pub fn optimistic_unchoke(&mut self, candidates: &[SocketAddrV4]) -> Option<(SocketAddrV4, Option<SocketAddrV4>)> {
        self.last_optimistic = Instant::now();

        if candidates.is_empty() {
            return None;
        }

        let choked_candidates: Vec<_> = candidates
            .iter()
            .filter(|addr| !self.unchoked_peers.contains(addr))
            .copied()
            .collect();

        if choked_candidates.is_empty() {
            return None;
        }

        let new_optimistic = {
            use std::time::{SystemTime, UNIX_EPOCH};
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let index = (nanos as usize) % choked_candidates.len();
            choked_candidates[index]
        };

        let old_optimistic = self.optimistic_peer.replace(new_optimistic);

        Some((new_optimistic, old_optimistic))
    }

    pub fn remove_peer(&mut self, addr: &SocketAddrV4) {
        self.unchoked_peers.retain(|a| a != addr);
        if self.optimistic_peer.as_ref() == Some(addr) {
            self.optimistic_peer = None;
        }
    }

    pub fn unchoked_count(&self) -> usize {
        let optimistic_count = if self.optimistic_peer.is_some() { 1 } else { 0 };
        self.unchoked_peers.len() + optimistic_count
    }

    pub fn get_unchoked_peers(&self) -> Vec<SocketAddrV4> {
        let mut result = self.unchoked_peers.clone();
        if let Some(opt) = self.optimistic_peer {
            if !result.contains(&opt) {
                result.push(opt);
            }
        }
        result
    }
}

impl Default for ChokingManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_addr(port: u16) -> SocketAddrV4 {
        SocketAddrV4::new([127, 0, 0, 1].into(), port)
    }

    #[test]
    fn test_new_manager() {
        let manager = ChokingManager::new();
        assert_eq!(manager.unchoked_count(), 0);
        assert!(!manager.is_seeding);
    }

    #[test]
    fn test_rechoke_simple() {
        let mut manager = ChokingManager::new();
        let peers = vec![
            make_addr(1000),
            make_addr(1001),
            make_addr(1002),
            make_addr(1003),
            make_addr(1004),
            make_addr(1005),
        ];

        let score_fn = |addr: &SocketAddrV4| addr.port() as f64;

        let changes = manager.rechoke(peers.clone(), score_fn);

        assert_eq!(manager.unchoked_peers.len(), 4);
        assert!(manager.is_unchoked(&make_addr(1005)));
        assert!(manager.is_unchoked(&make_addr(1004)));
        assert!(!manager.is_unchoked(&make_addr(1000)));
    }

    #[test]
    fn test_optimistic_unchoke() {
        let mut manager = ChokingManager::new();
        let peers = vec![make_addr(1000), make_addr(1001), make_addr(1002)];

        manager.unchoked_peers.push(make_addr(1000));

        let result = manager.optimistic_unchoke(&peers);
        assert!(result.is_some());

        let (new_opt, _) = result.unwrap();
        assert!(new_opt == make_addr(1001) || new_opt == make_addr(1002));
        assert!(manager.is_unchoked(&new_opt));
        assert!(manager.is_optimistic(&new_opt));
    }

    #[test]
    fn test_remove_peer() {
        let mut manager = ChokingManager::new();
        manager.unchoked_peers.push(make_addr(1000));
        manager.unchoked_peers.push(make_addr(1001));
        manager.optimistic_peer = Some(make_addr(1002));

        manager.remove_peer(&make_addr(1000));
        assert!(!manager.is_unchoked(&make_addr(1000)));
        assert_eq!(manager.unchoked_peers.len(), 1);

        manager.remove_peer(&make_addr(1002));
        assert!(manager.optimistic_peer.is_none());
    }

    #[test]
    fn test_rechoke_intervals() {
        let manager = ChokingManager::new();
        assert!(!manager.should_rechoke());
        assert!(!manager.should_optimistic_unchoke());
    }

    #[test]
    fn test_get_unchoked_peers() {
        let mut manager = ChokingManager::new();
        manager.unchoked_peers.push(make_addr(1000));
        manager.unchoked_peers.push(make_addr(1001));
        manager.optimistic_peer = Some(make_addr(1002));

        let unchoked = manager.get_unchoked_peers();
        assert_eq!(unchoked.len(), 3);
        assert!(unchoked.contains(&make_addr(1000)));
        assert!(unchoked.contains(&make_addr(1001)));
        assert!(unchoked.contains(&make_addr(1002)));
    }

    #[test]
    fn test_optimistic_not_in_regular() {
        let mut manager = ChokingManager::new();
        manager.unchoked_peers.push(make_addr(1000));
        manager.optimistic_peer = Some(make_addr(1000));

        let unchoked = manager.get_unchoked_peers();
        assert_eq!(unchoked.len(), 1);
    }
}
