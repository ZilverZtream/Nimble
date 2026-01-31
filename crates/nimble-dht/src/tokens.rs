use nimble_util::ids::generate_random_bytes;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

const SECRET_LEN: usize = 8;
const TOKEN_LEN: usize = SECRET_LEN + 4;
const DEFAULT_ROTATE_INTERVAL: Duration = Duration::from_secs(300);

pub struct TokenIssuer {
    secret: [u8; SECRET_LEN],
    previous_secret: [u8; SECRET_LEN],
    last_rotate: Instant,
    rotate_interval: Duration,
}

impl TokenIssuer {
    pub fn new() -> Self {
        let secret = generate_random_bytes::<SECRET_LEN>();
        Self {
            secret,
            previous_secret: secret,
            last_rotate: Instant::now(),
            rotate_interval: DEFAULT_ROTATE_INTERVAL,
        }
    }

    pub fn token_for(&mut self, ip: Ipv4Addr) -> Vec<u8> {
        self.maybe_rotate();
        let mut token = Vec::with_capacity(TOKEN_LEN);
        token.extend_from_slice(&self.secret);
        token.extend_from_slice(&ip.octets());
        token
    }

    pub fn validate(&mut self, ip: Ipv4Addr, token: &[u8]) -> bool {
        if token.len() != TOKEN_LEN {
            return false;
        }
        self.maybe_rotate();
        let (secret, addr_bytes) = token.split_at(SECRET_LEN);
        addr_bytes == ip.octets()
            && (secret == self.secret || secret == self.previous_secret)
    }

    fn maybe_rotate(&mut self) {
        if self.last_rotate.elapsed() < self.rotate_interval {
            return;
        }
        self.previous_secret = self.secret;
        self.secret = generate_random_bytes::<SECRET_LEN>();
        self.last_rotate = Instant::now();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn token_validates_for_matching_ip() {
        let mut issuer = TokenIssuer::new();
        let ip = Ipv4Addr::new(10, 0, 0, 1);
        let token = issuer.token_for(ip);
        assert!(issuer.validate(ip, &token));
    }

    #[test]
    fn token_rejects_wrong_ip() {
        let mut issuer = TokenIssuer::new();
        let token = issuer.token_for(Ipv4Addr::new(192, 168, 1, 10));
        assert!(!issuer.validate(Ipv4Addr::new(10, 0, 0, 2), &token));
    }
}
