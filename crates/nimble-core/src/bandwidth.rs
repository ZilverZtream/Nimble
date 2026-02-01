use std::time::{Duration, Instant};

const TOKEN_RESOLUTION: u64 = 100;

#[derive(Debug, Clone, Copy)]
pub struct BandwidthLimit {
    rate_bytes_per_sec: u64,
    tokens: u64,
    last_update: Instant,
}

impl BandwidthLimit {
    pub fn new(rate_bytes_per_sec: u64) -> Self {
        BandwidthLimit {
            rate_bytes_per_sec,
            tokens: rate_bytes_per_sec.saturating_mul(2),
            last_update: Instant::now(),
        }
    }

    pub fn unlimited() -> Self {
        BandwidthLimit {
            rate_bytes_per_sec: 0,
            tokens: u64::MAX / 2,
            last_update: Instant::now(),
        }
    }

    pub fn is_unlimited(&self) -> bool {
        self.rate_bytes_per_sec == 0
    }

    pub fn update_rate(&mut self, rate_bytes_per_sec: u64) {
        self.rate_bytes_per_sec = rate_bytes_per_sec;
        if rate_bytes_per_sec == 0 {
            self.tokens = u64::MAX / 2;
        }
    }

    fn refill(&mut self) {
        if self.is_unlimited() {
            return;
        }

        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update);
        self.last_update = now;

        let elapsed_ms = elapsed.as_millis() as u64;
        if elapsed_ms == 0 {
            return;
        }

        let tokens_to_add = (self.rate_bytes_per_sec * elapsed_ms) / 1000;
        let bucket_capacity = self.rate_bytes_per_sec.saturating_mul(2);
        self.tokens = self.tokens.saturating_add(tokens_to_add).min(bucket_capacity);
    }

    pub fn request(&mut self, bytes: u64) -> bool {
        if self.is_unlimited() {
            return true;
        }

        self.refill();

        if self.tokens >= bytes {
            self.tokens -= bytes;
            true
        } else {
            false
        }
    }

    pub fn consume(&mut self, bytes: u64) {
        if self.is_unlimited() {
            return;
        }

        self.refill();
        self.tokens = self.tokens.saturating_sub(bytes);
    }

    pub fn wait_time(&mut self, bytes: u64) -> Option<Duration> {
        if self.is_unlimited() {
            return None;
        }

        self.refill();

        if self.tokens >= bytes {
            return None;
        }

        let needed = bytes.saturating_sub(self.tokens);
        let wait_ms = (needed * 1000) / self.rate_bytes_per_sec.max(1);
        Some(Duration::from_millis(wait_ms))
    }

    pub fn available(&mut self) -> u64 {
        if self.is_unlimited() {
            return u64::MAX / 2;
        }

        self.refill();
        self.tokens
    }
}

pub struct BandwidthManager {
    global_download: BandwidthLimit,
    global_upload: BandwidthLimit,
}

impl BandwidthManager {
    pub fn new() -> Self {
        BandwidthManager {
            global_download: BandwidthLimit::unlimited(),
            global_upload: BandwidthLimit::unlimited(),
        }
    }

    pub fn with_limits(download_bytes_per_sec: u64, upload_bytes_per_sec: u64) -> Self {
        BandwidthManager {
            global_download: BandwidthLimit::new(download_bytes_per_sec),
            global_upload: BandwidthLimit::new(upload_bytes_per_sec),
        }
    }

    pub fn set_download_limit(&mut self, bytes_per_sec: u64) {
        self.global_download.update_rate(bytes_per_sec);
    }

    pub fn set_upload_limit(&mut self, bytes_per_sec: u64) {
        self.global_upload.update_rate(bytes_per_sec);
    }

    pub fn request_download(&mut self, bytes: u64) -> bool {
        self.global_download.request(bytes)
    }

    pub fn request_upload(&mut self, bytes: u64) -> bool {
        self.global_upload.request(bytes)
    }

    pub fn consume_download(&mut self, bytes: u64) {
        self.global_download.consume(bytes);
    }

    pub fn consume_upload(&mut self, bytes: u64) {
        self.global_upload.consume(bytes);
    }

    pub fn download_available(&mut self) -> u64 {
        self.global_download.available()
    }

    pub fn upload_available(&mut self) -> u64 {
        self.global_upload.available()
    }
}

impl Default for BandwidthManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_unlimited() {
        let mut limiter = BandwidthLimit::unlimited();
        assert!(limiter.is_unlimited());
        assert!(limiter.request(1000000));
        assert!(limiter.request(1000000));
    }

    #[test]
    fn test_limited() {
        let mut limiter = BandwidthLimit::new(1000);
        assert!(!limiter.is_unlimited());
        assert!(limiter.request(500));
        assert!(limiter.request(500));
    }

    #[test]
    fn test_refill() {
        let mut limiter = BandwidthLimit::new(1000);
        assert!(limiter.request(2000));
        thread::sleep(Duration::from_millis(100));
        limiter.refill();
        assert!(limiter.tokens >= 100);
    }

    #[test]
    fn test_bucket_capacity() {
        let mut limiter = BandwidthLimit::new(1000);
        thread::sleep(Duration::from_millis(5000));
        limiter.refill();
        assert!(limiter.tokens <= 2000);
    }

    #[test]
    fn test_wait_time() {
        let mut limiter = BandwidthLimit::new(1000);
        limiter.consume(2000);
        let wait = limiter.wait_time(100);
        assert!(wait.is_some());
    }

    #[test]
    fn test_manager() {
        let mut manager = BandwidthManager::with_limits(10000, 5000);
        assert!(manager.request_download(5000));
        assert!(manager.request_upload(2500));
    }
}
