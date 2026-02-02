use std::time::{Duration, Instant};

const SCORE_WEIGHT_THROUGHPUT: f64 = 0.5;
const SCORE_WEIGHT_LATENCY: f64 = 0.3;
const SCORE_WEIGHT_RELIABILITY: f64 = 0.2;
const THROUGHPUT_WINDOW: Duration = Duration::from_secs(30);
const LATENCY_WINDOW: usize = 10;
const GOOD_LATENCY_MS: f64 = 100.0;
const FAST_THROUGHPUT_BPS: f64 = 100_000.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportType {
    Tcp,
    Utp,
}

#[derive(Debug, Clone)]
pub struct PeerScore {
    download_bytes: u64,
    upload_bytes: u64,
    download_start: Instant,
    upload_start: Instant,
    recent_latencies: Vec<Duration>,
    requests_sent: u64,
    blocks_received: u64,
    connection_failures: u32,
    choke_count: u32,
    last_score_update: Instant,
    cached_score: f64,
    transport_type: TransportType,
    utp_rtt_us: Option<u32>,
}

impl PeerScore {
    pub fn new() -> Self {
        Self::with_transport(TransportType::Tcp)
    }

    pub fn with_transport(transport: TransportType) -> Self {
        let now = Instant::now();
        PeerScore {
            download_bytes: 0,
            upload_bytes: 0,
            download_start: now,
            upload_start: now,
            recent_latencies: Vec::with_capacity(LATENCY_WINDOW),
            requests_sent: 0,
            blocks_received: 0,
            connection_failures: 0,
            choke_count: 0,
            last_score_update: now,
            cached_score: 0.5,
            transport_type: transport,
            utp_rtt_us: None,
        }
    }

    pub fn transport_type(&self) -> TransportType {
        self.transport_type
    }

    pub fn update_utp_rtt(&mut self, rtt_us: u32) {
        self.utp_rtt_us = Some(rtt_us);
    }

    pub fn record_download(&mut self, bytes: u64) {
        self.download_bytes = self.download_bytes.saturating_add(bytes);
    }

    pub fn record_upload(&mut self, bytes: u64) {
        self.upload_bytes = self.upload_bytes.saturating_add(bytes);
    }

    pub fn record_request(&mut self) {
        self.requests_sent = self.requests_sent.saturating_add(1);
    }

    pub fn record_block_received(&mut self, latency: Duration) {
        self.blocks_received = self.blocks_received.saturating_add(1);

        if self.recent_latencies.len() >= LATENCY_WINDOW {
            self.recent_latencies.remove(0);
        }
        self.recent_latencies.push(latency);
    }

    pub fn record_choke(&mut self) {
        self.choke_count = self.choke_count.saturating_add(1);
    }

    pub fn record_connection_failure(&mut self) {
        self.connection_failures = self.connection_failures.saturating_add(1);
    }

    fn calculate_throughput_score(&self) -> f64 {
        let elapsed = self.download_start.elapsed();
        if elapsed.is_zero() {
            return 0.0;
        }

        let bytes_per_sec = self.download_bytes as f64 / elapsed.as_secs_f64();
        let normalized = (bytes_per_sec / FAST_THROUGHPUT_BPS).min(1.0);
        normalized
    }

    fn calculate_latency_score(&self) -> f64 {
        if self.transport_type == TransportType::Utp {
            if let Some(rtt_us) = self.utp_rtt_us {
                let rtt_ms = rtt_us as f64 / 1000.0;
                return (GOOD_LATENCY_MS / rtt_ms.max(1.0)).min(1.0);
            }
        }

        if self.recent_latencies.is_empty() {
            return 0.5;
        }

        let sum: Duration = self.recent_latencies.iter().sum();
        let avg_ms = (sum.as_millis() as f64) / (self.recent_latencies.len() as f64);

        let normalized = (GOOD_LATENCY_MS / avg_ms.max(1.0)).min(1.0);
        normalized
    }

    fn calculate_reliability_score(&self) -> f64 {
        let delivery_rate = if self.requests_sent == 0 {
            1.0
        } else {
            (self.blocks_received as f64) / (self.requests_sent as f64)
        };

        let failure_penalty = (self.connection_failures as f64 * 0.1).min(0.5);
        let choke_penalty = (self.choke_count as f64 * 0.05).min(0.3);

        (delivery_rate - failure_penalty - choke_penalty).max(0.0).min(1.0)
    }

    pub fn calculate_score(&mut self) -> f64 {
        let now = Instant::now();
        if now.duration_since(self.last_score_update) < Duration::from_secs(5) {
            return self.cached_score;
        }

        let throughput_score = self.calculate_throughput_score();
        let latency_score = self.calculate_latency_score();
        let reliability_score = self.calculate_reliability_score();

        let score = (throughput_score * SCORE_WEIGHT_THROUGHPUT)
            + (latency_score * SCORE_WEIGHT_LATENCY)
            + (reliability_score * SCORE_WEIGHT_RELIABILITY);

        self.cached_score = score;
        self.last_score_update = now;
        score
    }

    pub fn get_cached_score(&self) -> f64 {
        self.cached_score
    }

    pub fn download_rate(&self) -> u64 {
        let elapsed = self.download_start.elapsed().as_secs().max(1);
        self.download_bytes / elapsed
    }

    pub fn upload_rate(&self) -> u64 {
        let elapsed = self.upload_start.elapsed().as_secs().max(1);
        self.upload_bytes / elapsed
    }

    pub fn avg_latency(&self) -> Option<Duration> {
        if self.recent_latencies.is_empty() {
            return None;
        }

        let sum: Duration = self.recent_latencies.iter().sum();
        Some(sum / self.recent_latencies.len() as u32)
    }

    pub fn is_slow(&mut self) -> bool {
        self.calculate_score() < 0.3
    }

    pub fn is_fast(&mut self) -> bool {
        self.calculate_score() > 0.7
    }
}

impl Default for PeerScore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn test_new_score() {
        let score = PeerScore::new();
        assert_eq!(score.download_bytes, 0);
        assert_eq!(score.upload_bytes, 0);
        assert_eq!(score.blocks_received, 0);
    }

    #[test]
    fn test_record_download() {
        let mut score = PeerScore::new();
        score.record_download(1000);
        assert_eq!(score.download_bytes, 1000);
    }

    #[test]
    fn test_latency_tracking() {
        let mut score = PeerScore::new();
        score.record_request();
        score.record_block_received(Duration::from_millis(50));
        score.record_block_received(Duration::from_millis(100));

        let avg = score.avg_latency().unwrap();
        assert!(avg.as_millis() >= 70 && avg.as_millis() <= 80);
    }

    #[test]
    fn test_reliability_score() {
        let mut score = PeerScore::new();
        for _ in 0..10 {
            score.record_request();
        }
        for _ in 0..8 {
            score.record_block_received(Duration::from_millis(100));
        }

        let reliability = score.calculate_reliability_score();
        assert!(reliability >= 0.7);
    }

    #[test]
    fn test_throughput_score() {
        let mut score = PeerScore::new();
        thread::sleep(Duration::from_millis(100));
        score.record_download(100_000);

        let throughput = score.calculate_throughput_score();
        assert!(throughput > 0.0);
    }

    #[test]
    fn test_penalties() {
        let mut score = PeerScore::new();
        score.record_connection_failure();
        score.record_choke();

        let reliability = score.calculate_reliability_score();
        assert!(reliability < 1.0);
    }

    #[test]
    fn test_score_caching() {
        let mut score = PeerScore::new();
        let first = score.calculate_score();
        let second = score.get_cached_score();
        assert!((first - second).abs() < 0.001);
    }

    #[test]
    fn test_utp_transport_type() {
        let score = PeerScore::with_transport(TransportType::Utp);
        assert_eq!(score.transport_type(), TransportType::Utp);
    }

    #[test]
    fn test_utp_rtt_latency() {
        let mut score = PeerScore::with_transport(TransportType::Utp);
        score.update_utp_rtt(50_000);
        let latency = score.calculate_latency_score();
        assert!(latency > 0.9);
    }

    #[test]
    fn test_utp_high_rtt() {
        let mut score = PeerScore::with_transport(TransportType::Utp);
        score.update_utp_rtt(500_000);
        let latency = score.calculate_latency_score();
        assert!(latency < 0.3);
    }
}
