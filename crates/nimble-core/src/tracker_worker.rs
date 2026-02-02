use anyhow::Result;
use nimble_net::tracker_http::{announce, announce_async, AnnounceRequest as HttpAnnounceRequest, HttpAnnounceEvent, TrackerEvent};
use nimble_net::tracker_udp::{UdpTracker, UdpAnnounceRequest, UdpTrackerEvent, parse_udp_tracker_url};
use std::net::SocketAddr;
use std::sync::mpsc::{channel, sync_channel, Receiver, Sender, SyncSender};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

const WORKER_THREAD_COUNT: usize = 4;
const ANNOUNCE_QUEUE_DEPTH: usize = 256;
const HTTP_PENDING_TIMEOUT: Duration = Duration::from_secs(90);

pub struct AnnounceWorker {
    task_tx: SyncSender<AnnounceTask>,
    result_rx: Receiver<AnnounceResult>,
    http_result_rx: Receiver<HttpAnnounceEvent>,
    http_result_tx: Sender<HttpAnnounceEvent>,
    pending_http: HashMap<u64, PendingHttp>,
    pending_results: VecDeque<AnnounceResult>,
    request_id: AtomicU64,
    _workers: Vec<JoinHandle<()>>,
}

struct PendingHttp {
    task: AnnounceTask,
    submitted_at: Instant,
}

#[derive(Debug, Clone)]
pub struct AnnounceTask {
    pub infohash_hex: String,
    pub url: String,
    pub info_hash: [u8; 20],
    pub peer_id: [u8; 20],
    pub port: u16,
    pub uploaded: u64,
    pub downloaded: u64,
    pub left: u64,
    pub event: TrackerEvent,
}

#[derive(Debug)]
pub struct AnnounceResult {
    pub infohash_hex: String,
    pub success: bool,
    pub peers: Vec<SocketAddr>,
    pub interval: Option<u32>,
    pub error: Option<String>,
}

impl AnnounceWorker {
    pub fn new() -> Self {
        let (task_tx, task_rx) = sync_channel::<AnnounceTask>(ANNOUNCE_QUEUE_DEPTH);
        let (result_tx, result_rx) = channel::<AnnounceResult>();
        let (http_result_tx, http_result_rx) = channel::<HttpAnnounceEvent>();

        let task_rx = Arc::new(Mutex::new(task_rx));
        let mut workers = Vec::with_capacity(WORKER_THREAD_COUNT);

        for _ in 0..WORKER_THREAD_COUNT {
            let task_rx = Arc::clone(&task_rx);
            let result_tx = result_tx.clone();

            let handle = thread::spawn(move || {
                loop {
                    let task = {
                        let rx = match task_rx.lock() {
                            Ok(rx) => rx,
                            Err(_) => break,
                        };
                        match rx.recv() {
                            Ok(task) => task,
                            Err(_) => break,
                        }
                    };

                    let result = if task.url.starts_with("udp://") {
                        Self::announce_udp(&task)
                    } else {
                        Self::announce_http(&task)
                    };

                    if result_tx.send(result).is_err() {
                        break;
                    }
                }
            });

            workers.push(handle);
        }

        AnnounceWorker {
            task_tx,
            result_rx,
            http_result_rx,
            http_result_tx,
            pending_http: HashMap::new(),
            pending_results: VecDeque::new(),
            request_id: AtomicU64::new(1),
            _workers: workers,
        }
    }

    pub fn submit_announce(&mut self, task: AnnounceTask) {
        if task.url.starts_with("udp://") {
            let _ = self.task_tx.try_send(task);
            return;
        }

        let request_id = self.request_id.fetch_add(1, Ordering::Relaxed);
        let request = HttpAnnounceRequest {
            info_hash: &task.info_hash,
            peer_id: &task.peer_id,
            port: task.port,
            uploaded: task.uploaded,
            downloaded: task.downloaded,
            left: task.left,
            compact: true,
            event: task.event,
        };

        match announce_async(&task.url, &request, request_id, self.http_result_tx.clone()) {
            Ok(()) => {
                self.pending_http.insert(
                    request_id,
                    PendingHttp {
                        task,
                        submitted_at: Instant::now(),
                    },
                );
            }
            Err(e) => {
                self.pending_results.push_back(AnnounceResult {
                    infohash_hex: task.infohash_hex,
                    success: false,
                    peers: Vec::new(),
                    interval: None,
                    error: Some(e.to_string()),
                });
            }
        }
    }

    pub fn try_recv_result(&mut self) -> Option<AnnounceResult> {
        self.expire_pending_http();

        if let Some(result) = self.pending_results.pop_front() {
            return Some(result);
        }

        if let Ok(result) = self.result_rx.try_recv() {
            return Some(result);
        }

        if let Ok(event) = self.http_result_rx.try_recv() {
            return self.handle_http_event(event);
        }

        None
    }

    fn announce_udp(task: &AnnounceTask) -> AnnounceResult {
        let addr = match parse_udp_tracker_url(&task.url) {
            Ok(addr) => addr,
            Err(e) => {
                return AnnounceResult {
                    infohash_hex: task.infohash_hex.clone(),
                    success: false,
                    peers: Vec::new(),
                    interval: None,
                    error: Some(format!("Failed to parse UDP tracker URL: {}", e)),
                };
            }
        };

        let mut tracker = match UdpTracker::new(addr) {
            Ok(t) => t,
            Err(e) => {
                return AnnounceResult {
                    infohash_hex: task.infohash_hex.clone(),
                    success: false,
                    peers: Vec::new(),
                    interval: None,
                    error: Some(format!("Failed to create UDP tracker: {}", e)),
                };
            }
        };

        let event = match task.event {
            TrackerEvent::Started => UdpTrackerEvent::Started,
            TrackerEvent::Stopped => UdpTrackerEvent::Stopped,
            TrackerEvent::Completed => UdpTrackerEvent::Completed,
            TrackerEvent::None => UdpTrackerEvent::None,
        };

        let request = UdpAnnounceRequest {
            info_hash: &task.info_hash,
            peer_id: &task.peer_id,
            downloaded: task.downloaded,
            left: task.left,
            uploaded: task.uploaded,
            event,
            ip: 0,
            key: 0,
            num_want: -1,
            port: task.port,
        };

        match tracker.announce(&request) {
            Ok(response) => AnnounceResult {
                infohash_hex: task.infohash_hex.clone(),
                success: true,
                peers: response.peers,
                interval: Some(response.interval),
                error: None,
            },
            Err(e) => AnnounceResult {
                infohash_hex: task.infohash_hex.clone(),
                success: false,
                peers: Vec::new(),
                interval: None,
                error: Some(e.to_string()),
            },
        }
    }

    fn handle_http_event(&mut self, event: HttpAnnounceEvent) -> Option<AnnounceResult> {
        match event {
            HttpAnnounceEvent::Completed { request_id, result } => {
                let pending = self.pending_http.remove(&request_id)?;
                Some(Self::http_result_from_task(pending.task, result))
            }
        }
    }

    fn expire_pending_http(&mut self) {
        let now = Instant::now();
        let mut expired = Vec::new();

        for (request_id, pending) in self.pending_http.iter() {
            if now.duration_since(pending.submitted_at) >= HTTP_PENDING_TIMEOUT {
                expired.push(*request_id);
            }
        }

        for request_id in expired {
            if let Some(pending) = self.pending_http.remove(&request_id) {
                self.pending_results.push_back(AnnounceResult {
                    infohash_hex: pending.task.infohash_hex,
                    success: false,
                    peers: Vec::new(),
                    interval: None,
                    error: Some("HTTP tracker announce timed out".to_string()),
                });
            }
        }
    }

    fn announce_http(task: &AnnounceTask) -> AnnounceResult {
        let request = HttpAnnounceRequest {
            info_hash: &task.info_hash,
            peer_id: &task.peer_id,
            port: task.port,
            uploaded: task.uploaded,
            downloaded: task.downloaded,
            left: task.left,
            compact: true,
            event: task.event,
        };

        let result = announce(&task.url, &request);
        Self::http_result_from_task(task.clone(), result)
    }

    fn http_result_from_task(task: AnnounceTask, result: Result<nimble_net::tracker_http::AnnounceResponse>) -> AnnounceResult {
        match result {
            Ok(response) => {
                if let Some(failure) = response.failure_reason {
                    AnnounceResult {
                        infohash_hex: task.infohash_hex,
                        success: false,
                        peers: Vec::new(),
                        interval: None,
                        error: Some(format!("Tracker failure: {}", failure)),
                    }
                } else {
                    let mut peers: Vec<SocketAddr> = Vec::new();
                    peers.extend(response.peers.into_iter().map(SocketAddr::V4));
                    peers.extend(response.peers6.into_iter().map(SocketAddr::V6));

                    AnnounceResult {
                        infohash_hex: task.infohash_hex,
                        success: true,
                        peers,
                        interval: Some(response.interval),
                        error: None,
                    }
                }
            }
            Err(e) => AnnounceResult {
                infohash_hex: task.infohash_hex,
                success: false,
                peers: Vec::new(),
                interval: None,
                error: Some(e.to_string()),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_http_times_out_without_callback() {
        let mut worker = AnnounceWorker::new();
        let task = AnnounceTask {
            infohash_hex: "deadbeef".to_string(),
            url: "http://tracker.invalid/announce".to_string(),
            info_hash: [0; 20],
            peer_id: [1; 20],
            port: 6881,
            uploaded: 0,
            downloaded: 0,
            left: 0,
            event: TrackerEvent::Started,
        };

        worker.pending_http.insert(
            42,
            PendingHttp {
                task,
                submitted_at: Instant::now() - HTTP_PENDING_TIMEOUT - Duration::from_secs(1),
            },
        );

        let result = worker.try_recv_result().expect("expected timeout result");
        assert!(!result.success);
        assert_eq!(
            result.error.as_deref(),
            Some("HTTP tracker announce timed out")
        );
        assert!(worker.pending_http.is_empty());
    }
}
