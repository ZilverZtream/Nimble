use anyhow::Result;
use nimble_net::tracker_http::{announce, announce_async, AnnounceRequest as HttpAnnounceRequest, HttpAnnounceEvent, TrackerEvent};
use nimble_net::tracker_udp::{UdpTracker, UdpAnnounceRequest, UdpTrackerEvent};
use std::net::{SocketAddrV4, ToSocketAddrs};
use std::sync::mpsc::{channel, sync_channel, Receiver, Sender, SyncSender};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::collections::{HashMap, VecDeque};

const WORKER_THREAD_COUNT: usize = 4;
const ANNOUNCE_QUEUE_DEPTH: usize = 256;

pub struct AnnounceWorker {
    task_tx: SyncSender<AnnounceTask>,
    result_rx: Receiver<AnnounceResult>,
    http_result_rx: Receiver<HttpAnnounceEvent>,
    http_result_tx: Sender<HttpAnnounceEvent>,
    pending_http: HashMap<u64, AnnounceTask>,
    pending_results: VecDeque<AnnounceResult>,
    request_id: AtomicU64,
    _workers: Vec<JoinHandle<()>>,
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
    pub peers: Vec<SocketAddrV4>,
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
                self.pending_http.insert(request_id, task);
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
        let addr = match Self::parse_udp_url(&task.url) {
            Some(addr) => addr,
            None => {
                return AnnounceResult {
                    infohash_hex: task.infohash_hex.clone(),
                    success: false,
                    peers: Vec::new(),
                    interval: None,
                    error: Some("Failed to parse UDP tracker URL".to_string()),
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

    fn parse_udp_url(url: &str) -> Option<SocketAddrV4> {
        if !url.starts_with("udp://") {
            return None;
        }

        let without_scheme = &url[6..];
        let host_port = without_scheme.split('/').next()?;

        host_port.to_socket_addrs().ok()?.find_map(|addr| {
            if let std::net::SocketAddr::V4(v4) = addr {
                Some(v4)
            } else {
                None
            }
        })
    }

    fn handle_http_event(&mut self, event: HttpAnnounceEvent) -> Option<AnnounceResult> {
        match event {
            HttpAnnounceEvent::Completed { request_id, result } => {
                let task = self.pending_http.remove(&request_id)?;
                Some(Self::http_result_from_task(task, result))
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
                    AnnounceResult {
                        infohash_hex: task.infohash_hex,
                        success: true,
                        peers: response.peers,
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
