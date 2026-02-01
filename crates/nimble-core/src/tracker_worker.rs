use nimble_net::tracker_http::{announce, AnnounceRequest as HttpAnnounceRequest, TrackerEvent};
use std::net::SocketAddrV4;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

const WORKER_THREAD_COUNT: usize = 4;

pub struct AnnounceWorker {
    task_tx: Sender<AnnounceTask>,
    result_rx: Receiver<AnnounceResult>,
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
        let (task_tx, task_rx) = channel::<AnnounceTask>();
        let (result_tx, result_rx) = channel::<AnnounceResult>();

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

                    let result = match announce(&task.url, &request) {
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
            _workers: workers,
        }
    }

    pub fn submit_announce(&self, task: AnnounceTask) {
        let _ = self.task_tx.send(task);
    }

    pub fn try_recv_result(&self) -> Option<AnnounceResult> {
        self.result_rx.try_recv().ok()
    }
}
