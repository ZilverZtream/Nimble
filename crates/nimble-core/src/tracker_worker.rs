use anyhow::Result;
use nimble_net::tracker_http::{announce, AnnounceRequest as HttpAnnounceRequest, TrackerEvent};
use std::net::SocketAddrV4;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

pub struct AnnounceWorker {
    result_rx: Receiver<AnnounceResult>,
    result_tx: Sender<AnnounceResult>,
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
        let (result_tx, result_rx) = channel();
        AnnounceWorker {
            result_rx,
            result_tx,
        }
    }

    pub fn submit_announce(&self, task: AnnounceTask) {
        let result_tx = self.result_tx.clone();
        thread::spawn(move || {
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

            let _ = result_tx.send(result);
        });
    }

    pub fn try_recv_result(&self) -> Option<AnnounceResult> {
        self.result_rx.try_recv().ok()
    }
}
