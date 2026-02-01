use sha1::{Digest, Sha1};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError};
use std::thread::{self, JoinHandle};

const WORKER_THREADS: usize = 2;
const VERIFY_QUEUE_DEPTH: usize = 128;

pub struct VerifyRequest {
    pub piece_index: u64,
    pub data: Vec<u8>,
    pub expected_hash: [u8; 20],
}

pub struct VerifyResult {
    pub piece_index: u64,
    pub data: Vec<u8>,
    pub hash_matches: bool,
}

pub struct HashVerifier {
    request_tx: SyncSender<VerifyRequest>,
    result_rx: Receiver<VerifyResult>,
    _workers: Vec<JoinHandle<()>>,
}

impl HashVerifier {
    pub fn new() -> Self {
        let (request_tx, request_rx) = mpsc::sync_channel::<VerifyRequest>(VERIFY_QUEUE_DEPTH);
        let (result_tx, result_rx) = mpsc::sync_channel::<VerifyResult>(VERIFY_QUEUE_DEPTH);

        let request_rx = std::sync::Arc::new(std::sync::Mutex::new(request_rx));
        let mut workers = Vec::with_capacity(WORKER_THREADS);

        for _ in 0..WORKER_THREADS {
            let rx = request_rx.clone();
            let tx = result_tx.clone();

            let handle = thread::spawn(move || {
                loop {
                    let request = {
                        let guard = match rx.lock() {
                            Ok(g) => g,
                            Err(_) => break,
                        };
                        match guard.recv() {
                            Ok(req) => req,
                            Err(_) => break,
                        }
                    };

                    let mut hasher = Sha1::new();
                    hasher.update(&request.data);
                    let computed_hash: [u8; 20] = hasher.finalize().into();
                    let hash_matches = computed_hash == request.expected_hash;

                    let result = VerifyResult {
                        piece_index: request.piece_index,
                        data: request.data,
                        hash_matches,
                    };

                    if tx.send(result).is_err() {
                        break;
                    }
                }
            });

            workers.push(handle);
        }

        HashVerifier {
            request_tx,
            result_rx,
            _workers: workers,
        }
    }

    pub fn submit(&self, request: VerifyRequest) -> bool {
        self.request_tx.try_send(request).is_ok()
    }

    pub fn try_recv(&self) -> Option<VerifyResult> {
        match self.result_rx.try_recv() {
            Ok(result) => Some(result),
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => None,
        }
    }
}

impl Default for HashVerifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_verifier_correct_hash() {
        let verifier = HashVerifier::new();

        let data = vec![0u8; 16384];
        let mut hasher = Sha1::new();
        hasher.update(&data);
        let expected_hash: [u8; 20] = hasher.finalize().into();

        let request = VerifyRequest {
            piece_index: 0,
            data,
            expected_hash,
        };

        assert!(verifier.submit(request));

        std::thread::sleep(std::time::Duration::from_millis(100));

        let result = verifier.try_recv();
        assert!(result.is_some());
        let result = result.unwrap();
        assert_eq!(result.piece_index, 0);
        assert!(result.hash_matches);
    }

    #[test]
    fn test_hash_verifier_incorrect_hash() {
        let verifier = HashVerifier::new();

        let data = vec![0u8; 16384];
        let expected_hash = [0u8; 20];

        let request = VerifyRequest {
            piece_index: 1,
            data,
            expected_hash,
        };

        assert!(verifier.submit(request));

        std::thread::sleep(std::time::Duration::from_millis(100));

        let result = verifier.try_recv();
        assert!(result.is_some());
        let result = result.unwrap();
        assert_eq!(result.piece_index, 1);
        assert!(!result.hash_matches);
    }
}
