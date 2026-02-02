use std::io::{self, Read, Write};
use num_bigint::BigUint;
use nimble_util::hash::sha1;

const DH_PRIME_HEX: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A36210000000000090563";
const DH_GENERATOR: u32 = 2;
const VC_LENGTH: usize = 8;
pub const MSE_KEY_LENGTH: usize = 96;

pub struct Rc4 {
    state: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    pub fn new(key: &[u8]) -> Self {
        let mut state = [0u8; 256];
        for (i, val) in state.iter_mut().enumerate() {
            *val = i as u8;
        }

        let mut j: u8 = 0;
        for i in 0..256 {
            j = j.wrapping_add(state[i]).wrapping_add(key[i % key.len()]);
            state.swap(i, j as usize);
        }

        Rc4 { state, i: 0, j: 0 }
    }

    pub fn process(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.state[self.i as usize]);
            self.state.swap(self.i as usize, self.j as usize);
            let k = self.state[(self.state[self.i as usize]
                .wrapping_add(self.state[self.j as usize])) as usize];
            *byte ^= k;
        }
    }

    pub fn discard(&mut self, count: usize) {
        for _ in 0..count {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.state[self.i as usize]);
            self.state.swap(self.i as usize, self.j as usize);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MseStage {
    Init,
    SendPublicKey,
    ReceivePublicKey,
    SendVc,
    ReceiveVc,
    Established,
}

pub struct MseHandshake {
    stage: MseStage,
    private_key: BigUint,
    public_key: Vec<u8>,
    shared_secret: Option<Vec<u8>>,
    send_cipher: Option<Rc4>,
    recv_cipher: Option<Rc4>,
    is_initiator: bool,
}

impl MseHandshake {
    pub fn new_initiator(_info_hash: &[u8; 20]) -> Self {
        let prime = BigUint::parse_bytes(DH_PRIME_HEX.as_bytes(), 16)
            .expect("invalid DH prime");

        let private_key = generate_random_key();
        let public_key = compute_public_key(&private_key, &prime);

        MseHandshake {
            stage: MseStage::Init,
            private_key,
            public_key,
            shared_secret: None,
            send_cipher: None,
            recv_cipher: None,
            is_initiator: true,
        }
    }

    pub fn new_responder() -> Self {
        let prime = BigUint::parse_bytes(DH_PRIME_HEX.as_bytes(), 16)
            .expect("invalid DH prime");

        let private_key = generate_random_key();
        let public_key = compute_public_key(&private_key, &prime);

        MseHandshake {
            stage: MseStage::Init,
            private_key,
            public_key,
            shared_secret: None,
            send_cipher: None,
            recv_cipher: None,
            is_initiator: false,
        }
    }

    pub fn get_public_key(&self) -> &[u8] {
        &self.public_key
    }

    pub fn compute_shared_secret(&mut self, peer_public_key: &[u8], info_hash: &[u8; 20]) -> Result<(), &'static str> {
        let prime = BigUint::parse_bytes(DH_PRIME_HEX.as_bytes(), 16)
            .expect("invalid DH prime");

        let peer_pub = BigUint::from_bytes_be(peer_public_key);

        let zero = BigUint::from(0u32);
        let one = BigUint::from(1u32);
        let p_minus_one = &prime - &one;

        if peer_pub == zero || peer_pub == one || peer_pub == p_minus_one || peer_pub >= prime {
            return Err("invalid DH public key: weak or out-of-range key rejected");
        }

        let shared = peer_pub.modpow(&self.private_key, &prime);
        let mut shared_bytes = shared.to_bytes_be();

        if shared_bytes.len() < MSE_KEY_LENGTH {
            let mut padded = vec![0u8; MSE_KEY_LENGTH - shared_bytes.len()];
            padded.extend_from_slice(&shared_bytes);
            shared_bytes = padded;
        } else if shared_bytes.len() > MSE_KEY_LENGTH {
            shared_bytes = shared_bytes[shared_bytes.len() - MSE_KEY_LENGTH..].to_vec();
        }

        let send_key = derive_key(&shared_bytes, info_hash, self.is_initiator, true);
        let recv_key = derive_key(&shared_bytes, info_hash, self.is_initiator, false);

        let mut send_cipher = Rc4::new(&send_key);
        send_cipher.discard(1024);

        let mut recv_cipher = Rc4::new(&recv_key);
        recv_cipher.discard(1024);

        self.shared_secret = Some(shared_bytes);
        self.send_cipher = Some(send_cipher);
        self.recv_cipher = Some(recv_cipher);

        Ok(())
    }

    pub fn encrypt(&mut self, data: &mut [u8]) {
        if let Some(cipher) = self.send_cipher.as_mut() {
            cipher.process(data);
        }
    }

    pub fn decrypt(&mut self, data: &mut [u8]) {
        if let Some(cipher) = self.recv_cipher.as_mut() {
            cipher.process(data);
        }
    }

    pub fn is_established(&self) -> bool {
        self.stage == MseStage::Established
    }

    pub fn set_stage(&mut self, stage: MseStage) {
        self.stage = stage;
    }

    pub fn stage(&self) -> MseStage {
        self.stage
    }

    pub fn clone_without_ciphers(&self) -> Self {
        MseHandshake {
            stage: MseStage::Init,
            private_key: self.private_key.clone(),
            public_key: self.public_key.clone(),
            shared_secret: None,
            send_cipher: None,
            recv_cipher: None,
            is_initiator: self.is_initiator,
        }
    }
}

fn generate_random_key() -> BigUint {
    let bytes = nimble_util::ids::generate_random_bytes::<20>()
        .expect("failed to generate cryptographically secure random key");
    BigUint::from_bytes_be(&bytes)
}

fn compute_public_key(private_key: &BigUint, prime: &BigUint) -> Vec<u8> {
    let generator = BigUint::from(DH_GENERATOR);
    let public = generator.modpow(private_key, prime);
    let mut bytes = public.to_bytes_be();

    if bytes.len() < MSE_KEY_LENGTH {
        let mut padded = vec![0u8; MSE_KEY_LENGTH - bytes.len()];
        padded.extend_from_slice(&bytes);
        bytes = padded;
    } else if bytes.len() > MSE_KEY_LENGTH {
        bytes = bytes[bytes.len() - MSE_KEY_LENGTH..].to_vec();
    }

    bytes
}

fn derive_key(shared_secret: &[u8], info_hash: &[u8; 20], is_initiator: bool, is_send: bool) -> [u8; 20] {
    let mut data = Vec::with_capacity(shared_secret.len() + info_hash.len());

    let use_req = (is_initiator && is_send) || (!is_initiator && !is_send);

    if use_req {
        data.extend_from_slice(b"keyA");
        data.extend_from_slice(shared_secret);
        data.extend_from_slice(info_hash);
    } else {
        data.extend_from_slice(b"keyB");
        data.extend_from_slice(shared_secret);
        data.extend_from_slice(info_hash);
    }

    sha1(&data)
}

pub struct EncryptedStream<S> {
    inner: S,
    send_cipher: Option<Rc4>,
    recv_cipher: Option<Rc4>,
}

impl<S> EncryptedStream<S> {
    pub fn new_plaintext(stream: S) -> Self {
        EncryptedStream {
            inner: stream,
            send_cipher: None,
            recv_cipher: None,
        }
    }

    pub fn new_encrypted(stream: S, send_key: &[u8], recv_key: &[u8]) -> Self {
        let mut send_cipher = Rc4::new(send_key);
        send_cipher.discard(1024);

        let mut recv_cipher = Rc4::new(recv_key);
        recv_cipher.discard(1024);

        EncryptedStream {
            inner: stream,
            send_cipher: Some(send_cipher),
            recv_cipher: Some(recv_cipher),
        }
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: Read> Read for EncryptedStream<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if let Some(cipher) = self.recv_cipher.as_mut() {
            cipher.process(&mut buf[..n]);
        }
        Ok(n)
    }
}

impl<S: Write> Write for EncryptedStream<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let Some(cipher) = self.send_cipher.as_mut() {
            let mut encrypted = buf.to_vec();
            cipher.process(&mut encrypted);
            self.inner.write(&encrypted)
        } else {
            self.inner.write(buf)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rc4_basic() {
        let key = b"TestKey123";
        let mut cipher1 = Rc4::new(key);
        let mut cipher2 = Rc4::new(key);

        let mut data = b"Hello, World!".to_vec();
        let original = data.clone();

        cipher1.process(&mut data);
        assert_ne!(data, original);

        cipher2.process(&mut data);
        assert_eq!(data, original);
    }

    #[test]
    fn test_rc4_discard() {
        let key = b"TestKey123";
        let mut cipher1 = Rc4::new(key);
        cipher1.discard(1024);

        let mut cipher2 = Rc4::new(key);
        let mut discard_buf = vec![0u8; 1024];
        cipher2.process(&mut discard_buf);

        let mut data1 = b"Test".to_vec();
        let mut data2 = data1.clone();

        cipher1.process(&mut data1);
        cipher2.process(&mut data2);

        assert_eq!(data1, data2);
    }

    #[test]
    fn test_dh_key_exchange() {
        let info_hash = [0x12u8; 20];

        let mut initiator = MseHandshake::new_initiator(&info_hash);
        let mut responder = MseHandshake::new_responder();

        let initiator_pubkey = initiator.get_public_key().to_vec();
        let responder_pubkey = responder.get_public_key().to_vec();

        initiator.compute_shared_secret(&responder_pubkey, &info_hash).unwrap();
        responder.compute_shared_secret(&initiator_pubkey, &info_hash).unwrap();

        assert_eq!(initiator.shared_secret, responder.shared_secret);
    }

    #[test]
    fn test_mse_encryption() {
        let info_hash = [0x34u8; 20];

        let mut initiator = MseHandshake::new_initiator(&info_hash);
        let mut responder = MseHandshake::new_responder();

        let initiator_pubkey = initiator.get_public_key().to_vec();
        let responder_pubkey = responder.get_public_key().to_vec();

        initiator.compute_shared_secret(&responder_pubkey, &info_hash).unwrap();
        responder.compute_shared_secret(&initiator_pubkey, &info_hash).unwrap();

        let mut data = b"Test message".to_vec();
        let original = data.clone();

        initiator.encrypt(&mut data);
        assert_ne!(data, original);

        responder.decrypt(&mut data);
        assert_eq!(data, original);
    }

    #[test]
    fn test_clone_without_ciphers_preserves_keys() {
        let info_hash = [0x56u8; 20];

        let responder = MseHandshake::new_responder();
        let responder_clone = responder.clone_without_ciphers();

        assert_eq!(responder.get_public_key(), responder_clone.get_public_key());

        let peer_pubkey = responder.get_public_key().to_vec();

        let mut derived = responder.clone_without_ciphers();
        let mut derived_clone = responder_clone.clone_without_ciphers();

        derived.compute_shared_secret(&peer_pubkey, &info_hash).unwrap();
        derived_clone.compute_shared_secret(&peer_pubkey, &info_hash).unwrap();

        assert_eq!(derived.shared_secret, derived_clone.shared_secret);
    }
}
