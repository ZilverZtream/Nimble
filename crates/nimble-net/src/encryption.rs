use std::io::{self, Read, Write};

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

pub struct MseHandshake {
    stage: MseStage,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum MseStage {
    Init,
    SendPublicKey,
    ReceivePublicKey,
    SendVc,
    ReceiveVc,
    Established,
}

impl MseHandshake {
    pub fn new_initiator() -> Self {
        MseHandshake {
            stage: MseStage::Init,
        }
    }

    pub fn new_responder() -> Self {
        MseHandshake {
            stage: MseStage::Init,
        }
    }

    pub fn is_established(&self) -> bool {
        self.stage == MseStage::Established
    }
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
}
