// Placeholder: compact bitfield implementation for pieces/blocks.

#[derive(Clone, Debug, Default)]
pub struct Bitfield {
    bytes: Vec<u8>,
    bits: usize,
}

impl Bitfield {
    pub fn new(bits: usize) -> Self {
        let bytes = (bits + 7) / 8;
        Self { bytes: vec![0; bytes], bits }
    }

    pub fn set(&mut self, idx: usize, value: bool) {
        if idx >= self.bits { return; }
        let byte = idx / 8;
        let mask = 1u8 << (7 - (idx % 8));
        if value { self.bytes[byte] |= mask; } else { self.bytes[byte] &= !mask; }
    }

    pub fn get(&self, idx: usize) -> bool {
        if idx >= self.bits { return false; }
        let byte = idx / 8;
        let mask = 1u8 << (7 - (idx % 8));
        (self.bytes[byte] & mask) != 0
    }

    pub fn count_ones(&self) -> usize {
        let mut count: usize = 0;
        let full_bytes = self.bits / 8;

        for i in 0..full_bytes {
            count += self.bytes[i].count_ones() as usize;
        }

        let remaining_bits = self.bits % 8;
        if remaining_bits > 0 && full_bytes < self.bytes.len() {
            let mask = 0xFF << (8 - remaining_bits);
            count += (self.bytes[full_bytes] & mask).count_ones() as usize;
        }

        count
    }

    pub fn len(&self) -> usize {
        self.bits
    }

    pub fn is_empty(&self) -> bool {
        self.bits == 0
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn from_bytes(bytes: &[u8], bits: usize) -> Self {
        let expected_bytes = (bits + 7) / 8;
        let mut bf = Self {
            bytes: vec![0; expected_bytes],
            bits,
        };
        let copy_len = bytes.len().min(expected_bytes);
        bf.bytes[..copy_len].copy_from_slice(&bytes[..copy_len]);
        bf
    }

    pub fn is_all_set(&self) -> bool {
        self.count_ones() == self.bits
    }
}
