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
}
