//! CRC32C (Castagnoli), the checksum the store's on-disk format specifies.
//!
//! Chosen over IEEE CRC32 because it is what the storage stack around us uses
//! (ext4, btrfs, RocksDB) and because the polynomial has a hardware
//! implementation on every ARMv8 core, so a later change to the CRC is a
//! performance change, not a format change. Collision behaviour is what matters
//! here: a torn or rotted SD card writes in blocks, and the checksum has to
//! notice without a second pass over the data.
//!
//! Byte-at-a-time over a 256-entry table. At the sizes the WAL actually hashes
//! (a frame plus its 20-byte header) that is a few microseconds, and it keeps
//! the checksum auditable in-tree: `cargo deny` has no say in whether we can
//! read it, and a reviewer can check the vectors by hand.

/// The reflected Castagnoli polynomial.
const POLY: u32 = 0x82f6_3b78;

const fn table() -> [u32; 256] {
    let mut out = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut crc = i as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ POLY
            } else {
                crc >> 1
            };
            bit += 1;
        }
        out[i] = crc;
        i += 1;
    }
    out
}

const TABLE: [u32; 256] = table();

/// Streaming state, so a caller that hashes a frame in pieces does not have to
/// concatenate them first.
#[derive(Debug, Clone)]
pub struct Crc32c(u32);

impl Default for Crc32c {
    fn default() -> Self {
        Self::new()
    }
}

impl Crc32c {
    /// A fresh hasher. The initial value is the one the format uses, so a
    /// one-shot `crc32c(bytes)` and a streamed `Crc32c` produce the same number.
    pub const fn new() -> Self {
        Self(0xffff_ffff)
    }

    /// Folds in one more chunk. Chunks may be any size and order is preserved.
    pub fn update(&mut self, data: &[u8]) {
        let mut crc = self.0;
        for &byte in data {
            let index = ((crc ^ u32::from(byte)) & 0xff) as usize;
            crc = (crc >> 8) ^ TABLE[index];
        }
        self.0 = crc;
    }

    /// The checksum of everything fed in so far.
    pub const fn finish(&self) -> u32 {
        self.0 ^ 0xffff_ffff
    }
}

/// CRC32C of one buffer.
pub fn crc32c(data: &[u8]) -> u32 {
    let mut hasher = Crc32c::new();
    hasher.update(data);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_standard_vector() {
        // The check value every CRC32C implementation must agree on.
        assert_eq!(crc32c(b"123456789"), 0xe306_9283);
        assert_eq!(crc32c(b""), 0);
    }

    #[test]
    fn streaming_equals_one_shot_for_any_chunking() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        let want = crc32c(&data);
        for split in [1usize, 7, 64, 999] {
            let mut hasher = Crc32c::new();
            for chunk in data.chunks(split) {
                hasher.update(chunk);
            }
            assert_eq!(hasher.finish(), want, "split every {split} bytes");
        }
    }

    #[test]
    fn a_single_flipped_bit_changes_the_checksum() {
        let mut data = vec![0u8; 64];
        let before = crc32c(&data);
        data[31] ^= 0x01;
        assert_ne!(crc32c(&data), before);
    }

    #[test]
    fn it_is_not_the_ieee_polynomial() {
        // Guards against a silent swap back to CRC32/ISO-HDLC, which would
        // still pass a round-trip test and would silently invalidate every
        // file already on disk.
        assert_ne!(crc32c(b"123456789"), 0xcbf4_3926);
    }
}
