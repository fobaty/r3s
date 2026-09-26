//! Content digests.
//!
//! The digest is computed over the **uncompressed** stream, which is what the
//! registry manifest specifies. Compressing first and hashing the compressed
//! bytes would make the digest depend on our own zstd settings.

use std::fmt;
use std::str::FromStr;

use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use serde::{Deserialize, Serialize};
// `Digest` is both a trait here and a type in this module, so the trait is
// brought in anonymously: it is only needed for `update`/`finalize`.
use sha2::Digest as _;
use sha2::Sha256;

pub const DIGEST_LEN: usize = 32;
pub const DIGEST_PREFIX: &str = "sha256:";

#[derive(
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
    Serialize,
    Deserialize,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
)]
pub struct Digest([u8; DIGEST_LEN]);

impl Digest {
    pub const fn from_bytes(bytes: [u8; DIGEST_LEN]) -> Self {
        Self(bytes)
    }

    pub fn of(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    /// Incremental hashing for streams that must not be buffered (image pulls,
    /// layer extraction). Keep the hasher alive across chunks.
    pub fn hasher() -> Hasher {
        Hasher(Sha256::new())
    }

    pub const fn as_bytes(&self) -> &[u8; DIGEST_LEN] {
        &self.0
    }

    /// The canonical registry form, `sha256:<64 hex>`.
    pub fn to_hex(&self) -> String {
        format!("{DIGEST_PREFIX}{}", hex::encode(self.0))
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "digest({})", &self.to_hex()[..19])
    }
}

impl FromStr for Digest {
    type Err = DigestError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let body = s
            .strip_prefix(DIGEST_PREFIX)
            .ok_or(DigestError::MissingAlgorithm)?;
        let bytes = hex::decode(body)?;
        <[u8; DIGEST_LEN]>::try_from(bytes.as_slice())
            .map(Self)
            .map_err(|_| DigestError::WrongLength { got: bytes.len() })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DigestError {
    #[error("digest must start with '{DIGEST_PREFIX}'")]
    MissingAlgorithm,
    #[error("digest must be {DIGEST_LEN} bytes, got {got}")]
    WrongLength { got: usize },
    #[error("invalid hex in digest: {0}")]
    Hex(#[from] hex::FromHexError),
}

/// Streaming digest accumulator.
pub struct Hasher(Sha256);

impl Hasher {
    pub fn update(&mut self, chunk: &[u8]) {
        self.0.update(chunk);
    }

    pub fn finish(self) -> Digest {
        Digest(self.0.finalize().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_matches_the_known_sha256_of_empty_input() {
        assert_eq!(
            Digest::of(b"").to_hex(),
            "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn streaming_matches_one_shot() {
        let data: Vec<u8> = (0u8..=255).cycle().take(100_000).collect();
        let mut hasher = Digest::hasher();
        for chunk in data.chunks(997) {
            hasher.update(chunk);
        }
        assert_eq!(hasher.finish(), Digest::of(&data));
    }

    #[test]
    fn digest_roundtrips_through_its_text_form() {
        let d = Digest::of(b"r3s");
        assert_eq!(Digest::from_str(&d.to_hex()).expect("parses"), d);
        assert!(Digest::from_str("abcd").is_err());
    }
}
