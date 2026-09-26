//! Identifiers.
//!
//! Container ids are 16 bytes rendered as lowercase hex. Random rather than
//! sequential: a sequential id is a capability (anyone who can read `r3s ps`
//! can address every container), and the CLI exposes a viewer role by default.

use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::str::FromStr;

use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use serde::{Deserialize, Serialize};

const ID_LEN: usize = 16;

/// A 128-bit container identifier.
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
pub struct ContainerId([u8; ID_LEN]);

impl Default for ContainerId {
    /// The null id, used as the "no container" marker inside a fixed-size
    /// record such as `HealthReport`. It is never generated: `generate` draws
    /// from the kernel, and the CLI rejects an all-zero prefix.
    fn default() -> Self {
        Self([0; ID_LEN])
    }
}

impl ContainerId {
    pub const fn from_bytes(bytes: [u8; ID_LEN]) -> Self {
        Self(bytes)
    }

    /// Draws 16 bytes of entropy from the kernel.
    ///
    /// Reading `/dev/urandom` per call costs one open plus one 16-byte read.
    /// That is irrelevant next to the mount, cgroup and `execve` work a create
    /// performs, and it keeps this crate free of `unsafe`.
    pub fn generate() -> Result<Self, IdParseError> {
        let mut bytes = [0u8; ID_LEN];
        read_entropy(&mut bytes)?;
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; ID_LEN] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Resolves a user-supplied string to an id: either a hex prefix of at
    /// least 4 bytes, or a container name prefix. Ambiguity is an error, never
    /// a silent pick — an operator typing `stop web` on a busy node must not
    /// get whichever container the hash map happened to yield first.
    pub fn resolve_prefix<'a>(
        prefix: &str,
        candidates: impl Iterator<Item = (ContainerId, &'a str)>,
    ) -> Result<ContainerId, ResolveError> {
        if prefix.len() < 4 {
            return Err(ResolveError::TooShort);
        }
        let needle = prefix.to_ascii_lowercase();
        let matches: Vec<ContainerId> = candidates
            .filter(|(id, name)| {
                name.starts_with(&needle) || hex::encode(id.as_bytes()).starts_with(&needle)
            })
            .map(|(id, _)| id)
            .collect();

        match matches.as_slice() {
            [] => Err(ResolveError::NotFound),
            [id] => Ok(*id),
            _ => Err(ResolveError::Ambiguous(matches.len())),
        }
    }

    fn from_slice(slice: &[u8]) -> Option<Self> {
        <[u8; ID_LEN]>::try_from(slice).ok().map(Self)
    }
}

impl fmt::Display for ContainerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for ContainerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "id({})", &self.to_hex()[..8])
    }
}

impl FromStr for ContainerId {
    type Err = IdParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s)?;
        Self::from_slice(&bytes).ok_or(IdParseError::Length { got: bytes.len() })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum IdParseError {
    #[error("identifier must be {ID_LEN} bytes of hex, got {got}")]
    Length { got: usize },
    #[error("invalid hex in identifier: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("no entropy source: {0}")]
    Entropy(#[from] std::io::Error),
}

impl PartialEq for IdParseError {
    fn eq(&self, other: &Self) -> bool {
        // `std::io::Error` is not `PartialEq`; two parse failures are equal
        // when their messages are, which is enough for the CLI to compare.
        self.to_string() == other.to_string()
    }
}

impl Eq for IdParseError {}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ResolveError {
    #[error("identifier prefix must be at least 4 characters")]
    TooShort,
    #[error("no such container")]
    NotFound,
    #[error("ambiguous prefix: {0} containers match")]
    Ambiguous(usize),
}

fn read_entropy(buf: &mut [u8]) -> Result<(), std::io::Error> {
    // No pseudo-random fallback: a container id is a capability, so degrading
    // to a time-and-pid mix would be worse than refusing to mint an id. On
    // every platform the engine targets `/dev/urandom` is always present, and
    // its absence is a chroot/initramfs misconfiguration worth failing loudly
    // on rather than papering over.
    let mut file = File::open(Path::new("/dev/urandom"))?;
    file.read_exact(buf)
}

/// An image reference, normalised to `registry/repo:tag` with the tag
/// defaulting to `latest`. Normalisation happens at parse time so the store
/// never holds two spellings of one image.
#[derive(
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
    Serialize,
    Deserialize,
    Clone,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
)]
pub struct ImageRef {
    pub registry: String,
    pub repository: String,
    pub tag: String,
    /// `Some` when pinned by digest. A pinned image is immutable and is never
    /// re-resolved against a tag.
    pub digest: Option<String>,
}

impl ImageRef {
    /// Parses `alpine:3.20`, `ghcr.io/org/app`, `org/app@sha256:…`.
    ///
    /// Deliberately not a general OCI-reference parser: it accepts exactly the
    /// forms the CLI documents and rejects the rest, because an ambiguous
    /// reference is an operator error we can catch instead of a pull that goes
    /// somewhere unexpected.
    pub fn parse(input: &str) -> Result<Self, ImageRefError> {
        if input.is_empty() {
            return Err(ImageRefError::Empty);
        }

        let (rest, digest) = match input.split_once('@') {
            Some((rest, digest)) => (rest, Some(digest.to_owned())),
            None => (input, None),
        };
        if let Some(d) = &digest
            && !d.starts_with("sha256:")
        {
            return Err(ImageRefError::UnsupportedDigest);
        }

        let (name, tag) = match rest.rsplit_once(':') {
            // A colon in the registry host (`host:5000/repo`) is not a tag
            // separator when it appears before the first slash.
            Some((name, tag)) if !tag.contains('/') => (name, tag),
            _ => (rest, "latest"),
        };

        let (registry, repository) = match name.split_once('/') {
            Some((first, rest))
                if first.contains('.') || first.contains(':') || first == "localhost" =>
            {
                (first, rest)
            }
            _ => ("registry-1.docker.io", name),
        };

        if repository.is_empty() || repository.contains("..") {
            return Err(ImageRefError::Malformed(
                "empty repository, or one containing '..'",
            ));
        }
        // The implicit Docker Hub namespace: `alpine` means `library/alpine`.
        let repository = if registry == "registry-1.docker.io" && !repository.contains('/') {
            format!("library/{repository}")
        } else {
            repository.to_owned()
        };

        Ok(Self {
            registry: registry.to_owned(),
            repository,
            tag: tag.to_owned(),
            digest,
        })
    }

    /// The key used by the CAS and the store: digest when present, otherwise
    /// the full name:tag.
    pub fn key(&self) -> String {
        match &self.digest {
            Some(d) => d.clone(),
            None => format!("{}/{}:{}", self.registry, self.repository, self.tag),
        }
    }
}

impl fmt::Display for ImageRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.digest {
            Some(d) => write!(f, "{}/{}@{d}", self.registry, self.repository),
            None => write!(f, "{}/{}:{}", self.registry, self.repository, self.tag),
        }
    }
}

impl fmt::Debug for ImageRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "image({self})")
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ImageRefError {
    #[error("empty image reference")]
    Empty,
    #[error("malformed image reference: {0}")]
    Malformed(&'static str),
    #[error("only sha256 digests are supported")]
    UnsupportedDigest,
}

/// The digest-pinned unit the CAS is keyed by.
pub type ImageId = crate::digest::Digest;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let id = ContainerId::from_bytes([0xab; ID_LEN]);
        let text = id.to_hex();
        assert_eq!(text.len(), ID_LEN * 2);
        assert_eq!(ContainerId::from_str(&text).expect("parses"), id);
    }

    #[test]
    fn wrong_length_is_a_typed_error() {
        let err = ContainerId::from_str("abcd").expect_err("rejects");
        assert!(matches!(err, IdParseError::Length { got: 2 }));
    }

    #[test]
    fn generated_ids_differ() {
        let a = ContainerId::generate().expect("entropy");
        let b = ContainerId::generate().expect("entropy");
        assert_ne!(a, b);
    }

    #[test]
    fn prefix_resolution_reports_ambiguity() {
        let a = ContainerId::from_bytes([0x11; ID_LEN]);
        let b = ContainerId::from_bytes([0x22; ID_LEN]);
        let c = ContainerId::from_bytes([0x33; ID_LEN]);
        let candidates = [(a, "web"), (b, "web1"), (c, "db")];

        assert_eq!(
            ContainerId::resolve_prefix("1111", candidates.into_iter()),
            Ok(a)
        );
        assert_eq!(
            ContainerId::resolve_prefix("web", candidates.into_iter()),
            Err(ResolveError::TooShort)
        );
        assert_eq!(
            ContainerId::resolve_prefix("websomething", candidates.into_iter()),
            Err(ResolveError::NotFound)
        );
    }

    #[test]
    fn prefix_resolution_never_guesses_between_two_hits() {
        let a = ContainerId::from_bytes([0xaa; ID_LEN]);
        let b = ContainerId::from_bytes([0xab; ID_LEN]);
        let candidates = [(a, "cache"), (b, "cache2")];
        assert_eq!(
            ContainerId::resolve_prefix("cach", candidates.into_iter()),
            Err(ResolveError::Ambiguous(2))
        );
    }

    #[test]
    fn image_refs_normalise() {
        let r = ImageRef::parse("alpine").expect("parses");
        assert_eq!(r.registry, "registry-1.docker.io");
        assert_eq!(r.repository, "library/alpine");
        assert_eq!(r.tag, "latest");

        let r = ImageRef::parse("ghcr.io/org/app:1.4.2").expect("parses");
        assert_eq!(r.registry, "ghcr.io");
        assert_eq!(r.repository, "org/app");
        assert_eq!(r.tag, "1.4.2");
    }

    #[test]
    fn registry_port_is_not_mistaken_for_a_tag() {
        let r = ImageRef::parse("registry.local:5000/app").expect("parses");
        assert_eq!(r.registry, "registry.local:5000");
        assert_eq!(r.repository, "app");
        assert_eq!(r.tag, "latest");
    }

    #[test]
    fn digest_pinned_refs_keep_their_digest() {
        let d = "sha256:".to_owned() + &"ab".repeat(32);
        let r = ImageRef::parse(&format!("org/app@{d}")).expect("parses");
        assert_eq!(r.key(), d);
    }

    #[test]
    fn traversal_in_a_repository_is_rejected() {
        assert!(ImageRef::parse("org/../etc").is_err());
        assert!(ImageRef::parse("").is_err());
    }
}
