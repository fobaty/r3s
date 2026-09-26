//! Container specification, the engine's declared state input.

use std::path::Path;

use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use serde::{Deserialize, Serialize};

use crate::id::ImageRef;

/// A sorted, archive-friendly key/value collection.
///
/// `HashMap` has no rkyv representation and no deterministic iteration order;
/// a sorted `Vec` gives byte-identical snapshots for identical state, which is
/// what makes the migration fixtures and the snapshot CRC meaningful.
#[derive(
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
    Serialize,
    Deserialize,
    Clone,
    Default,
    Debug,
    PartialEq,
    Eq,
)]
#[serde(transparent)]
pub struct Index<K, V>(Vec<(K, V)>);

impl<K: Ord, V> Index<K, V> {
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        match self.0.binary_search_by(|(k, _)| k.cmp(&key)) {
            Ok(at) => Some(std::mem::replace(&mut self.0[at].1, value)),
            Err(at) => {
                self.0.insert(at, (key, value));
                None
            }
        }
    }

    pub fn get(&self, key: &K) -> Option<&V> {
        self.0
            .binary_search_by(|(k, _)| k.cmp(key))
            .ok()
            .map(|at| &self.0[at].1)
    }

    pub fn remove(&mut self, key: &K) -> Option<V> {
        self.0
            .binary_search_by(|(k, _)| k.cmp(key))
            .ok()
            .map(|at| self.0.remove(at).1)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.0.iter().map(|(k, v)| (k, v))
    }

    pub fn keys(&self) -> impl Iterator<Item = &K> {
        self.0.iter().map(|(k, _)| k)
    }
}

impl<K: Ord, V> FromIterator<(K, V)> for Index<K, V> {
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        let iter = iter.into_iter();
        let mut idx = Index(Vec::with_capacity(iter.size_hint().0));
        for (k, v) in iter {
            idx.insert(k, v);
        }
        idx
    }
}

/// `cgroup v2` limits. Every field has a documented default: a spec that omits
/// a limit still has an enforceable value, so admission control never has to
/// special-case "unset".
#[derive(
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
    Serialize,
    Deserialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
)]
pub struct ResourceLimits {
    /// `memory.max`. 0 means "unlimited", which admission control rejects on a
    /// node with less than `reserved_memory_bytes` free.
    pub memory_bytes: u64,
    /// `memory.high` — reclaim pressure before the hard limit. 0 = unset.
    pub memory_high_bytes: u64,
    /// `memory.swap.max`. Defaults to 0: swap on an SD card is a way to turn a
    /// memory limit into a latency cliff.
    pub memory_swap_bytes: u64,
    /// `cpu.max` quota, expressed in percent of one core.
    pub cpu_shares: u32,
    /// `pids.max`.
    pub max_pids: u32,
    /// `io.max` read/write bandwidth in bytes/s; 0 = unlimited.
    pub io_read_bps: u64,
    pub io_write_bps: u64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            memory_bytes: 256 * 1024 * 1024,
            memory_high_bytes: 0,
            memory_swap_bytes: 0,
            cpu_shares: 100,
            max_pids: 512,
            io_read_bps: 0,
            io_write_bps: 0,
        }
    }
}

impl ResourceLimits {
    /// `cpu.max` is written as `<quota_us> <period_us>`.
    pub const PERIOD_US: u64 = 100_000;

    pub fn cpu_quota_us(&self) -> u64 {
        u64::from(self.cpu_shares) * Self::PERIOD_US / 100
    }

    /// Parses `256m`, `1g`, `512k`, `1000000`. A bare number is bytes.
    pub fn parse_memory(input: &str) -> Result<u64, ParseLimitError> {
        let input = input.trim();
        let (digits, scale) = match input.as_bytes().last() {
            Some(b'k' | b'K') => (&input[..input.len() - 1], 1024u64),
            Some(b'm' | b'M') => (&input[..input.len() - 1], 1024 * 1024),
            Some(b'g' | b'G') => (&input[..input.len() - 1], 1024 * 1024 * 1024),
            _ => (input, 1),
        };
        let value: u64 = digits
            .parse()
            .map_err(|_| ParseLimitError(input.to_owned()))?;
        value
            .checked_mul(scale)
            .ok_or_else(|| ParseLimitError(input.to_owned()))
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("invalid limit: {0}")]
pub struct ParseLimitError(pub String);

/// An environment variable. `secret` marks values that must not be persisted
/// in cleartext and never appear in `inspect` output.
#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq,
)]
pub struct EnvVar {
    pub name: String,
    pub value: String,
    pub secret: bool,
}

impl EnvVar {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            secret: false,
        }
    }

    pub fn secret(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            secret: true,
        }
    }
}

#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq,
)]
pub struct MountSpec {
    pub source: String,
    pub target: String,
    pub readonly: bool,
    pub nosuid: bool,
    pub nodev: bool,
    pub noexec: bool,
}

impl MountSpec {
    pub fn bind(source: impl Into<String>, target: impl Into<String>) -> Self {
        Self {
            source: source.into(),
            target: target.into(),
            readonly: false,
            // The secure default: a bind mount gets no setuid, no devices and
            // no exec unless the spec says otherwise, so `--volume` can never
            // be the thing that hands a container host capabilities.
            nosuid: true,
            nodev: true,
            noexec: false,
        }
    }

    pub fn target_path(&self) -> &Path {
        Path::new(&self.target)
    }
}

#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq,
)]
pub struct VolumeSpec {
    pub name: String,
    /// `None` for a tmpfs volume.
    pub source: Option<String>,
    /// Hard size cap enforced before pull, not after.
    pub max_bytes: u64,
    pub readonly: bool,
}

impl VolumeSpec {
    pub fn path(&self) -> &Path {
        // Named volumes are always laid out under the engine root; the caller
        // supplies the root, so this only ever produces a relative name.
        Path::new(&self.name)
    }
}

#[derive(
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
    Serialize,
    Deserialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
)]
pub struct NetworkSpec {
    /// Join the engine-managed bridge with a leased address.
    pub managed: bool,
    /// Publish `host:container` port pairs on the host.
    pub published_ports: u16,
    /// `default` permits host egress; `none` denies everything not published.
    pub egress: Egress,
}

#[derive(
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
    Serialize,
    Deserialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Default,
)]
pub enum Egress {
    #[default]
    Host,
    None,
}

impl Default for NetworkSpec {
    fn default() -> Self {
        Self {
            managed: true,
            published_ports: 0,
            egress: Egress::Host,
        }
    }
}

/// The complete declared state of one container.
///
/// Paths are `String` because rkyv does not archive `PathBuf`; the engine
/// converts them once, at the boundary.
#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq,
)]
pub struct ContainerSpec {
    pub id: crate::id::ContainerId,
    pub name: String,
    pub image: ImageRef,
    pub argv: Vec<String>,
    pub env: Vec<EnvVar>,
    pub mounts: Vec<MountSpec>,
    pub volumes: Vec<VolumeSpec>,
    pub limits: ResourceLimits,
    pub network: NetworkSpec,
    /// Slice name: the cgroup's parent, so a whole class is reprioritised at
    /// once instead of container by container.
    pub slice: String,
    pub rootless: bool,
    pub readonly_rootfs: bool,
    pub restart: crate::state::RestartPolicy,
    pub hostname: String,
}

impl ContainerSpec {
    pub fn new(id: crate::id::ContainerId, name: impl Into<String>, image: ImageRef) -> Self {
        Self {
            id,
            name: name.into(),
            image,
            argv: vec!["/bin/sh".to_owned()],
            env: Vec::new(),
            mounts: Vec::new(),
            volumes: Vec::new(),
            limits: ResourceLimits::default(),
            network: NetworkSpec::default(),
            slice: "default".to_owned(),
            rootless: false,
            readonly_rootfs: true,
            restart: crate::state::RestartPolicy::No,
            hostname: "r3s".to_owned(),
        }
    }

    pub fn validate(&self) -> Result<(), SpecError> {
        if self.name.is_empty() || self.name.len() > 63 {
            return Err(SpecError::NameLength);
        }
        if !self
            .name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(SpecError::NameCharset);
        }
        if self.argv.is_empty() {
            return Err(SpecError::EmptyArgv);
        }
        if !self.argv[0].starts_with('/') {
            // A relative argv[0] would be resolved against the container's PATH
            // and is a surprise the operator cannot debug from the CLI.
            return Err(SpecError::Argv0NotAbsolute);
        }
        for m in &self.mounts {
            if !m.target.starts_with('/') {
                return Err(SpecError::RelativeTarget);
            }
            if m.target.split('/').any(|c| c == "..") {
                return Err(SpecError::TargetTraversal);
            }
        }
        if self.limits.memory_bytes == 0 {
            return Err(SpecError::NoMemoryLimit);
        }
        if self.limits.max_pids == 0 {
            return Err(SpecError::NoPidLimit);
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum SpecError {
    #[error("name must be 1..=63 characters")]
    NameLength,
    #[error("name may only contain [A-Za-z0-9_-]")]
    NameCharset,
    #[error("argv must not be empty")]
    EmptyArgv,
    #[error("argv[0] must be an absolute path")]
    Argv0NotAbsolute,
    #[error("mount target must be absolute")]
    RelativeTarget,
    #[error("mount target must not contain '..'")]
    TargetTraversal,
    #[error("memory limit must be non-zero; use a limit, not 'unlimited'")]
    NoMemoryLimit,
    #[error("pids limit must be non-zero")]
    NoPidLimit,
}

/// Signals accepted by `container kill`. A small allowlist instead of
/// `libc::SIG*` so the CLI grammar, the audit log and the docs stay in sync.
#[derive(
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
    Serialize,
    Deserialize,
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
)]
#[non_exhaustive]
pub enum Signal {
    Term,
    Kill,
    Hup,
    Int,
    Quit,
    Usr1,
    Usr2,
}

impl Signal {
    pub fn parse(input: &str) -> Option<Self> {
        Some(match input.to_ascii_uppercase().as_str() {
            "TERM" | "SIGTERM" | "15" => Signal::Term,
            "KILL" | "SIGKILL" | "9" => Signal::Kill,
            "HUP" | "SIGHUP" | "1" => Signal::Hup,
            "INT" | "SIGINT" | "2" => Signal::Int,
            "QUIT" | "SIGQUIT" | "3" => Signal::Quit,
            "USR1" | "SIGUSR1" => Signal::Usr1,
            "USR2" | "SIGUSR2" => Signal::Usr2,
            _ => return None,
        })
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Signal::Term => "SIGTERM",
            Signal::Kill => "SIGKILL",
            Signal::Hup => "SIGHUP",
            Signal::Int => "SIGINT",
            Signal::Quit => "SIGQUIT",
            Signal::Usr1 => "SIGUSR1",
            Signal::Usr2 => "SIGUSR2",
        }
    }
}

/// The full user→host id map written to `/proc/<pid>/uid_map` in rootless mode.
#[derive(
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
    Serialize,
    Deserialize,
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
)]
pub struct IdMapping {
    pub container_uid: u32,
    pub host_uid: u32,
    pub container_gid: u32,
    pub host_gid: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::ImageRef;

    fn spec() -> ContainerSpec {
        let mut s = ContainerSpec::new(
            crate::id::ContainerId::from_bytes([1; 16]),
            "web",
            ImageRef::parse("alpine:3").expect("parses"),
        );
        s.argv = vec!["/bin/sh".to_owned(), "-c".to_owned(), "sleep 1".to_owned()];
        s
    }

    #[test]
    fn index_is_sorted_and_overwrites() {
        let mut idx = Index::from_iter([("b", 2), ("a", 1)]);
        assert_eq!(idx.keys().copied().collect::<Vec<_>>(), ["a", "b"]);
        assert_eq!(idx.insert("a", 9), Some(1));
        assert_eq!(idx.get(&"a"), Some(&9));
        assert_eq!(idx.len(), 2);
    }

    #[test]
    fn index_roundtrips_through_archive() {
        let idx: Index<String, u32> = Index::from_iter([("b".into(), 2), ("a".into(), 1)]);
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&idx).expect("archives");
        let live: Index<String, u32> =
            rkyv::from_bytes::<Index<String, u32>, rkyv::rancor::Error>(&bytes)
                .expect("deserialises");
        assert_eq!(live, idx);
    }

    #[test]
    fn memory_limits_parse() {
        assert_eq!(
            ResourceLimits::parse_memory("256m").expect("parses"),
            268_435_456
        );
        assert_eq!(
            ResourceLimits::parse_memory("1g").expect("parses"),
            1_073_741_824
        );
        assert_eq!(
            ResourceLimits::parse_memory("512k").expect("parses"),
            524_288
        );
        assert_eq!(ResourceLimits::parse_memory("4096").expect("parses"), 4096);
        assert!(ResourceLimits::parse_memory("lots").is_err());
    }

    #[test]
    fn cpu_quota_is_in_microseconds() {
        let limits = ResourceLimits {
            cpu_shares: 250,
            ..ResourceLimits::default()
        };
        assert_eq!(limits.cpu_quota_us(), 250_000);
        assert_eq!(ResourceLimits::PERIOD_US, 100_000);
    }

    #[test]
    fn spec_validation_rejects_operator_mistakes() {
        let s = spec();
        s.validate().expect("valid");

        let mut bad = spec();
        bad.name = "bad name".into();
        assert_eq!(bad.validate(), Err(SpecError::NameCharset));

        let mut bad = spec();
        bad.argv[0] = "sh".into();
        assert_eq!(bad.validate(), Err(SpecError::Argv0NotAbsolute));

        let mut bad = spec();
        bad.mounts.push(MountSpec::bind("/host", "/data/../../etc"));
        assert_eq!(bad.validate(), Err(SpecError::TargetTraversal));

        let mut bad = spec();
        bad.limits.memory_bytes = 0;
        assert_eq!(bad.validate(), Err(SpecError::NoMemoryLimit));
    }

    #[test]
    fn bind_mounts_are_insecure_by_default() {
        let m = MountSpec::bind("/srv/data", "/data");
        assert!(m.nosuid, "nosuid must default on");
        assert!(m.nodev, "nodev must default on");
    }

    #[test]
    fn signals_parse_from_names_and_numbers() {
        assert_eq!(Signal::parse("9"), Some(Signal::Kill));
        assert_eq!(Signal::parse("sigterm"), Some(Signal::Term));
        assert_eq!(Signal::parse("SIGKILL"), Some(Signal::Kill));
        assert_eq!(Signal::parse("nope"), None);
    }
}
