//! Error taxonomy.
//!
//! Every operator-visible failure is a variant here, not a string. The CLI
//! maps a variant to an exit code; the reconciler maps a variant to a retry
//! decision. `docs/RUNBOOK.md` has a row per variant.

use crate::id::ContainerId;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("configuration invalid: {0}")]
    Config(String),

    #[error("kernel does not support {feature}: {detail}")]
    Unsupported {
        feature: &'static str,
        detail: String,
    },

    #[error("not root, or missing capability: {0}")]
    Permission(String),

    #[error("store failure: {0}")]
    Store(#[from] StoreError),

    #[error("runtime failure: {0}")]
    Runtime(#[from] RuntimeError),

    #[error("network failure: {0}")]
    Network(#[from] NetworkError),

    #[error("image failure: {0}")]
    Image(#[from] ImageError),

    #[error("{resource} exhausted: requested {requested}, available {available}")]
    ResourceExhausted {
        resource: Resource,
        requested: u64,
        available: u64,
    },

    #[error("illegal transition {from} -> {to}")]
    IllegalTransition {
        from: &'static str,
        to: &'static str,
    },

    #[error("no such container: {0}")]
    NotFound(ContainerId),

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("command cancelled")]
    Cancelled,

    #[error("internal: {0}")]
    Internal(String),
}

impl Error {
    /// The CLI exit code. Documented in ARCHITECTURE §3.2.1 and asserted by
    /// the CLI test suite.
    pub fn exit_code(&self) -> i32 {
        match self {
            Error::Config(_) => 2,
            Error::NotFound(_) => 3,
            Error::Conflict(_) => 4,
            Error::ResourceExhausted { .. } => 5,
            Error::Store(_) | Error::Runtime(_) | Error::Network(_) | Error::Image(_) => 1,
            Error::Unsupported { .. }
            | Error::Permission(_)
            | Error::IllegalTransition { .. }
            | Error::Cancelled
            | Error::Internal(_) => 1,
        }
    }

    /// Whether the reconciler may retry. Everything kernel- and
    /// I/O-shaped is retried with backoff; operator mistakes are not.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Error::Store(StoreError::Io(_))
                | Error::Store(StoreError::Busy)
                | Error::Runtime(RuntimeError::Busy(_))
                | Error::Runtime(RuntimeError::Interrupted)
                | Error::Network(NetworkError::Busy)
                | Error::Image(ImageError::Transient(_))
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Resource {
    Memory,
    Cpu,
    Pids,
    Disk,
    Containers,
    FileDescriptors,
}

impl Resource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Resource::Memory => "memory",
            Resource::Cpu => "cpu",
            Resource::Pids => "pids",
            Resource::Disk => "disk",
            Resource::Containers => "containers",
            Resource::FileDescriptors => "file descriptors",
        }
    }
}

impl std::fmt::Display for Resource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    #[error("second engine instance holds the lock")]
    Locked,
    #[error("snapshot failed validation: {0}")]
    CorruptSnapshot(String),
    #[error("WAL record {index} failed its CRC")]
    WalChecksum { index: u64 },
    #[error(
        "store is damaged: WAL segment {segment} at offset {offset} ({reason}); \
         nothing was written, nothing was deleted — see RUNBOOK.md §6.6"
    )]
    StoreDamaged {
        /// Segment index that holds the damaged frame.
        segment: u32,
        /// Byte offset of the damaged frame within that segment.
        offset: u64,
        /// Which check rejected it.
        reason: &'static str,
    },
    #[error("store format v{found} is newer than this binary (v{supported})")]
    StoreTooNew { found: u32, supported: u32 },
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("{path}: {source}")]
    Path {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("busy")]
    Busy,
    #[error("interrupted")]
    Interrupted,
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RuntimeError {
    #[error("cgroup path escapes the hierarchy: {0}")]
    CgroupPathEscape(String),
    #[error("cgroup controller '{0}' is not available on this kernel")]
    MissingController(String),
    #[error("cgroup busy: {0}")]
    Busy(String),
    #[error("no-internal-processes rule violated at {0}")]
    InternalProcesses(String),
    #[error("spawn failed: {0}")]
    Spawn(#[source] std::io::Error),
    #[error("namespace fd unavailable: {0}")]
    Namespace(#[source] std::io::Error),
    #[error("preflight: {0}")]
    Preflight(String),
    #[error("interrupted")]
    Interrupted,
    #[error("unsupported on this kernel: {0}")]
    Unsupported(&'static str),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NetworkError {
    #[error("no free address in {cidr}")]
    AddressPoolExhausted { cidr: String },
    #[error("address {0} is already allocated")]
    AddressInUse(String),
    #[error("port {host}/{proto} is already published")]
    PortInUse { host: String, proto: &'static str },
    #[error("netlink: {0}")]
    Netlink(#[source] std::io::Error),
    #[error("nftables transaction failed: {detail}")]
    Nft { detail: String },
    #[error("another netfilter owner was detected on this host")]
    ForeignNetfilterOwner,
    #[error("busy")]
    Busy,
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ImageError {
    #[error("blob digest mismatch: expected {expected}, got {actual}")]
    DigestMismatch { expected: String, actual: String },
    #[error("layer path escapes the extraction root: {0}")]
    PathEscape(String),
    #[error("forbidden node type in layer: {0}")]
    ForbiddenNodeType(String),
    #[error("unpacked size limit exceeded: {limit} bytes")]
    UnpackLimitExceeded { limit: u64 },
    #[error("malformed manifest: {0}")]
    Manifest(String),
    #[error("transient registry failure: {0}")]
    Transient(String),
    #[error("registry refused the request: {status}")]
    Status { status: u16 },
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_are_stable() {
        assert_eq!(Error::Config("x".into()).exit_code(), 2);
        assert_eq!(
            Error::NotFound(ContainerId::from_bytes([0; 16])).exit_code(),
            3
        );
        assert_eq!(Error::Conflict("x".into()).exit_code(), 4);
        assert_eq!(
            Error::ResourceExhausted {
                resource: Resource::Memory,
                requested: 2,
                available: 1
            }
            .exit_code(),
            5
        );
    }

    #[test]
    fn operator_mistakes_are_not_retryable() {
        assert!(!Error::Config("x".into()).is_retryable());
        assert!(!Error::Conflict("x".into()).is_retryable());
        assert!(
            !Error::ResourceExhausted {
                resource: Resource::Memory,
                requested: 1,
                available: 0
            }
            .is_retryable()
        );
    }

    #[test]
    fn io_shaped_failures_are_retryable() {
        assert!(Error::Store(StoreError::Busy).is_retryable());
        assert!(
            Error::Store(StoreError::Io(std::io::Error::from(
                std::io::ErrorKind::WouldBlock
            )))
            .is_retryable()
        );
        assert!(!Error::Image(ImageError::Manifest("x".into())).is_retryable());
    }
}
