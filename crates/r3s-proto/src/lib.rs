#![forbid(unsafe_code)]
//! Shared vocabulary for every other crate.
//!
//! Types here have two representations on purpose:
//!
//! * the **live** form (`ContainerSpec`, serde), used by the engine and the CLI;
//! * the **archived** form (`ArchivedContainerSpec`, rkyv), used on the store's
//!   memory-mapped snapshot for zero-copy reads.
//!
//! Both come from one definition, so a schema change has a single blast
//! radius. A type in this module must:
//!
//! * archive deterministically — two identical stores must produce identical
//!   bytes, otherwise the migration tests are useless;
//! * avoid `PathBuf` and `HashMap` — rkyv does not archive them natively, and
//!   paths are exposed as `String` behind `AsPath` helpers;
//! * be `#[non_exhaustive]` if it is an enum other crates match on, so adding a
//!   variant is not a breaking change.

pub mod command;
pub mod crc32c;
pub mod digest;
pub mod error;
pub mod id;
pub mod state;
pub mod types;

pub use command::{Command, CommandAck, CommandError, EngineEvent};
pub use crc32c::{Crc32c, crc32c};
pub use digest::{Digest, DigestError, Hasher};
pub use error::{Error, ImageError, NetworkError, Resource, Result, RuntimeError, StoreError};
pub use id::{ContainerId, IdParseError, ImageId, ImageRef, ImageRefError, ResolveError};
pub use state::{
    ContainerState, ExitRecord, HealthReport, MetricSample, Phase, RestartPolicy, StateSnapshot,
};
pub use types::{
    ContainerSpec, Egress, EnvVar, IdMapping, Index, MountSpec, NetworkSpec, ParseLimitError,
    ResourceLimits, Signal, SpecError, VolumeSpec,
};

/// On-disk format version of the state store. Bumped by every migration; the
/// store refuses to open a snapshot newer than this (see ADR-0003).
pub const STORE_VERSION: u32 = 1;
