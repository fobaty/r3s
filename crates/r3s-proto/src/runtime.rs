//! The isolation-plane record: the full description of one container that the
//! daemon authors for `r3s container-init` (ADR-0004) and that the init
//! re-reads at `main`, long before any kernel state is touched.
//!
//! These types are *data only* — nothing here touches a syscall, `libc` does
//! not appear, and the module carries `#![forbid(unsafe_code)]` from the crate
//! root. The kernel half lives in `r3s-runtime::isolation` (UNSAFE.md J-03..
//! J-07). What this module gives the engine is the one place where the
//! container *boundary* is described deterministically, so two identical specs
//! archive to identical bytes and the seccomp allowlist is printable by
//! `r3s inspect` instead of living in a loader's head.

use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use serde::{Deserialize, Serialize};

use crate::types::{ContainerSpec, EnvVar, MountSpec};

use std::fmt;

/// The set of kernel namespaces a container gets, kept as booleans instead of
/// a bitfield so it survives serialization without an integer ABI to version.
///
/// Defaults to every namespace the engine always creates ([`Self::standard`])
/// and the flags field of [`ChildSetup`].
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
pub struct NamespaceFlags {
    /// `CLONE_NEWUSER` — only set in rootless mode; see [`Self::standard`].
    pub user: bool,
    /// `CLONE_NEWIPC`.
    pub ipc: bool,
    /// `CLONE_NEWUTS` (the container's own hostname).
    pub uts: bool,
    /// `CLONE_NEWNET` (the container's own network stack).
    pub net: bool,
    /// `CLONE_NEWPID` (takes effect for *children*, hence the re-exec fork).
    pub pid: bool,
    /// `CLONE_NEWNS` (the mount namespace the whole rootfs dance happens in).
    pub mnt: bool,
    /// `CLONE_NEWCGROUP` — relative cgroup roots if the container ever mounts
    /// the hierarchy itself. Harmless when it does not.
    pub cgroup: bool,
    /// `CLONE_NEWTIME` — opt-in only (ARCHITECTURE §1.2.2): it silently
    /// changes what `CLOCK_REALTIME` a container reads.
    pub time: bool,
}

impl NamespaceFlags {
    /// The namespaces every container gets, rootful or not.
    pub const fn standard() -> Self {
        Self {
            user: false,
            ipc: true,
            uts: true,
            net: true,
            pid: true,
            mnt: true,
            cgroup: true,
            time: false,
        }
    }

    /// The rootless posture: [`Self::standard`] plus `CLONE_NEWUSER`.
    pub const fn rootless() -> Self {
        Self {
            user: true,
            ..Self::standard()
        }
    }
}

impl Default for NamespaceFlags {
    fn default() -> Self {
        Self::standard()
    }
}

/// A capability the container is explicitly granted. The engine's default is
/// the empty set (ADR-0007: bounding set dropped, nothing kept), so this
/// exists for the spec that opts out — never for the default path.
///
/// Only the `as_str`/`name` forms are stable; the numeric values live in the
/// Linux gateway in `r3s-runtime` where the arch-specific tables are.
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
    PartialOrd,
    Ord,
    Hash,
)]
#[non_exhaustive]
pub enum Capability {
    /// `CAP_CHOWN`.
    Chown,
    /// `CAP_DAC_OVERRIDE`.
    DacOverride,
    /// `CAP_DAC_READ_SEARCH`.
    DacReadSearch,
    /// `CAP_FOWNER`.
    Fowner,
    /// `CAP_FSETID`.
    Fsetid,
    /// `CAP_KILL`.
    Kill,
    /// `CAP_SETGID`.
    Setgid,
    /// `CAP_SETUID`.
    Setuid,
    /// `CAP_SETPCAP`.
    Setpcap,
    /// `CAP_NET_BIND_SERVICE`.
    NetBindService,
    /// `CAP_NET_RAW`.
    NetRaw,
    /// `CAP_SYS_CHROOT`.
    SysChroot,
    /// `CAP_MKNOD`.
    Mknod,
    /// `CAP_AUDIT_WRITE`.
    AuditWrite,
    /// `CAP_SETFCAP`.
    Setfcap,
}

impl Capability {
    /// The usual candidates a container might legitimately request. "Exactly
    /// what the spec requests" gives an operator a single drop-list to read.
    pub const ALL: &'static [Capability] = &[
        Capability::Chown,
        Capability::DacOverride,
        Capability::DacReadSearch,
        Capability::Fowner,
        Capability::Fsetid,
        Capability::Kill,
        Capability::Setgid,
        Capability::Setuid,
        Capability::Setpcap,
        Capability::NetBindService,
        Capability::NetRaw,
        Capability::SysChroot,
        Capability::Mknod,
        Capability::AuditWrite,
        Capability::Setfcap,
    ];

    /// The stable capability name, as `capabilities(7)` spells it.
    pub const fn name(self) -> &'static str {
        match self {
            Capability::Chown => "CAP_CHOWN",
            Capability::DacOverride => "CAP_DAC_OVERRIDE",
            Capability::DacReadSearch => "CAP_DAC_READ_SEARCH",
            Capability::Fowner => "CAP_FOWNER",
            Capability::Fsetid => "CAP_FSETID",
            Capability::Kill => "CAP_KILL",
            Capability::Setgid => "CAP_SETGID",
            Capability::Setuid => "CAP_SETUID",
            Capability::Setpcap => "CAP_SETPCAP",
            Capability::NetBindService => "CAP_NET_BIND_SERVICE",
            Capability::NetRaw => "CAP_NET_RAW",
            Capability::SysChroot => "CAP_SYS_CHROOT",
            Capability::Mknod => "CAP_MKNOD",
            Capability::AuditWrite => "CAP_AUDIT_WRITE",
            Capability::Setfcap => "CAP_SETFCAP",
        }
    }

    /// Parses a capability from its `CAP_*` name, case-insensitively.
    pub fn parse(input: &str) -> Option<Capability> {
        let upper = input.trim().to_ascii_uppercase();
        Self::ALL.iter().copied().find(|c| c.name() == upper)
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// What a syscall that is *not* in the allowlist gets. The profile producer
/// enforces the ordering contraction over the filtered set.
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
pub enum SeccompAction {
    /// Not filtered (the syscall is allowed).
    Allow,
    /// The syscall fails with this errno.
    Errno(i32),
    /// The calling thread is killed (the loudest safe default).
    Kill,
}

/// A seccomp personality: an allowlist over otherwise-`default_action`
/// syscalls. The BPF is generated from this by `r3s-runtime` (UNSAFE.md J-07).
#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq,
)]
pub struct SeccompProfile {
    /// What an unlisted syscall gets.
    pub default_action: SeccompAction,
    /// Syscall names (not numbers — portable across arch) that bypass the
    /// default. Sorted for byte-deterministic archives.
    pub allow: Vec<String>,
}

impl SeccompProfile {
    /// The conservative base the engine ships: enough for a dynamically
    /// linked payload to start and run on aarch64 or x86_64, nothing more.
    /// A container that needs another syscall opts in by extending it;
    /// a container that needs none of these would not boot.
    pub fn base() -> Self {
        const BASE: &[&str] = &[
            // exit and signal plumbing
            "exit",
            "exit_group",
            "rt_sigaction",
            "rt_sigprocmask",
            "rt_sigreturn",
            "sigaltstack",
            // files
            "open",
            "openat",
            "read",
            "write",
            "pread64",
            "pwrite64",
            "readv",
            "writev",
            "close",
            "lseek",
            "fstat",
            "newfstatat",
            "access",
            "getdents64",
            "readlink",
            "readlinkat",
            "statfs",
            "fstatfs",
            "unlink",
            "unlinkat",
            "mkdir",
            "mkdirat",
            "rename",
            "renameat",
            "truncate",
            "ftruncate",
            "fchmod",
            "fchmodat",
            "chmod",
            "umask",
            "fsync",
            "fdatasync",
            "dup",
            "dup2",
            "dup3",
            "fcntl",
            "ioctl",
            "flock",
            "fallocate",
            "sendfile",
            // memory
            "mmap",
            "mprotect",
            "munmap",
            "brk",
            "madvise",
            "mlock",
            "munlock",
            "mremap",
            "msync",
            "membarrier",
            // process
            "clone",
            "clone3",
            "fork",
            "vfork",
            "execve",
            "execveat",
            "wait4",
            "set_tid_address",
            "set_robust_list",
            "getpid",
            "gettid",
            "getppid",
            "getpgid",
            "setpgid",
            "getsid",
            "setsid",
            "getuid",
            "getgid",
            "geteuid",
            "getegid",
            "getgroups",
            "prlimit64",
            "sched_getaffinity",
            "sched_setaffinity",
            "setuid",
            "setgid",
            "getuid",
            "capget",
            "capset",
            "prctl",
            "arch_prctl",
            "getrandom",
            "uname",
            "getrusage",
            "getrlimit",
            "setrlimit",
            "times",
            // time
            "clock_gettime",
            "clock_getres",
            "clock_nanosleep",
            "gettimeofday",
            // sync
            "futex",
            "futex_waitv",
            "futex_time64",
            "nanosleep",
            "poll",
            "epoll_create1",
            "epoll_ctl",
            "epoll_pwait",
            "ppoll",
            "select",
            "pselect6",
            "eventfd2",
            "timerfd_create",
            "timerfd_settime",
            // networking
            "socket",
            "socketpair",
            "connect",
            "bind",
            "listen",
            "accept",
            "accept4",
            "getsockname",
            "getpeername",
            "sendto",
            "recvfrom",
            "sendmsg",
            "recvmsg",
            "setsockopt",
            "getsockopt",
            "shutdown",
            "socketcall",
            // shared memory / ipc
            "shmget",
            "shmat",
            "shmdt",
            "semget",
            "semop",
            "semctl",
            "semtimedop",
            "msgget",
            "msgsnd",
            "msgrcv",
            "msgctl",
            // threading
            "set_thread_area",
            "set_tls",
            // misc kernel interfaces a loader or libc may touch
            "gettid",
            "getrandom",
            "sysinfo",
            "sched_yield",
            "sched_getaffinity",
            "membarrier",
            "rseq",
            "set_robust_list",
            "set_tid_address",
        ];
        let mut set: Vec<String> = BASE.iter().map(|s| s.to_string()).collect();
        set.sort();
        set.dedup();
        Self {
            default_action: SeccompAction::Errno(1), // EPERM
            allow: set,
        }
    }

    /// Refuses profiles with a nonsense default or empty/ill-formed syscall
    /// names. Kept portable (no kernel knowledge) so the engine can validate
    /// user-authored profiles on any host.
    pub fn validate(&self) -> Result<(), &'static str> {
        for name in &self.allow {
            if name.is_empty()
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
            {
                return Err("syscall name must be `[a-z0-9_]+`");
            }
        }
        if self.allow.windows(2).any(|w| w[0] == w[1])
            || !self.allow.windows(2).all(|w| *w[0] <= *w[1])
        {
            return Err("syscall allowlist must be sorted and deduplicated");
        }
        // A default that allows everything while listing an allowlist is
        // contradictory and always a config bug, never a security posture.
        if self.default_action == SeccompAction::Allow && !self.allow.is_empty() {
            return Err("default_action Allow with a non-empty allowlist is nonsensical");
        }
        Ok(())
    }
}

impl Default for SeccompProfile {
    fn default() -> Self {
        Self::base()
    }
}

/// A resource that gets an explicit `setrlimit` before exec.
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
    PartialOrd,
    Ord,
)]
#[non_exhaustive]
pub enum RlimitResource {
    /// `RLIMIT_NOFILE` — the fd table ceiling.
    NoFile,
    /// `RLIMIT_NPROC` — processes per uid.
    Nproc,
    /// `RLIMIT_STACK`.
    Stack,
    /// `RLIMIT_CORE`.
    Core,
    /// `RLIMIT_DATA`.
    Data,
    /// `RLIMIT_AS` — address space.
    AddressSpace,
}

impl RlimitResource {
    /// The `getrlimit(2)` name, for logs and `inspect`.
    pub const fn name(self) -> &'static str {
        match self {
            RlimitResource::NoFile => "RLIMIT_NOFILE",
            RlimitResource::Nproc => "RLIMIT_NPROC",
            RlimitResource::Stack => "RLIMIT_STACK",
            RlimitResource::Core => "RLIMIT_CORE",
            RlimitResource::Data => "RLIMIT_DATA",
            RlimitResource::AddressSpace => "RLIMIT_AS",
        }
    }
}

/// One `setrlimit` entry applied between the namespace setup and `execve`.
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
pub struct Rlimit {
    /// Which limit.
    pub resource: RlimitResource,
    /// Soft limit (what the process sees).
    pub soft: u64,
    /// Hard limit (what root could raise to).
    pub hard: u64,
}

/// The complete, self-contained description of one container boundary,
/// authored by the daemon's spawner and consumed by the re-exec'd
/// `r3s container-init` (ADR-0004).
///
/// Paths are `String` for the same reason `ContainerSpec` keeps them as
/// strings: the record must round-trip through the archived and JSON forms
/// without `PathBuf`'s platform baggage.
#[derive(
    Archive, RkyvSerialize, RkyvDeserialize, Serialize, Deserialize, Clone, Debug, PartialEq, Eq,
)]
pub struct ChildSetup {
    /// Absolute path of the directory that becomes `/` after `pivot_root`.
    pub rootfs: String,
    /// Absolute path of a user namespace to `setns` into first (rootless
    /// mode only): the container init joins the daemon's userns so it is
    /// already mapped before it creates the container's own.
    pub userns_fd: Option<String>,
    /// The `root` *inside* the user namespace, applied right after `setns`.
    pub inside_uid: Option<u32>,
    /// The namespaces to create via `unshare`.
    pub ns: NamespaceFlags,
    /// Declared bind mounts, applied after `/proc`/`/dev`/`/sys`.
    pub mounts: Vec<MountSpec>,
    /// Explicit `setrlimit` entries.
    pub rlimits: Vec<Rlimit>,
    /// Capabilities the container keeps. Empty is the default and means
    /// "bounding set dropped, nothing requested" (ADR-0007).
    pub capabilities: Vec<Capability>,
    /// The seccomp profile installed the last step before `execve`.
    pub seccomp: Option<SeccompProfile>,
    /// The payload's argv; `argv[0]` must be absolute.
    pub argv: Vec<String>,
    /// Environment, in order; each carries its own `secret` flag.
    pub env: Vec<EnvVar>,
    /// The hostname set in the new UTS namespace.
    pub hostname: String,
    /// Bind `/sys` read-only in the container.
    pub readonly_sys: bool,
}

impl ChildSetup {
    /// Default rlimits the engine always applies, even for a spec that
    /// requests none: an unbounded fd table is the classic prelude to an
    /// escape via a resource the kernel does not otherwise cap.
    pub fn default_rlimits() -> Vec<Rlimit> {
        vec![Rlimit {
            resource: RlimitResource::NoFile,
            soft: 1024,
            hard: 1024,
        }]
    }

    /// Builds the record the spawner writes, spreading the spec onto the
    /// isolation-plane fields the container boundary fixes.
    ///
    /// `rootfs` is the absolute host path of the image root, decided by the
    /// spawner (it lives under the declared bundle dir).
    pub fn from_spec(spec: &ContainerSpec, rootfs: impl Into<String>) -> Self {
        Self {
            rootfs: rootfs.into(),
            userns_fd: None,
            inside_uid: spec.rootless.then_some(0),
            ns: if spec.rootless {
                NamespaceFlags::rootless()
            } else {
                NamespaceFlags::standard()
            },
            mounts: spec.mounts.clone(),
            rlimits: Self::default_rlimits(),
            capabilities: Vec::new(),
            seccomp: Some(SeccompProfile::base()),
            argv: spec.argv.clone(),
            env: spec.env.clone(),
            hostname: spec.hostname.clone(),
            readonly_sys: true,
        }
    }

    /// Refuses records that would escape their own boundary: a relative
    /// rootfs, an argv that resolves against the host `PATH`, a target that
    /// walks up, or an embedded NUL is a mistake no kernel-side check can
    /// recover from. Mirrors `ContainerSpec::validate` plus the fields only
    /// this record has.
    pub fn validate(&self) -> Result<(), ChildSetupError> {
        const NUL: &str = "embedded NUL byte";
        if !self.rootfs.starts_with('/') {
            return Err(ChildSetupError::RootfsRelative);
        }
        if self.argv.is_empty() {
            return Err(ChildSetupError::EmptyArgv);
        }
        if !self.argv[0].starts_with('/') {
            return Err(ChildSetupError::Argv0Relative);
        }
        for arg in &self.argv {
            if arg.as_bytes().contains(&0) {
                return Err(ChildSetupError::Invalid(String::from(NUL)));
            }
        }
        for (i, var) in self.env.iter().enumerate() {
            if var.name.is_empty() || var.name.contains('=') || var.value.as_bytes().contains(&0) {
                return Err(ChildSetupError::InvalidEnv(i));
            }
        }
        if self.hostname.is_empty() || self.hostname.as_bytes().contains(&0) {
            return Err(ChildSetupError::InvalidHostname);
        }
        if self.rootfs.as_bytes().contains(&0) || self.hostname.as_bytes().contains(&0) {
            return Err(ChildSetupError::Invalid(String::from(NUL)));
        }
        for m in &self.mounts {
            if !m.target.starts_with('/') {
                return Err(ChildSetupError::RelativeMount);
            }
            if m.target.split('/').any(|component| component == "..") {
                return Err(ChildSetupError::Traversal);
            }
        }
        if let Some(path) = &self.userns_fd
            && !path.starts_with('/')
        {
            return Err(ChildSetupError::RelativeUserns);
        }
        if let Some(profile) = &self.seccomp {
            profile
                .validate()
                .map_err(|why| ChildSetupError::InvalidSeccomp(why.to_owned()))?;
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChildSetupError {
    #[error("rootfs must be an absolute path")]
    RootfsRelative,
    #[error("argv must not be empty")]
    EmptyArgv,
    #[error("argv[0] must be an absolute path inside the rootfs")]
    Argv0Relative,
    #[error("invalid ChildSetup: {0}")]
    Invalid(String),
    #[error("env[{0}] has an empty or '='-containing name, or a NUL value")]
    InvalidEnv(usize),
    #[error("hostname must be non-empty and NUL-free")]
    InvalidHostname,
    #[error("mount target must be absolute")]
    RelativeMount,
    #[error("mount target must not contain '..'")]
    Traversal,
    #[error("userns fd path must be absolute")]
    RelativeUserns,
    #[error("invalid seccomp profile: {0}")]
    InvalidSeccomp(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::ImageRef;
    use crate::types::{ContainerSpec, EnvVar};

    fn spec() -> ContainerSpec {
        ContainerSpec::new(
            crate::id::ContainerId::from_bytes([1; 16]),
            "web",
            ImageRef::parse("alpine:3").expect("parses"),
        )
    }

    #[test]
    fn standard_namespace_flags_have_the_engine_defaults() {
        let ns = NamespaceFlags::default();
        assert!(!ns.user && !ns.time);
        assert!(ns.mnt);
        let _ = NamespaceFlags {
            ipc: true,
            uts: true,
            net: true,
            pid: true,
            mnt: true,
            cgroup: true,
            ..ns
        };
    }

    #[test]
    fn from_spec_spreads_the_container_boundary() {
        let mut s = spec();
        s.hostname = "web-1".into();
        s.argv = vec!["/bin/sh".to_owned(), "-c".to_owned(), "sleep 1".to_owned()];
        s.env = vec![EnvVar::new("PATH", "/usr/bin:/bin")];
        s.rootless = false;

        let setup = ChildSetup::from_spec(&s, "/var/lib/r3s/containers/x/rootfs");
        assert_eq!(setup.rootfs, "/var/lib/r3s/containers/x/rootfs");
        assert!(setup.ns.mnt && setup.ns.pid && setup.ns.net && setup.ns.uts && setup.ns.ipc);
        assert!(!setup.ns.user && !setup.ns.time);
        assert!(setup.inside_uid.is_none());
        assert!(setup.userns_fd.is_none());
        assert_eq!(setup.argv[0], "/bin/sh");
        assert_eq!(setup.env[0].name, "PATH");
        assert_eq!(setup.hostname, "web-1");
        // The default posture: read-only sysfs, a base seccomp profile,
        // no requested capabilities, an fd-table rlimit.
        assert!(setup.readonly_sys);
        assert!(setup.seccomp.is_some());
        assert!(setup.capabilities.is_empty());
        assert_eq!(setup.rlimits.len(), 1);
        assert_eq!(setup.rlimits[0].resource, RlimitResource::NoFile);
        setup.validate().expect("base setup validates");
    }

    #[test]
    fn rootless_mode_requests_the_user_namespace_and_mapping() {
        let mut s = spec();
        s.rootless = true;
        let setup = ChildSetup::from_spec(&s, "/r");
        assert!(setup.ns.user);
        assert_eq!(setup.inside_uid, Some(0));
    }

    #[test]
    fn validate_rejects_boundary_escapes() {
        let ok = ChildSetup::from_spec(&spec(), "/r");
        ok.validate().expect("valid");

        let mut bad = ok.clone();
        bad.rootfs = "relative".into();
        assert_eq!(bad.validate(), Err(ChildSetupError::RootfsRelative));

        let mut bad = ok.clone();
        bad.argv = vec!["sh".into()];
        assert_eq!(bad.validate(), Err(ChildSetupError::Argv0Relative));

        let mut bad = ok.clone();
        bad.argv = vec![];
        assert_eq!(bad.validate(), Err(ChildSetupError::EmptyArgv));

        let mut bad = ok.clone();
        bad.argv = vec!["/bin/sh\u{0}x".into()];
        assert_eq!(
            bad.validate(),
            Err(ChildSetupError::Invalid("embedded NUL byte".into()))
        );

        let mut bad = ok.clone();
        bad.hostname.clear();
        assert_eq!(bad.validate(), Err(ChildSetupError::InvalidHostname));

        let mut bad = ok.clone();
        bad.mounts.push(MountSpec::bind("/h", "/data/.."));
        assert_eq!(bad.validate(), Err(ChildSetupError::Traversal));

        let mut bad = ok.clone();
        bad.userns_fd = Some("relative/path".into());
        assert_eq!(bad.validate(), Err(ChildSetupError::RelativeUserns));
    }

    #[test]
    fn setup_round_trips_through_archive_and_json() {
        let ok = ChildSetup::from_spec(&spec(), "/r");
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&ok).expect("archives");
        let live: ChildSetup =
            rkyv::from_bytes::<ChildSetup, rkyv::rancor::Error>(&bytes).expect("deserialises");
        assert_eq!(live, ok);

        let json = serde_json::to_vec(&ok).expect("serialises");
        let back: ChildSetup = serde_json::from_slice(&json).expect("deserialises");
        assert_eq!(back, ok);
    }

    #[test]
    fn capability_names_round_trip() {
        for cap in Capability::ALL {
            assert_eq!(Capability::parse(cap.name()), Some(*cap));
        }
        assert_eq!(
            Capability::parse("CAP_NET_BIND_SERVICE"),
            Some(Capability::NetBindService)
        );
        assert_eq!(
            Capability::parse("cap_sys_chroot"),
            Some(Capability::SysChroot)
        );
        assert_eq!(Capability::parse("CAP_NOT_CAP"), None);
    }

    #[test]
    fn base_seccomp_profile_covers_exit_and_io_and_validates() {
        let base = SeccompProfile::base();
        base.validate().expect("base validates");
        assert!(base.allow.iter().any(|s| s == "exit_group"));
        assert!(base.allow.iter().any(|s| s == "write"));
        assert!(base.allow.iter().any(|s| s == "openat"));
        assert!(base.allow.iter().any(|s| s == "mmap"));
        assert!(base.allow.iter().any(|s| s == "execve"));
        assert!(base.default_action == SeccompAction::Errno(1));
        // Sorted and deduplicated, so the profile archives deterministically.
        assert!(base.allow.windows(2).all(|w| *w[0] <= *w[1]));
        assert!(!base.allow.windows(2).any(|w| w[0] == w[1]));
    }

    #[test]
    fn seccomp_validation_rejects_idiots() {
        assert_eq!(
            SeccompProfile {
                default_action: SeccompAction::Allow,
                allow: vec!["read".into()],
            }
            .validate(),
            Err("default_action Allow with a non-empty allowlist is nonsensical")
        );
        assert_eq!(
            SeccompProfile {
                default_action: SeccompAction::Kill,
                allow: vec!["Bad^.Name".into()],
            }
            .validate(),
            Err("syscall name must be `[a-z0-9_]+`")
        );
    }
}
