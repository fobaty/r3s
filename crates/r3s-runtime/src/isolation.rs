//! The isolation plane: namespaces, `pivot_root`, mounts, rlimits,
//! capabilities and seccomp for one container (ADR-0004, ADR-0007).
//!
//! This is stage 4 of the build plan (docs/ARCHITECTURE.md §1.3, §3.3). It has
//! two halves, split on a hard rule:
//!
//! * a **pure** half — namespace-name/path arithmetic, config layout, the
//!   capability bitmaps — that compiles and is unit-tested on any host, like
//!   the `fakefs` plane does for cgroups;
//! * a **Linux** half — every syscall. The kernel API nix/libc expose here is
//!   Linux-only, and the module is `#[cfg(target_os = "linux")]` for exactly
//!   that reason (this host is a macOS dev box; the aarch64 cross-build and
//!   the CI ubuntu job compile it, and `scripts/ondevice.sh` runs it).
//!
//! Shape of one lifecycle (the contract `r3s container-init` implements):
//!
//! ```text
//! setns(userns)  →  unshare(mnt uts ipc net cgroup [pid] [time])  →  sethostname
//! make / r-private  →  bind rootfs  →  mkdir mount points
//! pivot_root  →  chdir("/")  →  umount2(old root, MNT_DETACH)
//! mount /proc /dev /sys + spec binds  →  mknod/links in /dev
//! rlimits  →  drop caps  →  no_new_privs  →  seccomp  →  fork → execve
//! ```
//!
//! The everything-from-`unshare`-onwards runs in the re-exec'd
//! `container-init`, a fresh single-threaded process, so allocation is
//! allowed until the final `fork`. The child, PID 1 of the new PID namespace,
//! touches **only** async-signal-safe syscalls between `fork` and `execve`
//! (setsid, dup2, `_exit`) — UNSAFE.md §3. A failure anywhere leaks loudly
//! (`_exit(127)`) rather than unwinding a half-configured namespace.
//!
//! Every `unsafe` block cites its J-row from docs/UNSAFE.md.

use std::io;
use std::path::{Path, PathBuf};
use std::process;

use nix::unistd::Pid;
use r3s_proto::{Capability, ChildSetup, RlimitResource, SeccompAction, SeccompProfile, NamespaceFlags};
use thiserror::Error;

/// Filename of the per-container isolation record under its run directory.
pub const INIT_CONFIG_FILE: &str = "init.rkyv";

/// The namespaces, in the fixed order the kernel's `/proc/<pid>/ns` names
/// them. A `true` flag means "the engine creates this namespace" and is the
/// one piece of host-side logic `container-init` shares: it must not guess
/// which namespaces it asked for.
pub fn namespace_names(ns: NamespaceFlags) -> Vec<&'static str> {
    let mut out = Vec::with_capacity(8);
    if ns.user {
        out.push("user");
    }
    if ns.ipc {
        out.push("ipc");
    }
    if ns.uts {
        out.push("uts");
    }
    if ns.net {
        out.push("net");
    }
    if ns.pid {
        out.push("pid");
    }
    if ns.mnt {
        out.push("mnt");
    }
    if ns.cgroup {
        out.push("cgroup");
    }
    if ns.time {
        out.push("time");
    }
    out
}

/// `/proc/<pid>/ns/<name>` for a pid as seen by whatever namespace we run in,
/// i.e. the path the daemon holds before it passes the fd across.
pub fn namespace_fd_path(pid: Pid, name: &str) -> PathBuf {
    PathBuf::from(format!("/proc/{pid}/ns/{name}"))
}

/// Where the [`ChildSetup`] for a container lives under a run root.
///
/// The record is written once by the spawner and read once by
/// `container-init`; keeping it at a path derivable from the container id
/// alone means the init can find it without owning a handle to the store.
pub fn init_config_path(run_root: &Path, container: &str) -> PathBuf {
    run_root.join(container).join(INIT_CONFIG_FILE)
}

/// Failure of a container-boundary operation. Everything the daemon or the
/// init can hit is typed; the `Io` variants keep the path and the errno so
/// RUNBOOK fixes are unambiguous.
#[derive(Debug, Error)]
pub enum IsolationError {
    /// The [`ChildSetup`] the spawner handed over failed its own contract.
    /// Caught before the first syscall, so this is always an operator config
    /// bug, never a kernel condition.
    #[error("isolation config invalid: {0}")]
    InvalidConfig(#[from] r3s_proto::ChildSetupError),

    /// A kernel operation failed. `phase` names the step (RUNBOOK §4), the
    /// source keeps the errno, and the `path` is what it was touching.
    #[error("isolation {phase} on {path}: {source}")]
    Io {
        /// Which step (from the `write!`-style names in RUNBOOK §4).
        phase: &'static str,
        /// The object being operated on.
        path: PathBuf,
        /// The errno.
        source: io::Error,
    },

    /// The kernel refused to create a namespace that the setup recorded. A
    /// capability/`seccomp`-interaction or a kernel build without the feature
    /// — the setup record and the kernel disagree.
    #[error("namespace {name} unavailable: {source}")]
    Namespace {
        /// The `CLONE_*` short name.
        name: &'static str,
        /// The errno.
        source: io::Error,
    },

    /// The seccomp profile allowed a syscall this architecture has no number
    /// for. Reported so the operator sees the mismatch rather than a
    /// mysteriously shut container.
    #[error("seccomp profile names an unsupported syscall: {0}")]
    UnsupportedSyscall(String),

    /// The re-exec'd init is a regular process; a raw `fork` failure here
    /// means the whole container fails to start (parent stays functional).
    #[error("failed to fork the container's PID 1: {0}")]
    Fork(#[from] nix::errno::Errno),
}

impl IsolationError {
    fn errno(phase: &'static str, path: &Path, e: impl Into<io::Error>) -> Self {
        IsolationError::Io {
            phase,
            path: path.to_path_buf(),
            source: e.into(),
        }
    }
}

// ===========================================================================
// Linux half — every syscall lives behind the compile-time gate.
// ===========================================================================

/// Drops capability `CAP_CLEARED`, returning the two 32-bit words of a
/// version-3 capability set. Pure so the bit arithmetic can be unit-tested on
/// any host; the values mirror `<linux/capability.h>`, a stable UAPI.
pub fn cap_data(keep: &[Capability]) -> (u32, u32) {
    let clear = |c: Capability| -> Option<u32> {
        Some(match c {
            Capability::Chown => 0,
            Capability::DacOverride => 1,
            Capability::DacReadSearch => 2,
            Capability::Fowner => 3,
            Capability::Fsetid => 4,
            Capability::Kill => 5,
            Capability::Setgid => 6,
            Capability::Setuid => 7,
            Capability::Setpcap => 8,
            Capability::NetBindService => 10,
            Capability::NetRaw => 13,
            Capability::SysChroot => 18,
            Capability::Mknod => 27,
            Capability::AuditWrite => 29,
            Capability::Setfcap => 31,
            _ => return None,
        })
    };
    let mut w0 = 0u32;
    let mut w1 = 0u32;
    for cap in keep {
        let Some(n) = clear(*cap) else { continue };
        if n < 32 {
            w0 |= 1u32 << n;
        } else {
            w1 |= 1u32 << (n - 32);
        }
    }
    (w0, w1)
}

/// Number of the highest capability the kernel knows, bounds the bounding-set
/// drop loop. Mirrors `CAP_LAST_CAP`.
pub const CAP_LAST: u32 = 40;

#[cfg(target_os = "linux")]
mod linux {
    use super::*;

    #[cfg(test)]
    mod tests;

    use std::ffi::{CStr, CString};
    use std::os::unix::io::{BorrowedFd, RawFd};

    use nix::fcntl::OFlag;
    use nix::mount::{mount, umount2, MsFlags, MntFlags};
    use nix::sched::{setns, unshare, CloneFlags};
    use nix::sys::prctl;
    use nix::sys::resource::{setrlimit, Resource, Rlim};
    use nix::sys::stat::{makedev, mkdir, mknod, Mode, SFlag};
    use nix::unistd::{fchdir, fork, pivot_root, sethostname, setresgid, setresuid, setsid, ForkResult};
    use r3s_proto::MountSpec;

    /// The classic-pidns sequence needs the init's *parent* namespace to stay
    /// put while the child lands in the new one; the child is the payload and
    /// its PID is relayed by the caller, not waited on here (spawn.rs).
    const FD_SYNC: i32 = 3;

    // Kernel UAPI constants that `libc` does not carry (verified against
    // `<linux/mount.h>`, `<linux/audit.h>`, `<linux/capability.h>`). Stable.
    const MOUNT_ATTR_RDONLY: u64 = 0x1;
    const AT_RECURSIVE: u64 = 0x4000;
    const AT_EMPTY_PATH: u64 = 0x1000;
    const SYS_MOUNT_SETATTR: libc::c_long = 442; // aarch64 == x86_64
    const _LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
    const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
    const AUDIT_ARCH_AARCH64: u32 = 0xC000_00B7;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CapHeader {
        version: u32,
        pid: i32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct MountAttr {
        attr_set: u64,
        attr_clr: u64,
        propagation: u64,
        userns_fd: u64,
    }

    fn io_errno(e: nix::errno::Errno) -> io::Error {
        io::Error::from_raw_os_error(e as i32)
    }

    /// Maps the record's namespace booleans onto the kernel's clone flags.
    fn clone_flags(ns: NamespaceFlags) -> CloneFlags {
        let mut f = CloneFlags::empty();
        if ns.user {
            f |= CloneFlags::CLONE_NEWUSER;
        }
        if ns.ipc {
            f |= CloneFlags::CLONE_NEWIPC;
        }
        if ns.uts {
            f |= CloneFlags::CLONE_NEWUTS;
        }
        if ns.net {
            f |= CloneFlags::CLONE_NEWNET;
        }
        if ns.pid {
            f |= CloneFlags::CLONE_NEWPID;
        }
        if ns.mnt {
            f |= CloneFlags::CLONE_NEWNS;
        }
        if ns.cgroup {
            f |= CloneFlags::CLONE_NEWCGROUP;
        }
        f
    }

    /// Runs the whole boundary setup for a container and forks the payload.
    ///
    /// `stdio` is the fd triad the payload inherits on `0`/`1`/`2`. It returns
    /// the payload's PID **as the init sees it** (the PID-1 process in the new
    /// namespace); the caller relays that pid to the daemon over its sync fd.
    pub fn child_main(setup: &ChildSetup, stdio: [RawFd; 3]) -> Result<Pid, IsolationError> {
        setup.validate()?;

        // Enter the daemon's user namespace first (rootless only): every later
        // operation is then already mapped, so one `setns` covers the grand
        // total of user-namespace plumbing.
        if let Some(path) = &setup.userns_fd {
            let fd = open_ns(path)?;
            // SAFETY: J-05. `setns` needs no unsafe; the fd is opened above.
            setns(BorrowedFd::borrow_raw(fd), CloneFlags::CLONE_NEWUSER)
                .map_err(|e| IsolationError::Namespace {
                    name: "setns(user)",
                    source: io_errno(e),
                })?;
            if let Some(uid) = setup.inside_uid {
                // The payload runs as its root inside the namespace; the
                // namespace's own mapping already translated that uid, so this
                // is only ever identity within the new namespace.
                setresuid(uid.into(), uid.into(), uid.into())
                    .map_err(|e| IsolationError::errno("setresuid", Path::new("/"), io_errno(e)))?;
            }
        }

        // Create the container's own namespaces (PID included; it is PID 1's
        // namespace — the child of the fork below lands in it, and the caller
        // is not moved by unshare(CLONE_NEWPID) — ADR-0004).
        let flags = clone_flags(setup.ns);
        unshare(flags).map_err(|e| {
            IsolationError::Namespace {
                name: "unshare",
                source: io_errno(e),
            }
        })?;
        if setup.ns.time {
            // `nix::sched` has no CLONE_NEWTIME yet; the flag is the libc
            // constant even on the gnu/musl builds we target.
            let res = unsafe {
                libc::unshare(libc::CLONE_NEWTIME)
            };
            if res != 0 {
                return Err(IsolationError::Namespace {
                    name: "unshare(time)",
                    source: io::Error::last_os_error(),
                });
            }
        }

        // Hostname inside the fresh UTS namespace, before anything that logs.
        if !setup.hostname.is_empty() {
            sethostname(&setup.hostname)
                .map_err(|e| IsolationError::errno("sethostname", Path::new("/"), io_errno(e)))?;
        }

        // The mount namespace must not leak the host hierarchy; everything the
        // rootfs dance does below is under this `rprivate`.
        make_rprivate()?;

        let root = Path::new(&setup.rootfs);
        bind_self(root)?;

        // A pivot_root needs somewhere to park the old root that is *inside*
        // the new one, hidden from the payload afterwards.
        let put_old = root.join(".r3s_old_root");
        prepare_tree(&setup, root, &put_old)?;

        pivot_root_with(root, &put_old)?;

        make_readonly(root)?;

        populate_root(&setup)?;

        apply_rlimits(setup)?;
        drop_caps(&setup.capabilities)?;

        prctl::set_no_new_privs()
            .map_err(|e| IsolationError::errno("no_new_privs", Path::new("/"), io_errno(e)))?;

        if let Some(profile) = &setup.seccomp {
            install_seccomp(profile)?;
        }

        // Everything from here on is the async-signal-safe zone.
        fork_payload(setup, stdio)
    }

    fn open_ns(path: &str) -> Result<RawFd, IsolationError> {
        nix::fcntl::open(
            path,
            OFlag::O_RDONLY | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| IsolationError::errno("open(ns)", Path::new(path), io_errno(e)))
    }

    /// `mount --make-rprivate /` in the fresh mount namespace.
    fn make_rprivate() -> Result<(), IsolationError> {
        mount(
            None::<&str>,
            "/",
            None::<&str>,
            MsFlags::MS_REC | MsFlags::MS_PRIVATE,
            None::<&str>,
        )
        .map_err(|e| IsolationError::errno("make-rprivate", Path::new("/"), io_errno(e)))
    }

    fn bind_self(root: &Path) -> Result<(), IsolationError> {
        mount(
            Some(root),
            root,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REC,
            None::<&str>,
        )
        .map_err(|e| IsolationError::errno("bind(rootfs)", root, io_errno(e)))
    }

    fn mkdir_p(root: &Path, rel: &Path) -> Result<(), IsolationError> {
        let path = root.join(rel);
        if path.exists() {
            return Ok(());
        }
        std::fs::create_dir_all(&path)
            .map_err(|e| IsolationError::errno("mkdir_p", &path, e))
    }

    /// Creates every mount point the payload will see under the (still live)
    /// rootfs: `/proc`, `/dev`, `/sys`, the bind targets and `put_old`.
    fn prepare_tree(setup: &ChildSetup, root: &Path, put_old: &Path) -> Result<(), IsolationError> {
        for dir in ["proc", "dev", "sys"] {
            mkdir_p(root, Path::new(dir))?;
        }
        for m in &setup.mounts {
            mkdir_p(root, Path::new(&m.target))?;
        }
        mkdir_p(root, put_old.strip_prefix(root).unwrap_or(Path::new(".")))?;
        Ok(())
    }

    fn pivot_root_with(root: &Path, put_old: &Path) -> Result<(), IsolationError> {
        pivot_root(root, put_old)
            .map_err(|e| IsolationError::errno("pivot_root", root, io_errno(e)))?;
        fchdir(
            BorrowedFd::borrow_raw(
                nix::fcntl::open("/", OFlag::O_RDONLY | OFlag::O_CLOEXEC, Mode::empty())
                    .map_err(|e| IsolationError::errno("open(/)", Path::new("/"), io_errno(e)))?,
            ),
        )
        .map_err(|e| IsolationError::errno("chdir(/)", Path::new("/"), io_errno(e)))?;
        umount2("/.r3s_old_root", MntFlags::MNT_DETACH)
            .map_err(|e| IsolationError::errno("umount(old root)", Path::new("/.r3s_old_root"), io_errno(e)))
    }

    /// Makes the *whole* current tree read-only recursively, so a boxed image
    /// cannot be written through. The `mount_setattr` syscall is not exposed
    /// by nix or rustix (rustix 1.x stubs it), so it is one raw syscall (J-05).
    fn make_readonly(root: &Path) -> Result<(), IsolationError> {
        let c = CString::new(root.as_os_str().as_encoded_bytes())
            .map_err(|_| IsolationError::UnsupportedSyscall("rootfs path NUL".into()))?;
        let attr = MountAttr {
            attr_set: MOUNT_ATTR_RDONLY,
            attr_clr: 0,
            propagation: 0,
            userns_fd: 0,
        };
        // SAFETY: J-05. The buffer outlives the syscall; the kernel reads
        // `attr` and validates the path against our permissions in-tree.
        let res = unsafe {
            libc::syscall(
                SYS_MOUNT_SETATTR,
                libc::AT_FDCWD,
                c.as_ptr(),
                AT_RECURSIVE | AT_EMPTY_PATH,
                &attr,
                0u64,
            )
        };
        if res != 0 {
            return Err(IsolationError::errno(
                "mount_setattr(RDONLY)",
                root,
                io::Error::last_os_error(),
            ));
        }
        Ok(())
    }

    const DEV_NODES: &[(usize, usize)] = &[(1, 3), (1, 5), (1, 7), (1, 8), (1, 9), (5, 0)];

    fn populate_root(setup: &ChildSetup) -> Result<(), IsolationError> {
        mount(
            Some("proc"),
            "/proc",
            Some("proc"),
            MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV,
            None::<&str>,
        )
        .map_err(|e| IsolationError::errno("mount(/proc)", Path::new("/proc"), io_errno(e)))?;

        mount(
            Some("tmpfs"),
            "/dev",
            Some("tmpfs"),
            MsFlags::MS_NOSUID,
            None::<&str>,
        )
        .map_err(|e| IsolationError::errno("mount(/dev)", Path::new("/dev"), io_errno(e)))?;

        // The device nodes a base image's binaries legitimately open. `mknod`
        // still needs CAP_MKNOD, which is why it runs before `drop_caps`.
        for (major, minor) in DEV_NODES {
            let dev = PathBuf::from(format!("/dev/{major}{minor}"));
            let _ = dev;
        }
        for (major, minor, name) in [
            (1, 3, "null"),
            (1, 5, "zero"),
            (1, 7, "full"),
            (1, 8, "random"),
            (1, 9, "urandom"),
            (5, 0, "tty"),
        ] {
            mknod(
                &format!("/dev/{name}"),
                SFlag::S_IFCHR,
                Mode::from_bits_truncate(0o666),
                makedev(major as u64, minor as u64),
            )
            .map_err(|e| IsolationError::errno("mknod(/dev)", Path::new("/dev"), io_errno(e)))?;
        }
        for (link, target) in [
            ("/dev/fd", "/proc/self/fd"),
            ("/dev/stdin", "/proc/self/fd/0"),
            ("/dev/stdout", "/proc/self/fd/1"),
            ("/dev/stderr", "/proc/self/fd/2"),
        ] {
            std::os::unix::fs::symlink(target, link)
                .map_err(|e| IsolationError::errno("symlink(/dev)", Path::new(link), e))?;
        }

        mkdir_p(Path::new("/"), Path::new("dev/pts"))?;
        mount(
            Some("devpts"),
            "/dev/pts",
            Some("devpts"),
            MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
            Some("newinstance,ptmxmode=0666"),
        )
        .map_err(|e| IsolationError::errno("mount(/dev/pts)", Path::new("/dev/pts"), io_errno(e)))?;
        std::os::unix::fs::symlink("pts/ptmx", "/dev/ptmx")
            .map_err(|e| IsolationError::errno("symlink(/dev/ptmx)", Path::new("/dev/ptmx"), e))?;

        mkdir_p(Path::new("/"), Path::new("dev/shm"))?;
        mount(
            Some("tmpfs"),
            "/dev/shm",
            Some("tmpfs"),
            MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
            Some("mode=1777"),
        )
        .map_err(|e| IsolationError::errno("mount(/dev/shm)", Path::new("/dev/shm"), io_errno(e)))?;

        let sys_flags = if setup.readonly_sys {
            MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV
        } else {
            MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV
        };
        mount(
            Some("sysfs"),
            "/sys",
            Some("sysfs"),
            sys_flags,
            None::<&str>,
        )
        .map_err(|e| IsolationError::errno("mount(/sys)", Path::new("/sys"), io_errno(e)))?;

        for m in &setup.mounts {
            apply_bind_mount(m)?;
        }
        Ok(())
    }

    fn apply_bind_mount(m: &MountSpec) -> Result<(), IsolationError> {
        let flags = bind_flags(m);
        let target = PathBuf::from(&m.target);
        mount(
            Some(&m.source),
            &target,
            None::<&str>,
            flags,
            None::<&str>,
        )
        .map_err(|e| IsolationError::errno("bind-mount", &target, io_errno(e)))?;

        if m.readonly {
            mount(
                Some(&m.source),
                &target,
                None::<&str>,
                flags | MsFlags::MS_REMOUNT | MsFlags::MS_BIND,
                None::<&str>,
            )
            .map_err(|e| IsolationError::errno("bind-remount-ro", &target, io_errno(e)))?;
        }
        Ok(())
    }

    fn bind_flags(m: &MountSpec) -> MsFlags {
        let mut f = MsFlags::MS_BIND;
        if m.nosuid {
            f |= MsFlags::MS_NOSUID;
        }
        if m.nodev {
            f |= MsFlags::MS_NODEV;
        }
        if m.noexec {
            f |= MsFlags::MS_NOEXEC;
        }
        f
    }

    fn apply_rlimits(setup: &ChildSetup) -> Result<(), IsolationError> {
        for lim in &setup.rlimits {
            let resource = match lim.resource {
                RlimitResource::NoFile => Resource::RLIMIT_NOFILE,
                RlimitResource::Nproc => Resource::RLIMIT_NPROC,
                RlimitResource::Stack => Resource::RLIMIT_STACK,
                RlimitResource::Core => Resource::RLIMIT_CORE,
                RlimitResource::Data => Resource::RLIMIT_DATA,
                RlimitResource::AddressSpace => Resource::RLIMIT_AS,
            };
            setrlimit(resource, Rlim::from_raw(lim.soft), Rlim::from_raw(lim.hard))
                .map_err(|e| IsolationError::errno("setrlimit", Path::new("/"), io_errno(e)))?;
        }
        Ok(())
    }

    /// Version-3 `capset`: keep exactly what the record requested, clear every
    /// other effective/permitted bit. Then drop the whole bounding set so a
    /// later exec can never restore a capability (ADR-0007).
    fn drop_caps(keep: &[Capability]) -> Result<(), IsolationError> {
        let (w0, w1) = super::cap_data(keep);
        let header = CapHeader {
            version: _LINUX_CAPABILITY_VERSION_3,
            pid: 0,
        };
        let mut data = [CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        }; 2];
        data[0].effective = w0;
        data[0].permitted = w0;
        data[1].effective = w1;
        data[1].permitted = w1;
        // SAFETY: J-06. Header/data are plain aggregate copies with the exact
        // layout the kernel's `_LINUX_CAPABILITY_VERSION_3` expects.
        let res = unsafe { libc::capset(&header, data.as_mut_ptr()) };
        if res != 0 {
            return Err(IsolationError::errno("capset", Path::new("/"), io::Error::last_os_error()));
        }
        // Bounding set must fall in descending order: dropping one only needs
        // CAP_SETPCAP, but a half-cleared set is a security half-answer.
        for cap in (0..=super::CAP_LAST).rev() {
            // SAFETY: J-06. `PR_CAPBSET_DROP` with a 0..=CAP_LAST index.
            let res = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) };
            if res != 0 {
                let e = io::Error::last_os_error();
                if e.raw_os_error() != Some(libc::EPERM) {
                    return Err(IsolationError::errno("PR_CAPBSET_DROP", Path::new("/"), e));
                }
                // EPERM means the cap was already gone; continue.
            }
        }
        Ok(())
    }

    // ---------------- seccomp (J-07) ----------------

    /// A completed BPF filter. The `Vec` is the install target's authority:
    /// the kernel reads it, so it must outlive `install`.
    pub struct Filter {
        prog: Vec<libc::sock_filter>,
    }

    impl Filter {
        /// Builds the classic-BPF allowlist program for the *current*
        /// architecture. Unknown syscalls (a name this arch has no number for)
        /// are simply dropped — they cannot be invoked here anyway.
        pub fn build(profile: &SeccompProfile) -> Result<Self, IsolationError> {
            profile.validate()?;
            let arch = audit_arch();
            let mut prog = Vec::new();
            // Guard everything on the recorded architecture; a syscall number
            // from another arch must not match an allowlist entry.
            prog.push(sock(
                op(BPF_LD | BPF_W | BPF_ABS),
                0,
                0,
                4,
            ));
            prog.push(sock(op(BPF_JMP | BPF_JEQ | BPF_K), 0, 1, arch));
            prog.push(ret(default_rets(profile)?));

            // Load the syscall number and check each allowed syscall.
            let allow = prog.len(); // everything after this is per-syscall
            prog.push(sock(op(BPF_LD | BPF_W | BPF_ABS), 0, 0, 0));
            for name in &profile.allow {
                let Some(nr) = syscall_number(name) else {
                    continue;
                };
                // jeq nr → allow; else fall to the next comparison.
                prog.push(sock(op(BPF_JMP | BPF_JEQ | BPF_K), allow_jt(&prog, allow), 1, nr as u32));
            }
            prog.push(ret(default_rets(profile)?));
            prog.push(sock(op(BPF_RET | BPF_K), 0, 0, libc::SECCOMP_RET_ALLOW));
            Ok(Self { prog })
        }

        /// Installs the filter on the calling thread (the init has one thread).
        pub fn install(&self) -> Result<(), IsolationError> {
            let fprog = libc::sock_fprog {
                len: self.prog.len() as u16,
                filter: self.prog.as_ptr() as *mut libc::sock_filter,
            };
            // SAFETY: J-07. `fprog` refers to `self.prog`, alive for the call;
            // PR_SET_SECCOMP with MODE_FILTER only permits UID-0 or
            // CAP_SYS_ADMIN callers, which the init still has at this point.
            let res = unsafe {
                libc::prctl(
                    libc::PR_SET_SECCOMP,
                    libc::SECCOMP_MODE_FILTER,
                    &fprog,
                )
            };
            if res != 0 {
                return Err(IsolationError::errno(
                    "PR_SET_SECCOMP",
                    Path::new("/"),
                    io::Error::last_os_error(),
                ));
            }
            Ok(())
        }
    }

    fn install_seccomp(profile: &SeccompProfile) -> Result<(), IsolationError> {
        Filter::build(profile)?.install()
    }

    fn default_rets(profile: &SeccompProfile) -> Result<u32, IsolationError> {
        Ok(match profile.default_action {
            SeccompAction::Allow => libc::SECCOMP_RET_ALLOW,
            SeccompAction::Kill => libc::SECCOMP_RET_KILL_PROCESS,
            SeccompAction::Errno(e) => libc::SECCOMP_RET_ERRNO | (e as u32 & 0xffff),
        })
    }

    fn sock(code: u16, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
        libc::sock_filter { code, jt, jf, k }
    }

    fn op(class: u16) -> u16 {
        class
    }

    fn allow_jt(prog: &[libc::sock_filter], allow: usize) -> u8 {
        // Jump from after this instruction to the ALLOW at the end.
        let remaining = prog.len().saturating_sub(allow);
        if remaining > u8::MAX as usize {
            0xff
        } else {
            remaining as u8
        }
    }

    const BPF_LD: u16 = 0x00;
    const BPF_W: u16 = 0x00;
    const BPF_ABS: u16 = 0x20;
    const BPF_JMP: u16 = 0x05;
    const BPF_JEQ: u16 = 0x10;
    const BPF_JGT: u16 = 0x20;
    const BPF_K: u16 = 0x00;
    const BPF_RET: u16 = 0x06;

    fn audit_arch() -> u32 {
        #[cfg(target_arch = "aarch64")]
        {
            AUDIT_ARCH_AARCH64
        }
        #[cfg(target_arch = "x86_64")]
        {
            AUDIT_ARCH_X86_64
        }
        #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
        {
            0
        }
    }

    /// The syscall table for the current architecture, straight out of the
    /// platform's `libc` bindings — never hand-copied, so a cross build for a
    /// foreign arch is verified by the compiler itself. Names that exist on
    /// only one of our architectures are cfg-gated.
    fn syscall_number(name: &str) -> Option<libc::c_long> {
        #[cfg(target_arch = "x86_64")]
        {
            Some(match name {
                "read" => libc::SYS_read,
                "write" => libc::SYS_write,
                "open" => libc::SYS_open,
                "close" => libc::SYS_close,
                "stat" => libc::SYS_open,
                "fstat" => libc::SYS_fstat,
                "newfstatat" => libc::SYS_newfstatat,
                "access" => libc::SYS_access,
                "mkdir" => libc::SYS_mkdir,
                "readlink" => libc::SYS_readlink,
                "unlink" => libc::SYS_unlink,
                "rename" => libc::SYS_rename,
                "chmod" => libc::SYS_chmod,
                "truncate" => libc::SYS_truncate,
                "ftruncate" => libc::SYS_ftruncate,
                "openat" => libc::SYS_openat,
                "mkdirat" => libc::SYS_mkdirat,
                "unlinkat" => libc::SYS_unlinkat,
                "renameat" => libc::SYS_renameat,
                "readlinkat" => libc::SYS_readlinkat,
                "fchmod" => libc::SYS_fchmod,
                "fchmodat" => libc::SYS_fchmodat,
                "umask" => libc::SYS_umask,
                "fsync" => libc::SYS_fsync,
                "fdatasync" => libc::SYS_fdatasync,
                "dup" => libc::SYS_dup,
                "dup2" => libc::SYS_dup2,
                "dup3" => libc::SYS_dup3,
                "fcntl" => libc::SYS_fcntl,
                "ioctl" => libc::SYS_ioctl,
                "flock" => libc::SYS_flock,
                "fallocate" => libc::SYS_fallocate,
                "sendfile" => libc::SYS_sendfile,
                "lseek" => libc::SYS_lseek,
                "pread64" => libc::SYS_pread64,
                "pwrite64" => libc::SYS_pwrite64,
                "readv" => libc::SYS_readv,
                "writev" => libc::SYS_writev,
                "getdents64" => libc::SYS_getdents64,
                "mmap" => libc::SYS_mmap,
                "mprotect" => libc::SYS_mprotect,
                "munmap" => libc::SYS_munmap,
                "brk" => libc::SYS_brk,
                "madvise" => libc::SYS_madvise,
                "mlock" => libc::SYS_mlock,
                "munlock" => libc::SYS_munlock,
                "mremap" => libc::SYS_mremap,
                "msync" => libc::SYS_msync,
                "membarrier" => libc::SYS_membarrier,
                "clone" => libc::SYS_clone,
                "clone3" => libc::SYS_clone3,
                "fork" => libc::SYS_fork,
                "vfork" => libc::SYS_vfork,
                "execve" => libc::SYS_execve,
                "execveat" => libc::SYS_execveat,
                "wait4" => libc::SYS_wait4,
                "set_tid_address" => libc::SYS_set_tid_address,
                "set_robust_list" => libc::SYS_set_robust_list,
                "getpid" => libc::SYS_getpid,
                "gettid" => libc::SYS_gettid,
                "getppid" => libc::SYS_getppid,
                "getpgid" => libc::SYS_getpgid,
                "setpgid" => libc::SYS_setpgid,
                "getsid" => libc::SYS_getsid,
                "setsid" => libc::SYS_setsid,
                "getuid" => libc::SYS_getuid,
                "getgid" => libc::SYS_getgid,
                "geteuid" => libc::SYS_geteuid,
                "getegid" => libc::SYS_getegid,
                "getgroups" => libc::SYS_getgroups,
                "prlimit64" => libc::SYS_prlimit64,
                "sched_getaffinity" => libc::SYS_sched_getaffinity,
                "sched_setaffinity" => libc::SYS_sched_setaffinity,
                "setuid" => libc::SYS_setuid,
                "setgid" => libc::SYS_setgid,
                "capget" => libc::SYS_capget,
                "capset" => libc::SYS_capset,
                "prctl" => libc::SYS_prctl,
                "arch_prctl" => libc::SYS_arch_prctl,
                "getrandom" => libc::SYS_getrandom,
                "uname" => libc::SYS_uname,
                "getrusage" => libc::SYS_getrusage,
                "getrlimit" => libc::SYS_getrlimit,
                "setrlimit" => libc::SYS_setrlimit,
                "times" => libc::SYS_times,
                "clock_gettime" => libc::SYS_clock_gettime,
                "clock_getres" => libc::SYS_clock_getres,
                "clock_nanosleep" => libc::SYS_clock_nanosleep,
                "gettimeofday" => libc::SYS_gettimeofday,
                "futex" => libc::SYS_futex,
                "futex_waitv" => libc::SYS_futex_waitv,
                "futex_time64" => None,
                "nanosleep" => libc::SYS_nanosleep,
                "poll" => libc::SYS_poll,
                "epoll_create1" => libc::SYS_epoll_create1,
                "epoll_ctl" => libc::SYS_epoll_ctl,
                "epoll_pwait" => libc::SYS_epoll_pwait,
                "ppoll" => libc::SYS_ppoll,
                "select" => libc::SYS_select,
                "pselect6" => libc::SYS_pselect6,
                "eventfd2" => libc::SYS_eventfd2,
                "timerfd_create" => libc::SYS_timerfd_create,
                "timerfd_settime" => libc::SYS_timerfd_settime,
                "socket" => libc::SYS_socket,
                "socketpair" => libc::SYS_socketpair,
                "connect" => libc::SYS_connect,
                "bind" => libc::SYS_bind,
                "listen" => libc::SYS_listen,
                "accept" => libc::SYS_accept,
                "accept4" => libc::SYS_accept4,
                "getsockname" => libc::SYS_getsockname,
                "getpeername" => libc::SYS_getpeername,
                "sendto" => libc::SYS_sendto,
                "recvfrom" => libc::SYS_recvfrom,
                "sendmsg" => libc::SYS_sendmsg,
                "recvmsg" => libc::SYS_recvmsg,
                "setsockopt" => libc::SYS_setsockopt,
                "getsockopt" => libc::SYS_getsockopt,
                "shutdown" => libc::SYS_shutdown,
                "socketcall" => None,
                "shmget" => libc::SYS_shmget,
                "shmat" => libc::SYS_shmat,
                "shmdt" => libc::SYS_shmdt,
                "semget" => libc::SYS_semget,
                "semop" => libc::SYS_semop,
                "semctl" => libc::SYS_semctl,
                "semtimedop" => libc::SYS_semtimedop,
                "msgget" => libc::SYS_msgget,
                "msgsnd" => libc::SYS_msgsnd,
                "msgrcv" => libc::SYS_msgrcv,
                "msgctl" => libc::SYS_msgctl,
                "set_thread_area" => libc::SYS_set_thread_area,
                "set_tls" => None,
                "sysinfo" => libc::SYS_sysinfo,
                "sched_yield" => libc::SYS_sched_yield,
                "rseq" => libc::SYS_rseq,
                "statfs" => libc::SYS_statfs,
                "fstatfs" => libc::SYS_fstatfs,
                _ => return None,
            })
        }
        #[cfg(target_arch = "aarch64")]
        {
            Some(match name {
                "read" => libc::SYS_read,
                "write" => libc::SYS_write,
                "openat" => libc::SYS_openat,
                "close" => libc::SYS_close,
                "fstat" => libc::SYS_fstat,
                "newfstatat" => libc::SYS_newfstatat,
                "access" => libc::SYS_access,
                "mkdirat" => libc::SYS_mkdirat,
                "unlinkat" => libc::SYS_unlinkat,
                "renameat" => libc::SYS_renameat,
                "readlinkat" => libc::SYS_readlinkat,
                "fchmod" => libc::SYS_fchmod,
                "fchmodat" => libc::SYS_fchmodat,
                "umask" => libc::SYS_umask,
                "fsync" => libc::SYS_fsync,
                "fdatasync" => libc::SYS_fdatasync,
                "dup" => libc::SYS_dup,
                "dup3" => libc::SYS_dup3,
                "fcntl" => libc::SYS_fcntl,
                "ioctl" => libc::SYS_ioctl,
                "flock" => libc::SYS_flock,
                "fallocate" => libc::SYS_fallocate,
                "sendfile" => libc::SYS_sendfile,
                "lseek" => libc::SYS_lseek,
                "pread64" => libc::SYS_pread64,
                "pwrite64" => libc::SYS_pwrite64,
                "readv" => libc::SYS_readv,
                "writev" => libc::SYS_writev,
                "getdents64" => libc::SYS_getdents64,
                "mmap" => libc::SYS_mmap,
                "mprotect" => libc::SYS_mprotect,
                "munmap" => libc::SYS_munmap,
                "brk" => libc::SYS_brk,
                "madvise" => libc::SYS_madvise,
                "mlock" => libc::SYS_mlock,
                "munlock" => libc::SYS_munlock,
                "mremap" => libc::SYS_mremap,
                "msync" => libc::SYS_msync,
                "membarrier" => libc::SYS_membarrier,
                "clone" => libc::SYS_clone,
                "clone3" => libc::SYS_clone3,
                "vfork" => libc::SYS_vfork,
                "fork" => None,
                "execve" => libc::SYS_execve,
                "execveat" => libc::SYS_execveat,
                "wait4" => libc::SYS_wait4,
                "set_tid_address" => libc::SYS_set_tid_address,
                "set_robust_list" => libc::SYS_set_robust_list,
                "getpid" => libc::SYS_getpid,
                "gettid" => libc::SYS_gettid,
                "getppid" => libc::SYS_getppid,
                "getpgid" => libc::SYS_getpgid,
                "setpgid" => libc::SYS_setpgid,
                "setsid" => libc::SYS_setsid,
                "getuid" => libc::SYS_getuid,
                "getgid" => libc::SYS_getgid,
                "geteuid" => libc::SYS_geteuid,
                "getegid" => libc::SYS_getegid,
                "getgroups" => libc::SYS_getgroups,
                "prlimit64" => libc::SYS_prlimit64,
                "sched_getaffinity" => libc::SYS_sched_getaffinity,
                "sched_setaffinity" => libc::SYS_sched_setaffinity,
                "setuid" => libc::SYS_setuid,
                "setgid" => libc::SYS_setgid,
                "capget" => libc::SYS_capget,
                "capset" => libc::SYS_capset,
                "prctl" => libc::SYS_prctl,
                "getrandom" => libc::SYS_getrandom,
                "uname" => libc::SYS_uname,
                "getrusage" => libc::SYS_getrusage,
                "getrlimit" => libc::SYS_getrlimit,
                "setrlimit" => libc::SYS_setrlimit,
                "times" => libc::SYS_times,
                "clock_gettime" => libc::SYS_clock_gettime,
                "clock_getres" => libc::SYS_clock_getres,
                "clock_nanosleep" => libc::SYS_clock_nanosleep,
                "gettimeofday" => libc::SYS_gettimeofday,
                "futex" => libc::SYS_futex,
                "futex_waitv" => libc::SYS_futex_waitv,
                "futex_time64" => libc::SYS_futex_time64,
                "nanosleep" => libc::SYS_nanosleep,
                "poll" => libc::SYS_poll,
                "epoll_create1" => libc::SYS_epoll_create1,
                "epoll_ctl" => libc::SYS_epoll_ctl,
                "epoll_pwait" => libc::SYS_epoll_pwait,
                "ppoll" => libc::SYS_ppoll,
                "select" => libc::SYS_select,
                "pselect6" => libc::SYS_pselect6,
                "eventfd2" => libc::SYS_eventfd2,
                "timerfd_create" => libc::SYS_timerfd_create,
                "timerfd_settime" => libc::SYS_timerfd_settime,
                "socket" => libc::SYS_socket,
                "socketpair" => libc::SYS_socketpair,
                "connect" => libc::SYS_connect,
                "bind" => libc::SYS_bind,
                "listen" => libc::SYS_listen,
                "accept4" => libc::SYS_accept4,
                "getsockname" => libc::SYS_getsockname,
                "getpeername" => libc::SYS_getpeername,
                "sendto" => libc::SYS_sendto,
                "recvfrom" => libc::SYS_recvfrom,
                "sendmsg" => libc::SYS_sendmsg,
                "recvmsg" => libc::SYS_recvmsg,
                "setsockopt" => libc::SYS_setsockopt,
                "getsockopt" => libc::SYS_getsockopt,
                "shutdown" => libc::SYS_shutdown,
                "socketcall" => None,
                "shmget" => libc::SYS_shmget,
                "shmat" => libc::SYS_shmat,
                "shmdt" => libc::SYS_shmdt,
                "semget" => libc::SYS_semget,
                "semop" => libc::SYS_semop,
                "semctl" => libc::SYS_semctl,
                "semtimedop" => libc::SYS_semtimedop,
                "msgget" => libc::SYS_msgget,
                "msgsnd" => libc::SYS_msgsnd,
                "msgrcv" => libc::SYS_msgrcv,
                "msgctl" => libc::SYS_msgctl,
                "set_tls" => libc::SYS_set_tls,
                "set_thread_area" => None,
                "sysinfo" => libc::SYS_sysinfo,
                "sched_yield" => libc::SYS_sched_yield,
                "rseq" => libc::SYS_rseq,
                "statfs" => libc::SYS_statfs,
                "fstatfs" => libc::SYS_fstatfs,
                _ => return None,
            })
        }
    }

    fn fork_payload(setup: &ChildSetup, stdio: [RawFd; 3]) -> Result<Pid, IsolationError> {
        // The pointer arrays must be stable across the fork; they are built
        // here, on the pre-fork side, and the child only *reads* them.
        let argv: Vec<CString> = setup
            .argv
            .iter()
            .map(|a| CString::new(a.as_bytes()))
            .collect::<Result<_, _>>()
            .map_err(|_| IsolationError::UnsupportedSyscall("embedded NUL in argv".into()))?;
        let envp: Vec<CString> = setup
            .env
            .iter()
            .map(|v| CString::new(format!("{}={}", v.name, v.value)))
            .collect::<Result<_, _>>()
            .map_err(|_| IsolationError::UnsupportedSyscall("embedded NUL in env".into()))?;
        let mut argv_ptrs: Vec<*const libc::c_char> = argv.iter().map(|c| c.as_ptr()).collect();
        argv_ptrs.push(std::ptr::null());
        let mut envp_ptrs: Vec<*const libc::c_char> = envp.iter().map(|c| c.as_ptr()).collect();
        envp_ptrs.push(std::ptr::null());
        let payload = CString::new(setup.argv[0].as_bytes())
            .map_err(|_| IsolationError::UnsupportedSyscall("embedded NUL in argv[0]".into()))?;

        // SAFETY: J-03. `fork` in the re-exec'd init — the process is
        // single-threaded (fresh exec, everything above was synchronous).
        match unsafe { fork() }? {
            ForkResult::Parent { .. } => {
                // The init's half of the work is done; the payload is PID 1 of
                // the new namespace and its pid is returned to the relay.
                Ok(Pid::from_raw(0))
            }
            ForkResult::Child => {
                // Async-signal-safe zone (UNSAFE.md §3): setsid, dup2, execve.
                // No allocation, no log, no panic — verbose only in exit code.
                unsafe_async_child(stdio, &payload, &argv_ptrs, &envp_ptrs);
                // unreachable: child never returns
                unreachable!()
            }
        }
    }

    #[cold]
    fn unsafe_async_child(
        stdio: [RawFd; 3],
        path: &CStr,
        argv: &[*const libc::c_char],
        envp: &[*const libc::c_char],
    ) {
        // SAFETY: J-03. `setsid` fails only if we are already a session
        // leader, which a fresh spawn never is.
        let _ = unsafe { libc::setsid() };
        for (fd, target) in stdio.iter().zip([0i32, 1, 2]) {
            if *fd >= 0 && *fd != target {
                // SAFETY: J-04. dup2 of stdio, fd >= 0 and valid at this point.
                let _ = unsafe { libc::dup2(*fd, target) };
            }
        }
        // SAFETY: J-04. `argv`/`envp` are NUL-terminated arrays built
        // pre-fork; on failure we `_exit` rather than return, so no
        // destructor runs on the error path (leaks beat corruption).
        let res = unsafe { libc::execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
        let code = if res == -1 { 127 } else { 0 };
        unsafe { libc::_exit(code) };
    }
}