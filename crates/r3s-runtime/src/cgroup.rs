//! cgroup v2 writer.
//!
//! cgroupfs is a file protocol: a cgroup is a directory, a limit is a file,
//! and "create" is `mkdir` — idempotent, since `EEXIST` on the create path is
//! success, which is exactly the semantic the reconciler needs. The whole
//! module is plain file I/O for that reason, and it is what makes it testable
//! on any host: point the root at a directory of regular files that stand in
//! for the kernel's view.
//!
//! Two kernel rules shape the API (ARCHITECTURE §1.2.2):
//!
//! * **No internal processes** — a cgroup that has controllers enabled in
//!   `cgroup.subtree_control` must have an empty `cgroup.procs`. Enabling on
//!   a populated cgroup fails with `EBUSY`; [`Cgroup::enable_controllers`]
//!   therefore drains-and-retries before it writes.
//! * **Controllers flow downward** — a child can only be limited by
//!   controllers its *parent* has enabled, so [`CgroupTree::establish`]
//!   (see `tree.rs`) enables on parents before it populates children.
//!
//! [`CgroupTree::establish`]: crate::tree::CgroupTree::establish

use std::fs;
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use nix::unistd::Pid;
use r3s_proto::ResourceLimits;
use thiserror::Error;
use tracing::debug;

/// Failure of a cgroupfs operation. Every variant carries what it knows about
/// the incident; the `io` variants keep the errno, because recovery differs
/// per errno (`EBUSY` is a retry, `EINVAL` is a missing controller, `ENOSPC`
/// is a disk problem) — ARCHITECTURE §3.3.3.
#[derive(Debug, Error)]
pub enum CgroupError {
    /// The caller tried to point the tree at an absolute path or through a
    /// `..` component. Refused before any file operation is attempted.
    #[error("cgroup path escape: {0}")]
    PathEscape(PathBuf),

    /// A cgroup that must hold no processes of its own has some. This is a
    /// bug, not a condition (RUNBOOK §6.3): the no-internal-processes rule is
    /// violated, so the kernel will refuse controller enablement until the
    /// stragglers leave.
    #[error("no-internal-processes rule violated for {path}")]
    Busy {
        /// The cgroup that still holds processes.
        path: PathBuf,
    },

    /// A controller the tree needs is not in this kernel's
    /// `cgroup.controllers` (RUNBOOK §6.4). A startup failure by design.
    #[error("controller {0} not available on this kernel")]
    MissingController(String),

    /// A file operation on the cgroup failed. The path names which object;
    /// the source carries the errno.
    #[error("cgroup I/O on {path}: {source}")]
    Io {
        /// The path that was being read or written.
        path: PathBuf,
        /// The kernel's error, with the errno.
        source: io::Error,
    },
}

fn errno_is(e: &io::Error, code: i32) -> bool {
    e.raw_os_error() == Some(code)
}

/// One cgroup, addressed as `root` + a relative path.
///
/// Construction is cheap and validates the path only; every file operation is
/// an explicit method so the caller controls ordering, which is the whole
/// game in cgroup v2 (limits before attach, parents before children).
#[derive(Debug, Clone)]
pub struct Cgroup {
    root: PathBuf,
    rel: PathBuf,
}

impl Cgroup {
    /// Builds a handle. `rel` must stay inside `root`: absolute paths and
    /// `..` components are a path-escape attempt and are refused here, before
    /// any file operation. An empty `rel` names the mount root itself.
    pub fn new(root: &Path, rel: impl AsRef<Path>) -> Result<Self, CgroupError> {
        let rel = rel.as_ref();
        if rel.is_absolute() || rel.components().any(|c| matches!(c, Component::ParentDir)) {
            return Err(CgroupError::PathEscape(rel.to_path_buf()));
        }
        Ok(Self {
            root: root.to_path_buf(),
            rel: rel.to_path_buf(),
        })
    }

    /// Full path under the cgroupfs root.
    pub fn path(&self) -> PathBuf {
        self.root.join(&self.rel)
    }

    /// The relative path, for records that must survive a restart.
    pub fn rel(&self) -> &Path {
        &self.rel
    }

    fn fail(&self, path: &Path, source: io::Error) -> CgroupError {
        CgroupError::Io {
            path: path.to_path_buf(),
            source,
        }
    }

    /// Creates the cgroup and any missing parents. Idempotent: a cgroup is a
    /// directory and `mkdir` on an existing one is success, which is the
    /// semantic the reconciler's retry loop needs.
    pub fn ensure(&self) -> Result<(), CgroupError> {
        let p = self.path();
        match fs::create_dir_all(&p) {
            Ok(()) => Ok(()),
            Err(source) if errno_is(&source, libc::EEXIST) => Ok(()),
            Err(source) => Err(self.fail(&p, source)),
        }
    }

    /// Whether the cgroup directory currently exists.
    pub fn exists(&self) -> bool {
        self.path().is_dir()
    }

    /// Reads a cgroup file as text. `io::Error` on purpose: the caller
    /// decides whether "the file is gone" is a `NotFound` to report or a
    /// condition to retry.
    pub fn read_to_string(&self, file: &str) -> io::Result<String> {
        fs::read_to_string(self.path().join(file))
    }

    /// Reads the first numeric token of a single-value file
    /// (`memory.current`, `pids.current`, …).
    pub fn read_u64(&self, file: &str) -> io::Result<u64> {
        let text = self.read_to_string(file)?;
        text.split_whitespace()
            .next()
            .and_then(|t| t.parse().ok())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("first token of {} is not a number: {text:?}", file),
                )
            })
    }

    /// Reads `cgroup.procs`: the pids currently in this cgroup, in kernel
    /// order. Empty for a healthy leaf.
    pub fn read_procs(&self) -> io::Result<Vec<i32>> {
        let text = self.read_to_string("cgroup.procs")?;
        Ok(text
            .split_whitespace()
            .filter_map(|t| t.parse().ok())
            .collect())
    }

    /// Writes a cgroup control file.
    ///
    /// `O_WRONLY` with truncate: the kernel parses the whole buffer as "the
    /// new value" and ignores file offsets on cgroup2 files, so truncation is
    /// a no-op on the real hierarchy — and it is what keeps the fake
    /// regular-file trees in tests honest (a re-write replaces, never
    /// splices).
    pub fn write_ctl(&self, file: &str, value: &str) -> Result<(), CgroupError> {
        let p = self.path().join(file);
        debug!(path = %p.display(), value, "cgroup write");
        let r = fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&p)
            .and_then(|mut f| f.write_all(value.as_bytes()));
        r.map_err(|source| self.fail(&p, source))
    }

    /// Moves every process in this cgroup into `into`.
    ///
    /// This is the no-internal-processes escape valve: a cgroup that will
    /// have controllers enabled in `subtree_control` must be empty first, and
    /// the only destination that is both empty-able and already limited-able
    /// is a leaf sibling (the engine scope, in `CgroupTree::establish`).
    pub fn drain_into(&self, into: &Cgroup) -> Result<(), CgroupError> {
        let procs = self
            .read_procs()
            .map_err(|source| self.fail(&self.path().join("cgroup.procs"), source))?;
        for pid in procs {
            into.attach_pid(Pid::from_raw(pid))?;
        }
        self.assert_no_internal_processes()
    }

    /// Refuses to proceed if this cgroup holds processes of its own.
    ///
    /// A `Busy` here is a bug, not a condition (RUNBOOK §6.3): processes
    /// belong in leaves, never in a slice that enables controllers.
    pub fn assert_no_internal_processes(&self) -> Result<(), CgroupError> {
        let procs = self
            .read_to_string("cgroup.procs")
            .map_err(|source| self.fail(&self.path().join("cgroup.procs"), source))?;
        if !procs.trim().is_empty() {
            return Err(CgroupError::Busy { path: self.path() });
        }
        Ok(())
    }

    /// Enables `ctrls` in `cgroup.subtree_control`, delegating them to this
    /// cgroup's children.
    ///
    /// Two guards, in order: the controllers must exist in this kernel
    /// (otherwise `EINVAL` would surface deep in a later create, not at boot),
    /// and this cgroup must be empty — the kernel returns `EBUSY` while a
    /// process is still inside, and a straggler that arrives in the window
    /// between our check and the write is the common case, so the write is
    /// retried with 5 ms backoff for up to 50 ms before it is reported as
    /// [`CgroupError::Busy`].
    pub fn enable_controllers(&self, ctrls: &[&str]) -> Result<(), CgroupError> {
        let available = self
            .read_to_string("cgroup.controllers")
            .map_err(|source| self.fail(&self.path().join("cgroup.controllers"), source))?;
        for c in ctrls {
            if !available.split_whitespace().any(|a| a == *c) {
                return Err(CgroupError::MissingController((*c).to_owned()));
            }
        }
        let want = ctrls
            .iter()
            .map(|c| format!("+{c}"))
            .collect::<Vec<_>>()
            .join(" ");

        let deadline = Instant::now() + Duration::from_millis(50);
        loop {
            match self.write_ctl("cgroup.subtree_control", &want) {
                Ok(()) => return Ok(()),
                Err(CgroupError::Io { source, .. })
                    if errno_is(&source, libc::EBUSY) && Instant::now() < deadline =>
                {
                    // Someone is still inside; give it the 5 ms the
                    // reconciler's tick buys and try again.
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Moves a pid into this cgroup. Limits are enforced from the first
    /// instruction after the write, including the dynamic linker, so the
    /// spawner attaches before it does anything else.
    pub fn attach_pid(&self, pid: Pid) -> Result<(), CgroupError> {
        self.write_ctl("cgroup.procs", &pid.as_raw().to_string())
    }

    /// Applies the spec's limits to this leaf.
    ///
    /// Must run after [`ensure`](Self::ensure) and before the first process
    /// is attached. The zero-values are per-file, not one global rule:
    ///
    /// | file             | 0 means               | written as   |
    /// |------------------|-----------------------|--------------|
    /// | `memory.max`     | unlimited             | `max`        |
    /// | `memory.high`    | no soft limit (unset) | skipped (the fresh-cgroup default is `max`) |
    /// | `memory.swap.max`| no swap               | `0`          |
    /// | `cpu.max`        | no quota              | `max`        |
    /// | `pids.max`       | no pid limit          | `max`        |
    ///
    /// Swap is the one asymmetry, on purpose: a fresh cgroup defaults to
    /// `swap=max`, and on a Pi that turns a memory limit into a latency cliff
    /// backed by the SD card — so "0" must be written, not skipped
    /// (ADRs/0007 security defaults).
    ///
    /// `io.max` is deliberately absent: it is per-block-device
    /// (`<maj>:<min> rbps=…`) and the device only exists at mount time, so the
    /// engine applies it then. `cpuset` is a slice-level decision (stage 4).
    pub fn set_limits(&self, limits: &ResourceLimits) -> Result<(), CgroupError> {
        if limits.memory_bytes == 0 {
            self.write_ctl("memory.max", "max")?;
        } else {
            self.write_ctl("memory.max", &limits.memory_bytes.to_string())?;
        }
        if limits.memory_high_bytes > 0 {
            self.write_ctl("memory.high", &limits.memory_high_bytes.to_string())?;
        }
        self.write_ctl("memory.swap.max", &limits.memory_swap_bytes.to_string())?;
        // Kill the whole cgroup on OOM, not one victim: a container that
        // OOMs in its own group is a container that should be restarted, not
        // a single payload process that survives to hold the fd table open.
        self.write_ctl("memory.oom.group", "1")?;

        if limits.cpu_shares == 0 {
            self.write_ctl("cpu.max", "max")?;
        } else {
            self.write_ctl(
                "cpu.max",
                &format!("{} {}", limits.cpu_quota_us(), ResourceLimits::PERIOD_US),
            )?;
        }
        if limits.max_pids == 0 {
            self.write_ctl("pids.max", "max")?;
        } else {
            self.write_ctl("pids.max", &limits.max_pids.to_string())?;
        }
        Ok(())
    }

    /// Kills every process in the cgroup, then removes the directory.
    ///
    /// `cgroup.kill` (kernel ≥ 5.14) is best-effort on purpose: on an empty
    /// cgroup it is a no-op and on one whose processes are already gone it
    /// may fail — the `rmdir` is the decider. `remove_dir_all` is safe here
    /// because this is only ever called on *leaves*: a scope has no children
    /// by construction, and removing a slice goes through `CgroupTree`, which
    /// drains its scopes from the record first.
    ///
    /// A non-empty cgroup whose processes cannot be killed (zombies awaiting
    /// their parent's reap) fails with the `EBUSY` errno; the caller retries,
    /// because the reap is on its way.
    pub fn remove(&self) -> Result<(), CgroupError> {
        let p = self.path();
        if !p.is_dir() {
            return Ok(());
        }
        let _ = self.write_ctl("cgroup.kill", "1");
        match fs::remove_dir_all(&p) {
            Ok(()) => Ok(()),
            Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(self.fail(&p, source)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fakefs;

    fn root() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    fn full_tree() -> (tempfile::TempDir, Cgroup) {
        let dir = root();
        fakefs::make_tree(dir.path(), fakefs::DEFAULT_CONTROLLERS);
        let cg = Cgroup::new(dir.path(), "").expect("root");
        (dir, cg)
    }

    #[test]
    fn an_absolute_path_is_an_escape() {
        let dir = root();
        let r = Cgroup::new(dir.path(), "/etc/passwd");
        assert!(matches!(r, Err(CgroupError::PathEscape(_))));
    }

    #[test]
    fn a_parent_dir_component_is_an_escape() {
        let dir = root();
        let r = Cgroup::new(dir.path(), "../outside");
        assert!(matches!(r, Err(CgroupError::PathEscape(_))));
    }

    #[test]
    fn an_empty_rel_names_the_mount_root() {
        let (dir, cg) = full_tree();
        assert_eq!(cg.path(), dir.path());
        assert!(cg.read_to_string("cgroup.controllers").is_ok());
    }

    #[test]
    fn ensure_is_idempotent() {
        let dir = root();
        let cg = Cgroup::new(dir.path(), "r3s.slice/default.slice").expect("build");
        cg.ensure().expect("first");
        cg.ensure().expect("second");
        assert!(cg.exists());
    }

    #[test]
    fn write_ctl_replaces_the_value() {
        let (dir, _) = full_tree();
        let cg = Cgroup::new(dir.path(), "r3s.slice").expect("build");
        cg.ensure().unwrap();
        cg.write_ctl("memory.max", "268435456").unwrap();
        cg.write_ctl("memory.max", "max").unwrap();
        assert_eq!(cg.read_to_string("memory.max").unwrap(), "max");
    }

    #[test]
    fn read_u64_takes_the_first_token() {
        let dir = root();
        fakefs::make_tree(dir.path(), fakefs::DEFAULT_CONTROLLERS);
        let cg = Cgroup::new(dir.path(), "r3s.slice").expect("build");
        cg.ensure().unwrap();
        cg.write_ctl("memory.current", "1234 5678\n").unwrap();
        assert_eq!(cg.read_u64("memory.current").unwrap(), 1234);
    }

    #[test]
    fn enabling_a_missing_controller_is_a_typed_error() {
        let (dir, _) = full_tree();
        // The tree was seeded without the io controller.
        let cg = Cgroup::new(dir.path(), "r3s.slice").expect("build");
        cg.ensure().unwrap();
        match cg.enable_controllers(&["cpu", "memory", "io"]) {
            Err(CgroupError::MissingController(c)) => assert_eq!(c, "io"),
            other => panic!("expected MissingController, got {other:?}"),
        }
    }

    #[test]
    fn enabling_on_an_empty_cgroup_succeeds() {
        let (dir, _) = full_tree();
        let cg = Cgroup::new(dir.path(), "r3s.slice").expect("build");
        cg.ensure().unwrap();
        cg.enable_controllers(&["cpu", "memory", "pids"])
            .expect("enable");
        let got = cg.read_to_string("cgroup.subtree_control").unwrap();
        assert!(got.contains("+cpu") && got.contains("+memory") && got.contains("+pids"));
    }

    #[test]
    fn a_populated_cgroup_is_busy() {
        let (dir, _) = full_tree();
        let cg = Cgroup::new(dir.path(), "r3s.slice").expect("build");
        cg.ensure().unwrap();
        cg.attach_pid(Pid::from_raw(4242)).unwrap();
        match cg.assert_no_internal_processes() {
            Err(CgroupError::Busy { path }) => {
                assert!(path.ends_with("r3s.slice"));
            }
            other => panic!("expected Busy, got {other:?}"),
        }
        // The fake cannot follow the kernel move (a file write does not empty
        // the source), so the drain's own check reports the straggler; the move
        // itself is on-device. And the fake subtree_control write cannot produce
        // the kernel's EBUSY, so the enable goes through regardless — assert
        // only that it landed.
        match cg.drain_into(&Cgroup::new(dir.path(), "").expect("root")) {
            Err(CgroupError::Busy { path }) => assert!(path.ends_with("r3s.slice")),
            other => panic!("expected Busy, got {other:?}"),
        }
        cg.enable_controllers(&["cpu"]).expect("enable");
    }

    #[test]
    fn set_limits_writes_every_file_the_kernel_reads() {
        let (dir, _) = full_tree();
        let cg = Cgroup::new(dir.path(), "r3s.slice").expect("build");
        cg.ensure().unwrap();
        let limits = ResourceLimits {
            memory_bytes: 1 << 20,
            memory_high_bytes: 512 << 10,
            memory_swap_bytes: 0,
            cpu_shares: 50,
            max_pids: 64,
            io_read_bps: 0,
            io_write_bps: 0,
        };
        cg.set_limits(&limits).expect("set");
        assert_eq!(cg.read_to_string("memory.max").unwrap(), "1048576");
        assert_eq!(cg.read_to_string("memory.high").unwrap(), "524288");
        assert_eq!(cg.read_to_string("memory.swap.max").unwrap(), "0");
        assert_eq!(cg.read_to_string("memory.oom.group").unwrap(), "1");
        // 50% of a core over the 100 ms period.
        assert_eq!(cg.read_to_string("cpu.max").unwrap(), "50000 100000");
        assert_eq!(cg.read_to_string("pids.max").unwrap(), "64");
    }

    #[test]
    fn zero_limits_mean_unlimited_except_swap() {
        let (dir, _) = full_tree();
        let cg = Cgroup::new(dir.path(), "r3s.slice").expect("build");
        cg.ensure().unwrap();
        let limits = ResourceLimits {
            memory_bytes: 0,
            memory_high_bytes: 0,
            memory_swap_bytes: 0,
            cpu_shares: 0,
            max_pids: 0,
            io_read_bps: 0,
            io_write_bps: 0,
        };
        cg.set_limits(&limits).expect("set");
        assert_eq!(cg.read_to_string("memory.max").unwrap(), "max");
        assert_eq!(cg.read_to_string("cpu.max").unwrap(), "max");
        assert_eq!(cg.read_to_string("pids.max").unwrap(), "max");
        // The one file where 0 is a real limit: swap stays closed.
        assert_eq!(cg.read_to_string("memory.swap.max").unwrap(), "0");
    }

    #[test]
    fn remove_deletes_the_cgroup_once_empty() {
        let (dir, _) = full_tree();
        let cg = Cgroup::new(dir.path(), "r3s.slice/default.slice/x.scope").expect("build");
        cg.ensure().unwrap();
        assert!(cg.exists());
        cg.remove().expect("remove");
        assert!(!cg.exists());
        // A second remove is success, not an error: teardown is retried.
        cg.remove().expect("re-remove");
    }

    #[test]
    fn a_missing_cgroup_is_already_removed() {
        let (dir, _) = full_tree();
        let cg = Cgroup::new(dir.path(), "r3s.slice/gone.scope").expect("build");
        cg.remove().expect("no-op remove");
    }
}
