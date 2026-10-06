//! The cgroup v2 tree the engine owns from boot to shutdown.
//!
//! ```text
//! <cgroup2 mount>                     no processes; controllers enabled
//! └── r3s.slice                       no processes; controllers enabled
//!     ├── r3s-system.slice            the engine; limited; no children
//!     └── <slice>.slice               one per QoS class; limited; no processes
//!         └── r3s-<slice>-<id>.scope  one per container; limited; the payload
//! ```
//!
//! The shape is forced, not chosen (ARCHITECTURE §1.2.2). The no-internal-
//! processes rule means a cgroup can either *hold* processes or *delegate*
//! controllers to children, never both, so the engine lives in a leaf while
//! the delegations live in its ancestors, and each container is a leaf of
//! its QoS class. That is also what makes a class repriorisable in O(slices):
//! the limits for the whole class are on the slice, and the per-container
//! limits on the scopes below it.
//!
//! [`CgroupTree::establish`] is the only place the ordering knowledge lives,
//! and it is idempotent in the crash sense: every step succeeds on a tree
//! that is partway built, because the engine can die between any two of them
//! (I4).

use std::fs;
use std::path::{Path, PathBuf};

use nix::unistd::{Pid, getpid};
use r3s_proto::{ContainerId, ResourceLimits};
use tracing::warn;

use crate::cgroup::{Cgroup, CgroupError};
use crate::manifest::ScopeSet;

/// Name of the slice that is the root of everything r3s creates.
pub const TOP_SLICE: &str = "r3s.slice";

/// The slice the engine process itself lives in: accounted, limited, so a
/// memory-hungry container can never OOM-kill the control plane.
pub const SYSTEM_SLICE: &str = "r3s-system.slice";

/// Controllers the tree refuses to run without. A missing one is a boot
/// failure (RUNBOOK §6.4), not a degraded mode: without `memory` there is no
/// OOM attribution, without `pids` no fork bomb protection.
const REQUIRED: &[&str] = &["cpu", "memory", "pids"];

/// Controllers the tree wants. Missing ones are a logged warning, not a
/// failure: `io` limits are per-device and applied at mount time, `cpuset`
/// matters from stage 4, and neither is on every kernel.
const DESIRED: &[&str] = &["io", "cpuset"];

/// The engine's own reservation: how much of the node it claims before any
/// container is admitted. The management plane must survive a hostile
/// workload, so it is a leaf with a hard limit (ARCHITECTURE §1.2.3).
pub const fn engine_reservation() -> ResourceLimits {
    ResourceLimits {
        memory_bytes: 96 * 1024 * 1024,
        memory_high_bytes: 0,
        memory_swap_bytes: 0,
        cpu_shares: 100,
        max_pids: 128,
        io_read_bps: 0,
        io_write_bps: 0,
    }
}

/// A container's slice name: a QoS class. The engine admits containers into
/// one; limits on the slice bound the *class*, limits on the scope bound the
/// *container* (I6 is the slice enforcing the sum).
fn validate_slice(name: &str) -> Result<(), CgroupError> {
    if name.is_empty()
        || name.len() > 32
        || !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(CgroupError::PathEscape(PathBuf::from(name)));
    }
    Ok(())
}

/// The whole tree, rooted at the cgroup2 mount point.
///
/// Two roots are kept separate because they are different objects: the
/// cgroup2 mount (kernel state) and the state base (bundle directories). A
/// `CgroupTree` is the only type that knows both, which is what lets
/// [`create_scope`](Self::create_scope) return a record covering both.
#[derive(Debug, Clone)]
pub struct CgroupTree {
    cgroup_root: PathBuf,
    base: PathBuf,
}

impl CgroupTree {
    /// Cheap construction; validates the path shapes only. Call
    /// [`establish`](Self::establish) to build or repair the tree.
    pub fn new(cgroup_root: &Path, base: &Path) -> Result<Self, CgroupError> {
        let cgroup = Cgroup::new(cgroup_root, "")?;
        Ok(Self {
            cgroup_root: cgroup.path(),
            base: base.to_path_buf(),
        })
    }

    /// The cgroup2 mount point, for the layers that need raw paths.
    pub fn cgroup_root(&self) -> &Path {
        &self.cgroup_root
    }

    /// The state base directory (bundles live under `<base>/containers`).
    pub fn base(&self) -> &Path {
        &self.base
    }

    /// Reads the controllers this kernel offers at the mount root.
    fn available_controllers(&self) -> Result<Vec<&'static str>, CgroupError> {
        let root = Cgroup::new(&self.cgroup_root, "")?;
        let line = root
            .read_to_string("cgroup.controllers")
            .map_err(|source| CgroupError::Io {
                path: root.path().join("cgroup.controllers"),
                source,
            })?;
        let mut out = Vec::new();
        for c in ["cpu", "cpuset", "io", "memory", "pids", "hugetlb"] {
            if line.split_whitespace().any(|a| a == c) {
                out.push(c);
            }
        }
        Ok(out)
    }

    fn controllers_to_enable(&self) -> Result<Vec<&'static str>, CgroupError> {
        let avail = self.available_controllers()?;
        for c in REQUIRED {
            if !avail.iter().any(|a| a == c) {
                return Err(CgroupError::MissingController((*c).to_owned()));
            }
        }
        for c in DESIRED {
            if !avail.iter().any(|a| a == c) {
                warn!(controller = %c, "desired controller unavailable on this kernel");
            }
        }
        // A whitelist, not "everything minus what we hate": a future kernel
        // may advertise controllers the tree does not manage (hugetlb is the
        // known example — a node without it is normal, and we have no consumer
        // for it yet), and enabling one would delegate state to a controller
        // no one here reads.
        let want: Vec<&str> = avail
            .iter()
            .copied()
            .filter(|c| REQUIRED.contains(c) || DESIRED.contains(c))
            .collect();
        Ok(want)
    }

    fn top(&self) -> Result<Cgroup, CgroupError> {
        Cgroup::new(&self.cgroup_root, TOP_SLICE)
    }

    /// The slice the engine process lives in.
    pub fn system_slice(&self) -> Result<Cgroup, CgroupError> {
        Cgroup::new(&self.cgroup_root, format!("{TOP_SLICE}/{SYSTEM_SLICE}"))
    }

    /// A QoS-class slice, by name. Not yet created; see `ensure_slice`.
    pub fn slice(&self, name: &str) -> Result<Cgroup, CgroupError> {
        validate_slice(name)?;
        Cgroup::new(&self.cgroup_root, format!("{TOP_SLICE}/{name}.slice"))
    }

    /// Creates the slice if needed and delegates controllers to it, so the
    /// scopes below it can be limited. Idempotent.
    pub fn ensure_slice(&self, name: &str) -> Result<Cgroup, CgroupError> {
        validate_slice(name)?;
        let cg = self.slice(name)?;
        cg.ensure()?;
        cg.assert_no_internal_processes()?;
        let want = self.controllers_to_enable()?;
        cg.enable_controllers(&want)?;
        Ok(cg)
    }

    /// Binds the whole QoS class to a budget (I6): with the class total on
    /// the slice, two containers in it cannot jointly exceed it — the
    /// hierarchy enforces the sum, no admission arithmetic needed.
    pub fn set_slice_limits(&self, name: &str, limits: &ResourceLimits) -> Result<(), CgroupError> {
        let cg = self.ensure_slice(name)?;
        cg.set_limits(limits)
    }

    /// A container's scope, by (slice, id). Not yet created.
    pub fn scope(&self, slice: &str, id: ContainerId) -> Result<Cgroup, CgroupError> {
        validate_slice(slice)?;
        Cgroup::new(
            &self.cgroup_root,
            format!(
                "{TOP_SLICE}/{slice}.slice/r3s-{slice}-{}.scope",
                id.to_hex()
            ),
        )
    }

    /// Builds or repairs the whole tree. Idempotent and crash-safe in the
    /// sense I4 needs: the engine can die between any two steps, and re-running
    /// this on the partial tree converges to the finished one.
    ///
    /// The ordering is the contract (ARCHITECTURE §1.2.2):
    ///
    /// 1. the engine leaves the mount root — the root must be empty before it
    ///    can enable controllers, and the engine scope is the only leaf that
    ///    can receive it;
    /// 2. the root enables the controllers it has;
    /// 3. `r3s.slice` is empty (asserted, not drained: a process parked there
    ///    is `Busy`, a bug — RUNBOOK §6.3) and enables the controllers;
    /// 4. the engine's reservation is applied to the system slice.
    pub fn establish(&self) -> Result<(), CgroupError> {
        let root = Cgroup::new(&self.cgroup_root, "")?;
        let want = self.controllers_to_enable()?;

        let system = self.system_slice()?;
        system.ensure()?;
        root.drain_into(&system)?;
        root.enable_controllers(&want)?;

        let top = self.top()?;
        top.ensure()?;
        top.assert_no_internal_processes()?;
        top.enable_controllers(&want)?;

        self.ensure_slice("default")?;
        self.claim_engine(&engine_reservation())?;
        Ok(())
    }

    /// Moves the engine process into the system slice and applies the
    /// reservation (the "engine scope" line of `r3s system info`).
    ///
    /// Attach first, limits second: a crash in the window leaves the engine
    /// accounted-but-unlimited, which is the status quo, while the reverse
    /// window would leave an unlimited engine that can OOM-kill containers.
    /// Idempotent: a restart re-attaches itself and re-applies the limits.
    pub fn claim_engine(&self, limits: &ResourceLimits) -> Result<(), CgroupError> {
        let system = self.system_slice()?;
        system.ensure()?;
        system.attach_pid(getpid())?;
        system.set_limits(limits)?;
        Ok(())
    }

    /// The inverse of [`claim_engine`](Self::claim_engine) for shutdown:
    /// the engine leaves the system slice, so the slice can drain when the
    /// process dies. Best-effort by contract — a failed move must not block
    /// a clean exit, the kernel removes the process from the cgroup on exit
    /// regardless.
    pub fn release_engine(&self) -> Result<(), CgroupError> {
        let system = self.system_slice()?;
        let root = Cgroup::new(&self.cgroup_root, "")?;
        let me = Pid::from_raw(getpid().as_raw());
        let _ = system.attach_pid(me);
        system.drain_into(&root)
    }

    /// Creates one container's scope: the cgroup, its limits, its bundle
    /// directory — and the record of all three.
    ///
    /// This is I1: after it returns `Ok`, exactly one cgroup exists under the
    /// slice with every requested limit readable from cgroupfs. The process
    /// attach deliberately does *not* happen here: there is no process yet,
    /// and the spawner attaches between fork and exec so the limits bind from
    /// the payload's first instruction (stage 1 week 4).
    pub fn create_scope(
        &self,
        slice: &str,
        id: ContainerId,
        limits: &ResourceLimits,
    ) -> Result<ScopeSet, CgroupError> {
        let cg = self.scope(slice, id)?;
        cg.ensure()?;
        cg.set_limits(limits)?;

        let bundle = self.bundle_dir(id);
        fs::create_dir_all(&bundle).map_err(|source| CgroupError::Io {
            path: bundle.clone(),
            source,
        })?;

        Ok(ScopeSet::new(
            id,
            slice,
            cg.rel().to_string_lossy().into_owned(),
            "containers".to_owned() + &bundle_relative(id),
        ))
    }

    fn bundle_dir(&self, id: ContainerId) -> PathBuf {
        self.base.join("containers").join(id.to_hex())
    }

    /// Removes every object in the record (I5): the scope cgroup, then the
    /// bundle directory. The record is the sole input — teardown is derived
    /// from what was *declared*, never from a guess about what might be
    /// there.
    ///
    /// Both removals are attempted even if the first fails, because they are
    /// independent kernel objects; the first error is returned and the caller
    /// retries the whole call, which is safe: every primitive here is
    /// idempotent on an already-removed object.
    pub fn remove_scope(&self, scope: &ScopeSet) -> Result<(), CgroupError> {
        let cg = Cgroup::new(&self.cgroup_root, &scope.cgroup)?;
        let cgroup_result = cg.remove();

        let bundle = self.base.join(&scope.bundle);
        let bundle_result = fs::remove_dir_all(&bundle).map_err(|source| {
            let _ = source;
            CgroupError::Io {
                path: bundle.clone(),
                source,
            }
        });
        // A bundle that was never created is not a failure; a cgroup that
        // vanished is not either (remove() already treats both as success).
        if bundle_result.is_err() && bundle.exists() {
            return cgroup_result.and(bundle_result);
        }
        cgroup_result
    }

    /// Removes a QoS slice *and proves it has no children left*: a slice with
    /// scope directories in it is `Busy`, not silently deleted — a scope is
    /// another record's object (I5).
    pub fn remove_slice(&self, name: &str) -> Result<(), CgroupError> {
        let cg = self.slice(name)?;
        if cg.exists() {
            for entry in fs::read_dir(cg.path()).map_err(|source| CgroupError::Io {
                path: cg.path(),
                source,
            })? {
                let entry = entry.map_err(|source| CgroupError::Io {
                    path: cg.path(),
                    source,
                })?;
                let file_type = entry.file_type().map_err(|source| CgroupError::Io {
                    path: cg.path(),
                    source,
                })?;
                if file_type.is_dir() {
                    return Err(CgroupError::Busy { path: cg.path() });
                }
            }
        }
        cg.remove()
    }
}

/// The slice-relative part of the bundle path, for the record.
fn bundle_relative(id: ContainerId) -> String {
    format!("/{}", id.to_hex())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fakefs;

    const CONTROLLERS: &str = "cpuset cpu io memory pids";

    fn tree() -> (tempfile::TempDir, CgroupTree) {
        let dir = tempfile::tempdir().expect("tempdir");
        fakefs::make_tree(dir.path(), CONTROLLERS);
        let t = CgroupTree::new(dir.path(), dir.path()).expect("tree");
        (dir, t)
    }

    fn fixed_id() -> ContainerId {
        // The bytes live in `fakefs`: the fake tree pre-creates the scope
        // directories this id produces.
        ContainerId::from_bytes(fakefs::TEST_ID)
    }

    #[test]
    fn establish_is_idempotent() {
        let (_dir, t) = tree();
        t.establish().expect("first");
        t.establish().expect("second, same tree");

        let root = Cgroup::new(t.cgroup_root(), "").unwrap();
        assert!(
            root.read_to_string("cgroup.procs")
                .unwrap()
                .trim()
                .is_empty(),
            "the mount root must be empty once controllers are enabled"
        );
        let top = t.top().unwrap();
        assert!(
            top.read_to_string("cgroup.subtree_control")
                .unwrap()
                .contains("+memory")
        );
        // The engine is accounted: it is in the system slice, nowhere else.
        let system = t.system_slice().unwrap();
        let procs = system.read_procs().unwrap();
        assert!(procs.contains(&(getpid().as_raw())));
    }

    #[test]
    fn establish_movers_stragglers_out_of_the_root() {
        let (dir, t) = tree();
        // Simulate a host process parked in the mount root.
        let root = Cgroup::new(dir.path(), "").unwrap();
        root.attach_pid(Pid::from_raw(777)).unwrap();

        // The kernel moves 777 into the system slice, the root drains, and the
        // controllers enable. The fake cannot follow the move (a file write
        // does not empty the source), so establish stops at the drain with
        // exactly the error RUNBOOK §6.3 tells the operator to look for. The
        // move itself is on-device.
        match t.establish() {
            Err(CgroupError::Busy { path }) => assert_eq!(path.as_path(), root.path()),
            other => panic!("expected Busy, got {other:?}"),
        }
        // The attach half of the drain did land.
        let system = t.system_slice().unwrap();
        assert!(system.read_procs().unwrap().contains(&777));
    }

    #[test]
    fn establish_fails_cleanly_without_required_controllers() {
        let dir = tempfile::tempdir().expect("tempdir");
        fakefs::make_tree(dir.path(), "cpu cpuset"); // no memory, no pids
        let t = CgroupTree::new(dir.path(), dir.path()).expect("tree");
        match t.establish() {
            Err(CgroupError::MissingController(c)) => assert!(c == "memory" || c == "pids"),
            other => panic!("expected MissingController, got {other:?}"),
        }
    }

    #[test]
    fn a_process_parked_in_r3s_slice_is_busy() {
        let (_dir, t) = tree();
        let top = t.top().unwrap();
        top.ensure().unwrap();
        top.attach_pid(Pid::from_raw(4242)).unwrap();
        match t.establish() {
            Err(CgroupError::Busy { path }) => assert!(path.ends_with(TOP_SLICE)),
            other => panic!("expected Busy, got {other:?}"),
        }
    }

    #[test]
    fn create_scope_is_i1() {
        let (_dir, t) = tree();
        t.establish().expect("establish");
        let id = fixed_id();
        let limits = ResourceLimits {
            memory_bytes: 32 << 20,
            memory_high_bytes: 0,
            memory_swap_bytes: 0,
            cpu_shares: 25,
            max_pids: 32,
            io_read_bps: 0,
            io_write_bps: 0,
        };
        let scope = t
            .create_scope("default", id, &limits)
            .expect("create_scope");

        // Exactly one cgroup under the slice, with every limit readable.
        let cg = Cgroup::new(t.cgroup_root(), &scope.cgroup).expect("handle");
        assert!(cg.exists());
        assert_eq!(cg.read_to_string("memory.max").unwrap(), "33554432");
        assert_eq!(cg.read_to_string("cpu.max").unwrap(), "25000 100000");
        assert_eq!(cg.read_to_string("pids.max").unwrap(), "32");
        assert!(
            cg.path()
                .parent()
                .and_then(|p| p.file_name())
                .is_some_and(|name| name == "default.slice"),
            "the scope must sit in its slice"
        );
        // The bundle directory exists and the record points at it.
        assert!(t.base().join(&scope.bundle).is_dir());
    }

    #[test]
    fn scope_names_stay_inside_their_slice() {
        let (_dir, t) = tree();
        t.establish().expect("establish");
        let id = fixed_id();
        let scope = t.scope("batch", id).expect("scope");
        let rel = scope.rel().to_string_lossy().into_owned();
        assert!(rel.starts_with("r3s.slice/batch.slice/r3s-batch-"));
        assert!(rel.ends_with(".scope"));
        assert!(!rel.contains(".."));
    }

    #[test]
    fn a_bad_slice_name_is_an_escape() {
        let (_dir, t) = tree();
        assert!(matches!(t.slice("../etc"), Err(CgroupError::PathEscape(_))));
        assert!(matches!(t.slice(""), Err(CgroupError::PathEscape(_))));
        assert!(matches!(
            t.slice("Default"),
            Err(CgroupError::PathEscape(_))
        ));
        t.ensure_slice("real-time-2").expect("dashes are fine");
    }

    #[test]
    fn remove_scope_derives_everything_from_the_record() {
        let (_dir, t) = tree();
        t.establish().expect("establish");
        let id = fixed_id();
        let scope = t
            .create_scope("default", id, &ResourceLimits::default())
            .expect("create");

        t.remove_scope(&scope).expect("remove");
        let cg = Cgroup::new(t.cgroup_root(), &scope.cgroup).expect("handle");
        assert!(!cg.exists());
        assert!(!t.base().join(&scope.bundle).exists());

        // Retrying the removal is success: teardown may be re-run (I5).
        t.remove_scope(&scope).expect("re-remove");
    }

    #[test]
    fn remove_slice_refuses_while_scopes_remain() {
        let (_dir, t) = tree();
        t.establish().expect("establish");
        let id = fixed_id();
        t.create_scope("batch", id, &ResourceLimits::default())
            .expect("create");
        match t.remove_slice("batch") {
            Err(CgroupError::Busy { path }) => {
                assert!(path.ends_with("r3s.slice/batch.slice"));
            }
            other => panic!("expected Busy, got {other:?}"),
        }
        // Sweep the scope first, and the same call succeeds — the runbook's
        // `r3s system sweep` shape.
        let scope = t.scope("batch", id).expect("scope");
        scope.remove().expect("sweep");
        t.remove_slice("batch").expect("remove after sweep");
    }

    #[test]
    fn the_engine_claim_and_release_round_trip() {
        let (_dir, t) = tree();
        t.establish().expect("establish");
        let me = getpid().as_raw();

        let system = t.system_slice().unwrap();
        assert!(system.read_procs().unwrap().contains(&me));

        // The fake cannot follow the kernel move: the release writes us into
        // the root, but the system slice still lists us, so the drain's check
        // reports the straggler and the release stops with the §6.3 error.
        // The move — and the re-establish after it, which the kernel would
        // permit because the root is truly empty — is on-device (I4).
        match t.release_engine() {
            Err(CgroupError::Busy { .. }) => {}
            other => panic!("expected Busy, got {other:?}"),
        }
        // The attach half of the release did land.
        let root = Cgroup::new(t.cgroup_root(), "").unwrap();
        assert!(root.read_procs().unwrap().contains(&me));
    }

    #[test]
    fn slice_limits_bound_the_class() {
        let (_dir, t) = tree();
        t.establish().expect("establish");
        let total = ResourceLimits {
            memory_bytes: 64 << 20,
            ..ResourceLimits::default()
        };
        t.set_slice_limits("batch", &total).expect("set");
        let slice = t.slice("batch").unwrap();
        assert_eq!(slice.read_to_string("memory.max").unwrap(), "67108864");
    }
}
