//! A fake cgroup v2 filesystem for host-side tests.
//!
//! [`crate::cgroup`] and [`crate::tree`] are written against the real control
//! files, and two of the kernel behaviors they rely on do not exist on a plain
//! directory tree. What *is* reproducible on the host — and what the tests
//! here cover — is the file surface: paths, the write-then-read contract,
//! controller availability, and the checks this code performs *before*
//! trusting the kernel.
//!
//! What a plain file cannot reproduce:
//!
//! - the pid move: writing a pid into a cgroup's `cgroup.procs` detaches it
//!   from its previous cgroup in the kernel; a file write only touches the
//!   destination. So a drained cgroup still reads as populated in the fake,
//!   and tests that reach a move assert the `Busy` check instead. The move
//!   itself is verified on-device (AGENTS.md).
//! - `EBUSY` from `cgroup.subtree_control` on a non-empty cgroup: the fake
//!   write always succeeds, so controller enablement is asserted through the
//!   availability check, not through the write.
//!
//! `make_tree` pre-creates every cgroup directory with the full control-file
//! set, because [`Cgroup::ensure`](crate::Cgroup::ensure) is a bare
//! `create_dir_all` even against the real kernel: a `mkdir` in the fake would
//! leave a cgroup without the files the kernel would have given it, and the
//! first write into it would fail `ENOENT`. The pre-creation mirrors a tree
//! the kernel already built — which is what the daemon boot sequence leaves
//! behind before any container exists.

use std::fs;
use std::path::Path;

/// Controllers the fake root advertises by default.
///
/// Deliberately no `io` and no `cpuset`: the `MissingController` and
/// `REQUIRED` tests need a controller that is *absent*, and the host suite
/// must not depend on what the host kernel happens to expose.
pub const DEFAULT_CONTROLLERS: &str = "cpu memory pids";

/// The fixed id the tests use, so the fake tree can pre-create the scope
/// directories `create_scope` would `mkdir` at runtime.
pub const TEST_ID: [u8; 16] = [
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
];

/// `TEST_ID` hex-encoded, the form `CgroupTree` puts into a scope name.
pub const TEST_ID_HEX: &str = "0123456789abcdef0123456789abcdef";

/// Control files every cgroup v2 directory carries that this crate reads or
/// writes, with the value a freshly created kernel cgroup has.
const CONTROL_FILES: &[(&str, &str)] = &[
    ("cgroup.procs", ""),
    ("cgroup.subtree_control", ""),
    ("cgroup.kill", "0"),
    ("memory.max", "max"),
    ("memory.high", "max"),
    ("memory.swap.max", "max"),
    ("memory.oom.group", "0"),
    ("memory.current", "0"),
    ("cpu.max", "max 100000"),
    ("pids.max", "max"),
];

/// Every cgroup directory the tests can reach, relative to the cgroup2 root.
///
/// The scope directories are pre-created because the tests use `TEST_ID` and
/// `create_scope` does not itself leave the control files behind.
fn tree_dirs() -> Vec<String> {
    vec![
        String::new(),
        "r3s.slice".to_owned(),
        "r3s.slice/r3s-system.slice".to_owned(),
        "r3s.slice/default.slice".to_owned(),
        format!("r3s.slice/default.slice/r3s-default-{TEST_ID_HEX}.scope"),
        "r3s.slice/batch.slice".to_owned(),
        format!("r3s.slice/batch.slice/r3s-batch-{TEST_ID_HEX}.scope"),
        "r3s.slice/real-time-2.slice".to_owned(),
    ]
}

/// Builds the fake tree under `root`, advertising `controllers` at every
/// level. Test-only: panics instead of returning an error because a fixture
/// that cannot build is a bug in the fixture, not in the code under test.
pub fn make_tree(root: &Path, controllers: impl AsRef<str>) {
    for rel in tree_dirs() {
        let dir = if rel.is_empty() {
            root.to_path_buf()
        } else {
            root.join(&rel)
        };
        fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("fakefs: cannot create {dir:?}: {e}"));
        fs::write(dir.join("cgroup.controllers"), controllers.as_ref())
            .unwrap_or_else(|e| panic!("fakefs: cannot seed controllers in {dir:?}: {e}"));
        for (name, initial) in CONTROL_FILES {
            fs::write(dir.join(name), *initial)
                .unwrap_or_else(|e| panic!("fakefs: cannot seed {name} in {dir:?}: {e}"));
        }
    }
}
