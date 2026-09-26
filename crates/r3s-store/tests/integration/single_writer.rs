//! J-02: exactly one writer per state directory, across processes.
//!
//! The unit test in `lib.rs` proves the lock is taken and released within one
//! process. This proves the thing the register actually claims: a *second
//! engine*, started as a separate process against the same root, is refused
//! rather than allowed to interleave writes.

use std::path::Path;
use std::process::{Command, Stdio};

use r3s_store::{Store, StoreError};

/// The engine binary, when it exists. Without it there is no second *process*
/// to test, and a test that quietly passes without asserting anything is worse
/// than no test at all — so this one is `#[ignore]`d and says why.
const ENGINE: Option<&str> = option_env!("R3S_ENGINE_BIN");

#[test]
fn a_second_store_in_this_process_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let _first = Store::open(dir.path()).expect("open");
    match Store::open(dir.path()) {
        Err(StoreError::Locked) => {}
        Err(other) => panic!("a second store must be refused with Locked, got {other:?}"),
        Ok(_) => panic!("a second store must never open on the same root"),
    }
}

#[test]
fn the_lock_is_released_when_the_process_exits() {
    let dir = tempfile::tempdir().expect("tempdir");
    {
        let _store = Store::open(dir.path()).expect("open");
    }
    // The guard is dropped, so the next open must succeed. This is the same
    // guarantee a `kill -9` gets from the kernel, minus the kernel: nothing
    // here has to be cleaned up.
    Store::open(dir.path()).expect("the lock must not outlive the handle");
}

/// `#[ignore]` until `r3s-bin` exists. Run with
/// `R3S_ENGINE_BIN=target/debug/r3s cargo test -p r3s-store -- --ignored`
/// once it does; `docs/UNSAFE.md` cites this test as J-02's cross-process
/// verification, and an ignored test is the honest state of that claim.
#[test]
#[ignore = "needs a real r3s binary; see docs/UNSAFE.md J-02"]
fn a_child_process_is_refused_the_store() {
    let Some(engine) = ENGINE else {
        panic!("R3S_ENGINE_BIN is not set; run with it to exercise this test");
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let _store = Store::open(dir.path()).expect("open");
    let status = Command::new(engine)
        .arg("system")
        .arg("status")
        .arg("--store-only")
        .env("R3S_STATE_DIR", dir.path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .status()
        .expect("spawn the engine");
    assert!(
        !status.success(),
        "a second engine must not be able to open a held store"
    );
}

#[test]
fn the_lock_file_is_not_the_only_thing_that_matters() {
    // A stale `LOCK` file from a crashed engine must not keep the node down:
    // the file is permanent, only the `flock` is held. This asserts the file
    // exists afterwards, because a lock implemented as "delete the file on
    // exit" would pass every test above and fail this one.
    let dir = tempfile::tempdir().expect("tempdir");
    {
        let _store = Store::open(dir.path()).expect("open");
    }
    let lock = dir.path().join("LOCK");
    assert!(
        lock.exists(),
        "the lock file must survive the process that held it"
    );
    assert!(
        is_empty(lock.as_path()),
        "nothing is written to the lock file; it is only flocked"
    );
}

fn is_empty(path: &Path) -> bool {
    std::fs::metadata(path)
        .map(|m| m.len() == 0)
        .unwrap_or(false)
}
