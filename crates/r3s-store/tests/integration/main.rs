//! Integration tests that need more than one process, one thread, or a real
//! file layout. The unit tests inside each module cover the logic; these cover
//! the claims that only hold when the parts are wired together.
//!
//! Referenced from `docs/UNSAFE.md` as `tests/integration/single_writer.rs`
//! (J-02) and `tests/integration/compaction.rs` (J-01/J-02). Cargo compiles a
//! `tests/<dir>/main.rs` as a single target, which is why the modules live in a
//! directory rather than at the top of `tests/`.

mod compaction;
mod single_writer;
