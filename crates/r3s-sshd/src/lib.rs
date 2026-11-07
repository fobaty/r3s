//! Embedded SSH server for the r3s management plane.
//!
//! This is Stage 2, Week 1 of the build plan (docs/ARCHITECTURE.md §5.2).
//! The SSH server provides the full management interface — no external SSH
//! tooling needed on the node.
//!
//! Core responsibilities:
//! - Bind to a TCP port, accept connections
//! - Authenticate via `authorized_keys` (stat-cached)
//! - Handle channel lifecycle: PTY (`openpty` + `TIOCSWINSZ`), `exec`, 
//!   extended-data (stderr), `exit-status`
//! - Refuse `sftp`/`x11`/`direct-tcpip`/`agent` forwarding
//! - Brute-force protection: LRU cache with exponential backoff
//! - Session/connection caps

#![deny(missing_docs, unsafe_op_in_unsafe_fn)]

pub mod auth;
pub mod channel;
pub mod server;

pub use server::Sshd;
