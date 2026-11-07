//! The r3s CLI: hand-written parser, router, RBAC, and renderers.
//!
//! This is Stage 2, Week 3 (docs/ARCHITECTURE.md §5.2). The CLI is the
//! operator's primary interface to the engine — no Docker-compatible shim,
//! a native r3s grammar.
//!
//! Core components:
//! - **Parser**: hand-written, no external parser crates. Supports subcommands
//!   like `r3s container create`, `r3s container start`, `r3s image pull`.
//! - **Router**: dispatches commands to the engine via the Command surface.
//! - **RBAC**: role-based access control with allow/deny matrix.
//! - **Renderers**: table and JSON output formats for `r3s ps`, `r3s stats`.
//! - **Exit codes**: standardized exit codes for operator tooling.

#![deny(unsafe_op_in_unsafe_fn)]
// missing_docs denied in individual modules where needed

pub mod parser;
pub mod router;
pub mod rbac;
pub mod render;
pub mod exit_codes;

pub use parser::CliParser;
pub use router::Router;
pub use rbac::{Role, AccessMatrix};
pub use render::{TableRenderer, JsonRenderer};
pub use exit_codes::ExitCode;
