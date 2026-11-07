//! Network orchestration: netlink, nftables, namespace management.
//!
//! This is Stage 2, Week 3 of the build plan (docs/ARCHITECTURE.md §5.3).
//! The networking crate provides bare-metal network management without
//! external tools (`ip`, `nft`, `iptables`).
//!
//! Core responsibilities:
//! - Netlink socket for interface/route/addr management
//! - nftables integration for firewall/rules
//! - Network namespace creation and manipulation
//! - Container network interface (veth pair) setup

#![deny(missing_docs, unsafe_op_in_unsafe_fn)]

#[cfg(target_os = "linux")]
pub mod netlink;
#[cfg(not(target_os = "linux"))]
mod netlink_stub;
#[cfg(not(target_os = "linux"))]
pub use netlink_stub::NetlinkSocket;

#[cfg(target_os = "linux")]
pub use netlink::NetlinkSocket;

pub mod nftables;
pub mod namespace;

pub use nftables::Nftables;
pub use namespace::NetworkNamespace;
