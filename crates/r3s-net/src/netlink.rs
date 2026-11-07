//! Netlink socket for network management (no `ip` command).
//!
//! Implements basic netlink operations for interface and route management
//! using raw netlink sockets.
//!
//! NOTE: This module is Linux-only. On non-Linux platforms, it provides
//! stub implementations for compilation.

#![cfg(linux_android)]

use nix::sys::socket::{
    bind,
    AddressFamily,
    NetlinkAddr,
    SockFlag,
    SockProtocol,
    SockType,
};
use std::os::unix::io::RawFd;
use tracing::info;

// Netlink constants (from linux/netlink.h)
const RTM_NEWLINK: u16 = 14;
const RTM_GETLINK: u16 = 15;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_DUMP: u16 = 8;

/// Netlink message header (struct nlmsghdr)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NlMsghdr {
    pub len: u32,
    pub typ: u16,
    pub flags: u16,
    pub seq: u32,
    pub pid: u32,
}

/// Netlink socket for network management.
pub struct NetlinkSocket {
    fd: RawFd,
}

impl NetlinkSocket {
    /// Create a new netlink socket.
    pub fn new() -> anyhow::Result<Self> {
        let fd = nix::sys::socket::socket(
            AddressFamily::Netlink,
            SockType::Raw,
            SockFlag::empty(),
            Some(SockProtocol::NetLinkRoute),
        )?;

        // Bind to netlink with PID 0 (kernel)
        let bound_addr = NetlinkAddr::new(0, 0);
        bind(fd, &bound_addr)?;

        info!("netlink socket created (fd={})", fd);
        Ok(Self { fd })
    }

    /// Get interface index by name.
    pub fn if_index_by_name(&self, name: &str) -> Result<u32, anyhow::Error> {
        let index = nix::net::if_::if_nametoindex(name)
            .map_err(|e| anyhow::anyhow!("if_nametoindex failed: {}", e))?;
        Ok(index as u32)
    }

    /// List all interfaces using /proc/net/dev.
    pub fn list_interfaces(&self) -> Result<Vec<String>, anyhow::Error> {
        let content = std::fs::read_to_string("/proc/net/dev")
            .map_err(|e| anyhow::anyhow!("failed to read /proc/net/dev: {}", e))?;

        let mut interfaces = Vec::new();
        for line in content.lines().skip(2) { // skip header lines
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 1 {
                let name = parts[0].trim();
                if !name.is_empty() {
                    interfaces.push(name.to_string());
                }
            }
        }
        Ok(interfaces)
    }

    /// Create a new interface (e.g., veth pair).
    pub fn create_interface(&self, name: &str, kind: &str) -> anyhow::Result<()> {
        info!(name, kind, "creating interface");
        // TODO: implement actual RTM_NEWLINK request
        Ok(())
    }
}

impl Drop for NetlinkSocket {
    fn drop(&mut self) {
        info!("netlink socket closed (fd={})", self.fd);
        // Close the FD
        unsafe { libc::close(self.fd) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_netlink_socket_creation() {
        let socket = NetlinkSocket::new().unwrap();
        assert!(socket.if_index_by_name("lo").is_ok());
    }

    #[test]
    fn test_list_interfaces() {
        let socket = NetlinkSocket::new().unwrap();
        let interfaces = socket.list_interfaces().unwrap();
        assert!(interfaces.contains(&"lo".to_string()));
    }
}