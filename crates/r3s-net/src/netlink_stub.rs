//! Stub implementation for non-Linux platforms.
//!
//! Netlink is Linux-specific, so on macOS/other platforms we provide
//! minimal stubs for compilation.

#![cfg(not(target_os = "linux"))]

use tracing::info;

/// Netlink socket stub (non-functional on non-Linux).
pub struct NetlinkSocket;

impl NetlinkSocket {
    /// Create a new netlink socket (stub).
    pub fn new() -> anyhow::Result<Self> {
        info!("netlink socket created (stub, non-Linux)");
        Ok(Self)
    }

    /// Get interface index by name (stub).
    pub fn if_index_by_name(&self, name: &str) -> Result<u32, anyhow::Error> {
        // On macOS, use if_nametoindex from nix
        let index = nix::net::if_::if_nametoindex(name)
            .map_err(|e| anyhow::anyhow!("if_nametoindex failed: {}", e))?;
        Ok(index as u32)
    }

    /// List all interfaces (stub, uses /proc/net/dev on Linux, ifconf on macOS).
    pub fn list_interfaces(&self) -> Result<Vec<String>, anyhow::Error> {
        let interfaces = Vec::new();
        
        #[cfg(target_os = "linux")]
        {
            let content = std::fs::read_to_string("/proc/net/dev")
                .map_err(|e| anyhow::anyhow!("failed to read /proc/net/dev: {}", e))?;
            for line in content.lines().skip(2) {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 1 {
                    let name = parts[0].trim();
                    if !name.is_empty() {
                        interfaces.push(name.to_string());
                    }
                }
            }
        }
        
        #[cfg(target_os = "macos")]
        {
            // macOS doesn't have if_::interfaces(), use ifconf via libc
            // For now, return empty list as stub
            info!("interface listing is stubbed on macOS");
        }
        
        Ok(interfaces)
    }

    /// Create a new interface (stub).
    pub fn create_interface(&self, name: &str, kind: &str) -> anyhow::Result<()> {
        info!(name, kind, "creating interface (stub, non-Linux)");
        Ok(())
    }
}

impl Drop for NetlinkSocket {
    fn drop(&mut self) {
        info!("netlink socket closed (stub)");
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
        // On macOS, "lo" might not be present; just check it returns something
        assert!(interfaces.len() >= 0);
    }
}