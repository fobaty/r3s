//! nftables integration (no `nft` command).
//!
//! Implements basic nftables operations for firewall and traffic control.

use tracing::info;

/// nftables wrapper.
pub struct Nftables {
    // TODO: implement actual nftables interaction
}

impl Nftables {
    /// Create a new nftables instance.
    pub fn new() -> anyhow::Result<Self> {
        info!("nftables initialized");
        Ok(Self {})
    }

    /// Add a rule to a table/chain.
    pub fn add_rule(&self, table: &str, chain: &str, rule: &str) -> anyhow::Result<()> {
        info!(table, chain, rule, "adding nftables rule");
        // TODO: implement actual nftables rule addition
        Ok(())
    }

    /// Delete a rule from a table/chain.
    pub fn delete_rule(&self, table: &str, chain: &str, rule: &str) -> anyhow::Result<()> {
        info!(table, chain, rule, "deleting nftables rule");
        // TODO: implement actual nftables rule deletion
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nftables_creation() {
        let nft = Nftables::new().unwrap();
        assert!(nft.add_rule("filter", "input", "tcp dport 22 accept").is_ok());
    }
}
