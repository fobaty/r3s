//! Output renderers: table and JSON formats for CLI output.

use r3s_proto::state::{ContainerState, HealthReport};
use serde::Serialize;

// Re-export for convenience
pub use crate::parser::CliCommand;

/// Table renderer for `r3s ps`-like output.
pub struct TableRenderer;

impl TableRenderer {
    /// Render a list of containers as a table.
    pub fn render_containers(&self, containers: &[ContainerState]) -> String {
        let mut output = String::new();
        output.push_str("ID NAME IMAGE STATUS\n");
        output.push_str("---- ---- ----- ------\n");

        for c in containers {
            output.push_str(&format!(
                "{:?} {:<10} {:<20} {}\n",
                c.spec.id,
                c.spec.name,
                c.spec.image,
                c.phase.status_text(c.exit.as_ref())
            ));
        }

        output
    }
}

/// JSON renderer for structured output.
pub struct JsonRenderer;

impl JsonRenderer {
    /// Render a container state as JSON.
    pub fn render_container(&self, container: &ContainerState) -> String {
        serde_json::to_string_pretty(container).expect("serializes")
    }
}

/// Health report serialized for Prometheus-style metrics.
#[derive(Serialize)]
pub struct HealthMetrics {
    pub container: String,
    pub memory_current: u64,
    pub cpu_usage_us: u64,
    pub pids: u32,
}
