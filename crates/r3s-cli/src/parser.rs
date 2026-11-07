//! Hand-written CLI parser. No external parser crates for v1.
//!
//! Supports subcommands with the grammar:
//! ```text
//! r3s <command> [arguments]
//! ```
//!
//! Commands:
//! - `container create <spec>`
//! - `container start <id>`
//! - `container stop <id>`
//! - `container rm <id>`
//! - `image pull <ref>`
//! - `ps`
//! - `stats`
//! - `version`

use anyhow::Result;

/// Parsed CLI command.
#[derive(Debug)]
pub enum CliCommand {
    ContainerCreate { spec: String },
    ContainerStart { id: String },
    ContainerStop { id: String },
    ContainerRemove { id: String, force: bool },
    ImagePull { ref_: String },
    Ps,
    Stats,
    Version,
}

/// Hand-written parser. Splits input string into tokens and dispatches
/// to the appropriate command variant.
pub struct CliParser;

impl CliParser {
    /// Parse a CLI input string into a `CliCommand`.
    pub fn parse(input: &str) -> Result<CliCommand> {
        let mut tokens = input.trim().split_whitespace();

        let cmd = match tokens.next() {
            Some("container") => Self::parse_container(&mut tokens)?,
            Some("image") => Self::parse_image(&mut tokens)?,
            Some("ps") => CliCommand::Ps,
            Some("stats") => CliCommand::Stats,
            Some("version") => CliCommand::Version,
            Some(_) => anyhow::bail!("unknown top-level command"),
            None => anyhow::bail!("empty command"),
        };

        Ok(cmd)
    }

    fn parse_container(tokens: &mut std::str::SplitWhitespace<'_>) -> Result<CliCommand> {
        let subcmd = match tokens.next() {
            Some("create") => {
                let spec = tokens.next().ok_or_else(|| anyhow::anyhow!("missing container spec"))?;
                CliCommand::ContainerCreate { spec: spec.to_string() }
            }
            Some("start") => {
                let id = tokens.next().ok_or_else(|| anyhow::anyhow!("missing container id"))?;
                CliCommand::ContainerStart { id: id.to_string() }
            }
            Some("stop") => {
                let id = tokens.next().ok_or_else(|| anyhow::anyhow!("missing container id"))?;
                CliCommand::ContainerStop { id: id.to_string() }
            }
            Some("rm") => {
                let id = tokens.next().ok_or_else(|| anyhow::anyhow!("missing container id"))?;
                let force = tokens.any(|t| t == "--force");
                CliCommand::ContainerRemove { id: id.to_string(), force }
            }
            Some(_) => anyhow::bail!("unknown container subcommand"),
            None => anyhow::bail!("missing container subcommand"),
        };

        Ok(subcmd)
    }

    fn parse_image(tokens: &mut std::str::SplitWhitespace<'_>) -> Result<CliCommand> {
        let subcmd = match tokens.next() {
            Some("pull") => {
                let ref_ = tokens.next().ok_or_else(|| anyhow::anyhow!("missing image reference"))?;
                CliCommand::ImagePull { ref_: ref_.to_string() }
            }
            Some(_) => anyhow::bail!("unknown image subcommand"),
            None => anyhow::bail!("missing image subcommand"),
        };

        Ok(subcmd)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_version() {
        let cmd = CliParser::parse("version").expect("parses");
        assert!(matches!(cmd, CliCommand::Version));
    }

    #[test]
    fn parse_container_start() {
        let cmd = CliParser::parse("container start web-1").expect("parses");
        assert!(matches!(cmd, CliCommand::ContainerStart { id } if id == "web-1"));
    }

    #[test]
    fn parse_image_pull() {
        let cmd = CliParser::parse("image pull alpine:3").expect("parses");
        assert!(matches!(cmd, CliCommand::ImagePull { ref_ } if ref_ == "alpine:3"));
    }

    #[test]
    fn parse_container_rm_force() {
        let cmd = CliParser::parse("container rm web-1 --force").expect("parses");
        assert!(matches!(cmd, CliCommand::ContainerRemove { id, force } if id == "web-1" && force));
    }
}
