//! Channel lifecycle: PTY (`openpty` + `TIOCSWINSZ`), `exec`, extended-data
//! (stderr), `exit-status`. Refusal of `sftp`/`x11`/`direct-tcpip`/`agent`.

use tracing::{info, warn};

/// Handle a SSH session channel request.
pub async fn handle_session_channel(
    _shell: Option<String>,
) -> anyhow::Result<()> {
    info!("opening PTY for session channel");
    // TODO: implement PTY setup and exec
    Ok(())
}

/// Handle a SSH channel request.
pub fn handle_channel(
    channel_type: &str,
) -> anyhow::Result<()> {
    info!(channel_type, "channel request");

    match channel_type {
        "session" => Ok(()),
        "sftp" | "x11" | "direct-tcpip" | "agent" => {
            warn!(channel_type, "refusing unsupported channel type");
            anyhow::bail!("unsupported channel type: {channel_type}");
        }
        _ => {
            warn!(channel_type, "unknown channel type");
            anyhow::bail!("unknown channel type: {channel_type}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_refusal() {
        assert!(handle_channel("sftp").is_err());
        assert!(handle_channel("x11").is_err());
        assert!(handle_channel("direct-tcpip").is_err());
        assert!(handle_channel("agent").is_err());
        assert!(handle_channel("session").is_ok());
    }
}