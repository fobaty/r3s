//! SSH server implementation using russh.

use russh::server::{Handler, Auth};
use russh::keys::PublicKey;
use russh::{Channel, ChannelId};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

use crate::auth::{AuthorizedKeysFile, BruteForceProtector};

/// Error type for the SSH server.
#[derive(thiserror::Error, Debug)]
pub enum SshdError {
    #[error("authentication failed: {0}")]
    AuthFailed(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("general error: {0}")]
    General(#[from] anyhow::Error),
}

impl From<russh::Error> for SshdError {
    fn from(err: russh::Error) -> Self {
        SshdError::General(anyhow::anyhow!(err))
    }
}

/// The SSH daemon. Binds to a port, accepts connections, and handles authentication.
pub struct Sshd {
    bind_addr: SocketAddr,
    authorized_keys_path: PathBuf,
    brute_force_protector: BruteForceProtector,
}

impl Sshd {
    /// Create a new SSH daemon.
    pub fn new(bind_addr: SocketAddr, authorized_keys_path: PathBuf) -> Self {
        Self {
            bind_addr,
            authorized_keys_path,
            brute_force_protector: BruteForceProtector::new(1000, Duration::from_secs(1), Duration::from_secs(300)),
        }
    }

    /// Start listening on the configured address.
    pub async fn run(&self) -> anyhow::Result<()> {
        info!(addr = %self.bind_addr, "SSH server starting");

        let handler = AuthHandler {
            authorized_keys: Arc::new(AuthorizedKeysFile::new(&self.authorized_keys_path)),
            protector: Arc::new(self.brute_force_protector.clone()),
        };

        // Start the server
        let listener = tokio::net::TcpListener::bind(self.bind_addr).await?;
        
        while let Ok((stream, addr)) = listener.accept().await {
            info!(addr = %addr, "new connection");
            // Handler is passed by value, not by Arc
            let handler_clone = AuthHandler {
                authorized_keys: Arc::clone(&handler.authorized_keys),
                protector: Arc::clone(&handler.protector),
            };
            tokio::spawn(async move {
                if let Err(e) = russh::server::run_stream(Arc::new(russh::server::Config::default()), stream, handler_clone).await {
                    warn!(addr = %addr, error = %e, "connection handling failed");
                }
            });
        }

        Ok(())
    }
}

/// Authentication and channel handler for russh.
struct AuthHandler {
    authorized_keys: Arc<AuthorizedKeysFile>,
    protector: Arc<BruteForceProtector>,
}

impl Handler for AuthHandler {
    type Error = SshdError;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Reject {
            proceed_with_methods: None,
            partial_success: false,
        })
    }

    async fn auth_publickey_offered(
        &mut self,
        user: &str,
        _public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        if let Err(backoff) = self.protector.check(user) {
            warn!(user, backoff_ms = backoff.as_millis(), "brute-force protection triggered");
            return Ok(Auth::Reject {
                proceed_with_methods: None,
                partial_success: false,
            });
        }
        Ok(Auth::Accept)
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        match crate::auth::authenticate(user, public_key, &self.authorized_keys, &self.protector) {
            Ok(()) => Ok(Auth::Accept),
            Err(e) => {
                warn!(user, error = %e, "public key authentication failed");
                Ok(Auth::Reject {
                    proceed_with_methods: None,
                    partial_success: false,
                })
            }
        }
    }

    // Minimal channel handling - just accept session channels
    async fn channel_open_session(
        &mut self,
        _channel: Channel<russh::server::Msg>,
        _reply: russh::server::ChannelOpenHandle,
        _session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        info!("channel open session");
        Ok(())
    }

    async fn exec_request(
        &mut self,
        _channel: ChannelId,
        _command: &[u8],
        _session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        _channel: ChannelId,
        _subsystem: &str,
        _session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        Err(SshdError::General(anyhow::anyhow!("subsystem not supported")))
    }

    async fn tcpip_forward(
        &mut self,
        _address: &str,
        _port: &mut u32,
        _session: &mut russh::server::Session,
    ) -> Result<bool, Self::Error> {
        Ok(false)
    }
}
