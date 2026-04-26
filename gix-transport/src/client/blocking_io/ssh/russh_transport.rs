//! Pure-Rust SSH transport using `russh`
//!
//! This module provides a native SSH transport that doesn't require shelling out
//! to the `ssh` binary. It uses `russh` for the SSH protocol and bridges to
//! gix-transport's sync `Connection` type for the git packet-line protocol.
//!
//! The design mirrors `SpawnProcessOnDemand`: the SSH channel is established at
//! `connect()` time, the git service command is exec'd in `handshake()`, and the
//! packet-line `Connection` is created lazily on first handshake.

use std::{
    any::Any,
    borrow::Cow,
    error::Error,
    io::{Cursor, Read, Write},
    sync::{Arc, Mutex},
};

use russh::keys::PrivateKeyWithHashAlg;
use russh::client::Handler;
use russh::ChannelMsg;
use tokio::runtime::Handle;

use crate::client::{
    blocking_io::{request::RequestWriter, SetServiceResponse, Transport},
    TransportWithoutIO, WriteMode,
};
use crate::client::git::blocking_io::Connection;
use crate::client::git::ConnectMode;
use crate::{Protocol, Service};

/// Shared state for an SSH channel, wrapped in `Arc<Mutex>` so reader and writer
/// can operate independently while sharing the same underlying channel.
struct SharedChannel {
    channel: Option<russh::Channel<russh::client::Msg>>,
    read_buffer: Vec<u8>,
    rt_handle: Handle,
}

impl Drop for SharedChannel {
    fn drop(&mut self) {
        // Send SSH_MSG_CHANNEL_EOF followed by SSH_MSG_CHANNEL_CLOSE
        // so the server's upload-pack handler unblocks and exits cleanly.
        // Without this, the server handler blocks forever waiting for
        // client input after the ref advertisement is read.
        if let Some(channel) = self.channel.take() {
            let rt_handle = self.rt_handle.clone();
            // Spawn a best-effort task — don't block the drop path
            let _ = rt_handle.spawn(async move {
                let _ = channel.eof().await;
                let _ = channel.close().await;
            });
        }
    }
}

/// Synchronous reader over an SSH channel.
pub struct ChannelReader {
    shared: Arc<Mutex<SharedChannel>>,
}

/// Synchronous writer over an SSH channel.
pub struct ChannelWriter {
    shared: Arc<Mutex<SharedChannel>>,
}

impl Read for ChannelReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut shared = self.shared.lock().unwrap();

        if !shared.read_buffer.is_empty() {
            let len = std::cmp::min(buf.len(), shared.read_buffer.len());
            buf[..len].copy_from_slice(&shared.read_buffer[..len]);
            shared.read_buffer.drain(..len);
            return Ok(len);
        }

        let msg = {
            let rt_handle = shared.rt_handle.clone();
            let channel = shared.channel.as_mut().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::ConnectionReset, "SSH channel already closed")
            })?;
            rt_handle.block_on(async { channel.wait().await })
        };

        match msg {
            Some(ChannelMsg::Data { data }) => {
                let len = std::cmp::min(buf.len(), data.len());
                buf[..len].copy_from_slice(&data[..len]);
                if data.len() > len {
                    shared.read_buffer.extend_from_slice(&data[len..]);
                }
                Ok(len)
            }
            Some(ChannelMsg::Eof) | None => Ok(0),
            _ => Err(std::io::Error::other("Unexpected SSH channel message")),
        }
    }
}

impl Write for ChannelWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let shared = self.shared.lock().unwrap();
        let cursor = Cursor::new(buf.to_vec());
        let channel = shared.channel.as_ref().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::BrokenPipe, "SSH channel already closed")
        })?;
        shared
            .rt_handle
            .block_on(async { channel.data(cursor).await })
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e.to_string()))?;

        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// SSH client handler that verifies server keys against known_hosts.
struct KnownHostsHandler {
    host: String,
    port: u16,
    accept_unknown: bool,
}

impl Handler for KnownHostsHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        if self.accept_unknown {
            // Insecure mode: accept any key (for development/testing)
            return Ok(true);
        }

        match russh::keys::check_known_hosts(&self.host, self.port, server_public_key) {
            Ok(true) => Ok(true),
            Ok(false) => {
                // Key not found in known_hosts
                gix_features::trace::warn!(
                    "Host {}:{} not found in known_hosts. Set accept_unknown_hosts: true to accept.",
                    self.host, self.port
                );
                Ok(false)
            }
            Err(e) => {
                // Key mismatch — possible MITM attack
                gix_features::trace::error!(
                    "Host key verification failed for {}:{}: {}",
                    self.host, self.port, e
                );
                Ok(false)
            }
        }
    }
}

/// The error used in [`connect()`].
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum RusshError {
    #[error("The scheme in \"{url}\" is not usable for an SSH connection")]
    UnsupportedScheme { url: gix_url::Url },
    #[error("SSH key error: {0}")]
    Key(String),
    #[error("SSH authentication failed: {0}")]
    AuthenticationFailed(String),
    #[error("SSH connection failed: {0}")]
    ConnectionFailed(String),
    #[error("SSH: {0}")]
    Russh(#[from] russh::Error),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
}

impl crate::IsSpuriousError for RusshError {}

/// Options for connecting via the native russh SSH transport.
#[derive(Debug, Clone)]
pub struct RusshConnectOptions {
    /// Path to the SSH private key file.
    pub key_path: std::path::PathBuf,
    /// Optional password for encrypted private keys.
    pub key_password: Option<String>,
    /// Accept unknown host keys (insecure, for development only).
    pub accept_unknown_hosts: bool,
}

impl Default for RusshConnectOptions {
    fn default() -> Self {
        Self {
            key_path: std::path::PathBuf::from("~/.ssh/id_ed25519"),
            key_password: None,
            accept_unknown_hosts: false,
        }
    }
}

/// A native SSH transport using russh that implements gix's `Transport` trait.
///
/// This mirrors `SpawnProcessOnDemand`'s design: the SSH channel is established
/// at connect time, the git service command (upload-pack/receive-pack) is exec'd
/// during `handshake()`, and the packet-line `Connection` is created lazily.
pub struct RusshOnDemand {
    /// The SSH channel — present before handshake, consumed to create the connection.
    channel_state: Option<PreHandshakeState>,
    /// The packet-line connection — created in handshake(), used for request().
    connection: Option<Connection<ChannelReader, ChannelWriter>>,
    /// The SSH URL.
    url: gix_url::Url,
    /// Desired protocol version.
    desired_version: Protocol,
    /// Whether to trace packetlines.
    trace: bool,
}

/// State held before the handshake is performed.
struct PreHandshakeState {
    channel: russh::Channel<russh::client::Msg>,
    rt_handle: Handle,
}

impl RusshOnDemand {
    /// Connect to an SSH server and prepare for git protocol communication.
    ///
    /// This establishes the SSH connection and authenticates, but does NOT yet
    /// exec the git service command. That happens in `handshake()`.
    pub fn connect(
        url: gix_url::Url,
        key: russh::keys::PrivateKey,
        desired_version: Protocol,
        trace: bool,
        rt_handle: Handle,
    ) -> Result<Self, RusshError> {
        if url.scheme != gix_url::Scheme::Ssh || url.host().is_none() {
            return Err(RusshError::UnsupportedScheme { url });
        }

        let user = url.user().unwrap_or("git").to_string();
        let host = url.host().expect("validated above").to_string();
        let port = url.port.unwrap_or(22);

        let key_with_alg = PrivateKeyWithHashAlg::new(std::sync::Arc::new(key), None);

        let config = std::sync::Arc::new(russh::client::Config::default());
        let handler = KnownHostsHandler {
            host: host.clone(),
            port,
            accept_unknown: true, // TODO: read from RusshConnectOptions
        };
        let mut session = rt_handle.block_on(async {
            russh::client::connect(config, (&*host, port), handler).await
        })?;

        let auth_result = rt_handle.block_on(async {
            session.authenticate_publickey(&user, key_with_alg).await
        })?;

        match auth_result {
            russh::client::AuthResult::Success => {}
            russh::client::AuthResult::Failure { .. } => {
                return Err(RusshError::AuthenticationFailed(
                    "SSH public key authentication failed".to_string(),
                ));
            }
        }

        let channel = rt_handle
            .block_on(async { session.channel_open_session().await })
            .map_err(|e| RusshError::ConnectionFailed(e.to_string()))?;

        Ok(Self {
            channel_state: Some(PreHandshakeState { channel, rt_handle }),
            connection: None,
            url,
            desired_version,
            trace,
        })
    }
}

impl TransportWithoutIO for RusshOnDemand {
    fn set_identity(
        &mut self,
        _identity: gix_sec::identity::Account,
    ) -> Result<(), crate::client::Error> {
        Err(crate::client::Error::AuthenticationUnsupported)
    }

    fn to_url(&self) -> Cow<'_, bstr::BStr> {
        Cow::Owned(self.url.to_bstring())
    }

    fn supported_protocol_versions(&self) -> &[Protocol] {
        &[]
    }

    fn connection_persists_across_multiple_requests(&self) -> bool {
        true
    }

    fn configure(
        &mut self,
        _config: &dyn Any,
    ) -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
        Ok(())
    }
}

impl Transport for RusshOnDemand {
    fn handshake<'a>(
        &mut self,
        service: Service,
        extra_parameters: &'a [(&'a str, Option<&'a str>)],
    ) -> Result<SetServiceResponse<'_>, crate::client::Error> {
        // Take the pre-handshake state and exec the git service command
        let pre = self
            .channel_state
            .take()
            .expect("handshake called twice without successful completion");

        let repo_path = gix_url::expand_path::for_shell(self.url.path.clone());
        let exec_cmd = format!("{} '{}'", service.as_str(), String::from_utf8_lossy(&repo_path));

        pre.rt_handle
            .block_on(async { pre.channel.exec(true, exec_cmd.as_bytes()).await })
            .map_err(|e| crate::client::Error::InvokeProgram {
                source: std::io::Error::new(std::io::ErrorKind::ConnectionRefused, e.to_string()),
                command: format!("ssh {} {}", self.url.host().unwrap_or_default(), service.as_str()).into(),
            })?;

        // Create the shared channel state and split into reader/writer
        let shared = Arc::new(Mutex::new(SharedChannel {
            channel: Some(pre.channel),
            read_buffer: Vec::new(),
            rt_handle: pre.rt_handle,
        }));

        let reader = ChannelReader { shared: shared.clone() };
        let writer = ChannelWriter { shared };

        // Create the packet-line Connection.
        // Use ConnectMode::Process so it doesn't send the service request over the protocol
        // (it was already sent via the SSH exec command).
        let connection = Connection::new(
            reader,
            writer,
            self.desired_version,
            self.url.path.clone(),
            None::<(String, Option<u16>)>,
            ConnectMode::Process,
            self.trace,
        );

        self.connection = Some(connection);

        // Now delegate to the inner Connection's handshake
        self.connection
            .as_mut()
            .expect("just set")
            .handshake(service, extra_parameters)
    }

    fn request(
        &mut self,
        write_mode: WriteMode,
        on_into_read: crate::client::MessageKind,
        trace: bool,
    ) -> Result<RequestWriter<'_>, crate::client::Error> {
        self.connection
            .as_mut()
            .ok_or(crate::client::Error::MissingHandshake)?
            .request(write_mode, on_into_read, trace)
    }
}
