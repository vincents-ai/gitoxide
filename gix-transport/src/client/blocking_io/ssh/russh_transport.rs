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
    io::{Cursor, Read, Write},
    sync::{Arc, Mutex},
};

use russh::client::Handler;
use russh::keys::PrivateKeyWithHashAlg;
use russh::ChannelMsg;
use tokio::runtime::Handle;

use crate::client::git::blocking_io::Connection;
use crate::client::git::ConnectMode;
use crate::client::{
    blocking_io::{request::RequestWriter, SetServiceResponse, Transport},
    TransportWithoutIO, WriteMode,
};
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
            // Benign messages the server sends during a git session that carry
            // no data on stdout (the channel's primary stream). We must not
            // error on them — a git-receive-pack run sends ExtendedData (stderr
            // "remote: ..." progress), WindowAdjusted, ExitStatus, etc.
            // Loop and wait for the next message.
            Some(
                ChannelMsg::ExtendedData { .. }
                | ChannelMsg::WindowAdjusted { .. }
                | ChannelMsg::ExitStatus { .. }
                | ChannelMsg::ExitSignal { .. }
                | ChannelMsg::Success
                | ChannelMsg::Failure
                | ChannelMsg::Close
                | ChannelMsg::XonXoff { .. },
            ) => {
                // Drop the channel borrow (the `block_on` above already released
                // it) and recurse to read the next message. This keeps the SSH
                // session progressing without surfacing these as IO errors.
                drop(shared);
                self.read(buf)
            }
            _ => Err(std::io::Error::other("Unexpected SSH channel message")),
        }
    }
}

impl Write for ChannelWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let shared = self.shared.lock().unwrap();
        let cursor = Cursor::new(buf.to_vec());
        let channel = shared
            .channel
            .as_ref()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "SSH channel already closed"))?;
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
        server_public_key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        if self.accept_unknown {
            // Insecure mode: accept any key (for development/testing)
            return Ok(true);
        }

        // A certificate names the same key data as a public key; normalize both
        // to `PublicKey` so known_hosts comparison is identical for either.
        let key: russh::keys::ssh_key::PublicKey = match server_public_key {
            russh::keys::PublicKeyOrCertificate::PublicKey { key, .. } => key.clone(),
            russh::keys::PublicKeyOrCertificate::Certificate(cert) => {
                cert.public_key().clone().into()
            }
        };
        match russh::keys::check_known_hosts(&self.host, self.port, &key) {
            Ok(true) => Ok(true),
            Ok(false) => {
                // Key not found in known_hosts
                gix_trace::warn!(
                    "Host {}:{} not found in known_hosts. Set accept_unknown_hosts: true to accept.",
                    self.host,
                    self.port
                );
                Ok(false)
            }
            Err(e) => {
                // Key mismatch — possible MITM attack
                gix_trace::error!("Host key verification failed for {}:{}: {}", self.host, self.port, e);
                Ok(false)
            }
        }
    }
}

/// The error used in [`connect()`].
#[derive(Debug)]
#[allow(missing_docs)]
pub enum RusshError {
    UnsupportedScheme { url: gix_url::Url },
    Key(String),
    AuthenticationFailed(String),
    ConnectionFailed(String),
    Russh(russh::Error),
    Io(std::io::Error),
}

impl From<std::io::Error> for RusshError {
    fn from(err: std::io::Error) -> Self {
        RusshError::Io(err)
    }
}

impl From<russh::Error> for RusshError {
    fn from(err: russh::Error) -> Self {
        RusshError::Russh(err)
    }
}

impl std::fmt::Display for RusshError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RusshError::UnsupportedScheme { url } => {
                write!(f, "The scheme in \"{url}\" is not usable for an SSH connection")
            }
            RusshError::Key(err) => write!(f, "SSH key error: {err}"),
            RusshError::AuthenticationFailed(err) => write!(f, "SSH authentication failed: {err}"),
            RusshError::ConnectionFailed(err) => write!(f, "SSH connection failed: {err}"),
            RusshError::Russh(err) => write!(f, "SSH: {err}"),
            RusshError::Io(err) => write!(f, "I/O: {err}"),
        }
    }
}

impl std::error::Error for RusshError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            RusshError::Russh(err) => Some(err),
            RusshError::Io(err) => Some(err),
            _ => None,
        }
    }
}


/// Private-key material for the native russh SSH transport.
#[derive(Debug, Clone)]
pub enum RusshKeyMaterial {
    /// Load the private key from a filesystem path.
    Path(std::path::PathBuf),
    /// Decode private-key PEM/OpenSSH/PPK text supplied in memory.
    InMemory(String),
}

impl Default for RusshKeyMaterial {
    fn default() -> Self {
        Self::Path(std::path::PathBuf::from("~/.ssh/id_ed25519"))
    }
}

/// Options for connecting via the native russh SSH transport.
#[derive(Debug, Clone)]
pub struct RusshConnectOptions {
    /// Private-key material used for SSH public-key authentication.
    pub key: RusshKeyMaterial,
    /// Optional password for encrypted private keys.
    pub key_password: Option<String>,
    /// Accept unknown host keys (insecure, for development only).
    pub accept_unknown_hosts: bool,
}

impl RusshConnectOptions {
    /// Create options that load the private key from `key_path`.
    pub fn from_key_path(key_path: impl Into<std::path::PathBuf>) -> Self {
        Self {
            key: RusshKeyMaterial::Path(key_path.into()),
            ..Default::default()
        }
    }

    /// Create options that decode private-key material from memory.
    pub fn from_private_key_pem(private_key_pem: impl Into<String>) -> Self {
        Self {
            key: RusshKeyMaterial::InMemory(private_key_pem.into()),
            ..Default::default()
        }
    }

    /// Resolve the configured key material into a russh private key.
    pub fn load_private_key(&self) -> Result<russh::keys::PrivateKey, RusshError> {
        match &self.key {
            RusshKeyMaterial::Path(key_path) => russh::keys::load_secret_key(key_path, self.key_password.as_deref())
                .map_err(|e| RusshError::Key(e.to_string())),
            RusshKeyMaterial::InMemory(private_key_pem) => {
                russh::keys::decode_secret_key(private_key_pem, self.key_password.as_deref())
                    .map_err(|e| RusshError::Key(e.to_string()))
            }
        }
    }
}

impl Default for RusshConnectOptions {
    fn default() -> Self {
        Self {
            key: RusshKeyMaterial::default(),
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
        let mut session =
            rt_handle.block_on(async { russh::client::connect(config, (&*host, port), handler).await })?;

        let auth_result = rt_handle.block_on(async { session.authenticate_publickey(&user, key_with_alg).await })?;

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

#[cfg(test)]
mod tests {
    use super::{RusshConnectOptions, RusshKeyMaterial};

    const ED25519_KEY: &str = "-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jYmMAAAAGYmNyeXB0AAAAGAAAABDLGyfA39
J2FcJygtYqi5ISAAAAEAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIN+Wjn4+4Fcvl2Jl
KpggT+wCRxpSvtqqpVrQrKN1/A22AAAAkOHDLnYZvYS6H9Q3S3Nk4ri3R2jAZlQlBbUos5
FkHpYgNw65KCWCTXtP7ye2czMC3zjn2r98pJLobsLYQgRiHIv/CUdAdsqbvMPECB+wl/UQ
e+JpiSq66Z6GIt0801skPh20jxOO3F52SoX1IeO5D5PXfZrfSZlw6S8c7bwyp2FHxDewRx
7/wNsnDM0T7nLv/Q==
-----END OPENSSH PRIVATE KEY-----";

    #[test]
    fn load_private_key_from_in_memory_pem() {
        let mut options = RusshConnectOptions::from_private_key_pem(ED25519_KEY);
        options.key_password = Some("blabla".to_string());

        let key = options.load_private_key().expect("in-memory key decodes");

        assert_eq!(key.algorithm(), russh::keys::Algorithm::Ed25519);
    }

    #[test]
    fn load_private_key_from_path_preserves_existing_behavior() {
        let key_path = std::env::temp_dir().join(format!("gix-transport-russh-test-{}-id_ed25519", std::process::id()));
        std::fs::write(&key_path, ED25519_KEY).expect("write temporary key file");

        let mut options = RusshConnectOptions::from_key_path(&key_path);
        options.key_password = Some("blabla".to_string());
        let key = options.load_private_key().expect("path key decodes");

        std::fs::remove_file(&key_path).ok();
        assert_eq!(key.algorithm(), russh::keys::Algorithm::Ed25519);
    }

    #[test]
    fn default_key_material_uses_legacy_key_path() {
        match RusshConnectOptions::default().key {
            RusshKeyMaterial::Path(path) => assert_eq!(path, std::path::PathBuf::from("~/.ssh/id_ed25519")),
            RusshKeyMaterial::InMemory(_) => panic!("default must keep path-based behavior"),
        }
    }
}

impl TransportWithoutIO for RusshOnDemand {
    fn set_identity(&mut self, _identity: gix_sec::identity::Account) -> Result<(), crate::client::Error> {
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

    fn configure(&mut self, _config: &dyn Any) -> gix_error::Result {
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
