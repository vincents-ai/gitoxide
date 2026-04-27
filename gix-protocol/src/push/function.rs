//! The push function — sends ref updates and a packfile to the server.

use std::io::Write;

use gix_features::progress::Progress;
use gix_transport::{
    client::{
        self,
        blocking_io::Transport,
        MessageKind, WriteMode,
    },
    Service,
};
use maybe_async::maybe_async;

use crate::push::{Arguments, Outcome, RefUpdate, Response, Status};

/// The error returned by the [push()] function.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum Error {
    #[error("IO error during push")]
    Io(#[from] std::io::Error),
    #[error("Transport error")]
    Transport(#[from] client::Error),
    #[error("Handshake error")]
    Handshake(#[from] crate::handshake::Error),
    #[error("Response parse error")]
    Response(#[from] crate::push::response::Error),
    #[error("Push rejected: {0}")]
    Rejected(String),
    #[error("No ref updates to push")]
    EmptyUpdate,
}

impl gix_transport::IsSpuriousError for Error {
    fn is_spurious(&self) -> bool {
        match self {
            Error::Io(err) => err.is_spurious(),
            Error::Transport(err) => err.is_spurious(),
            _ => false,
        }
    }
}

/// Options for the push operation.
pub struct Options {
    /// Whether to use thin packs (packs that reference base objects the server already has).
    pub thin_pack: bool,
    /// Trace packet lines for debugging.
    pub trace: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            thin_pack: true,
            trace: false,
        }
    }
}

/// Perform a push operation using V1 protocol over the given transport.
///
/// This function:
/// 1. Performs a handshake with `Service::ReceivePack` to get remote refs and capabilities
/// 2. Opens a request writer and sends ref update commands as pkt-line data
/// 3. Sends the packfile data as binary
/// 4. Reads the server's status report
///
/// `pack_data` contains the pre-generated packfile bytes. The caller is responsible
/// for enumerating the objects to include and generating the pack.
#[maybe_async]
pub async fn push<P, T>(
    mut transport: T,
    authenticate: impl FnMut(
        gix_credentials::helper::Action,
    ) -> gix_credentials::protocol::Result,
    ref_updates: Vec<RefUpdate>,
    pack_data: &[u8],
    mut progress: P,
    options: Options,
) -> Result<Outcome, Error>
where
    P: Progress,
    T: Transport,
{
    if ref_updates.is_empty() {
        return Err(Error::EmptyUpdate);
    }

    progress.set_name("push".into());
    progress.init(Some(4), gix_features::progress::steps());

    // Step 1: Handshake with ReceivePack service
    progress.step();
    let handshake_result = crate::handshake::function::handshake(
        &mut transport,
        Service::ReceivePack,
        authenticate,
        Vec::new(),
        &mut progress,
    )
    .await?;

    // Build arguments from capabilities and ref updates
    let arguments = Arguments::new(
        ref_updates,
        &handshake_result.capabilities,
        handshake_result.server_protocol_version,
    );

    // Step 2: Open a request writer for sending ref commands + pack
    // Use Binary mode so we can write raw data alongside pkt-line data.
    // on_into_read = Flush to send a final flush when converting to reader.
    progress.step();
    let mut writer = transport.request(
        WriteMode::Binary,
        MessageKind::Flush,
        options.trace,
    )?;

    // Write ref update commands as pkt-line text
    let encoded_args = arguments.encode();
    // Write the encoded args directly using the Write trait
    // (RequestWriter in binary mode writes raw bytes)
    writer.write_all(&encoded_args)?;
    writer.flush()?;
    // Flush after ref commands
    writer.write_message(MessageKind::Flush)?;
    writer.flush()?;

    // Step 3: Send packfile data as binary
    if !pack_data.is_empty() {
        progress.step();
        // In binary mode, write() sends raw bytes (not pkt-line encoded)
        writer.write_all(pack_data)?;
        writer.flush()?;
    }

    // Step 4: Convert writer to reader and parse status report
    progress.step();
    let ref_statuses = if arguments.report_status() {
        let reader = writer.into_read()?;
        let response = Response::from_blocking_reader(reader)?;
        response.ref_statuses
    } else {
        // No report-status: assume success for all refs
        arguments
            .updates()
            .iter()
            .map(|u| (u.name.clone(), Status::Ok))
            .collect()
    };

    Ok(Outcome { ref_statuses })
}
