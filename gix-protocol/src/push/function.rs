//! The push function — sends ref updates and a packfile to the server.

use std::io::Write;

use gix_features::progress::Progress;

#[cfg(feature = "async-client")]
use crate::transport::client::async_io::Transport;
#[cfg(feature = "blocking-client")]
use crate::transport::client::blocking_io::Transport;

use crate::transport::{client::MessageKind, Service};
use maybe_async::maybe_async;

use crate::push::{Arguments, Outcome, RefUpdate, Response, Status};

/// The error returned by the [push()] function.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum Error {
    #[error("IO error during push")]
    Io(#[from] std::io::Error),
    #[error("Transport error")]
    Transport(#[from] crate::transport::client::Error),
    #[error("Handshake error")]
    Handshake(#[from] crate::handshake::Error),
    #[error("Response parse error")]
    Response(#[from] crate::push::response::Error),
    #[error("Push rejected: {0}")]
    Rejected(String),
    #[error("No ref updates to push")]
    EmptyUpdate,
}

impl crate::transport::IsSpuriousError for Error {
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
        crate::credentials::helper::Action,
    ) -> crate::credentials::protocol::Result,
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

    // Step 2: Open a request writer for sending ref commands.
    // Binary mode frames each write() as a packet line — correct for the
    // ref-update commands, which must be pkt-line encoded in V1.
    // on_into_read is unused: we dissolve into parts to write the pack raw.
    progress.step();
    let mut writer = transport.request(
        crate::transport::client::WriteMode::Binary,
        MessageKind::Flush,
        options.trace,
    )?;

    // Write each ref-update command as its own packet line.
    // encode() yields one command per entry; emit them individually so each
    // is framed as a distinct pkt-line (V1: one ref-update command per line).
    for command in arguments.encode_lines() {
        writer.write_all(&command)?;
        writer.flush()?;
    }
    // Flush after the ref commands.
    writer.write_message(MessageKind::Flush)?;
    writer.flush()?;

    // Step 3: Send the packfile as RAW bytes (not pkt-line encoded).
    // V1 git-receive-pack expects commands+flush, then the packfile verbatim.
    // into_parts() yields a writer that writes verbatim (no packetline framing)
    // plus the response reader. The writer MUST be dropped before reading.
    let reader = if pack_data.is_empty() {
        writer.into_read()?
    } else {
        progress.step();
        let (mut raw_writer, reader) = writer.into_parts();
        raw_writer.write_all(pack_data)?;
        raw_writer.flush()?;
        drop(raw_writer);
        reader
    };

    // Step 4: Parse the server's status report.
    progress.step();
    let ref_statuses = if arguments.report_status() {
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
