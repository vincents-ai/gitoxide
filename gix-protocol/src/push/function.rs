//! The push function — sends ref updates and a packfile to the server.

#[crate::bisync::only_async]
use futures_lite::AsyncWriteExt;
#[crate::bisync::only_sync]
use std::io::Write;

use gix_error::{Result, ResultExt, bail, message};
use gix_utils::progress::{Progress, steps};

use crate::transport::{client::MessageKind, Service};
use crate::bisync::bisync;
#[crate::bisync::only_async]
use crate::transport::client::async_io::Transport;
#[crate::bisync::only_sync]
use crate::transport::client::blocking_io::Transport;

use crate::push::{Arguments, Outcome, RefUpdate, Response, Status};

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

/// Perform a push operation over the given `transport`, sending `ref_updates` and `pack_data`.
///
/// This function:
/// 1. Performs a handshake with `Service::ReceivePack` to get remote refs and capabilities
/// 2. Opens a request writer and sends ref update commands as pkt-line data
/// 3. Sends the packfile data as binary
/// 4. Reads the server's status report
///
/// `pack_data` contains the pre-generated packfile bytes. The caller is responsible
/// for enumerating the objects to include and generating the pack.
#[bisync]
pub async fn push<P, T>(
    mut transport: T,
    authenticate: impl FnMut(crate::credentials::helper::Action) -> Result<Option<crate::credentials::protocol::Outcome>>,
    ref_updates: Vec<RefUpdate>,
    pack_data: &[u8],
    mut progress: P,
    options: Options,
) -> Result<Outcome>
where
    P: Progress,
    T: Transport,
{
    if ref_updates.is_empty() {
        bail!("No ref updates to push");
    }

    progress.set_name("push".into());
    progress.init(Some(4), steps());

    // Step 1: Handshake with the ReceivePack service.
    progress.step();
    let handshake_result = crate::handshake::function::handshake(
        &mut transport,
        Service::ReceivePack,
        authenticate,
        Vec::new(),
        &mut progress,
    )
    .await
    .or_raise(|| message("Handshake for push failed"))?;

    // Build arguments from capabilities and ref updates.
    let arguments = Arguments::new(
        ref_updates,
        &handshake_result.capabilities,
        handshake_result.server_protocol_version,
    );

    // Step 2: Send the ref-update commands.
    //
    // Binary mode frames each write() as a packet line, which is what the ref
    // commands need; the pack itself is written raw afterwards.
    progress.step();
    let mut writer = transport
        .request(
            crate::transport::client::WriteMode::Binary,
            MessageKind::Flush,
            options.trace,
        )
        .or_raise(|| message("Could not open a request writer for the push"))?;

    for command in arguments.encode_lines() {
        writer
            .write_all(&command)
            .await
            .or_raise(|| message("Could not write a ref update command"))?;
        writer
            .flush()
            .await
            .or_raise(|| message("Could not flush a ref update command"))?;
    }
    writer
        .write_message(MessageKind::Flush)
        .await
        .or_raise(|| message("Could not write the end of the ref update commands"))?;
    writer
        .flush()
        .await
        .or_raise(|| message("Could not flush the ref update commands"))?;

    // Step 3: Send the packfile as raw bytes (not packet-line encoded). V1
    // git-receive-pack expects commands+flush, then the packfile verbatim.
    let reader = if pack_data.is_empty() {
        writer
            .into_read()
            .await
            .or_raise(|| message("Could not transition the request writer into a reader"))?
    } else {
        progress.step();
        let (mut raw_writer, reader) = writer.into_parts();
        raw_writer
            .write_all(pack_data)
            .await
            .or_raise(|| message("Could not write the packfile"))?;
        raw_writer
            .flush()
            .await
            .or_raise(|| message("Could not flush the packfile"))?;
        drop(raw_writer);
        reader
    };

    // Step 4: Parse the server's status report.
    progress.step();
    let ref_statuses = if arguments.report_status() {
        Response::from_reader(reader).await?.ref_statuses
    } else {
        arguments
            .updates()
            .iter()
            .map(|update| (update.name.clone(), Status::Ok))
            .collect()
    };

    Ok(Outcome { ref_statuses })
}
