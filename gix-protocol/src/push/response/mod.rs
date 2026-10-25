//! Push response — parse the server's status report that follows the packfile.

use bstr::ByteSlice;
use gix_error::{Result, bail};

use crate::push::Status;

#[crate::bisync::only_async]
use crate::transport::client::async_io::ExtendedBufRead;
#[crate::bisync::only_sync]
use crate::transport::client::blocking_io::ExtendedBufRead;

/// The response from a push operation.
#[derive(Debug)]
pub struct Response {
    /// The status of each ref update as reported by the server.
    pub ref_statuses: Vec<(bstr::BString, Status)>,
}

impl Response {
    /// Parse the status report from `reader`, which must be positioned after the packfile.
    ///
    /// Lines are `ok <ref>` or `ng <ref> <reason>`, preceded by an optional
    /// `unpack ...` line describing the pack itself.
    #[crate::bisync::bisync]
    pub async fn from_reader<'a>(mut reader: Box<dyn ExtendedBufRead<'a> + Unpin + 'a>) -> Result<Self> {
        let mut ref_statuses = Vec::new();

        while let Some(line_result) = reader.readline().await {
            let packet_line = match line_result {
                Ok(Ok(packet_line)) => packet_line,
                Ok(Err(_)) => break,
                Err(_) => break,
            };
            let Some(data) = packet_line.as_text() else {
                continue;
            };
            let text = data.as_bstr().to_str_lossy();
            let text = text.trim_end();

            if let Some(rest) = text.strip_prefix("ok ") {
                ref_statuses.push((rest.as_bytes().into(), Status::Ok));
            } else if let Some(rest) = text.strip_prefix("ng ") {
                let (name, reason) = match rest.split_once(' ') {
                    Some((name, reason)) => (name, reason.to_string()),
                    None => (rest, "unknown".to_string()),
                };
                ref_statuses.push((name.as_bytes().into(), Status::Rejected(reason)));
            } else if text.starts_with("unpack ok") {
                // The pack itself unpacked, individual refs follow.
            } else if text.starts_with("unpack ") {
                bail!("The server failed to unpack the packfile: {text}");
            }
        }

        Ok(Response { ref_statuses })
    }
}
