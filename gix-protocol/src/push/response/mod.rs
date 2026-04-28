//! Push response — parse the server's status report after receiving the packfile.

use bstr::ByteSlice;
use crate::transport::client::blocking_io::ExtendedBufRead;

use crate::push::Status;

/// The response from a push operation.
#[derive(Debug)]
pub struct Response {
    /// The status of each ref update as reported by the server.
    pub ref_statuses: Vec<(bstr::BString, Status)>,
}

/// Error during response parsing.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum Error {
    #[error("IO error reading push response")]
    Io(#[from] std::io::Error),
}

impl Response {
    /// Parse the status report from a blocking reader.
    pub fn from_blocking_reader<'a>(
        mut reader: Box<dyn ExtendedBufRead<'a> + Unpin + 'a>,
    ) -> Result<Self, Error> {
        let mut ref_statuses = Vec::new();

        // Read lines from the response (sideband-multiplexed)
        while let Some(line_result) = reader.readline() {
            match line_result {
                Ok(Ok(packet_line)) => {
                    // Try to get text from the packet line
                    if let Some(data) = packet_line.as_text() {
                        let text = data.as_bstr().to_str_lossy();
                        let text = text.trim_end();

                        if let Some(rest) = text.strip_prefix("ok ") {
                            ref_statuses.push((rest.as_bytes().into(), Status::Ok));
                        } else if let Some(rest) = text.strip_prefix("ng ") {
                            if let Some((name, reason)) = rest.split_once(' ') {
                                ref_statuses
                                    .push((name.as_bytes().into(), Status::Rejected(reason.to_string())));
                            } else {
                                ref_statuses
                                    .push((rest.as_bytes().into(), Status::Rejected("unknown".to_string())));
                            }
                        } else if text.starts_with("unpack ok") {
                            // Unpack result — skip
                        } else if text.starts_with("unpack error") {
                            return Err(Error::Io(std::io::Error::other(format!(
                                "Server failed to unpack: {text}"
                            ))));
                        }
                    }
                }
                Ok(Err(_decode_err)) => break,
                Err(_io_err) => break,
            }
        }

        Ok(Response { ref_statuses })
    }
}
