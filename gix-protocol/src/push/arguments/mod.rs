//! Push arguments — ref update commands sent to the server.

use gix_hash::ObjectId;

use crate::push::RefUpdate;

/// The arguments for a push operation — a list of ref update commands.
#[derive(Debug)]
pub struct Arguments {
    updates: Vec<RefUpdate>,
    /// Whether the server supports the `report-status` capability.
    report_status: bool,
    /// Whether the server supports the `side-band-64k` capability.
    sideband: bool,
    /// Whether the server supports the `quiet` capability.
    #[allow(dead_code)]
    quiet: bool,
    /// Protocol version being used.
    #[cfg(any(feature = "async-client", feature = "blocking-client"))]
    #[allow(dead_code)]
    version: gix_transport::Protocol,
}

impl Arguments {
    /// Create a new arguments instance with the given ref updates.
    #[cfg(any(feature = "async-client", feature = "blocking-client"))]
    pub fn new(
        updates: Vec<RefUpdate>,
        capabilities: &gix_transport::client::Capabilities,
        version: gix_transport::Protocol,
    ) -> Self {
        Self {
            updates,
            report_status: capabilities.contains("report-status")
                || capabilities.contains("report-status-v2"),
            sideband: capabilities.contains("side-band-64k")
                || capabilities.contains("side-band"),
            quiet: false,
            version,
        }
    }

    /// Returns true if there are no ref updates.
    pub fn is_empty(&self) -> bool {
        self.updates.is_empty()
    }

    /// Returns true if the server supports report-status.
    pub fn report_status(&self) -> bool {
        self.report_status
    }

    /// Returns true if the server supports sideband.
    pub fn sideband(&self) -> bool {
        self.sideband
    }

    /// Encode the ref update commands as pkt-line data.
    /// Returns the encoded bytes ready to send to the server (V1 format).
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        // In V1, each ref update command is: <old-oid> <new-oid> <ref-name>\0<capabilities>\n
        // First command includes capabilities, subsequent commands don't.
        let null_hash = ObjectId::null(gix_hash::Kind::Sha1);

        for (i, update) in self.updates.iter().enumerate() {
            let old = if update.old_id == null_hash {
                ObjectId::null(gix_hash::Kind::Sha1).to_hex().to_string()
            } else {
                update.old_id.to_hex().to_string()
            };
            let new = if update.new_id == null_hash {
                ObjectId::null(gix_hash::Kind::Sha1).to_hex().to_string()
            } else {
                update.new_id.to_hex().to_string()
            };

            if i == 0 {
                // First line: command + NUL + capabilities
                let mut caps = Vec::new();
                if self.report_status {
                    caps.extend_from_slice(b"report-status");
                }
                if self.sideband {
                    if !caps.is_empty() {
                        caps.push(b' ');
                    }
                    caps.extend_from_slice(b"side-band-64k");
                }
                let line = format!("{old} {new} ",);
                buf.extend_from_slice(line.as_bytes());
                buf.extend_from_slice(update.name.as_slice());
                buf.push(0); // NUL separator
                buf.extend_from_slice(&caps);
                buf.push(b'\n');
            } else {
                // Subsequent lines: just command
                let line = format!("{old} {new} ",);
                buf.extend_from_slice(line.as_bytes());
                buf.extend_from_slice(update.name.as_slice());
                buf.push(b'\n');
            }
        }

        buf
    }

    /// Return the ref updates.
    pub fn updates(&self) -> &[RefUpdate] {
        &self.updates
    }
}
