//! Push support via gix-protocol.

use crate::remote::Connection;
use crate::progress::Discard;
use gix_error::Result;
use gix_protocol::push::Options;

pub use gix_protocol::push::{Outcome, RefUpdate, Status};

impl<'remote, 'auth, 'repo, T> Connection<'remote, 'auth, 'repo, T>
where
    T: gix_transport::client::blocking_io::Transport,
{
    /// Push the given ref updates and pack data to the remote.
    ///
    /// The caller is responsible for generating the pack data (e.g. via
    /// [`crate::Repository::pack_from_objects()`]).
    ///
    /// Note: this consumes the connection. The connection is established
    /// by calling [`Remote::connect(Direction::Push)`](crate::Remote::connect).
    #[allow(unsafe_code)]
    pub fn push(self, ref_updates: Vec<RefUpdate>, pack_data: &[u8]) -> Result<Outcome> {
        let trace = self.trace;

        // Prevent SendFlushOnDrop from sending flush on drop — push manages its own lifecycle
        let wrapper = std::mem::ManuallyDrop::new(self.transport);
        // SAFETY: We just wrapped it in ManuallyDrop, so Drop won't run.
        // We take ownership of inner transport for the push protocol.
        #[allow(unused_unsafe)]
        let transport = unsafe { std::ptr::read(&wrapper.inner) };

        gix_protocol::push::push(
            transport,
            // No credential helper is consulted here; a push without usable
            // credentials fails in the transport instead.
            |_action| Ok(None),
            ref_updates,
            pack_data,
            Discard,
            Options { thin_pack: true, trace },
        )
    }
}
