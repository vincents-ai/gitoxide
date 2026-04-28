//! Push support via gix-protocol.

use crate::remote::Connection;
use gix_features::progress::Discard;
use gix_protocol::push::Options;

mod error;
pub use error::Error;

// Re-export push types for consumers
#[allow(unused_imports)]
pub use gix_protocol::push::{RefUpdate, Outcome, Status};
// Aliases for consumers


impl<'remote, 'repo, T> Connection<'remote, 'repo, T>
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
    pub fn push(
        self,
        ref_updates: Vec<RefUpdate>,
        pack_data: &[u8],
    ) -> Result<Outcome, Error> {
        let trace = self.trace;

        // Prevent SendFlushOnDrop from sending flush on drop — push manages its own lifecycle
        let wrapper = std::mem::ManuallyDrop::new(self.transport);
        // SAFETY: We just wrapped it in ManuallyDrop, so Drop won't run.
        // We take ownership of inner transport for the push protocol.
        #[allow(unused_unsafe)]
        let transport = unsafe { std::ptr::read(&wrapper.inner) };

        gix_protocol::push::push(
            transport,
            |_action| -> Result<_, gix_credentials::protocol::Error> {
                Err(gix_credentials::protocol::Error::IdentityMissing {
                    context: gix_credentials::protocol::Context {
                        protocol: None,
                        host: None,
                        path: None,
                        username: None,
                        password: None,
                        oauth_refresh_token: None,
                        password_expiry_utc: None,
                        url: None,
                        quit: None,
                    },
                })
            },
            ref_updates,
            pack_data,
            Discard,
            Options { thin_pack: true, trace },
        )
        .map_err(Error::from)
    }
}
