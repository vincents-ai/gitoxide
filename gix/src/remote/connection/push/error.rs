//! Push errors.

/// The error returned by [`Connection::push()`](super::Connection::push()).
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum Error {
    #[error("Push protocol error")]
    Protocol(#[from] gix_protocol::push::Error),
}
