//! Client-side `git-receive-pack` implementation for pushing refs and objects to a remote.
//!
//! The push protocol follows this flow:
//! 1. Handshake with `Service::ReceivePack` to get remote refs
//! 2. Send ref update commands (`<old-oid> <new-oid> <ref-name>\n`)
//! 3. Send a packfile containing all new objects
//! 4. Receive status report from server (`ok/ng <ref-name>` per ref)

mod arguments;
pub mod function;
mod response;
mod types;

pub use arguments::Arguments;
pub use function::{push, Error, Options};
pub use response::Response;
pub use types::{Outcome, RefUpdate, Status};
