//! Types for the push operation.

use bstr::BString;
use gix_hash::ObjectId;

/// A reference update command to send to the server.
#[derive(Debug, Clone)]
pub struct RefUpdate {
    /// The current object ID of the ref on the remote (zero for create).
    pub old_id: ObjectId,
    /// The new object ID to set the ref to (zero for delete).
    pub new_id: ObjectId,
    /// The full ref name (e.g. `refs/heads/main`).
    pub name: BString,
}

/// The status of a single ref update as reported by the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    /// The ref update was accepted.
    Ok,
    /// The ref update was rejected with a reason.
   Rejected(String),
}

/// The outcome of a push operation.
#[derive(Debug, Clone)]
pub struct Outcome {
    /// The status of each ref update, in the same order as the input.
    pub ref_statuses: Vec<(BString, Status)>,
}
