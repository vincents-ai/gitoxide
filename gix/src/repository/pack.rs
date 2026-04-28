//! Generate pack data from a list of object IDs for push operations.

use gix_hash::ObjectId;
use gix_object::Kind as ObjectKind;
use gix_pack::data::entry::Header;
use std::io::Write;

/// The error returned by [`Repository::pack_from_objects()`].
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum Error {
    #[error("Object {id} not found in repository")]
    NotFound { id: ObjectId },
    #[error("Failed to read object {id}")]
    Read { id: ObjectId, source: Box<dyn std::error::Error + Send + Sync> },
    #[error("IO error generating pack")]
    Io(#[from] std::io::Error),
}

impl crate::Repository {
    /// Generate pack data (PACK v2 format) from the given object IDs.
    ///
    /// No delta compression is used — each object is stored as a full entry.
    /// This is suitable for small numbers of objects (e.g. engram blob refs).
    /// For large pushes with many objects, delta compression would be more efficient.
    ///
    /// Returns the raw pack bytes ready to be sent to a remote via
    /// the git push protocol.
    pub fn pack_from_objects(
        &self,
        object_ids: &[ObjectId],
    ) -> Result<Vec<u8>, Error> {
        if object_ids.is_empty() {
            return Ok(Vec::new());
        }

        let mut pack = Vec::new();

        // Write pack header: "PACK" + version 2 + num objects
        let hdr = gix_pack::data::header::encode(gix_pack::data::Version::V2, object_ids.len() as u32);
        pack.extend_from_slice(&hdr);

        // Write each object as a pack entry
        for id in object_ids {
            let obj = self
                .try_find_object(*id)
                .map_err(|e| Error::Read { id: *id, source: Box::new(e) })?
                .ok_or_else(|| Error::NotFound { id: *id })?;

            let entry_header = match obj.kind {
                ObjectKind::Commit => Header::Commit,
                ObjectKind::Tree => Header::Tree,
                ObjectKind::Blob => Header::Blob,
                ObjectKind::Tag => Header::Tag,
            };

            // Write entry header (type + uncompressed size varint)
            entry_header.write_to(obj.data.len() as u64, &mut pack)?;

            // Write zlib-compressed object data
            let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
            encoder.write_all(&obj.data)?;
            let compressed = encoder.finish()?;
            pack.extend_from_slice(&compressed);
        }

        // Write trailing checksum (hash of all preceding pack data)
        let mut hasher = gix_hash::hasher(gix_hash::Kind::Sha1);
        hasher.update(&pack);
        let checksum = hasher.try_finalize().expect("SHA-1 hash never fails");
        pack.extend_from_slice(checksum.as_slice());

        Ok(pack)
    }
}
