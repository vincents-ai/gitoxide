//! Generate pack data from a list of object IDs for push operations.

use gix_error::{OptionExt, Result, ResultExt, bail, message};
use gix_hash::ObjectId;
use gix_object::Kind as ObjectKind;
use gix_pack::data::entry::Header;
use std::io::Write;

impl crate::Repository {
    /// Generate pack data (PACK v2 format) from the given object IDs.
    ///
    /// No delta compression is used — each object is stored as a full entry.
    /// This is suitable for small numbers of objects (e.g. engram blob refs).
    /// For large pushes with many objects, delta compression would be more efficient.
    ///
    /// Returns the raw pack bytes ready to be sent to a remote via
    /// the git push protocol.
    pub fn pack_from_objects(&self, object_ids: &[ObjectId]) -> Result<Vec<u8>> {
        if object_ids.is_empty() {
            return Ok(Vec::new());
        }

        let mut pack = Vec::new();
        let hdr = gix_pack::data::header::encode(gix_pack::data::Version::V2, object_ids.len() as u32);
        pack.extend_from_slice(&hdr);

        for id in object_ids {
            let obj = self
                .try_find_object(*id)
                .or_raise(|| message!("Failed to read an object for the pack"))?
                .ok_or_raise(|| message!("An object to pack was not found in the repository"))?;

            let entry_header = match obj.kind {
                ObjectKind::Commit => Header::Commit,
                ObjectKind::Tree => Header::Tree,
                ObjectKind::Blob => Header::Blob,
                ObjectKind::Tag => Header::Tag,
            };

            entry_header
                .write_to(obj.data.len() as u64, &mut pack)
                .or_raise(|| message!("Failed to write a pack entry header"))?;

            let mut encoder = gix_zlib::stream::deflate::Write::new(Vec::new(), gix_zlib::Compression::default());
            encoder
                .write_all(&obj.data)
                .or_raise(|| message!("Failed to compress an object for the pack"))?;
            encoder
                .flush()
                .or_raise(|| message!("Failed to finish compressing an object for the pack"))?;
            let compressed = encoder.into_inner();
            pack.extend_from_slice(&compressed);
        }

        let mut hasher = gix_hash::hasher(gix_hash::Kind::Sha1);
        hasher.update(&pack);
        let checksum = match hasher.try_finalize() {
            Ok(checksum) => checksum,
            Err(_) => bail!("SHA-1 hashing of the pack failed"),
        };
        pack.extend_from_slice(checksum.as_slice());

        Ok(pack)
    }
}
