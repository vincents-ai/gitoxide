#![no_main]
use anyhow::Result;
use arbitrary::Arbitrary;
use gix_merge::blob::builtin_driver::text::{self, Conflict, ConflictStyle};
use gix_merge::blob::Resolution;
use libfuzzer_sys::fuzz_target;
use std::hint::black_box;
use std::num::NonZero;
use std::sync::OnceLock;

fn fuzz_text_merge(
    Ctx {
        base,
        ours,
        theirs,
        marker_size,
    }: Ctx,
) -> Result<()> {
    let mut buf = Vec::new();
    let mut input = imara_diff::InternedInput::default();
    let algorithm = fuzz_algorithm();
    let cap = fuzz_buffer_cap();
    let base = cap_bytes(base, cap);
    let ours = cap_bytes(ours, cap);
    let theirs = cap_bytes(theirs, cap);
    for (left, right) in [(ours, theirs), (theirs, ours)] {
        input.clear();
        let prepared = text::Merge::new(&mut input, left, base, right, algorithm);
        let resolution = prepared.run(&mut buf, Default::default(), Conflict::default());
        if resolution == Resolution::Conflict {
            for conflict in [
                Conflict::ResolveWithOurs,
                Conflict::ResolveWithTheirs,
                Conflict::ResolveWithUnion,
                Conflict::Keep {
                    style: ConflictStyle::Diff3,
                    marker_size,
                },
                Conflict::Keep {
                    style: ConflictStyle::ZealousDiff3,
                    marker_size,
                },
            ] {
                prepared.run(&mut buf, Default::default(), conflict);
            }
        }
    }
    Ok(())
}

fn fuzz_algorithm() -> imara_diff::Algorithm {
    static ALGORITHM: OnceLock<imara_diff::Algorithm> = OnceLock::new();
    *ALGORITHM.get_or_init(|| match std::env::var("GIX_MERGE_FUZZ_DIFF_ALGORITHM").ok().as_deref() {
        Some("myers") => imara_diff::Algorithm::Myers,
        Some("myers-minimal") => imara_diff::Algorithm::MyersMinimal,
        Some("histogram") | None => imara_diff::Algorithm::Histogram,
        Some(value) => panic!(
            "unsupported GIX_MERGE_FUZZ_DIFF_ALGORITHM={value:?}, expected histogram|myers|myers-minimal"
        ),
    })
}

fn fuzz_buffer_cap() -> Option<usize> {
    static BUFFER_CAP: OnceLock<Option<usize>> = OnceLock::new();
    *BUFFER_CAP.get_or_init(|| {
        std::env::var("GIX_MERGE_FUZZ_BUFFER_CAP")
            .ok()
            .map(|value| value.parse().expect("GIX_MERGE_FUZZ_BUFFER_CAP must be a usize"))
    })
}

fn cap_bytes(data: &[u8], cap: Option<usize>) -> &[u8] {
    cap.and_then(|cap| data.get(..cap)).unwrap_or(data)
}

#[derive(Debug, Arbitrary)]
struct Ctx<'a> {
    base: &'a [u8],
    ours: &'a [u8],
    theirs: &'a [u8],
    marker_size: NonZero<u8>,
}

fuzz_target!(|ctx: Ctx<'_>| {
    _ = black_box(fuzz_text_merge(ctx));
});
