pub(super) mod function {
    use anyhow::Context;
    use arbitrary::Arbitrary;
    use gix_imara_diff::{Algorithm, InternedInput};
    use gix_merge::blob::{
        builtin_driver::text::{Conflict, ConflictStyle, Merge},
        Resolution,
    };
    use std::{hint::black_box, num::NonZero, path::PathBuf, time::Instant};

    #[derive(Debug, Arbitrary)]
    struct FuzzCtx<'a> {
        base: &'a [u8],
        ours: &'a [u8],
        theirs: &'a [u8],
        marker_size: NonZero<u8>,
    }

    pub fn replay_merge_fuzz_case(
        algorithm: Algorithm,
        repeat: usize,
        cap: Option<usize>,
        fixture_file: PathBuf,
    ) -> anyhow::Result<()> {
        let fixture = std::fs::read(&fixture_file)
            .with_context(|| format!("failed to read fixture '{}'", fixture_file.display()))?;
        let input = match cap {
            Some(cap) => fixture
                .get(..cap)
                .with_context(|| format!("cap {cap} exceeds fixture size {}", fixture.len()))?,
            None => fixture.as_slice(),
        };

        let ctx = FuzzCtx::arbitrary(&mut arbitrary::Unstructured::new(input))
            .with_context(|| format!("failed to decode fuzz fixture '{}'", fixture_file.display()))?;

        let mut interned_input = InternedInput::default();
        let mut out = Vec::new();
        let start = Instant::now();
        for _ in 0..repeat {
            run_fuzz_case(
                &mut interned_input,
                &mut out,
                ctx.ours,
                ctx.base,
                ctx.theirs,
                ctx.marker_size,
                algorithm,
            );
            black_box(out.len());
        }
        let elapsed = start.elapsed();

        println!("algorithm={}", algorithm_name(algorithm));
        println!("repeat={repeat}");
        println!("elapsed_ns={}", elapsed.as_nanos());
        println!("per_run_ns={}", elapsed.as_nanos() / repeat.max(1) as u128);
        println!("fixture_size={}", fixture.len());
        println!("input_size={}", input.len());
        println!("ours_size={}", ctx.ours.len());
        println!("base_size={}", ctx.base.len());
        println!("theirs_size={}", ctx.theirs.len());
        println!("marker_size={}", ctx.marker_size);
        println!("last_output_size={}", out.len());
        Ok(())
    }

    fn run_fuzz_case<'a>(
        input: &mut InternedInput<&'a [u8]>,
        out: &mut Vec<u8>,
        ours: &'a [u8],
        base: &'a [u8],
        theirs: &'a [u8],
        marker_size: NonZero<u8>,
        algorithm: Algorithm,
    ) {
        for (left, right) in [(ours, theirs), (theirs, ours)] {
            input.clear();
            out.clear();
            let merge = Merge::new(input, left, base, right, algorithm);
            let resolution = merge.run(out, Default::default(), Conflict::default());
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
                    out.clear();
                    merge.run(out, Default::default(), conflict);
                }
            }
        }
    }

    fn algorithm_name(algorithm: Algorithm) -> &'static str {
        match algorithm {
            Algorithm::Histogram => "histogram",
            Algorithm::Myers => "myers",
            Algorithm::MyersMinimal => "myers-minimal",
        }
    }
}
