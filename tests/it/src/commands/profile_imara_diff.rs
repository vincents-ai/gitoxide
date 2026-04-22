pub(super) mod function {
    use gix_imara_diff::{Algorithm, Diff, InternedInput};
    use std::{hint::black_box, path::PathBuf, time::Instant};

    pub fn profile_imara_diff(
        algorithm: Algorithm,
        repeat: usize,
        before_file: PathBuf,
        after_file: PathBuf,
    ) -> anyhow::Result<()> {
        let before = std::fs::read(&before_file)?;
        let after = std::fs::read(&after_file)?;

        let input = InternedInput::new(before.as_slice(), after.as_slice());
        let start = Instant::now();
        let mut diff = Diff::default();
        for _ in 0..repeat {
            diff = Diff::compute(algorithm, black_box(&input));
            black_box((diff.count_removals(), diff.count_additions()));
        }
        let elapsed = start.elapsed();

        println!("algorithm={}", algorithm_name(algorithm));
        println!("repeat={repeat}");
        println!("elapsed_ns={}", elapsed.as_nanos());
        println!("per_run_ns={}", elapsed.as_nanos() / repeat.max(1) as u128);
        println!("before_size={}", before.len());
        println!("after_size={}", after.len());
        println!("before_tokens={}", input.before.len());
        println!("after_tokens={}", input.after.len());
        println!("interner_tokens={}", input.interner.num_tokens());
        println!("removals={}", diff.count_removals());
        println!("additions={}", diff.count_additions());

        Ok(())
    }

    fn algorithm_name(algorithm: Algorithm) -> &'static str {
        match algorithm {
            Algorithm::Histogram => "histogram",
            Algorithm::Myers => "myers",
            Algorithm::MyersMinimal => "myers-minimal",
        }
    }
}
