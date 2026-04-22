// Modified for gitoxide from the upstream imara-diff crate.
// Upstream source: git cat-file -p 32d1e45d3df061e6ccba6db7fdce92db29e345d8:src/myers/preprocess.rs

use crate::intern::Token;
use crate::myers::sqrt;

/// Preprocesses token sequences by removing tokens that don't appear in the other sequence.
///
/// This optimization reduces the problem size for the Myers algorithm, improving performance
/// for files with many unique tokens.
pub fn preprocess<'a>(
    before: &[Token],
    after: &[Token],
    removed: &'a mut [bool],
    added: &'a mut [bool],
) -> (PreprocessedFile, PreprocessedFile) {
    let (occurrences_before, occurrences_after) = token_occurrences(before, after);
    let file1 = PreprocessedFile::new(&occurrences_before, before, removed);
    let file2 = PreprocessedFile::new(&occurrences_after, after, added);
    (file1, file2)
}

fn token_occurrences(file1: &[Token], file2: &[Token]) -> (Vec<Occurrences>, Vec<Occurrences>) {
    const MAX_EQLIMIT: u32 = 1024;

    // compute the limit after which tokens are treated as `Occurrences::COMMON`
    let eqlimit1 = sqrt(file1.len()).min(MAX_EQLIMIT);
    let eqlimit2 = sqrt(file2.len()).min(MAX_EQLIMIT);

    // first collect how often each token occurs in a file
    let mut occurrences1 = Vec::new();
    for token in file1 {
        let bucket = token.0 as usize;
        if bucket >= occurrences1.len() {
            occurrences1.resize(bucket + 1, 0u32);
        }
        occurrences1[bucket] += 1;
    }

    // do the same thing for
    let mut occurrences2 = Vec::new();
    let token_occurrences2: Vec<_> = file2
        .iter()
        .map(|token| {
            let bucket = token.0 as usize;
            if bucket >= occurrences2.len() {
                occurrences2.resize(bucket + 1, 0);
            }
            occurrences2[bucket] += 1;
            let occurrences1 = *occurrences1.get(bucket).unwrap_or(&0);
            Occurrences::from_occurrences(occurrences1, eqlimit2)
        })
        .collect();

    let token_occurrences1: Vec<_> = file1
        .iter()
        .map(|token| {
            let bucket = token.0 as usize;
            let occurrences2 = *occurrences2.get(bucket).unwrap_or(&0);
            Occurrences::from_occurrences(occurrences2, eqlimit1)
        })
        .collect();

    (token_occurrences1, token_occurrences2)
}

/// Categorizes how frequently a token appears in a file.
#[derive(Clone, Copy, Debug)]
enum Occurrences {
    /// Token does not occur in the other file.
    None,
    /// Token occurs at least once in the other file.
    Some,
    /// Token occurs very frequently in the other file (exact threshold depends on file size).
    /// Such tokens are usually empty lines or braces and are often not meaningful to a diff.
    Common,
}

impl Occurrences {
    pub fn from_occurrences(occurrences: u32, eqlimit: u32) -> Occurrences {
        if occurrences == 0 {
            Occurrences::None
        } else if occurrences >= eqlimit {
            Occurrences::Common
        } else {
            Occurrences::Some
        }
    }
}

/// A file after preprocessing has removed unmatched tokens.
#[derive(Debug)]
pub struct PreprocessedFile {
    /// Maps from new token positions to original positions in the unpreprocessed file.
    pub indices: Vec<u32>,
    /// The tokens that remain after preprocessing.
    pub tokens: Vec<Token>,
}

impl PreprocessedFile {
    fn new(token_occurrences: &[Occurrences], tokens: &[Token], changed: &mut [bool]) -> PreprocessedFile {
        let (tokens, indices) = prune_unmatched_tokens(tokens, token_occurrences, changed);
        PreprocessedFile { indices, tokens }
    }
}

fn prune_unmatched_tokens(
    file: &[Token],
    token_status: &[Occurrences],
    changed: &mut [bool],
) -> (Vec<Token>, Vec<u32>) {
    assert_eq!(token_status.len(), file.len());
    let prune_common = common_line_prune_map(token_status);
    file.iter()
        .zip(token_status)
        .enumerate()
        .filter_map(|(i, (&token, &status))| {
            let prune = match status {
                Occurrences::None => true,
                Occurrences::Some => false,
                Occurrences::Common => prune_common[i],
            };
            if prune {
                changed[i] = true;
                None
            } else {
                Some((token, i as u32))
            }
        })
        .unzip()
}

fn common_line_prune_map(token_status: &[Occurrences]) -> Vec<bool> {
    const WINDOW_SIZE: usize = 100;

    let mut prune = vec![false; token_status.len()];
    let mut start = 0;
    while start < token_status.len() {
        if matches!(token_status[start], Occurrences::Some) {
            start += 1;
            continue;
        }

        let mut end = start + 1;
        while end < token_status.len() && !matches!(token_status[end], Occurrences::Some) {
            end += 1;
        }

        let segment = &token_status[start..end];
        let mut none_prefix = vec![0usize; segment.len() + 1];
        let mut common_prefix = vec![0usize; segment.len() + 1];
        for (idx, status) in segment.iter().enumerate() {
            none_prefix[idx + 1] = none_prefix[idx] + usize::from(matches!(status, Occurrences::None));
            common_prefix[idx + 1] = common_prefix[idx] + usize::from(matches!(status, Occurrences::Common));
        }

        for (local_pos, status) in segment.iter().enumerate() {
            if !matches!(status, Occurrences::Common) {
                continue;
            }

            let before_start = local_pos.saturating_sub(WINDOW_SIZE);
            let unmatched_before = none_prefix[local_pos] - none_prefix[before_start];
            if unmatched_before == 0 {
                continue;
            }
            let common_before = common_prefix[local_pos] - common_prefix[before_start];

            let after_end = segment.len().min(local_pos + WINDOW_SIZE);
            let unmatched_after = none_prefix[after_end] - none_prefix[local_pos];
            if unmatched_after == 0 {
                continue;
            }
            let common_after = common_prefix[after_end] - common_prefix[local_pos];

            let common = common_before + common_after;
            let unmatched = unmatched_before + unmatched_after;
            prune[start + local_pos] = unmatched > 3 * common;
        }

        start = end;
    }
    prune
}

#[cfg(test)]
fn should_prune_common_line(token_status: &[Occurrences], pos: usize) -> bool {
    const WINDOW_SIZE: usize = 100;

    let mut unmatched_before = 0;
    let mut common_before = 0;

    let start = pos.saturating_sub(WINDOW_SIZE);
    for status in token_status[start..pos].iter().rev() {
        match status {
            Occurrences::None => {
                unmatched_before += 1;
            }
            Occurrences::Common => {
                common_before += 1;
            }
            Occurrences::Some => break,
        }
    }

    if unmatched_before == 0 {
        return false;
    }

    let end = token_status.len().min(pos + WINDOW_SIZE);
    let mut unmatched_after = 0;
    let mut common_after = 0;
    for status in token_status[pos..end].iter() {
        match status {
            Occurrences::None => {
                unmatched_after += 1;
            }
            Occurrences::Common => {
                common_after += 1;
            }
            Occurrences::Some => break,
        }
    }

    if unmatched_after == 0 {
        return false;
    }

    let common = common_before + common_after;
    let unmatched = unmatched_before + unmatched_after;

    unmatched > 3 * common
}

#[cfg(test)]
mod tests {
    use super::{common_line_prune_map, should_prune_common_line, Occurrences};

    #[test]
    fn common_line_pruning_ignores_distant_context() {
        let mut token_status = vec![Occurrences::Some; 700];
        token_status[100..400].fill(Occurrences::None);
        token_status[400..450].fill(Occurrences::None);
        token_status[450..500].fill(Occurrences::Common);
        token_status[500..550].fill(Occurrences::Common);
        token_status[550..600].fill(Occurrences::None);

        assert!(
            !should_prune_common_line(&token_status, 500),
            "only the last 100 items before the current line should contribute to the backward scan"
        );
    }

    #[test]
    fn common_line_prune_map_matches_scalar_logic() {
        for len in 0..=8 {
            let total = 3usize.pow(len as u32);
            for mut encoded in 0..total {
                let mut statuses = Vec::with_capacity(len);
                for _ in 0..len {
                    statuses.push(match encoded % 3 {
                        0 => Occurrences::None,
                        1 => Occurrences::Some,
                        _ => Occurrences::Common,
                    });
                    encoded /= 3;
                }

                let map = common_line_prune_map(&statuses);
                for (pos, status) in statuses.iter().enumerate() {
                    let expected = matches!(status, Occurrences::Common)
                        && should_prune_common_line(&statuses, pos);
                    assert_eq!(map[pos], expected, "statuses={statuses:?}, pos={pos}");
                }
            }
        }
    }
}
