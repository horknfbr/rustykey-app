//! Password generator (takes a caller-supplied CSPRNG).
//!
//! Port of `src/utils/passwordGenerator.ts`.

use rand_core::CryptoRng;
use std::fmt;

/// Generator settings; [`Default`] matches `DEFAULT_PASSWORD_OPTIONS`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordOptions {
    /// Requested length; clamped to 6–56.
    pub length: usize,
    /// A–Z.
    pub upper: bool,
    /// a–z.
    pub lower: bool,
    /// 0–9.
    pub digits: bool,
    /// `~!@#$%^&*+=-_`.
    pub special: bool,
    /// `"';:,.?`.
    pub punct: bool,
    /// `(){}[]<>`.
    pub braces: bool,
    /// A space (never first or last when avoidable).
    pub space: bool,
    /// Characters to remove from the selected sets.
    pub omit: String,
}

impl Default for PasswordOptions {
    /// Length 20 with upper, lower, digits and special on.
    fn default() -> Self {
        Self {
            length: 20,
            upper: true,
            lower: true,
            digits: true,
            special: true,
            punct: false,
            braces: false,
            space: false,
            omit: String::new(),
        }
    }
}

/// Why no password could be generated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordError {
    /// No set selected, or every selected character omitted.
    NoCharset,
}

impl fmt::Display for PasswordError {
    /// Writes the original error text.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Select at least one character set with available characters.")
    }
}

impl std::error::Error for PasswordError {}

/// The selected sets in order, minus omitted characters.
fn charset(opts: &PasswordOptions) -> Vec<char> {
    [
        (opts.upper, "ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        (opts.lower, "abcdefghijklmnopqrstuvwxyz"),
        (opts.digits, "0123456789"),
        (opts.special, "~!@#$%^&*+=-_"),
        (opts.punct, "\"';:,.?"),
        (opts.braces, "(){}[]<>"),
        (opts.space, " "),
    ]
    .into_iter()
    .filter(|(on, _)| *on)
    .flat_map(|(_, set)| set.chars())
    .filter(|c| !opts.omit.contains(*c))
    .collect()
}

/// Uniform index in `0..n` (n > 0).
fn random_index(n: usize, rng: &mut impl CryptoRng) -> usize {
    // The original used `u32 % n`, which favours low indices; rejecting the top partial
    // range of u32 values makes every index equally likely.
    let n = n as u64;
    let zone = (1u64 << 32) - (1u64 << 32) % n;
    loop {
        let v = u64::from(rng.next_u32());
        if v < zone {
            return (v % n) as usize;
        }
    }
}

/// Generates a password: length clamped to 6–56; with space on, the first and last characters
/// are re-rolled (up to 32 times) when they come out as a space.
pub fn generate(opts: &PasswordOptions, rng: &mut impl CryptoRng) -> Result<String, PasswordError> {
    let length = opts.length.clamp(6, 56);
    let set = charset(opts);
    if set.is_empty() {
        return Err(PasswordError::NoCharset);
    }
    let mut out = String::with_capacity(length);
    for i in 0..length {
        let mut c = set[random_index(set.len(), rng)];
        if opts.space && (i == 0 || i == length - 1) {
            for _ in 0..32 {
                if c != ' ' {
                    break;
                }
                c = set[random_index(set.len(), rng)];
            }
        }
        out.push(c);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    //! Ports of `passwordGenerator.test.ts`, plus clamp, bias and edge-space cases.

    use super::*;
    use core::convert::Infallible;
    use rand_core::{TryCryptoRng, TryRng};

    /// Deterministic test RNG: replays `script`, then a xorshift stream.
    struct TestRng {
        /// Values returned first, in order.
        script: Vec<u32>,
        /// Xorshift state for later values.
        state: u32,
    }

    impl TestRng {
        /// A pure xorshift stream from `seed`.
        fn new(seed: u32) -> Self {
            Self {
                script: Vec::new(),
                state: seed,
            }
        }
    }

    impl TryRng for TestRng {
        type Error = Infallible;

        /// Next scripted value, else the next xorshift value.
        fn try_next_u32(&mut self) -> Result<u32, Infallible> {
            if !self.script.is_empty() {
                return Ok(self.script.remove(0));
            }
            let mut x = self.state;
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            self.state = x;
            Ok(x)
        }

        /// Two u32 values.
        fn try_next_u64(&mut self) -> Result<u64, Infallible> {
            Ok(u64::from(self.try_next_u32()?) << 32 | u64::from(self.try_next_u32()?))
        }

        /// Fills with u32 bytes.
        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
            for chunk in dst.chunks_mut(4) {
                let v = self.try_next_u32()?.to_le_bytes();
                chunk.copy_from_slice(&v[..chunk.len()]);
            }
            Ok(())
        }
    }

    impl TryCryptoRng for TestRng {}

    /// Requested length is honoured.
    #[test]
    fn password_generator_generates_password_with_requested_length() {
        let opts = PasswordOptions {
            length: 16,
            ..Default::default()
        };
        assert_eq!(
            generate(&opts, &mut TestRng::new(1))
                .unwrap()
                .chars()
                .count(),
            16
        );
    }

    /// No set selected.
    #[test]
    fn password_generator_throws_when_no_charset_selected() {
        let opts = PasswordOptions {
            upper: false,
            lower: false,
            digits: false,
            special: false,
            ..Default::default()
        };
        assert_eq!(
            generate(&opts, &mut TestRng::new(1)),
            Err(PasswordError::NoCharset)
        );
    }

    /// Braces, punctuation and space are used.
    #[test]
    fn password_generator_includes_braces_punctuation_and_space_when_selected() {
        let opts = PasswordOptions {
            length: 40,
            upper: false,
            lower: false,
            digits: false,
            special: false,
            punct: true,
            braces: true,
            space: true,
            ..Default::default()
        };
        let pw = generate(&opts, &mut TestRng::new(7)).unwrap();
        assert_eq!(pw.chars().count(), 40);
        assert!(pw.chars().all(|c| "\"';:,.?(){}[]<> ".contains(c)));
        assert!(pw.chars().any(|c| " {}[]()<>.,;:!?".contains(c)));
    }

    /// Omitted characters never appear.
    #[test]
    fn password_generator_omits_excluded_characters() {
        let opts = PasswordOptions {
            length: 32,
            upper: false,
            digits: false,
            special: false,
            omit: "aeiou".into(),
            ..Default::default()
        };
        let pw = generate(&opts, &mut TestRng::new(3)).unwrap();
        assert!(!pw.contains(['a', 'e', 'i', 'o', 'u']));
    }

    /// Extra: length clamps to 6–56; omitting everything is an error.
    #[test]
    fn length_clamps_and_full_omit_errors() {
        let mut rng = TestRng::new(5);
        let short = PasswordOptions {
            length: 0,
            ..Default::default()
        };
        assert_eq!(generate(&short, &mut rng).unwrap().len(), 6);
        let long = PasswordOptions {
            length: 999,
            ..Default::default()
        };
        assert_eq!(generate(&long, &mut rng).unwrap().len(), 56);
        let none = PasswordOptions {
            upper: false,
            lower: false,
            special: false,
            omit: "0123456789".into(),
            ..Default::default()
        };
        assert_eq!(generate(&none, &mut rng), Err(PasswordError::NoCharset));
    }

    /// Extra: values in the biased top range of u32 are rejected, not folded with `%`.
    #[test]
    fn random_index_rejects_the_biased_tail() {
        // n = 10: zone = 2^32 - 6, so u32::MAX (2^32 - 1) is rejected and 13 → 3.
        let mut rng = TestRng {
            script: vec![u32::MAX, 13],
            state: 1,
        };
        assert_eq!(random_index(10, &mut rng), 3);
        assert!(rng.script.is_empty());
    }

    /// Extra: a space at either end is re-rolled; interior spaces stay.
    #[test]
    fn space_first_and_last_are_rerolled() {
        // Charset "a" + " " (index 1 = space). Script: first char space then 'a', middle spaces,
        // last char space then 'a'.
        let opts = PasswordOptions {
            length: 6,
            upper: false,
            digits: false,
            special: false,
            space: true,
            omit: "bcdefghijklmnopqrstuvwxyz".into(),
            ..Default::default()
        };
        let mut rng = TestRng {
            script: vec![1, 0, 1, 1, 1, 1, 1, 0],
            state: 1,
        };
        assert_eq!(generate(&opts, &mut rng).unwrap(), "a    a");
    }

    /// Extra: with only a space available, re-rolling gives up after 32 tries.
    #[test]
    fn space_only_charset_gives_up_after_32_rerolls() {
        let opts = PasswordOptions {
            upper: false,
            lower: false,
            digits: false,
            special: false,
            space: true,
            ..Default::default()
        };
        assert_eq!(
            generate(&opts, &mut TestRng::new(9)).unwrap(),
            " ".repeat(20)
        );
    }
}
